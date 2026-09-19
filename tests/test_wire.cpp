// Wire-format conformance tests.
//
// These deliberately assert against externally-fixed values (RFC check vectors
// and hand-computed byte layouts) rather than against the implementation's own
// output. A loopback test where both ends share a bug cannot detect that bug;
// that is exactly how the CRC-32C polynomial error survived.

#include "checksum.hpp"
#include "serialize.hpp"
#include <sctp/sctp.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <string>

static int failures = 0;

static void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

static void check_eq_u32(uint32_t got, uint32_t want, const std::string& what) {
    bool ok = (got == want);
    std::printf("  [%s] %s (got 0x%08X want 0x%08X)\n",
                ok ? "PASS" : "FAIL", what.c_str(), got, want);
    if (!ok) failures++;
}

/*---------------------------------------------------------------------------*/

static void test_crc32c_check_vector() {
    std::printf("CRC-32C known-answer vectors:\n");

    // RFC 3309 / Castagnoli published check value.
    const char* s = "123456789";
    check_eq_u32(calculate_sctp_checksum((const uint8_t*)s, 9), 0xE3069283u,
                 "CRC32C(\"123456789\")");

    // Additional fixed vectors for CRC-32C.
    check_eq_u32(calculate_sctp_checksum((const uint8_t*)"", 0), 0x00000000u,
                 "CRC32C(\"\")");

    const uint8_t zeros[32] = {0};
    check_eq_u32(calculate_sctp_checksum(zeros, 32), 0x8A9136AAu,
                 "CRC32C(32 zero bytes)");

    std::vector<uint8_t> ff(32, 0xFF);
    check_eq_u32(calculate_sctp_checksum(ff.data(), 32), 0x62A8AB43u,
                 "CRC32C(32 0xFF bytes)");
}

static void test_common_header_is_big_endian() {
    std::printf("Common header wire layout (RFC 9260 3.1):\n");

    SCTP_Packet pkt;
    pkt.header.src_port = 0x1234;
    pkt.header.des_port = 0x5678;
    pkt.header.verification_tag = 0xDEADBEEF;
    pkt.header.checksum = 0;
    pkt.chunks.push_back(SCTP_Chunk{
        .chunk_header = { .type = COOKIE_ACK, .flag = 0, .length = 0 },
        .chunk_value = empty_chunk_value{}
    });

    std::vector<uint8_t> w = serialize_sctp_packet(pkt);

    check(w.size() == SCTP_COMMON_HEADER_SIZE + 4, "packet is header + 4-byte COOKIE_ACK");

    check(w[0] == 0x12 && w[1] == 0x34, "src_port big-endian on wire");
    check(w[2] == 0x56 && w[3] == 0x78, "des_port big-endian on wire");
    check(w[4] == 0xDE && w[5] == 0xAD && w[6] == 0xBE && w[7] == 0xEF,
          "verification_tag big-endian on wire");

    // Chunk header: type, flags, length(BE). COOKIE_ACK has no body, so len==4.
    check(w[12] == 11, "chunk type byte == COOKIE_ACK (11)");
    check(w[13] == 0, "chunk flags byte == 0");
    check(w[14] == 0x00 && w[15] == 0x04, "chunk length big-endian == 4");
}

static void test_checksum_field_is_little_endian() {
    std::printf("Checksum field endianness (RFC 9260 6.8 / RFC 3309):\n");

    SCTP_Packet pkt;
    pkt.header.src_port = 1;
    pkt.header.des_port = 2;
    pkt.header.verification_tag = 3;
    pkt.chunks.push_back(SCTP_Chunk{
        .chunk_header = { .type = COOKIE_ACK, .flag = 0, .length = 0 },
        .chunk_value = empty_chunk_value{}
    });

    std::vector<uint8_t> w = serialize_sctp_packet(pkt);

    // Recompute independently: zero the field, CRC the whole packet.
    std::vector<uint8_t> zeroed = w;
    sctp_clear_wire_checksum(zeroed.data());
    uint32_t expect = calculate_sctp_checksum(zeroed.data(), zeroed.size());

    uint32_t on_wire_le = static_cast<uint32_t>(w[8])
                        | static_cast<uint32_t>(w[9])  << 8
                        | static_cast<uint32_t>(w[10]) << 16
                        | static_cast<uint32_t>(w[11]) << 24;
    check_eq_u32(on_wire_le, expect, "checksum stored little-endian");

    // And the accessor agrees with the raw bytes.
    check_eq_u32(sctp_read_wire_checksum(w.data()), expect,
                 "sctp_read_wire_checksum matches");

    // Guard against the "swapped it like everything else" regression.
    uint32_t on_wire_be = static_cast<uint32_t>(w[11])
                        | static_cast<uint32_t>(w[10]) << 8
                        | static_cast<uint32_t>(w[9])  << 16
                        | static_cast<uint32_t>(w[8])  << 24;
    check(on_wire_be != expect || on_wire_be == on_wire_le,
          "checksum is NOT big-endian (would be an interop bug)");
}

static void test_roundtrip() {
    std::printf("Serialize/deserialize round-trip:\n");

    SCTP_Packet pkt;
    pkt.header.src_port = 9899;
    pkt.header.des_port = 5000;
    pkt.header.verification_tag = 0xA1B2C3D4;

    pkt.chunks.push_back(SCTP_Chunk{
        .chunk_header = { .type = INIT, .flag = 0, .length = 0 },
        .chunk_value = init_chunk_value{
            .initiate_tag = 0x11223344,
            .a_rwnd = 65535,
            .out_streams = 7,
            .in_streams = 9,
            .initial_tsn = 0xFFFFFFF0,
            .optional_parameters = {}
        }
    });

    std::vector<uint8_t> w = serialize_sctp_packet(pkt);
    SCTP_Packet back = deserialize_sctp_packet(w.data(), w.size());

    check(back.header.src_port == 9899, "src_port survives round-trip");
    check(back.header.des_port == 5000, "des_port survives round-trip");
    check_eq_u32(back.header.verification_tag, 0xA1B2C3D4, "verification_tag round-trip");

    check(back.chunks.size() == 1, "one chunk decoded");
    const auto& iv = std::get<init_chunk_value>(back.chunks[0].chunk_value);
    check_eq_u32(iv.initiate_tag, 0x11223344, "initiate_tag round-trip");
    check_eq_u32(iv.a_rwnd, 65535, "a_rwnd round-trip");
    check(iv.out_streams == 7, "out_streams round-trip");
    check(iv.in_streams == 9, "in_streams round-trip");
    check_eq_u32(iv.initial_tsn, 0xFFFFFFF0, "initial_tsn round-trip");

    // DATA chunk with a body that needs padding (19 bytes -> pad to 20).
    SCTP_Packet d;
    d.header.src_port = 1; d.header.des_port = 2; d.header.verification_tag = 5;
    std::string msg = "Hello from socket1!";   // 19 bytes
    d.chunks.push_back(SCTP_Chunk{
        .chunk_header = { .type = DATA, .flag = 0, .length = 0 },
        .chunk_value = data_chunk_value{
            .tsn = 0xCAFEBABE, .stream_identifier = 3, .stream_seq_num = 4,
            .payload_protocal = 0,
            .user_data = std::vector<uint8_t>(msg.begin(), msg.end())
        }
    });
    std::vector<uint8_t> dw = serialize_sctp_packet(d);

    // Chunk: 4 chunk header + 12 DATA header (TSN 4, sid 2, ssn 2, ppid 4)
    // + 19 payload = 35, padded to 36. Packet: 12 common header + 36 = 48.
    check(dw.size() == 48, "DATA packet padded to 4-byte boundary");
    check(dw[14] == 0x00 && dw[15] == 35, "DATA chunk length excludes padding (35)");

    SCTP_Packet dback = deserialize_sctp_packet(dw.data(), dw.size());
    const auto& dv = std::get<data_chunk_value>(dback.chunks[0].chunk_value);
    check_eq_u32(dv.tsn, 0xCAFEBABE, "tsn round-trip");
    check(dv.stream_identifier == 3, "stream_identifier round-trip");
    check(dv.stream_seq_num == 4, "stream_seq_num round-trip");
    check(std::string(dv.user_data.begin(), dv.user_data.end()) == msg,
          "payload round-trip (padding stripped)");
}

static void test_sack_wire_layout() {
    std::printf("SACK wire layout (RFC 9260 3.3.4):\n");

    SCTP_Packet packet;
    packet.header.src_port = 1;
    packet.header.des_port = 2;
    packet.header.verification_tag = 3;
    packet.chunks.push_back(SCTP_Chunk{
        .chunk_header = { .type = SACK, .flag = 0, .length = 0 },
        .chunk_value = sack_chunk_value{
            .cumulative_tsn_ack = 0x11223344,
            .a_rwnd = 0x55667788,
            .number_of_gap_ack_blocks = 2,
            .number_of_duplicate_tsns = 1,
            .gap_ack_blocks = {{1, 2}, {5, 7}},
            .duplicate_tsns = {0xAABBCCDD},
        },
    });

    std::vector<uint8_t> wire = serialize_sctp_packet(packet);
    const uint8_t expected_chunk[] = {
        0x03, 0x00, 0x00, 0x1C,
        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
        0x00, 0x02, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x02,
        0x00, 0x05, 0x00, 0x07,
        0xAA, 0xBB, 0xCC, 0xDD,
    };
    check(wire.size() == 40, "SACK packet has expected length");
    check(std::memcmp(
              wire.data() + SCTP_COMMON_HEADER_SIZE,
              expected_chunk, sizeof(expected_chunk)) == 0,
          "SACK fields use the RFC-defined order and byte order");

    SCTP_Packet decoded =
        deserialize_sctp_packet(wire.data(), wire.size());
    const auto& sack =
        std::get<sack_chunk_value>(decoded.chunks[0].chunk_value);
    check_eq_u32(
        sack.cumulative_tsn_ack, 0x11223344,
        "Cumulative TSN Ack decoded");
    check(sack.number_of_gap_ack_blocks == 2,
          "Number of Gap Ack Blocks decoded");
    check(sack.number_of_duplicate_tsns == 1,
          "Number of Duplicate TSNs decoded");
    check(sack.gap_ack_blocks.size() == 2,
          "Gap Ack Blocks decoded");
    check(sack.duplicate_tsns.size() == 1
              && sack.duplicate_tsns[0] == 0xAABBCCDD,
          "Duplicate TSN list decoded");
}

static void test_sack_deserialization_replaces_existing_value() {
    std::printf("SACK deserialization replaces existing value:\n");

    const uint8_t empty_sack_body[] = {
        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
        0x00, 0x00, 0x00, 0x00,
    };
    sack_chunk_value sack{
        .cumulative_tsn_ack = 1,
        .a_rwnd = 2,
        .number_of_gap_ack_blocks = 1,
        .number_of_duplicate_tsns = 1,
        .gap_ack_blocks = {{1, 1}},
        .duplicate_tsns = {3},
    };

    deserialize_sack_chunk(empty_sack_body, sizeof(empty_sack_body), sack);

    check(sack.number_of_gap_ack_blocks == 0,
          "Number of Gap Ack Blocks is replaced");
    check(sack.number_of_duplicate_tsns == 0,
          "Number of Duplicate TSNs is replaced");
    check(sack.gap_ack_blocks.empty(),
          "existing Gap Ack Blocks are cleared");
    check(sack.duplicate_tsns.empty(),
          "existing Duplicate TSNs are cleared");
}

static void test_sack_count_mismatch_is_rejected() {
    std::printf("SACK count/list consistency:\n");

    sack_chunk_value sack{
        .cumulative_tsn_ack = 1,
        .a_rwnd = 2,
        .number_of_gap_ack_blocks = 0,
        .number_of_duplicate_tsns = 0,
        .gap_ack_blocks = {{1, 1}},
        .duplicate_tsns = {},
    };
    std::vector<uint8_t> body;
    bool threw = false;
    try {
        serialize_sack_chunk(sack, body);
    } catch (const std::runtime_error&) {
        threw = true;
    }

    check(threw, "mismatched RFC count fields are rejected");
}

static void test_malformed_input_is_rejected() {
    std::printf("Malformed input handling:\n");

    auto throws = [](const std::vector<uint8_t>& b) {
        try { deserialize_sctp_packet(b.data(), b.size()); return false; }
        catch (const std::exception&) { return true; }
    };

    check(throws(std::vector<uint8_t>(4, 0)), "truncated common header throws");

    // Valid header, chunk header claiming length 0 -> would underflow the
    // body-length subtraction and wrap to a huge size_t.
    std::vector<uint8_t> b(16, 0);
    b[12] = 11; b[13] = 0; b[14] = 0; b[15] = 0;   // COOKIE_ACK, length 0
    check(throws(b), "chunk length 0 rejected (no size_t underflow)");

    // Chunk claiming more body than the datagram contains.
    std::vector<uint8_t> c(16, 0);
    c[12] = 0; c[13] = 0; c[14] = 0xFF; c[15] = 0xFF;   // DATA, length 65535
    check(throws(c), "chunk length beyond datagram rejected");
}

static std::vector<uint8_t> packet_with(SCTP_Chunk chunk) {
    SCTP_Packet pkt;
    pkt.header = {1, 2, 0x01020304, 0};
    pkt.chunks.push_back(std::move(chunk));
    return serialize_sctp_packet(pkt);
}

static bool bytes_at(const std::vector<uint8_t>& w, size_t at, const std::vector<uint8_t>& want) {
    return w.size() >= at + want.size() && std::equal(want.begin(), want.end(), w.begin() + at);
}

static void test_shutdown_family_wire_layout() {
    std::printf("SHUTDOWN / SHUTDOWN ACK / SHUTDOWN COMPLETE (RFC 9260 3.3.8, 3.3.9, 3.3.13):\n");

    auto w = packet_with({{SHUTDOWN, 0, 0}, shutdown_chunk_value{0xCAFEBABE}});
    check(w.size() == 20, "SHUTDOWN packet is 12 + 8 bytes");
    check(bytes_at(w, 12, {7, 0, 0x00, 0x08, 0xCA, 0xFE, 0xBA, 0xBE}),
          "SHUTDOWN: type 7, length 8, Cumulative TSN Ack big-endian");
    auto back = deserialize_sctp_packet(w.data(), w.size());
    check_eq_u32(std::get<shutdown_chunk_value>(back.chunks[0].chunk_value).cumulative_tsn_ack,
                 0xCAFEBABE, "SHUTDOWN Cumulative TSN Ack round-trip");

    w = packet_with({{SHUTDOWN_ACK, 0, 0}, empty_chunk_value{}});
    check(w.size() == 16 && bytes_at(w, 12, {8, 0, 0x00, 0x04}), "SHUTDOWN ACK: type 8, length 4");

    w = packet_with({{SHUTDOWN_COMPLETE, CHUNK_FLAG_T_BIT, 0}, empty_chunk_value{}});
    check(w.size() == 16 && bytes_at(w, 12, {14, 0x01, 0x00, 0x04}),
          "SHUTDOWN COMPLETE: type 14, T bit in flags bit 0, length 4");
    back = deserialize_sctp_packet(w.data(), w.size());
    check(back.chunks[0].chunk_header.type == SHUTDOWN_COMPLETE
              && back.chunks[0].chunk_header.flag == CHUNK_FLAG_T_BIT
              && std::holds_alternative<empty_chunk_value>(back.chunks[0].chunk_value),
          "SHUTDOWN COMPLETE decodes with T bit");

    std::vector<uint8_t> bad = {0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0x00, 0x06, 0xAA, 0xBB};
    bool threw = false;
    try { deserialize_sctp_packet(bad.data(), bad.size()); } catch (const std::exception&) { threw = true; }
    check(threw, "SHUTDOWN with a 2-byte body is rejected");
}

static void test_abort_wire_layout() {
    std::printf("ABORT (RFC 9260 3.3.7):\n");

    error_chunk_value causes;
    causes.causes.push_back({CAUSE_USER_INITIATED_ABORT, {'b', 'y', 'e'}});
    auto w = packet_with({{ABORT, CHUNK_FLAG_T_BIT, 0}, causes});
    // 4 chunk header + cause (4 header + 3 reason = 7, padded to 8) = 12; the
    // cause padding is inside the chunk, so it counts toward Chunk Length.
    check(w.size() == 24, "ABORT with a 3-byte reason is 12 + 12 bytes");
    check(bytes_at(w, 12, {6, 0x01, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x07, 'b', 'y', 'e', 0}),
          "ABORT: type 6, T bit, length 12, cause 12 length 7, padded");

    auto back = deserialize_sctp_packet(w.data(), w.size());
    const auto& decoded = std::get<error_chunk_value>(back.chunks[0].chunk_value);
    check(back.chunks[0].chunk_header.type == ABORT && decoded.causes.size() == 1
              && decoded.causes[0].code == CAUSE_USER_INITIATED_ABORT
              && decoded.causes[0].info == std::vector<uint8_t>{'b', 'y', 'e'},
          "ABORT cause round-trip");

    w = packet_with({{ABORT, 0, 0}, error_chunk_value{}});
    check(w.size() == 16 && bytes_at(w, 12, {6, 0, 0x00, 0x04}), "ABORT with no causes is length 4");
    back = deserialize_sctp_packet(w.data(), w.size());
    check(std::get<error_chunk_value>(back.chunks[0].chunk_value).causes.empty(), "empty ABORT decodes");
}

static void test_heartbeat_wire_layout() {
    std::printf("HEARTBEAT / HEARTBEAT ACK (RFC 9260 3.3.5, 3.3.6):\n");

    std::vector<uint8_t> info = {0xDE, 0xAD, 0xBE, 0xEF, 0x42};
    auto w = packet_with({{HEARTBEAT, 0, 0}, heartbeat_chunk_value{info}});
    // 4 chunk header + param (4 header + 5 info = 9, padded to 12) = 16.
    check(w.size() == 28, "HEARTBEAT with 5-byte info is 12 + 16 bytes");
    check(bytes_at(w, 12, {4, 0, 0x00, 0x10, 0x00, 0x01, 0x00, 0x09, 0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0, 0, 0}),
          "HEARTBEAT: type 4, Heartbeat Info param type 1, length 9, padded");

    auto back = deserialize_sctp_packet(w.data(), w.size());
    check(std::get<heartbeat_chunk_value>(back.chunks[0].chunk_value).info == info,
          "Heartbeat Info round-trip, padding stripped");

    w = packet_with({{HEARTBEAT_ACK, 0, 0}, heartbeat_chunk_value{info}});
    check(w[12] == 5, "HEARTBEAT ACK: type 5");
    back = deserialize_sctp_packet(w.data(), w.size());
    check(std::get<heartbeat_chunk_value>(back.chunks[0].chunk_value).info == info,
          "HEARTBEAT ACK info round-trip");

    // Parameter of type 2 instead of Heartbeat Info.
    std::vector<uint8_t> bad = {0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0x00, 0x08, 0x00, 0x02, 0x00, 0x04};
    bool threw = false;
    try { deserialize_sctp_packet(bad.data(), bad.size()); } catch (const std::exception&) { threw = true; }
    check(threw, "HEARTBEAT without Heartbeat Info is rejected");
}

static void test_unknown_chunk_is_preserved() {
    std::printf("Unrecognized chunk types (RFC 9260 3.2):\n");

    // Type 0xC5 (upper bits 11: skip and report), odd-length body, followed by
    // a SHUTDOWN ACK that must still be parsed.
    std::vector<uint8_t> w = {0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
                              0xC5, 0x3C, 0x00, 0x07, 0xAA, 0xBB, 0xCC, 0x00,
                              8, 0, 0x00, 0x04};
    SCTP_Packet back;
    bool threw = false;
    try { back = deserialize_sctp_packet(w.data(), w.size()); } catch (const std::exception&) { threw = true; }
    check(!threw && back.chunks.size() == 2, "unknown chunk does not abort parsing");
    if (back.chunks.size() == 2) {
        const auto& unknown = back.chunks[0];
        check(unknown.chunk_header.type == 0xC5 && unknown.chunk_header.flag == 0x3C
                  && unknown.chunk_header.length == 7,
              "unknown chunk header preserved");
        check(std::get<unknown_chunk_value>(unknown.chunk_value).body == std::vector<uint8_t>{0xAA, 0xBB, 0xCC},
              "unknown chunk body preserved, padding stripped");
        check(back.chunks[1].chunk_header.type == SHUTDOWN_ACK, "chunk after it still parsed");

        SCTP_Packet again;
        again.header = back.header;
        again.chunks = back.chunks;
        std::vector<uint8_t> rw = serialize_sctp_packet(again);
        check(bytes_at(rw, 12, {0xC5, 0x3C, 0x00, 0x07, 0xAA, 0xBB, 0xCC, 0x00, 8, 0, 0x00, 0x04}),
              "unknown chunk re-serializes byte for byte");
    }
}

int main() {
    test_crc32c_check_vector();
    test_common_header_is_big_endian();
    test_checksum_field_is_little_endian();
    test_roundtrip();
    test_sack_wire_layout();
    test_sack_deserialization_replaces_existing_value();
    test_sack_count_mismatch_is_rejected();
    test_malformed_input_is_rejected();
    test_shutdown_family_wire_layout();
    test_abort_wire_layout();
    test_heartbeat_wire_layout();
    test_unknown_chunk_is_preserved();

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
