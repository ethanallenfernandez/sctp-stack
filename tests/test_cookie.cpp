// State cookie, TLV parameter and ERROR codecs in isolation.
//
// The wire-layout assertions are RFC-fixed - type 7, length 100, big-endian -
// so a self-consistent encoder bug cannot pass them. Round-trips are the
// weaker half.

#include <sctp/sctp.hpp>
#include "serialize.hpp"
#include "hmac.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

void check_eq(uint64_t got, uint64_t want, const std::string& what) {
    bool ok = got == want;
    std::printf("  [%s] %s", ok ? "PASS" : "FAIL", what.c_str());
    if (!ok) {
        std::printf(" (got %llu want %llu)", static_cast<unsigned long long>(got), static_cast<unsigned long long>(want));
        failures++;
    }
    std::printf("\n");
}

uint16_t rd16be(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] << 8 | p[1]);
}

// Every field distinct, so a serializer crossing two of them shows up.
State_Cookie sample_cookie() {
    State_Cookie cookie{};
    cookie.version = STATE_COOKIE_VERSION;
    cookie.secret_generation = 0x07;
    cookie.created_us = 0x0123456789ABCDEFull;
    cookie.lifespan_us = 60000000;
    cookie.sctp_src_port = 0x1234;
    cookie.sctp_dst_port = 0x5678;
    cookie.peer_ipv4 = 0x0A000205;              // 10.0.2.5 in host order
    cookie.peer_udp_port = 0x9ABC;
    cookie.local_ver_tag = 0xDEADBEEF;
    cookie.peer_ver_tag = 0xFEEDFACE;
    cookie.local_initial_tsn = 0x11111111;
    cookie.peer_initial_tsn = 0x22222222;
    cookie.peer_a_rwnd = 0x33333333;
    cookie.local_out_streams = 0x0101;
    cookie.local_in_streams = 0x0202;
    cookie.peer_out_streams = 0x0303;
    cookie.peer_in_streams = 0x0404;
    cookie.local_tie_tag = 0x55555555;
    cookie.peer_tie_tag = 0x66666666;
    for (size_t i = 0; i < STATE_COOKIE_MAC_SIZE; i++) {
        cookie.mac[i] = static_cast<uint8_t>(0x80 + i);
    }
    return cookie;
}

/*------------------------------ TLV parameters -----------------------------*/

void test_parameters() {
    std::printf("TLV parameters (RFC 9260 3.2.1):\n");

    std::vector<uint8_t> params;
    const uint8_t value[3] = {0xAA, 0xBB, 0xCC};
    append_parameter(params, PARAM_STATE_COOKIE, value, sizeof(value));

    // 4 + 3 = 7, padded to 8. Length excludes padding.
    check_eq(params.size(), 8, "3-byte value pads to 8 bytes");
    check_eq(rd16be(&params[0]), PARAM_STATE_COOKIE, "type is big-endian");
    check_eq(rd16be(&params[2]), 7, "length counts the header and excludes padding");
    check_eq(params[7], 0, "padding byte is zero");

    std::vector<uint8_t> found;
    check(find_parameter(params, PARAM_STATE_COOKIE, found), "padded parameter is found");
    check(found.size() == 3 && std::memcmp(found.data(), value, 3) == 0, "value recovered without padding");

    // Must be reachable across the first one's padding.
    const uint8_t second[4] = {0x01, 0x02, 0x03, 0x04};
    append_parameter(params, PARAM_COOKIE_PRESERVATIVE, second, sizeof(second));
    check(find_parameter(params, PARAM_COOKIE_PRESERVATIVE, found), "second parameter found across padding");
    check(found.size() == 4 && std::memcmp(found.data(), second, 4) == 0, "second value recovered");
    check(find_parameter(params, PARAM_STATE_COOKIE, found), "first parameter still found");

    check(!find_parameter(params, PARAM_IPV6_ADDRESS, found), "absent parameter reports false");
    check(!find_parameter({}, PARAM_STATE_COOKIE, found), "empty list reports false");

    // Attacker-controlled. Length < 4 spins the walk forever; an overrunning
    // one reads off the end.
    std::vector<uint8_t> malformed = {0x00, 0x07, 0x00, 0x02};
    check(!find_parameter(malformed, PARAM_STATE_COOKIE, found), "length below 4 is rejected, not looped on");

    std::vector<uint8_t> overrun = {0x00, 0x07, 0x00, 0xFF, 0x00, 0x00};
    check(!find_parameter(overrun, PARAM_STATE_COOKIE, found), "length overrunning the buffer is rejected");

    std::vector<uint8_t> truncated = {0x00, 0x07, 0x00};
    check(!find_parameter(truncated, PARAM_STATE_COOKIE, found), "header shorter than 4 bytes is rejected");
}

/*------------------------------- state cookie ------------------------------*/

void test_cookie_round_trip() {
    std::printf("State cookie codec (RFC 9260 5.1.3):\n");

    State_Cookie original = sample_cookie();
    std::vector<uint8_t> wire = serialize_state_cookie(original);

    check_eq(wire.size(), STATE_COOKIE_SIZE, "serialized cookie is 96 bytes");
    check_eq(STATE_COOKIE_BODY_SIZE, 64, "body is 64 bytes");

    State_Cookie decoded{};
    check(deserialize_state_cookie(wire, decoded), "round-trip deserializes");

    check_eq(decoded.version, original.version, "version");
    check_eq(decoded.secret_generation, original.secret_generation, "secret_generation");
    check_eq(decoded.created_us, original.created_us, "created_us (64-bit, split across two words)");
    check_eq(decoded.lifespan_us, original.lifespan_us, "lifespan_us");
    check_eq(decoded.sctp_src_port, original.sctp_src_port, "sctp_src_port");
    check_eq(decoded.sctp_dst_port, original.sctp_dst_port, "sctp_dst_port");
    check_eq(decoded.peer_ipv4, original.peer_ipv4, "peer_ipv4");
    check_eq(decoded.peer_udp_port, original.peer_udp_port, "peer_udp_port");
    check_eq(decoded.local_ver_tag, original.local_ver_tag, "local_ver_tag");
    check_eq(decoded.peer_ver_tag, original.peer_ver_tag, "peer_ver_tag");
    check_eq(decoded.local_initial_tsn, original.local_initial_tsn, "local_initial_tsn");
    check_eq(decoded.peer_initial_tsn, original.peer_initial_tsn, "peer_initial_tsn");
    check_eq(decoded.peer_a_rwnd, original.peer_a_rwnd, "peer_a_rwnd");
    check_eq(decoded.local_out_streams, original.local_out_streams, "local_out_streams");
    check_eq(decoded.local_in_streams, original.local_in_streams, "local_in_streams");
    check_eq(decoded.peer_out_streams, original.peer_out_streams, "peer_out_streams");
    check_eq(decoded.peer_in_streams, original.peer_in_streams, "peer_in_streams");
    check_eq(decoded.local_tie_tag, original.local_tie_tag, "local_tie_tag");
    check_eq(decoded.peer_tie_tag, original.peer_tie_tag, "peer_tie_tag");
    check(std::memcmp(decoded.mac, original.mac, STATE_COOKIE_MAC_SIZE) == 0, "mac");

    // Big-endian, like every other field in the stack.
    check_eq(wire[0], STATE_COOKIE_VERSION, "version at offset 0");
    check_eq(wire[1], 0x07, "secret_generation at offset 1");
    check_eq(rd16be(&wire[16]), 0x1234, "sctp_src_port big-endian at offset 16");
    check_eq(rd16be(&wire[2]), 0, "offset 2 is reserved and zeroed");
    check_eq(rd16be(&wire[26]), 0, "offset 26 is reserved and zeroed");

    // Plain suffix, never interleaved, so the caller can write it into the tail
    // after hashing the first 64 bytes.
    check(std::memcmp(wire.data() + STATE_COOKIE_BODY_SIZE, original.mac, STATE_COOKIE_MAC_SIZE) == 0,
          "mac occupies bytes 64..96");
}

void test_cookie_rejects_bad_input() {
    std::printf("State cookie rejection:\n");

    std::vector<uint8_t> wire = serialize_state_cookie(sample_cookie());
    State_Cookie decoded{};

    std::vector<uint8_t> short_cookie(wire.begin(), wire.end() - 1);
    check(!deserialize_state_cookie(short_cookie, decoded), "95-byte cookie is rejected");

    std::vector<uint8_t> long_cookie = wire;
    long_cookie.push_back(0);
    check(!deserialize_state_cookie(long_cookie, decoded), "97-byte cookie is rejected");

    check(!deserialize_state_cookie({}, decoded), "empty cookie is rejected");

    std::vector<uint8_t> wrong_version = wire;
    wrong_version[0] = STATE_COOKIE_VERSION + 1;
    check(!deserialize_state_cookie(wrong_version, decoded), "unknown version is rejected");
}

// The layout exists to serve a MAC: authenticate 64 bytes, cover every field.
void test_cookie_mac_placement() {
    std::printf("State cookie MAC coverage:\n");

    const uint8_t secret[COOKIE_SECRET_SIZE] = {0};
    State_Cookie cookie = sample_cookie();
    std::vector<uint8_t> wire = serialize_state_cookie(cookie);
    hmac_sha256(secret, sizeof(secret), wire.data(), STATE_COOKIE_BODY_SIZE, wire.data() + STATE_COOKIE_BODY_SIZE);

    uint8_t reference[SHA256_DIGEST_SIZE];
    std::memcpy(reference, wire.data() + STATE_COOKIE_BODY_SIZE, SHA256_DIGEST_SIZE);

    // Must reproduce the same 64 bytes, or a cookie fails to verify against the
    // MAC just minted for it.
    State_Cookie decoded{};
    check(deserialize_state_cookie(wire, decoded), "MAC'd cookie deserializes");
    std::vector<uint8_t> reserialized = serialize_state_cookie(decoded);
    check(std::memcmp(wire.data(), reserialized.data(), STATE_COOKIE_BODY_SIZE) == 0,
          "re-serializing a decoded cookie reproduces the body byte for byte");

    uint8_t recomputed[SHA256_DIGEST_SIZE];
    hmac_sha256(secret, sizeof(secret), reserialized.data(), STATE_COOKIE_BODY_SIZE, recomputed);
    check(constant_time_equal(reference, recomputed, SHA256_DIGEST_SIZE), "recomputed MAC matches after a round-trip");

    // A field outside the MAC'd range would be attacker-editable. 56-63 are
    // the tie-tags.
    for (size_t i = 0; i < STATE_COOKIE_BODY_SIZE; i++) {
        std::vector<uint8_t> tampered = wire;
        tampered[i] ^= 0x01;
        uint8_t tag[SHA256_DIGEST_SIZE];
        hmac_sha256(secret, sizeof(secret), tampered.data(), STATE_COOKIE_BODY_SIZE, tag);
        if (constant_time_equal(reference, tag, SHA256_DIGEST_SIZE)) {
            check(false, "flipping body byte " + std::to_string(i) + " changes the MAC");
            return;
        }
    }
    check(true, "flipping any of the 64 body bytes changes the MAC");
}

/*--------------------- cookie inside a real INIT ACK -----------------------*/

void test_cookie_in_init_ack() {
    std::printf("State Cookie parameter inside an INIT ACK (RFC 9260 3.3.3.1.1):\n");

    std::vector<uint8_t> cookie_bytes = serialize_state_cookie(sample_cookie());
    std::vector<uint8_t> parameters;
    append_parameter(parameters, PARAM_STATE_COOKIE, cookie_bytes.data(), cookie_bytes.size());

    check_eq(parameters.size(), 100, "State Cookie TLV is 100 bytes, needing no padding");
    check_eq(rd16be(&parameters[0]), 7, "parameter type is 7");
    check_eq(rd16be(&parameters[2]), 100, "parameter length is 100");

    SCTP_Packet packet;
    packet.header.src_port = 5000;
    packet.header.des_port = 6000;
    packet.header.verification_tag = 0xAABBCCDD;
    packet.chunks.push_back(SCTP_Chunk{
        .chunk_header = {.type = INIT_ACK, .flag = 0, .length = 0},
        .chunk_value = init_chunk_value{
            .initiate_tag = 0xDEADBEEF,
            .a_rwnd = RWND,
            .out_streams = 1,
            .in_streams = 1,
            .initial_tsn = 0x11111111,
            .optional_parameters = parameters,
        },
    });

    std::vector<uint8_t> wire = serialize_sctp_packet(packet);
    // 12 header + 4 chunk header + 16 fixed INIT fields + 100 TLV.
    check_eq(wire.size(), 132, "INIT ACK with a cookie is 132 bytes on the wire");
    check_eq(rd16be(&wire[14]), 120, "INIT ACK chunk length is 120");

    SCTP_Packet decoded = deserialize_sctp_packet(wire.data(), wire.size());
    check(decoded.chunks.size() == 1 && decoded.chunks[0].chunk_header.type == INIT_ACK, "INIT ACK decoded");

    const auto& init_ack = std::get<init_chunk_value>(decoded.chunks[0].chunk_value);
    std::vector<uint8_t> recovered;
    check(find_parameter(init_ack.optional_parameters, PARAM_STATE_COOKIE, recovered), "cookie located in optional_parameters");
    check(recovered == cookie_bytes, "cookie survives the full packet round-trip byte for byte");

    State_Cookie decoded_cookie{};
    check(deserialize_state_cookie(recovered, decoded_cookie), "recovered cookie deserializes");
    check_eq(decoded_cookie.peer_ver_tag, 0xFEEDFACE, "peer_ver_tag survives end to end");
}

/*--------------------------------- ERROR -----------------------------------*/

void test_error_chunk() {
    std::printf("ERROR chunk and Stale Cookie cause (RFC 9260 3.3.10.3):\n");

    error_chunk_value error;
    std::vector<uint8_t> staleness = {0x00, 0x01, 0x86, 0xA0};      // 100000 usec
    error.causes.push_back(error_cause{CAUSE_STALE_COOKIE, staleness});

    SCTP_Packet packet;
    packet.header.src_port = 5000;
    packet.header.des_port = 6000;
    packet.header.verification_tag = 0x12345678;
    packet.chunks.push_back(SCTP_Chunk{
        .chunk_header = {.type = OP_ERROR, .flag = 0, .length = 0},
        .chunk_value = error,
    });

    std::vector<uint8_t> wire = serialize_sctp_packet(packet);
    check_eq(wire.size(), 24, "ERROR with one 8-byte cause is 24 bytes");
    check_eq(wire[12], 9, "chunk type is 9");
    check_eq(rd16be(&wire[14]), 12, "chunk length is 12");
    check_eq(rd16be(&wire[16]), 3, "cause code is 3 (Stale Cookie)");
    check_eq(rd16be(&wire[18]), 8, "cause length is 8");

    SCTP_Packet decoded = deserialize_sctp_packet(wire.data(), wire.size());
    check(decoded.chunks.size() == 1 && decoded.chunks[0].chunk_header.type == OP_ERROR, "ERROR chunk decoded");

    const auto& decoded_error = std::get<error_chunk_value>(decoded.chunks[0].chunk_value);
    check(decoded_error.causes.size() == 1, "one cause decoded");
    if (decoded_error.causes.size() == 1) {
        check_eq(decoded_error.causes[0].code, CAUSE_STALE_COOKIE, "cause code round-trips");
        check(decoded_error.causes[0].info == staleness, "Measure of Staleness round-trips");
    }

    // First an odd length, to prove the walk crosses padding.
    error_chunk_value multi;
    multi.causes.push_back(error_cause{CAUSE_STALE_COOKIE, {0x01, 0x02, 0x03}});
    multi.causes.push_back(error_cause{CAUSE_COOKIE_WHILE_SHUTTING_DOWN, {}});
    std::vector<uint8_t> body;
    serialize_error_chunk(multi, body);
    check_eq(body.size(), 12, "7-byte cause pads to 8, plus a 4-byte cause");

    error_chunk_value reparsed;
    deserialize_error_chunk(body.data(), body.size(), reparsed);
    check(reparsed.causes.size() == 2, "both causes decoded across padding");
    if (reparsed.causes.size() == 2) {
        check_eq(reparsed.causes[1].code, CAUSE_COOKIE_WHILE_SHUTTING_DOWN, "second cause code");
        check(reparsed.causes[1].info.empty(), "zero-length cause value");
    }

    bool threw = false;
    std::vector<uint8_t> bad = {0x00, 0x03, 0x00, 0x02};
    try {
        error_chunk_value ignored;
        deserialize_error_chunk(bad.data(), bad.size(), ignored);
    } catch (const std::exception&) {
        threw = true;
    }
    check(threw, "cause length below 4 throws");
}

} // namespace

int main() {
    test_parameters();
    test_cookie_round_trip();
    test_cookie_rejects_bad_input();
    test_cookie_mac_placement();
    test_cookie_in_init_ack();
    test_error_chunk();

    if (failures == 0) {
        std::printf("\nALL TESTS PASSED (0 failures)\n");
    } else {
        std::printf("\n%d FAILURE(S)\n", failures);
    }
    return failures == 0 ? 0 : 1;
}
