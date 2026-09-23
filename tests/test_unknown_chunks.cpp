// Unrecognized chunk types (RFC 9260 3.2) and the Unrecognized Chunk Type
// error cause (3.3.10.6). Packets are fed straight into handle_recv_packet and
// the reply is read off the send queue, so no event loop or socket I/O runs.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "serialize.hpp"

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

namespace {

constexpr uint32_t OUR_TAG = 0x0A0B0C0D;
constexpr uint32_t PEER_TAG = 0x11223344;
constexpr uint16_t PEER_PORT = 40000;

sockaddr_in peer_address() {
    sockaddr_in src{};
    src.sin_family = AF_INET;
    src.sin_port = htons(PEER_PORT);
    sctp_parse_ipv4("127.0.0.1", src.sin_addr);
    return src;
}

} // namespace

struct SCTP_Socket_Test_Access {
    struct Result {
        size_t delivered;
        std::vector<SCTP_Packet> errors;
    };

    // state == nullptr means no TCB at all.
    static Result deliver(const Association_State* state, std::vector<SCTP_Chunk> chunks) {
        SCTP_Socket stack;
        sockaddr_in src = peer_address();
        Association_Key key{src};
        if (state) {
            Association assoc = stack.init_new_association(key);
            assoc.state = *state;
            assoc.this_ver_tag = OUR_TAG;
            assoc.peer_ver_tag = *state == COOKIE_WAIT ? 0 : PEER_TAG;
            assoc.last_peer_tsn = 0;
            stack.associations.insert_or_assign(key, assoc);
        }

        SCTP_Packet packet;
        packet.header = {PEER_PORT, 9899, OUR_TAG, 0};
        packet.chunks = std::move(chunks);
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.handle_recv_packet(wire.data(), wire.size(), src);

        Result result{0, {}};
        result.delivered = stack.receives.messages(key);
        auto now = std::chrono::steady_clock::now();
        while (auto pending = stack.sends.peek(now)) {
            const SCTP_Packet& sent = pending->deliverable.packet;
            if (!sent.chunks.empty() && sent.chunks[0].chunk_header.type == OP_ERROR) {
                result.errors.push_back(sent);
            }
            stack.sends.commit(pending->priority);
        }
        return result;
    }
};

namespace {

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

SCTP_Chunk unknown(uint8_t type, std::vector<uint8_t> body = {0xAA, 0xBB, 0xCC}, uint8_t flags = 0) {
    return {{static_cast<Chunk_Type>(type), flags, 0}, unknown_chunk_value{std::move(body)}};
}

SCTP_Chunk data(uint32_t tsn) {
    return {{DATA, 0, 0}, data_chunk_value{tsn, 0, 0, 0, {'x'}}};
}

const Association_State ESTABLISHED_STATE = ESTABLISHED;
const Association_State COOKIE_WAIT_STATE = COOKIE_WAIT;
const Association_State COOKIE_ECHOED_STATE = COOKIE_ECHOED;

using Access = SCTP_Socket_Test_Access;

void test_stop_and_report() {
    std::printf("01 (stop, report):\n");

    auto r = Access::deliver(&ESTABLISHED_STATE, {data(1), unknown(0x40, {0xAA, 0xBB, 0xCC}, 0x5A), data(2)});
    check(r.delivered == 1, "DATA before the chunk delivered, DATA after it discarded");
    check(r.errors.size() == 1, "one ERROR sent");
    if (r.errors.size() != 1) return;

    const SCTP_Packet& error = r.errors[0];
    check(error.header.verification_tag == PEER_TAG, "ERROR carries the peer's tag, not the inbound one");
    check(error.header.des_port == PEER_PORT, "ERROR goes back to the sender");

    // Chunk: 4 header + cause (4 header + 7-byte chunk = 11, padded to 12) = 16,
    // but Chunk Length is 4 + 12 = 16 since the cause padding sits inside it.
    std::vector<uint8_t> wire = serialize_sctp_packet(error);
    std::vector<uint8_t> want = {
        0x09, 0x00, 0x00, 0x10,                     // ERROR, length 16
        0x00, 0x06, 0x00, 0x0B,                     // cause 6, length 11
        0x40, 0x5A, 0x00, 0x07, 0xAA, 0xBB, 0xCC,   // the chunk as received, unpadded
        0x00,                                       // cause padding
    };
    check(wire.size() == SCTP_COMMON_HEADER_SIZE + want.size()
              && std::equal(want.begin(), want.end(), wire.begin() + SCTP_COMMON_HEADER_SIZE),
          "ERROR bytes match RFC 9260 3.3.10.6 layout");
}

void test_skip_and_report() {
    std::printf("11 (skip, report):\n");

    auto r = Access::deliver(&ESTABLISHED_STATE, {unknown(0xC0), unknown(0xC1), data(1)});
    check(r.delivered == 1, "DATA after skipped chunks delivered");
    check(r.errors.size() == 1, "one ERROR for the whole packet");
    if (r.errors.size() != 1) return;
    const auto& causes = std::get<error_chunk_value>(r.errors[0].chunks[0].chunk_value).causes;
    check(causes.size() == 2, "two causes in it");
    if (causes.size() == 2) {
        check(causes[0].code == CAUSE_UNRECOGNIZED_CHUNK && causes[0].info[0] == 0xC0
                  && causes[1].info[0] == 0xC1,
              "causes are cause 6, in packet order");
    }
}

void test_silent_types() {
    std::printf("00 (stop) and 10 (skip):\n");

    auto r = Access::deliver(&ESTABLISHED_STATE, {data(1), unknown(0x0F), data(2)});
    check(r.delivered == 1 && r.errors.empty(), "00: stops after the chunk, no ERROR");

    r = Access::deliver(&ESTABLISHED_STATE, {unknown(0x84), data(1)});
    check(r.delivered == 1 && r.errors.empty(), "10: skipped, DATA delivered, no ERROR");

    r = Access::deliver(&ESTABLISHED_STATE, {unknown(0x84), unknown(0x0F), data(1)});
    check(r.delivered == 0, "00 right after a skipped chunk still stops");

    r = Access::deliver(&ESTABLISHED_STATE, {unknown(0x0F), unknown(0x40), unknown(0xC0)});
    check(r.errors.empty(), "reportable chunks after a stop are not reported");

    r = Access::deliver(&ESTABLISHED_STATE, {unknown(0x0F)});
    check(r.delivered == 0 && r.errors.empty(), "packet left empty by a stop is harmless");
}

void test_who_gets_a_report() {
    std::printf("Report addressing:\n");

    auto r = Access::deliver(&COOKIE_ECHOED_STATE, {unknown(0xC0)});
    check(r.errors.size() == 1, "COOKIE_ECHOED knows the peer tag, so it reports");

    r = Access::deliver(&COOKIE_WAIT_STATE, {unknown(0xC0)});
    check(r.errors.empty(), "COOKIE_WAIT has no peer tag, so no report");

    r = Access::deliver(nullptr, {unknown(0xC0)});
    check(r.errors.empty(), "no TCB: packet fails the tag check, no report");
}

void test_report_fits_path() {
    std::printf("Report size:\n");

    // Each cause is 4 + (4 + 396) = 404 bytes. With a 4-byte chunk header,
    // two fit in 1200 (812) and a third does not (1216).
    std::vector<SCTP_Chunk> chunks;
    for (int i = 0; i < 5; ++i) chunks.push_back(unknown(0xC0, std::vector<uint8_t>(396, 0x55)));
    auto r = Access::deliver(&ESTABLISHED_STATE, std::move(chunks));
    check(r.errors.size() == 1, "one ERROR sent");
    if (r.errors.size() == 1) {
        const auto& causes = std::get<error_chunk_value>(r.errors[0].chunks[0].chunk_value).causes;
        check(causes.size() == 2, "trimmed to the causes that fit in PMDCS");
    }

    r = Access::deliver(&ESTABLISHED_STATE, {unknown(0xC0, std::vector<uint8_t>(1500, 0x55))});
    check(r.errors.empty(), "a single cause larger than PMDCS is not sent");
}

} // namespace

int main() {
    test_stop_and_report();
    test_skip_and_report();
    test_silent_types();
    test_who_gets_a_report();
    test_report_fits_path();

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
