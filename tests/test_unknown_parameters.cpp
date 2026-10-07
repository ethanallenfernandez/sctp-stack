// Unrecognized INIT and INIT ACK parameters (RFC 9260 3.2.1, 3.2.2) and the
// Host Name Address parameter (3.3.2.1.4). Packets are fed straight into
// handle_recv_packet and the reply is read off the send queue.

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
constexpr uint16_t OUR_PORT = 9899;

sockaddr_in peer_address() {
    sockaddr_in src{};
    src.sin_family = AF_INET;
    src.sin_port = htons(PEER_PORT);
    sctp_parse_ipv4("127.0.0.1", src.sin_addr);
    return src;
}

std::vector<uint8_t> parameter(uint16_t type, std::vector<uint8_t> value) {
    std::vector<uint8_t> out;
    append_parameter(out, type, value.data(), value.size());
    return out;
}

std::vector<uint8_t> concat(std::initializer_list<std::vector<uint8_t>> parts) {
    std::vector<uint8_t> out;
    for (const auto& part : parts) out.insert(out.end(), part.begin(), part.end());
    return out;
}

SCTP_Chunk init_chunk(Chunk_Type type, std::vector<uint8_t> params) {
    return {{type, 0, 0}, init_chunk_value{PEER_TAG, RWND, 10, 10, 1000, std::move(params)}};
}

} // namespace

struct SCTP_Socket_Test_Access {
    struct Result {
        std::vector<SCTP_Packet> sent;
        bool association_left = false;
        Association_State state{};
    };

    static Result deliver(bool cookie_wait, uint32_t tag, SCTP_Chunk chunk) {
        SCTP_Socket stack;
        sockaddr_in src = peer_address();
        Association_Key key{src};
        if (cookie_wait) {
            Association assoc = stack.init_new_association(key);
            assoc.state = COOKIE_WAIT;
            assoc.this_ver_tag = OUR_TAG;
            assoc.peer_ver_tag = 0;
            stack.associations.insert_or_assign(key, assoc);
        }

        SCTP_Packet packet;
        packet.header = {PEER_PORT, OUR_PORT, tag, 0};
        packet.chunks = {std::move(chunk)};
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.handle_recv_packet(wire.data(), wire.size(), src);

        Result result;
        auto now = std::chrono::steady_clock::now();
        while (auto pending = stack.sends.peek(now)) {
            // Round trip through the wire so the test sees what the peer would.
            std::vector<uint8_t> bytes = serialize_sctp_packet(pending->deliverable.packet);
            result.sent.push_back(deserialize_sctp_packet(bytes.data(), bytes.size()));
            stack.sends.commit(*pending);
        }
        auto it = stack.associations.find(key);
        result.association_left = it != stack.associations.end();
        if (result.association_left) result.state = it->second.state;
        return result;
    }
};

namespace {

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

using Access = SCTP_Socket_Test_Access;

const SCTP_Packet* first_with(const Access::Result& r, Chunk_Type type) {
    for (const auto& packet : r.sent) {
        if (!packet.chunks.empty() && packet.chunks[0].chunk_header.type == type) return &packet;
    }
    return nullptr;
}

// Every Unrecognized Parameter in an INIT ACK, values in order.
std::vector<std::vector<uint8_t>> unrecognized_in(const SCTP_Packet& init_ack) {
    const auto& params = std::get<init_chunk_value>(init_ack.chunks[0].chunk_value).optional_parameters;
    Parameter_Scan scan = scan_parameters(params, {PARAM_STATE_COOKIE, PARAM_UNRECOGNIZED});
    std::vector<std::vector<uint8_t>> out;
    size_t offset = 0;
    while (offset + 4 <= scan.recognized.size()) {
        uint16_t type = static_cast<uint16_t>(scan.recognized[offset] << 8 | scan.recognized[offset + 1]);
        uint16_t length = static_cast<uint16_t>(scan.recognized[offset + 2] << 8 | scan.recognized[offset + 3]);
        if (type == PARAM_UNRECOGNIZED) {
            out.emplace_back(scan.recognized.begin() + offset + 4, scan.recognized.begin() + offset + length);
        }
        offset += (length + 3u) & ~3u;
    }
    return out;
}

uint32_t cookie_lifespan_us(const SCTP_Packet& init_ack) {
    std::vector<uint8_t> cookie;
    State_Cookie decoded{};
    const auto& params = std::get<init_chunk_value>(init_ack.chunks[0].chunk_value).optional_parameters;
    if (!find_parameter(params, PARAM_STATE_COOKIE, cookie) || !deserialize_state_cookie(cookie, decoded)) return 0;
    return decoded.lifespan_us;
}

/*----------------------------- scan_parameters ------------------------------*/

void test_scan() {
    std::printf("Parameter walk (3.2.1):\n");

    auto known = parameter(PARAM_COOKIE_PRESERVATIVE, {0, 0, 0, 1});
    auto skip_silent = parameter(0x8008, {1, 2, 3});
    auto skip_report = parameter(0xC000, {});
    auto stop_report = parameter(0x4001, {9});
    auto stop_silent = parameter(0x0042, {});

    Parameter_Scan s = scan_parameters(concat({skip_silent, known, skip_report}), {PARAM_COOKIE_PRESERVATIVE});
    check(s.recognized == known, "10 and 11 skipped, recognized parameter kept");
    check(s.reported.size() == 1 && s.reported[0] == skip_report, "only 11 reported");

    s = scan_parameters(concat({skip_report, stop_report, known, skip_report}), {PARAM_COOKIE_PRESERVATIVE});
    check(s.recognized.empty(), "01 stops: nothing after it is processed");
    check(s.reported.size() == 2 && s.reported[1] == stop_report, "01 reported, later 11 is not");

    s = scan_parameters(concat({known, stop_silent, skip_report}), {PARAM_COOKIE_PRESERVATIVE});
    check(s.recognized == known && s.reported.empty(), "00 stops silently, earlier work kept");

    std::vector<uint8_t> unpadded = {0x80, 0x09, 0x00, 0x05, 0x77};   // last parameter, padding omitted
    std::vector<uint8_t> reported_unpadded = {0xC0, 0x09, 0x00, 0x05, 0x77};
    s = scan_parameters(unpadded, {});
    check(s.reported.empty(), "unpadded trailing 10 parameter accepted");
    s = scan_parameters(reported_unpadded, {});
    check(s.reported.size() == 1 && s.reported[0] == std::vector<uint8_t>({0xC0, 0x09, 0x00, 0x05, 0x77, 0, 0, 0}),
          "reported copy is the full TLV, padded");

    std::vector<uint8_t> bad_length = {0xC0, 0x00, 0x00, 0x02};
    s = scan_parameters(concat({known, bad_length, known}), {PARAM_COOKIE_PRESERVATIVE});
    check(s.recognized == known && s.reported.empty(), "a Length below 4 ends the walk");
}

/*----------------------------------- INIT -----------------------------------*/

void test_init_reports_in_init_ack() {
    std::printf("INIT: reports go in the INIT ACK (3.2.2):\n");

    // The kernel's INIT: ECN capable, Forward-TSN-Supported, Supported Extensions, Supported Address Types.
    auto params = concat({
        parameter(0x8000, {}),
        parameter(0xC000, {}),
        parameter(0x8008, {0xC0, 0x82}),
        parameter(PARAM_SUPPORTED_ADDRESS_TYPES, {0x00, 0x05}),
        parameter(0xC123, {1, 2, 3, 4, 5}),
    });
    auto r = Access::deliver(false, 0, init_chunk(INIT, params));
    const SCTP_Packet* init_ack = first_with(r, INIT_ACK);
    check(init_ack != nullptr, "INIT ACK sent");
    if (!init_ack) return;

    auto reports = unrecognized_in(*init_ack);
    check(reports.size() == 2, "one Unrecognized Parameter per reportable parameter");
    if (reports.size() == 2) {
        check(reports[0] == std::vector<uint8_t>({0xC0, 0x00, 0x00, 0x04}), "Forward-TSN-Supported echoed whole");
        check(reports[1] == std::vector<uint8_t>({0xC1, 0x23, 0x00, 0x09, 1, 2, 3, 4, 5, 0, 0, 0}),
              "second one echoed with its padding");
    }
    check(r.sent.size() == 1, "nothing else sent: Supported Address Types is recognized");

    // Exact bytes of the first Unrecognized Parameter, after the State Cookie.
    std::vector<uint8_t> wire = serialize_sctp_packet(*init_ack);
    std::vector<uint8_t> want = {0x00, 0x08, 0x00, 0x08, 0xC0, 0x00, 0x00, 0x04};
    check(std::search(wire.begin(), wire.end(), want.begin(), want.end()) != wire.end(),
          "Unrecognized Parameter bytes match 3.3.3.1 layout");
}

void test_init_stop_still_answers() {
    std::printf("INIT: 00/01 still answered (3.2.1):\n");

    auto preservative = parameter(PARAM_COOKIE_PRESERVATIVE, {0x00, 0x00, 0x03, 0xE8});   // 1000 ms

    auto r = Access::deliver(false, 0, init_chunk(INIT, concat({parameter(0x4005, {7}), preservative})));
    const SCTP_Packet* stopped = first_with(r, INIT_ACK);
    check(stopped != nullptr, "01: INIT ACK still sent");
    if (stopped) {
        check(unrecognized_in(*stopped).size() == 1, "01: reported");
        check(cookie_lifespan_us(*stopped) == 60'000'000, "01: Cookie Preservative after it ignored");
    }

    r = Access::deliver(false, 0, init_chunk(INIT, concat({preservative, parameter(0x0105, {}), parameter(0xC000, {})})));
    stopped = first_with(r, INIT_ACK);
    check(stopped != nullptr, "00: INIT ACK still sent");
    if (stopped) {
        check(unrecognized_in(*stopped).empty(), "00: nothing reported, later 11 never reached");
        check(cookie_lifespan_us(*stopped) == 61'000'000, "00: Cookie Preservative before it kept");
    }
}

void test_init_report_size() {
    std::printf("INIT: reports bounded by PMDCS:\n");

    std::vector<uint8_t> params;
    for (int i = 0; i < 5; ++i) {
        auto big = parameter(0xC100, std::vector<uint8_t>(396, 0x55));   // 400 bytes each
        params.insert(params.end(), big.begin(), big.end());
    }
    auto r = Access::deliver(false, 0, init_chunk(INIT, params));
    const SCTP_Packet* init_ack = first_with(r, INIT_ACK);
    check(init_ack != nullptr, "INIT ACK sent");
    if (!init_ack) return;
    check(unrecognized_in(*init_ack).size() == 2, "trimmed to the reports that fit");
    check(serialize_sctp_packet(*init_ack).size() <= SCTP_COMMON_HEADER_SIZE + 1200, "INIT ACK fits in PMDCS");
}

void test_init_host_name() {
    std::printf("INIT: Host Name Address (3.3.2.1.4):\n");

    auto host = parameter(PARAM_HOST_NAME_ADDRESS, {'h', 'o', 's', 't', 0});
    auto r = Access::deliver(false, 0, init_chunk(INIT, host));
    check(first_with(r, INIT_ACK) == nullptr, "no INIT ACK");
    const SCTP_Packet* abort = first_with(r, ABORT);
    check(abort != nullptr, "ABORT sent");
    if (!abort) return;
    check(abort->header.verification_tag == PEER_TAG && (abort->chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT) == 0,
          "ABORT carries the Initiate Tag, T bit clear");
    const auto& causes = std::get<error_chunk_value>(abort->chunks[0].chunk_value).causes;
    check(causes.size() == 1 && causes[0].code == CAUSE_UNRESOLVABLE_ADDRESS, "Unresolvable Address cause");
    if (causes.size() == 1) {
        check(std::equal(host.begin(), host.begin() + 9, causes[0].info.begin()), "cause holds the whole TLV");
    }

    r = Access::deliver(false, 0, init_chunk(INIT, concat({parameter(0x0100, {}), host})));
    check(first_with(r, INIT_ACK) != nullptr && first_with(r, ABORT) == nullptr,
          "Host Name after a stop is never processed");
}

/*--------------------------------- INIT ACK ---------------------------------*/

std::vector<uint8_t> some_cookie() {
    return parameter(PARAM_STATE_COOKIE, std::vector<uint8_t>(96, 0x42));
}

void test_init_ack_bundles_error() {
    std::printf("INIT ACK: report bundled after COOKIE ECHO (3.2.2):\n");

    auto params = concat({parameter(0xC000, {}), some_cookie(), parameter(0x8008, {1}), parameter(0xC001, {1, 2})});
    auto r = Access::deliver(true, OUR_TAG, init_chunk(INIT_ACK, params));
    check(r.state == COOKIE_ECHOED, "handshake continues");
    check(r.sent.size() == 1, "one packet sent");
    if (r.sent.size() != 1) return;
    const SCTP_Packet& packet = r.sent[0];
    check(packet.chunks.size() == 2 && packet.chunks[0].chunk_header.type == COOKIE_ECHO
              && packet.chunks[1].chunk_header.type == OP_ERROR,
          "COOKIE ECHO first, ERROR bundled after it");
    if (packet.chunks.size() != 2) return;

    const auto& causes = std::get<error_chunk_value>(packet.chunks[1].chunk_value).causes;
    std::vector<uint8_t> want = {0xC0, 0x00, 0x00, 0x04, 0xC0, 0x01, 0x00, 0x06, 1, 2, 0, 0};
    check(causes.size() == 1 && causes[0].code == CAUSE_UNRECOGNIZED_PARAMS && causes[0].info == want,
          "a single cause 8 holding both TLVs back to back");
}

void test_init_ack_silent_and_stop() {
    std::printf("INIT ACK: silent types and stops:\n");

    auto r = Access::deliver(true, OUR_TAG, init_chunk(INIT_ACK, concat({some_cookie(), parameter(0x8000, {}), parameter(PARAM_UNRECOGNIZED, {0, 9, 0, 8, 0, 0, 0, 1})})));
    check(r.sent.size() == 1 && r.sent[0].chunks.size() == 1, "10 and Unrecognized Parameter: COOKIE ECHO alone");

    r = Access::deliver(true, OUR_TAG, init_chunk(INIT_ACK, concat({parameter(0x4000, {}), some_cookie()})));
    check(r.sent.empty() && r.state == COOKIE_WAIT, "State Cookie behind a 01 is never reached");
}

void test_init_ack_host_name() {
    std::printf("INIT ACK: Host Name Address (3.3.3):\n");

    auto r = Access::deliver(true, OUR_TAG, init_chunk(INIT_ACK, concat({some_cookie(), parameter(PARAM_HOST_NAME_ADDRESS, {'h', 0})})));
    check(!r.association_left, "TCB removed");
    const SCTP_Packet* abort = first_with(r, ABORT);
    check(abort != nullptr && first_with(r, COOKIE_ECHO) == nullptr, "ABORT instead of COOKIE ECHO");
    if (abort) {
        const auto& causes = std::get<error_chunk_value>(abort->chunks[0].chunk_value).causes;
        check(abort->header.verification_tag == PEER_TAG, "ABORT carries the peer's Initiate Tag");
        check(causes.size() == 1 && causes[0].code == CAUSE_UNRESOLVABLE_ADDRESS, "Unresolvable Address cause");
    }
}

} // namespace

int main() {
    test_scan();
    test_init_reports_in_init_ack();
    test_init_stop_still_answers();
    test_init_report_size();
    test_init_host_name();
    test_init_ack_bundles_error();
    test_init_ack_silent_and_stop();
    test_init_ack_host_name();

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
