// The peer's transport addresses (RFC 9260 5.1.2, 5.2.1, 5.2.2, 5.4): IPv4
// Address parameters in INIT and INIT ACK, carried through the State Cookie,
// matched to the association they name, and never sent to while UNCONFIRMED.
// Packets are fed straight into handle_recv_packet and replies are read off the
// send queue together with the address each was sent to.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "serialize.hpp"
#include "socket_internal.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr uint32_t PEER_TAG = 0x11223344;
constexpr uint32_t PEER_TSN = 1000;
constexpr uint16_t PEER_PORT = 40000;
constexpr uint16_t OUR_PORT = 9899;

sockaddr_in address(const char* ip) {
    sockaddr_in out{};
    out.sin_family = AF_INET;
    out.sin_port = htons(PEER_PORT);
    sctp_parse_ipv4(ip, out.sin_addr);
    return out;
}

const sockaddr_in A = address("127.0.0.1");
const sockaddr_in B = address("127.0.0.2");
const sockaddr_in C = address("127.0.0.3");

std::vector<uint8_t> ipv4_parameter(const sockaddr_in& at) {
    std::vector<uint8_t> out;
    append_parameter(out, PARAM_IPV4_ADDRESS, reinterpret_cast<const uint8_t*>(&at.sin_addr.s_addr), 4);
    return out;
}

std::vector<uint8_t> ipv4_parameters(std::initializer_list<sockaddr_in> listed) {
    std::vector<uint8_t> out;
    for (const auto& at : listed) {
        auto one = ipv4_parameter(at);
        out.insert(out.end(), one.begin(), one.end());
    }
    return out;
}

SCTP_Chunk init_chunk(Chunk_Type type, std::vector<uint8_t> params, uint32_t initiate_tag = PEER_TAG) {
    return {{type, 0, 0}, init_chunk_value{initiate_tag, RWND, 10, 10, PEER_TSN, std::move(params)}};
}

bool same(const sockaddr_in& a, const sockaddr_in& b) {
    return same_transport_address(a, b);
}

} // namespace

struct SCTP_Socket_Test_Access {
    struct Sent {
        SCTP_Packet packet;
        sockaddr_in destination;
    };

    static void receive(SCTP_Socket& stack, const sockaddr_in& src, uint32_t tag, std::vector<SCTP_Chunk> chunks) {
        SCTP_Packet packet;
        packet.header = {PEER_PORT, OUR_PORT, tag, 0};
        packet.chunks = std::move(chunks);
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.handle_recv_packet(wire.data(), wire.size(), src);
    }

    static std::vector<Sent> drain(SCTP_Socket& stack) {
        std::vector<Sent> out;
        auto now = std::chrono::steady_clock::now();
        while (auto pending = stack.sends.peek(now)) {
            std::vector<uint8_t> bytes = serialize_sctp_packet(pending->deliverable.packet);
            out.push_back({deserialize_sctp_packet(bytes.data(), bytes.size()), pending->deliverable.destination});
            stack.sends.commit(*pending);
        }
        return out;
    }

    static Association* tcb(SCTP_Socket& stack, const sockaddr_in& at) {
        auto it = stack.associations.find(Association_Key{at});
        return it == stack.associations.end() ? nullptr : &it->second;
    }

    static Association_Key key_for(SCTP_Socket& stack, const sockaddr_in& at) {
        return stack.association_key_for(at);
    }

    static size_t aliases(SCTP_Socket& stack) {
        return stack.peer_addresses.size();
    }

    static void remove(SCTP_Socket& stack, const sockaddr_in& at) {
        stack.remove_association(Association_Key{at});
    }

    // Our side as initiator, in COOKIE-WAIT towards `at`, as sctp_associate leaves it.
    static uint32_t cookie_wait(SCTP_Socket& stack, const sockaddr_in& at) {
        Association_Key key{at};
        Association assoc = stack.init_new_association(key);
        stack.associations.insert_or_assign(key, assoc);
        return assoc.this_ver_tag;
    }
};

namespace {

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

using Access = SCTP_Socket_Test_Access;

const Access::Sent* first_with(const std::vector<Access::Sent>& sent, Chunk_Type type) {
    for (const auto& s : sent) {
        if (!s.packet.chunks.empty() && s.packet.chunks[0].chunk_header.type == type) return &s;
    }
    return nullptr;
}

bool all_to(const std::vector<Access::Sent>& sent, const sockaddr_in& at) {
    return std::all_of(sent.begin(), sent.end(), [&](const Access::Sent& s) { return same(s.destination, at); });
}

std::vector<uint8_t> cookie_of(const SCTP_Packet& init_ack) {
    std::vector<uint8_t> cookie;
    find_parameter(std::get<init_chunk_value>(init_ack.chunks[0].chunk_value).optional_parameters, PARAM_STATE_COOKIE, cookie);
    return cookie;
}

// Paths in TCB order, as "address:confirmed".
std::vector<std::pair<uint32_t, bool>> paths(const Association& assoc) {
    std::vector<std::pair<uint32_t, bool>> out;
    for (const auto& path : assoc.peer_address_list) {
        out.emplace_back(path.address.sin_addr.s_addr, path.confirmed);
    }
    return out;
}

std::pair<uint32_t, bool> path(const sockaddr_in& at, bool confirmed) {
    return {at.sin_addr.s_addr, confirmed};
}

// The peer's INIT from `from`, our INIT ACK, and its COOKIE ECHO back. Returns
// our tag, or 0 if the handshake did not complete.
uint32_t establish(SCTP_Socket& stack, const sockaddr_in& from, std::vector<uint8_t> params) {
    Access::receive(stack, from, 0, {init_chunk(INIT, std::move(params))});
    auto sent = Access::drain(stack);
    const Access::Sent* init_ack = first_with(sent, INIT_ACK);
    if (!init_ack) return 0;
    uint32_t our_tag = std::get<init_chunk_value>(init_ack->packet.chunks[0].chunk_value).initiate_tag;
    Access::receive(stack, from, our_tag, {{{COOKIE_ECHO, 0, 0}, cookie_echo_chunk_value{cookie_of(init_ack->packet)}}});
    Access::drain(stack);
    Association* assoc = Access::tcb(stack, from);
    return assoc && assoc->state == ESTABLISHED ? our_tag : 0;
}

/*------------------------------- State Cookie -------------------------------*/

void test_cookie_codec() {
    std::printf("State Cookie carries the peer's other addresses:\n");

    State_Cookie cookie{};
    cookie.version = STATE_COOKIE_VERSION;
    cookie.peer_addresses = {0x7F000002, 0x0A000001};
    std::vector<uint8_t> wire = serialize_state_cookie(cookie);
    check(wire.size() == STATE_COOKIE_SIZE + 8, "4 bytes per address on top of the fixed cookie");
    check(wire[26] == 0 && wire[27] == 2, "address count in the formerly reserved field");
    check(wire[64] == 0x7F && wire[67] == 0x02 && wire[68] == 0x0A && wire[71] == 0x01,
          "addresses follow the fixed body, big-endian");

    State_Cookie decoded{};
    check(deserialize_state_cookie(wire, decoded) && decoded.peer_addresses == cookie.peer_addresses, "round trip");
    std::vector<uint8_t> short_one(wire.begin(), wire.end() - 4);
    check(!deserialize_state_cookie(short_one, decoded), "a length disagreeing with the count is rejected");

    Cookie_Auth auth;
    init_chunk_value init{PEER_TAG, RWND, 10, 10, PEER_TSN, {}};
    SCTP_Common_Header header{PEER_PORT, OUR_PORT, 0, 0};
    std::vector<uint8_t> signed_cookie = auth.generate(header, init, A, 0x01020304, 1, 0, 0, 0, {0x7F000002});
    SCTP_Common_Header echo{PEER_PORT, OUR_PORT, 0x01020304, 0};
    uint32_t staleness = 0;
    check(auth.verify(signed_cookie, echo, A, decoded, staleness) == Cookie_Result::VALID, "a signed cookie with addresses verifies");
    check(auth.verify(signed_cookie, echo, B, decoded, staleness) == Cookie_Result::VALID, "and is accepted from an address it lists");
    check(auth.verify(signed_cookie, echo, C, decoded, staleness) == Cookie_Result::WRONG_ENDPOINT, "but not from one it does not");
    signed_cookie[STATE_COOKIE_BODY_SIZE + 3] ^= 0x01;
    check(auth.verify(signed_cookie, echo, A, decoded, staleness) == Cookie_Result::BAD_MAC, "the MAC covers the addresses");
}

/*-------------------------------- Responder ---------------------------------*/

void test_responder_records_addresses() {
    std::printf("Responder: INIT addresses reach the TCB (5.1.2 C, 5.4 rule 2):\n");

    SCTP_Socket stack;
    std::vector<uint8_t> ipv6;
    append_parameter(ipv6, PARAM_IPV6_ADDRESS, std::vector<uint8_t>(16, 0x20).data(), 16);
    auto params = ipv4_parameters({B, C, A, B});
    params.insert(params.end(), ipv6.begin(), ipv6.end());

    Access::receive(stack, A, 0, {init_chunk(INIT, params)});
    auto sent = Access::drain(stack);
    const Access::Sent* init_ack = first_with(sent, INIT_ACK);
    check(init_ack && same(init_ack->destination, A), "INIT ACK to the INIT's source");
    check(sent.size() == 1, "IPv6 address ignored without an error");
    if (!init_ack) return;

    State_Cookie decoded{};
    deserialize_state_cookie(cookie_of(init_ack->packet), decoded);
    check(decoded.peer_addresses == std::vector<uint32_t>({ntohl(B.sin_addr.s_addr), ntohl(C.sin_addr.s_addr)}),
          "cookie lists B and C once each, not the source");
    check(Access::tcb(stack, A) == nullptr, "no TCB before the COOKIE ECHO");

    uint32_t our_tag = std::get<init_chunk_value>(init_ack->packet.chunks[0].chunk_value).initiate_tag;
    Access::receive(stack, A, our_tag, {{{COOKIE_ECHO, 0, 0}, cookie_echo_chunk_value{cookie_of(init_ack->packet)}}});
    sent = Access::drain(stack);
    Association* assoc = Access::tcb(stack, A);
    check(assoc && assoc->state == ESTABLISHED, "association established");
    if (!assoc) return;
    check(paths(*assoc) == std::vector<std::pair<uint32_t, bool>>({path(A, true), path(B, false), path(C, false)}),
          "A CONFIRMED, B and C UNCONFIRMED");
    check(same(assoc->primary_path, A), "primary path is A");
    const Access::Sent* cookie_ack = first_with(sent, COOKIE_ACK);
    check(cookie_ack && same(cookie_ack->destination, A), "COOKIE ACK to A");
    check(Access::key_for(stack, B) == Association_Key{A} && Access::key_for(stack, C) == Association_Key{A},
          "B and C resolve to the association");
}

void test_alias_traffic() {
    std::printf("Packets from another of the peer's addresses:\n");

    SCTP_Socket stack;
    uint32_t our_tag = establish(stack, A, ipv4_parameters({B, C}));
    check(our_tag != 0, "established with A, B, C");
    if (!our_tag) return;

    Access::receive(stack, B, our_tag, {{{HEARTBEAT, 0, 0}, heartbeat_chunk_value{{1, 2, 3, 4}}}});
    auto sent = Access::drain(stack);
    const Access::Sent* ack = first_with(sent, HEARTBEAT_ACK);
    check(ack && same(ack->destination, B), "HEARTBEAT ACK back to UNCONFIRMED B");
    check(first_with(sent, ABORT) == nullptr, "not treated as out of the blue");

    SCTP_Chunk data{{DATA, DATA_FLAG_B | DATA_FLAG_E | DATA_IMMEDIATE_SACK_FLAG, 0}, data_chunk_value{PEER_TSN, 0, 0, 0, {'x'}}};
    Access::receive(stack, B, our_tag, {data});
    sent = Access::drain(stack);
    const Access::Sent* sack = first_with(sent, SACK);
    check(sack != nullptr, "DATA from B acknowledged");
    check(sack && same(sack->destination, A), "SACK to the primary path, not UNCONFIRMED B");

    SCTP_Chunk bad_stream{{DATA, DATA_FLAG_B | DATA_FLAG_E | DATA_IMMEDIATE_SACK_FLAG, 0}, data_chunk_value{PEER_TSN + 1, 999, 0, 0, {'y'}}};
    Access::receive(stack, C, our_tag, {bad_stream});
    sent = Access::drain(stack);
    const Access::Sent* error = first_with(sent, OP_ERROR);
    check(error && same(error->destination, A), "ERROR answering C goes to A: C is UNCONFIRMED");
    check(all_to(sent, A), "nothing sent to C");

    Access::remove(stack, A);
    check(Access::aliases(stack) == 0 && Access::key_for(stack, B) == Association_Key{B}, "removal drops B and C");
}

/*-------------------------------- Initiator ---------------------------------*/

void test_initiator_records_addresses() {
    std::printf("Initiator: INIT ACK addresses (5.1.2 A, C, 5.4 rule 1):\n");

    std::vector<uint8_t> cookie_param;
    std::vector<uint8_t> cookie(STATE_COOKIE_SIZE, 0x42);
    append_parameter(cookie_param, PARAM_STATE_COOKIE, cookie.data(), cookie.size());

    {
        SCTP_Socket stack;
        uint32_t our_tag = Access::cookie_wait(stack, A);
        Access::receive(stack, A, our_tag, {init_chunk(INIT_ACK, cookie_param)});
        Association* assoc = Access::tcb(stack, A);
        check(assoc && paths(*assoc) == std::vector<std::pair<uint32_t, bool>>({path(A, true)}),
              "no addresses: the source is the only destination");
    }
    {
        SCTP_Socket stack;
        uint32_t our_tag = Access::cookie_wait(stack, A);
        auto params = cookie_param;
        auto listed = ipv4_parameters({B});
        params.insert(params.end(), listed.begin(), listed.end());
        Access::receive(stack, A, our_tag, {init_chunk(INIT_ACK, params)});
        auto sent = Access::drain(stack);
        Association* assoc = Access::tcb(stack, A);
        check(assoc && assoc->state == COOKIE_ECHOED, "handshake continues");
        check(assoc && paths(*assoc) == std::vector<std::pair<uint32_t, bool>>({path(A, true), path(B, false)}),
              "A, given by the ULP, CONFIRMED; B UNCONFIRMED");
        const Access::Sent* echo = first_with(sent, COOKIE_ECHO);
        check(echo && same(echo->destination, A), "COOKIE ECHO to A");
    }
    {
        // 5.1.2 D: the INIT ACK comes from B but names A, which has the TCB.
        SCTP_Socket stack;
        uint32_t our_tag = Access::cookie_wait(stack, A);
        auto params = cookie_param;
        auto listed = ipv4_parameters({A});
        params.insert(params.end(), listed.begin(), listed.end());
        Access::receive(stack, B, our_tag, {init_chunk(INIT_ACK, params)});
        auto sent = Access::drain(stack);
        Association* assoc = Access::tcb(stack, A);
        check(assoc && assoc->state == COOKIE_ECHOED, "INIT ACK from B belongs to the TCB for A");
        check(Access::tcb(stack, B) == nullptr && first_with(sent, ABORT) == nullptr, "no second TCB, no ABORT");
        const Access::Sent* echo = first_with(sent, COOKIE_ECHO);
        check(echo && same(echo->destination, A), "COOKIE ECHO to A, not UNCONFIRMED B");
    }
}

void test_collision_in_cookie_wait() {
    std::printf("COOKIE-WAIT: INIT from another address naming ours (5.1.2 D, 5.2.1):\n");

    SCTP_Socket stack;
    uint32_t our_tag = Access::cookie_wait(stack, A);
    Access::receive(stack, B, 0, {init_chunk(INIT, ipv4_parameters({A}))});
    auto sent = Access::drain(stack);
    const Access::Sent* init_ack = first_with(sent, INIT_ACK);
    check(init_ack && same(init_ack->destination, A), "INIT ACK only to the address the ULP gave");
    check(init_ack && std::get<init_chunk_value>(init_ack->packet.chunks[0].chunk_value).initiate_tag == our_tag,
          "with our original Initiate Tag");
    Association* assoc = Access::tcb(stack, A);
    check(assoc && assoc->state == COOKIE_WAIT && assoc->peer_address_list.size() == 1, "TCB unchanged: B not learned");
    check(Access::key_for(stack, B) == Association_Key{B}, "B does not resolve to it");
}

/*------------------------- INIT adding new addresses ------------------------*/

void test_restart_with_new_addresses() {
    std::printf("INIT adding addresses to an existing association (5.2.1, 5.2.2):\n");

    SCTP_Socket stack;
    uint32_t our_tag = establish(stack, A, ipv4_parameters({B}));
    if (!our_tag) {
        check(false, "established");
        return;
    }

    constexpr uint32_t RESTART_TAG = 0x55667788;
    Access::receive(stack, A, 0, {init_chunk(INIT, ipv4_parameters({B, C}), RESTART_TAG)});
    auto sent = Access::drain(stack);
    const Access::Sent* abort = first_with(sent, ABORT);
    check(abort && first_with(sent, INIT_ACK) == nullptr, "ABORT instead of INIT ACK");
    if (abort) {
        check(abort->packet.header.verification_tag == RESTART_TAG
                  && (abort->packet.chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT) == 0,
              "under the INIT's Initiate Tag, T bit clear");
        const auto& causes = std::get<error_chunk_value>(abort->packet.chunks[0].chunk_value).causes;
        check(causes.size() == 1 && causes[0].code == CAUSE_RESTART_WITH_NEW_ADDRESSES && causes[0].info == ipv4_parameter(C),
              "cause 11 holds a copy of C's parameter only");
    }
    Association* assoc = Access::tcb(stack, A);
    check(assoc && assoc->state == ESTABLISHED && assoc->this_ver_tag == our_tag && assoc->peer_ver_tag == PEER_TAG
              && assoc->peer_address_list.size() == 2,
          "TCB unchanged");

    Access::receive(stack, A, 0, {init_chunk(INIT, ipv4_parameters({B}), RESTART_TAG)});
    sent = Access::drain(stack);
    check(first_with(sent, INIT_ACK) != nullptr && first_with(sent, ABORT) == nullptr, "same addresses: INIT ACK as before");

    // C is only the source, so there is no parameter to copy into the cause.
    Access::receive(stack, C, 0, {init_chunk(INIT, ipv4_parameters({A}), RESTART_TAG)});
    sent = Access::drain(stack);
    abort = first_with(sent, ABORT);
    check(abort && same(abort->destination, C), "INIT from new C naming A: ABORT back to C");
    check(abort && std::get<error_chunk_value>(abort->packet.chunks[0].chunk_value).causes.empty(), "with no cause");
    check(Access::tcb(stack, C) == nullptr, "no TCB for C");
}

void test_cookie_echoed_new_address() {
    std::printf("COOKIE-ECHOED: INIT adding an address is refused (5.2.1):\n");

    SCTP_Socket stack;
    uint32_t our_tag = Access::cookie_wait(stack, A);
    std::vector<uint8_t> params;
    std::vector<uint8_t> cookie(STATE_COOKIE_SIZE, 0x42);
    append_parameter(params, PARAM_STATE_COOKIE, cookie.data(), cookie.size());
    Access::receive(stack, A, our_tag, {init_chunk(INIT_ACK, params)});
    Access::drain(stack);

    Access::receive(stack, A, 0, {init_chunk(INIT, ipv4_parameters({B}))});
    auto sent = Access::drain(stack);
    check(first_with(sent, ABORT) != nullptr && first_with(sent, INIT_ACK) == nullptr, "ABORT, no INIT ACK");
    Association* assoc = Access::tcb(stack, A);
    check(assoc && assoc->state == COOKIE_ECHOED && assoc->peer_address_list.size() == 1, "TCB unchanged");
}

void test_restart_replaces_addresses() {
    std::printf("Peer restart takes the new cookie's addresses (5.2.4 A):\n");

    SCTP_Socket stack;
    uint32_t our_tag = establish(stack, A, ipv4_parameters({B, C}));
    if (!our_tag) {
        check(false, "established");
        return;
    }
    // Drop C: a restart that lists fewer addresses adds none.
    constexpr uint32_t RESTART_TAG = 0x55667788;
    Access::receive(stack, A, 0, {init_chunk(INIT, ipv4_parameters({B}), RESTART_TAG)});
    auto sent = Access::drain(stack);
    const Access::Sent* init_ack = first_with(sent, INIT_ACK);
    check(init_ack != nullptr, "INIT ACK for the restart");
    if (!init_ack) return;
    uint32_t new_tag = std::get<init_chunk_value>(init_ack->packet.chunks[0].chunk_value).initiate_tag;
    Access::receive(stack, A, new_tag, {{{COOKIE_ECHO, 0, 0}, cookie_echo_chunk_value{cookie_of(init_ack->packet)}}});
    Access::drain(stack);

    Association* assoc = Access::tcb(stack, A);
    check(assoc && assoc->peer_ver_tag == RESTART_TAG, "association restarted");
    check(assoc && paths(*assoc) == std::vector<std::pair<uint32_t, bool>>({path(A, true), path(B, false)}), "paths are A and B");
    check(Access::key_for(stack, C) == Association_Key{C} && Access::aliases(stack) == 1, "C no longer resolves to it");
}

/*------------------------- COOKIE ECHO from elsewhere ------------------------*/

void test_cookie_echo_from_listed_address() {
    std::printf("COOKIE ECHO from another address the INIT gave:\n");

    SCTP_Socket stack;
    Access::receive(stack, A, 0, {init_chunk(INIT, ipv4_parameters({B}))});
    auto sent = Access::drain(stack);
    const Access::Sent* init_ack = first_with(sent, INIT_ACK);
    if (!init_ack) {
        check(false, "INIT ACK sent");
        return;
    }
    uint32_t our_tag = std::get<init_chunk_value>(init_ack->packet.chunks[0].chunk_value).initiate_tag;
    std::vector<uint8_t> cookie = cookie_of(init_ack->packet);

    Access::receive(stack, C, our_tag, {{{COOKIE_ECHO, 0, 0}, cookie_echo_chunk_value{cookie}}});
    check(Access::tcb(stack, C) == nullptr && Access::tcb(stack, A) == nullptr && Access::drain(stack).empty(),
          "from C, which the INIT did not give: dropped");

    SCTP_Chunk data{{DATA, DATA_FLAG_B | DATA_FLAG_E, 0}, data_chunk_value{PEER_TSN, 0, 0, 0, {'x'}}};
    Access::receive(stack, B, our_tag, {{{COOKIE_ECHO, 0, 0}, cookie_echo_chunk_value{cookie}}, data});
    sent = Access::drain(stack);
    Association* assoc = Access::tcb(stack, A);
    check(assoc && assoc->state == ESTABLISHED && Access::tcb(stack, B) == nullptr, "from B: association keyed on the INIT's source");
    check(assoc && paths(*assoc) == std::vector<std::pair<uint32_t, bool>>({path(A, true), path(B, false)}),
          "A, where the INIT ACK went, CONFIRMED; B UNCONFIRMED");
    const Access::Sent* cookie_ack = first_with(sent, COOKIE_ACK);
    check(cookie_ack && same(cookie_ack->destination, A), "COOKIE ACK to A, not UNCONFIRMED B");
    const Access::Sent* sack = first_with(sent, SACK);
    check(sack && same(sack->destination, A), "DATA bundled behind it lands on the same association");
}

/*---------------------------------- No limit --------------------------------*/

void test_many_addresses() {
    std::printf("No limit on the addresses a peer gives:\n");

    std::vector<uint8_t> params;
    for (uint32_t i = 0; i < 200; ++i) {
        sockaddr_in at = A;
        at.sin_addr.s_addr = htonl(0x0A000001 + i);
        auto one = ipv4_parameter(at);
        params.insert(params.end(), one.begin(), one.end());
    }
    SCTP_Socket stack;
    check(establish(stack, A, params) != 0, "200 listed addresses: established");
    Association* assoc = Access::tcb(stack, A);
    check(assoc && assoc->peer_address_list.size() == 201, "every one of them recorded");
}

} // namespace

int main() {
    test_cookie_codec();
    test_responder_records_addresses();
    test_alias_traffic();
    test_initiator_records_addresses();
    test_collision_in_cookie_wait();
    test_restart_with_new_addresses();
    test_cookie_echoed_new_address();
    test_restart_replaces_addresses();
    test_cookie_echo_from_listed_address();
    test_many_addresses();

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
