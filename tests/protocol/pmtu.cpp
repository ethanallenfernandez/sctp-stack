// PMTU discovery (RFC 9260 7.3) by DPLPMTUD (RFC 8899 6.2): HEARTBEAT + PAD
// probes, the BASE / SEARCHING / SEARCH_COMPLETE / ERROR states per
// destination, the AMDCS DATA is fragmented to, black hole detection, chunks
// resent with IP fragmentation once their path's PMTU fell (6.9), and ICMP
// Packet Too Big handling (RFC 9260 10, RFC 8899 4.6).
//
// Timers are fired by hand through handle_expiration, so nothing waits on the
// clock. Sizes are UDP datagram sizes, as in RFC 8899 6.2.2.2.

#include <sctp/socket.hpp>
#include <sctp/platform/compat.hpp>
#include "protocol/serialize.hpp"
#include "socket/internal.hpp"

#include <chrono>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>
#include "support.hpp"

using Clock = std::chrono::steady_clock;

namespace {

constexpr uint32_t OUR_TAG = 0x0A0B0C0D;
constexpr uint32_t PEER_TAG = 0x11223344;
constexpr uint16_t PEER_PORT = 40000;
constexpr uint16_t LOCAL_PORT = 9899;
constexpr uint32_t INITIAL_TSN = 1000;

sockaddr_in address_of(const char* ip) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(PEER_PORT);
    sctp_parse_ipv4(ip, address.sin_addr);
    return address;
}

sockaddr_in peer_address() {
    return address_of("127.0.0.1");
}

} // namespace

struct SCTP_Socket_Test_Access {
    static Association_Key establish(SCTP_Socket& stack, const sockaddr_in& peer = peer_address()) {
        stack.local_address.sin_family = AF_INET;
        stack.local_address.sin_port = htons(LOCAL_PORT);
        sctp_parse_ipv4("127.0.0.1", stack.local_address.sin_addr);

        Association assoc = stack.init_new_association(peer, ntohs(peer.sin_port));
        assoc.this_ver_tag = OUR_TAG;
        assoc.peer_ver_tag = PEER_TAG;
        assoc.state = ESTABLISHED;
        assoc.next_tsn = INITIAL_TSN;
        assoc.cumulative_tsn_ack = INITIAL_TSN - 1;
        assoc.last_peer_tsn = 0;
        assoc.peer_rwnd = 1 << 20;
        assoc.peer_max_rwnd = 1 << 20;
        assoc.primary_path = peer;
        Association_Key key{stack.next_association_id++};
        Association& tcb = stack.associations.insert_or_assign(key, assoc).first->second;
        stack.add_peer_addresses(key, tcb, {peer});
        stack.start_heartbeats(key, tcb);
        return key;
    }

    static void deliver(SCTP_Socket& stack, const SCTP_Packet& packet) {
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.handle_recv_packet(wire.data(), wire.size(), peer_address());
    }

    static void fire(SCTP_Socket& stack, const Association_Key& key, Expiration_Timer_Type type, const sockaddr_in& path) {
        stack.handle_expiration(Expiration_Fallback{
            Expiration_Key{key, type, path_key(path)}, Clock::now(), 0, Deliverable{key, {}, SCTP_Packet{}}});
    }

    static void fire_t3(SCTP_Socket& stack, const Association_Key& key) {
        stack.handle_t3_expiration(key, peer_address());
    }

    static bool timer_armed(SCTP_Socket& stack, const Association_Key& key, Expiration_Timer_Type type) {
        return stack.expirations.is_active(Expiration_Key{key, type, path_key(peer_address())});
    }

    static std::vector<Deliverable> drain(SCTP_Socket& stack) {
        std::vector<Deliverable> sent;
        auto now = Clock::now();
        while (auto pending = stack.sends.peek(now)) {
            sent.push_back(pending->deliverable);
            stack.sends.commit(*pending);
        }
        return sent;
    }

    static std::optional<Deliverable> transmit(SCTP_Socket& stack) {
        stack.start_transmission_opportunity();
        auto pending = stack.next_packet();
        if (!pending) {
            return std::nullopt;
        }
        stack.packet_sent(*pending);
        return pending->deliverable;
    }

    static void ptb(SCTP_Socket& stack, const std::vector<uint8_t>& quoted, uint32_t mtu) {
        stack.handle_icmp_ptb(peer_address(), quoted.data(), quoted.size(), mtu);
    }

    static Association& tcb(SCTP_Socket& stack, const Association_Key& key) {
        return stack.associations.at(key);
    }

    static SCTP_Socket& api(SCTP_Socket& stack) {
        return stack;
    }
};

namespace {

using Access = SCTP_Socket_Test_Access;

Plpmtud& plpmtud(SCTP_Socket& stack, const Association_Key& key) {
    return primary(Access::tcb(stack, key)).plpmtud;
}

bool is_probe(const Deliverable& deliverable) {
    const auto& chunks = deliverable.packet.chunks;
    return chunks.size() == 2 && chunks[0].chunk_header.type == HEARTBEAT && chunks[1].chunk_header.type == PAD;
}

size_t datagram_size(const Deliverable& deliverable) {
    return 8 + serialize_sctp_packet(deliverable.packet).size();
}

// Fires the probe timer and returns the probe it sent, if one.
std::optional<Deliverable> probe_now(SCTP_Socket& stack, const Association_Key& key) {
    Access::fire(stack, key, Expiration_Timer_Type::PLPMTU_PROBE, peer_address());
    for (const auto& deliverable : Access::drain(stack)) {
        if (is_probe(deliverable)) {
            return deliverable;
        }
    }
    return std::nullopt;
}

void acknowledge(SCTP_Socket& stack, const Deliverable& probe) {
    SCTP_Packet ack;
    ack.header = {PEER_PORT, LOCAL_PORT, OUR_TAG, 0};
    ack.chunks.push_back({{HEARTBEAT_ACK, 0, 0}, std::get<heartbeat_chunk_value>(probe.packet.chunks[0].chunk_value)});
    Access::deliver(stack, ack);
}

// Probes and acknowledges until the search is over.
void complete_search(SCTP_Socket& stack, const Association_Key& key) {
    for (int i = 0; i < 16 && plpmtud(stack, key).state != Plpmtud_State::SEARCH_COMPLETE; ++i) {
        if (auto probe = probe_now(stack, key)) {
            acknowledge(stack, *probe);
        }
    }
}

std::vector<uint8_t> quoted_header(uint32_t tag) {
    return {LOCAL_PORT >> 8, LOCAL_PORT & 0xFF, PEER_PORT >> 8, PEER_PORT & 0xFF,
            static_cast<uint8_t>(tag >> 24), static_cast<uint8_t>(tag >> 16), static_cast<uint8_t>(tag >> 8), static_cast<uint8_t>(tag)};
}

void test_probe_format() {
    std::printf("Probe packets (RFC 8899 6.2.1.2, 6.2.2.2):\n");
    SCTP_Socket stack;
    Association_Key key = Access::establish(stack);

    check(plpmtud(stack, key).state == Plpmtud_State::BASE, "a confirmed path enters BASE once established");
    check(pmdcs(primary(Access::tcb(stack, key))) == 1180, "PMDCS is BASE_PLPMTU less the UDP and common headers");
    auto probe = probe_now(stack, key);
    check(probe.has_value(), "the first probe goes out when PROBE_TIMER first fires");
    if (!probe) return;
    check(datagram_size(*probe) == 1200, "it fills a 1200-byte UDP datagram exactly");
    check(probe->packet.header.verification_tag == PEER_TAG, "under the peer's tag");
    check(!probe->ip_fragment, "with DF set");
    check(Access::timer_armed(stack, key, Expiration_Timer_Type::PLPMTU_PROBE), "PROBE_TIMER runs");

    std::vector<uint8_t> wire = serialize_sctp_packet(probe->packet);
    SCTP_Packet parsed = deserialize_sctp_packet(wire.data(), wire.size());
    check(parsed.chunks.size() == 2 && parsed.chunks[1].chunk_header.type == 0x84, "a HEARTBEAT, then a PAD chunk (type 0x84)");
}

void test_search_climbs_to_max() {
    std::printf("Searching from BASE_PLPMTU (RFC 8899 5.2, 5.3):\n");
    SCTP_Socket stack;
    Association_Key key = Access::establish(stack);

    auto base = probe_now(stack, key);
    if (!base) { check(false, "BASE probe sent"); return; }
    acknowledge(stack, *base);
    check(plpmtud(stack, key).state == Plpmtud_State::SEARCHING && plpmtud(stack, key).plpmtu == 1200,
          "an acknowledged BASE probe confirms 1200 and starts the search");

    auto max = probe_now(stack, key);
    check(max && datagram_size(*max) == 1480, "MAX_PLPMTU is tried first");
    if (!max) return;
    acknowledge(stack, *max);
    check(plpmtud(stack, key).state == Plpmtud_State::SEARCH_COMPLETE && plpmtud(stack, key).plpmtu == 1480,
          "MAX_PLPMTU acknowledged: SEARCH_COMPLETE at 1480");
    check(amdcs(Access::tcb(stack, key)) == 1460, "AMDCS follows the only path's PMDCS");
    check(!Access::timer_armed(stack, key, Expiration_Timer_Type::PLPMTU_PROBE), "no probes in SEARCH_COMPLETE");
    check(Access::timer_armed(stack, key, Expiration_Timer_Type::PMTU_RAISE), "PMTU_RAISE_TIMER runs");

    Access::fire(stack, key, Expiration_Timer_Type::PMTU_RAISE, peer_address());
    check(plpmtud(stack, key).state == Plpmtud_State::SEARCH_COMPLETE, "at MAX_PLPMTU there is nothing to raise to");
}

void test_lost_probes_narrow_the_search() {
    std::printf("Unacknowledged probes (RFC 8899 5.1.2 MAX_PROBES, 6.2.1.2):\n");
    SCTP_Socket stack;
    Association_Key key = Access::establish(stack);
    auto base = probe_now(stack, key);
    if (!base) { check(false, "BASE probe sent"); return; }
    acknowledge(stack, *base);

    std::vector<size_t> sizes;
    for (int i = 0; i < 4; ++i) {
        if (auto probe = probe_now(stack, key)) {
            sizes.push_back(datagram_size(*probe));
        }
    }
    check(sizes == std::vector<size_t>{1480, 1480, 1480, 1340}, "MAX_PLPMTU three times, then the midpoint 1340");
    check(primary(Access::tcb(stack, key)).error_count == 0 && Access::tcb(stack, key).error_count == 0,
          "a lost probe counts no error against the path or the association");
    check(plpmtud(stack, key).plpmtu == 1200, "the PLPMTU stays at what was confirmed");

    auto again = probe_now(stack, key);
    if (!again) { check(false, "midpoint probe resent"); return; }
    acknowledge(stack, *again);
    auto next = probe_now(stack, key);
    check(plpmtud(stack, key).plpmtu == 1340 && next && datagram_size(*next) == 1408,
          "1340 acknowledged: the next probe halves (1340, 1480)");
}

void test_base_failure_is_an_error() {
    std::printf("BASE_PLPMTU never acknowledged (RFC 8899 5.2 ERROR):\n");
    SCTP_Socket stack;
    Association_Key key = Access::establish(stack);
    for (int i = 0; i < 4; ++i) {
        probe_now(stack, key);
    }
    check(plpmtud(stack, key).state == Plpmtud_State::ERROR, "MAX_PROBES lost at BASE enters ERROR");
    check(pmdcs(primary(Access::tcb(stack, key))) == 1180, "PMDCS stays at BASE");
    check(!probe_now(stack, key).has_value(), "no probes in ERROR");

    Access::fire(stack, key, Expiration_Timer_Type::PMTU_RAISE, peer_address());
    check(plpmtud(stack, key).state == Plpmtud_State::BASE, "PMTU_RAISE_TIMER tries BASE again");
}

void test_amdcs_is_the_smallest_pmdcs() {
    std::printf("AMDCS (RFC 9260 7.3 point 2, 6.9):\n");
    SCTP_Socket stack;
    Association_Key key = Access::establish(stack);
    complete_search(stack, key);

    Association& assoc = Access::tcb(stack, key);
    Peer_Path second = make_path(address_of("127.0.0.2"), true);
    second.plpmtud.plpmtu = 1300;
    assoc.peer_address_list.push_back(second);
    check(amdcs(assoc) == 1280, "the smallest PMDCS among confirmed paths");

    assoc.peer_address_list.back().active = false;
    check(amdcs(assoc) == 1460, "an inactive path does not count");
    assoc.peer_address_list.back().active = true;

    Access::api(stack).sctp_send_data(key, std::vector<uint8_t>(4000, 'x'));
    auto packet = Access::transmit(stack);
    if (!packet) { check(false, "DATA sent"); return; }
    const auto& data = std::get<data_chunk_value>(packet->packet.chunks.back().chunk_value);
    check(data.user_data.size() == 1280 - 16, "DATA is fragmented to the AMDCS, not the primary's PMDCS");
}

void test_black_hole_and_ip_fragmentation() {
    std::printf("Black hole detection and resending a chunk too big for the path (RFC 8899 4.3, RFC 9260 6.9):\n");
    SCTP_Socket stack;
    Association_Key key = Access::establish(stack);
    complete_search(stack, key);

    Access::api(stack).sctp_send_data(key, std::vector<uint8_t>(1444, 'x'));
    auto first = Access::transmit(stack);
    check(first && datagram_size(*first) == 1480, "a full-sized DATA packet at 1480");

    Access::fire_t3(stack, key);
    auto resent = Access::drain(stack);
    check(plpmtud(stack, key).confirming, "losing it starts a probe at the PLPMTU");
    check(resent.size() == 1 && !resent[0].ip_fragment, "the retransmission still fits and keeps DF");

    std::vector<size_t> sizes;
    for (int i = 0; i < 5; ++i) {
        if (auto probe = probe_now(stack, key)) {
            sizes.push_back(datagram_size(*probe));
        }
    }
    check(sizes == std::vector<size_t>{1480, 1480, 1480, 1200},
          "three lost probes at 1480 send the path back to BASE");
    check(plpmtud(stack, key).state == Plpmtud_State::BASE && amdcs(Access::tcb(stack, key)) == 1180,
          "PMDCS drops to BASE");

    Access::fire_t3(stack, key);
    resent = Access::drain(stack);
    check(resent.size() == 1 && resent[0].ip_fragment && datagram_size(resent[0]) == 1480,
          "the chunk is not re-fragmented: it is resent whole, without DF");
}

void test_raise_timer_searches_again() {
    std::printf("PMTU_RAISE_TIMER (RFC 8899 5.1.1):\n");
    SCTP_Socket stack;
    Association_Key key = Access::establish(stack);
    auto base = probe_now(stack, key);
    if (!base) { check(false, "BASE probe sent"); return; }
    acknowledge(stack, *base);
    for (int i = 0; i < 3; ++i) probe_now(stack, key);
    for (int i = 0; i < 64 && plpmtud(stack, key).state != Plpmtud_State::SEARCH_COMPLETE; ++i) {
        probe_now(stack, key);
    }
    check(plpmtud(stack, key).state == Plpmtud_State::SEARCH_COMPLETE && plpmtud(stack, key).plpmtu == 1200,
          "every larger size lost: SEARCH_COMPLETE at 1200");

    Access::fire(stack, key, Expiration_Timer_Type::PMTU_RAISE, peer_address());
    auto probe = probe_now(stack, key);
    check(plpmtud(stack, key).state == Plpmtud_State::SEARCHING && probe && datagram_size(*probe) == 1480,
          "on expiry the search starts over from MAX_PLPMTU");
}

void test_packet_too_big() {
    std::printf("ICMP Packet Too Big (RFC 9260 10 ICMP5-7, RFC 8899 4.6):\n");
    SCTP_Socket stack;
    Association_Key key = Access::establish(stack);
    auto base = probe_now(stack, key);
    if (!base) { check(false, "BASE probe sent"); return; }
    acknowledge(stack, *base);
    probe_now(stack, key);

    Access::ptb(stack, {0x26, 0xAB, 0x9C, 0x40}, 1420);
    check(plpmtud(stack, key).probed_size == 1480, "too short to hold the Verification Tag: ignored");
    Access::ptb(stack, quoted_header(PEER_TAG ^ 1), 1420);
    check(plpmtud(stack, key).probed_size == 1480, "a Verification Tag that is not the peer's: ignored");
    Access::ptb(stack, quoted_header(PEER_TAG), 1500);
    check(plpmtud(stack, key).probed_size == 1480, "PL_PTB_SIZE >= PROBED_SIZE: ignored");

    Access::ptb(stack, quoted_header(PEER_TAG), 1421);
    auto probe = probe_now(stack, key);
    check(plpmtud(stack, key).plpmtu == 1200 && probe && datagram_size(*probe) == 1400,
          "PLPMTU < PL_PTB_SIZE < PROBED_SIZE: the next probe is PL_PTB_SIZE, and the PLPMTU is left alone");
    if (!probe) return;
    acknowledge(stack, *probe);
    check(plpmtud(stack, key).state == Plpmtud_State::SEARCH_COMPLETE && plpmtud(stack, key).plpmtu == 1400,
          "nothing between 1400 and the reported limit is left to try");

    Access::ptb(stack, quoted_header(PEER_TAG), 1320);
    check(plpmtud(stack, key).plpmtu == 1200 && plpmtud(stack, key).state == Plpmtud_State::SEARCHING,
          "BASE_PLPMTU <= PL_PTB_SIZE < PLPMTU: a black hole, the PLPMTU drops to BASE");
    probe = probe_now(stack, key);
    check(probe && datagram_size(*probe) == 1300, "and the search resumes at PL_PTB_SIZE");

    Access::ptb(stack, quoted_header(PEER_TAG), 600);
    check(plpmtud(stack, key).state == Plpmtud_State::ERROR && plpmtud(stack, key).plpmtu == 1200,
          "MIN_PLPMTU < PL_PTB_SIZE < BASE_PLPMTU: ERROR, keeping BASE");
}

} // namespace

int main() {
    test_probe_format();
    test_search_climbs_to_max();
    test_lost_probes_narrow_the_search();
    test_base_failure_is_an_error();
    test_amdcs_is_the_smallest_pmdcs();
    test_black_hole_and_ip_fragmentation();
    test_raise_timer_searches_again();
    test_packet_too_big();

    return report();
}
