// Path heartbeats (RFC 9260 8.3): the HEARTBEAT ACK a peer is owed, the checks
// an answering HEARTBEAT ACK has to pass before it is believed, and the error
// counting that ends an association whose peer stopped answering.
//
// Packets go straight into handle_recv_packet and the timer is fired by hand
// through handle_expiration, so nothing here waits on wall-clock time.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "serialize.hpp"
#include "socket_internal.hpp"

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;

namespace {

constexpr uint32_t OUR_TAG = 0x0A0B0C0D;
constexpr uint32_t PEER_TAG = 0x11223344;
constexpr uint16_t PEER_PORT = 40000;
constexpr uint16_t LOCAL_PORT = 9899;

sockaddr_in peer_address() {
    sockaddr_in src{};
    src.sin_family = AF_INET;
    src.sin_port = htons(PEER_PORT);
    sctp_parse_ipv4("127.0.0.1", src.sin_addr);
    return src;
}

} // namespace

struct SCTP_Socket_Test_Access {
    // An established association, with the socket's own address filled in so
    // originated packets have ports to carry.
    static void establish(SCTP_Socket& stack, const Association_Key& key) {
        stack.local_address.sin_family = AF_INET;
        stack.local_address.sin_port = htons(LOCAL_PORT);
        sctp_parse_ipv4("127.0.0.1", stack.local_address.sin_addr);

        Association assoc = stack.init_new_association(key);
        assoc.this_ver_tag = OUR_TAG;
        assoc.peer_ver_tag = PEER_TAG;
        assoc.state = ESTABLISHED;
        assoc.last_peer_tsn = 0;
        stack.associations.insert_or_assign(key, assoc);
    }

    static void deliver(SCTP_Socket& stack, const SCTP_Packet& packet) {
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.handle_recv_packet(wire.data(), wire.size(), peer_address());
    }

    static void fire_heartbeat_timer(SCTP_Socket& stack, const Association_Key& key) {
        stack.handle_expiration(Expiration_Fallback{
            Expiration_Key{key, Expiration_Timer_Type::HEARTBEAT},
            Clock::now(), 0, Deliverable{key, SCTP_Packet{}}});
    }

    static std::vector<SCTP_Packet> drain_sends(SCTP_Socket& stack) {
        std::vector<SCTP_Packet> sent;
        auto now = Clock::now();
        while (auto pending = stack.sends.peek(now)) {
            sent.push_back(pending->deliverable.packet);
            stack.sends.commit(pending->priority);
        }
        return sent;
    }

    static std::vector<Notification> drain_notifications(SCTP_Socket& stack) {
        std::vector<Notification> out;
        while (auto notification = stack.notifications.dequeue()) {
            out.push_back(*notification);
        }
        return out;
    }

    static bool has_association(SCTP_Socket& stack, const Association_Key& key) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        return stack.associations.find(key) != stack.associations.end();
    }

    static Association& tcb(SCTP_Socket& stack, const Association_Key& key) {
        return stack.associations.at(key);
    }

    static bool timer_armed(SCTP_Socket& stack, const Association_Key& key) {
        return stack.expirations.is_active(Expiration_Key{key, Expiration_Timer_Type::HEARTBEAT});
    }

    // Marks one TSN outstanding, which is what makes a destination non-idle.
    static void add_outstanding_data(SCTP_Socket& stack, const Association_Key& key) {
        Association& assoc = stack.associations.at(key);
        data_chunk_value data{assoc.next_tsn, 0, 0, 0, {'x'}};
        stack.record_data_sent(key, data, Clock::now());
    }
};

namespace {

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

using Access = SCTP_Socket_Test_Access;

SCTP_Packet inbound(uint32_t tag, Chunk_Type type, std::vector<uint8_t> info) {
    SCTP_Packet packet;
    packet.header = {PEER_PORT, LOCAL_PORT, tag, 0};
    packet.chunks.push_back({{type, 0, 0}, heartbeat_chunk_value{std::move(info)}});
    return packet;
}

bool is_type(const SCTP_Packet& packet, Chunk_Type type) {
    return !packet.chunks.empty() && packet.chunks[0].chunk_header.type == type;
}

const std::vector<uint8_t>& info_of(const SCTP_Packet& packet) {
    return std::get<heartbeat_chunk_value>(packet.chunks[0].chunk_value).info;
}

void test_heartbeat_is_answered() {
    std::printf("Receiving a HEARTBEAT (3.3.5, 3.3.6):\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);

    std::vector<uint8_t> info = {0xDE, 0xAD, 0xBE, 0xEF, 0x01};
    Access::deliver(stack, inbound(OUR_TAG, HEARTBEAT, info));

    auto sent = Access::drain_sends(stack);
    check(sent.size() == 1 && is_type(sent[0], HEARTBEAT_ACK), "one HEARTBEAT ACK sent");
    if (sent.size() != 1 || !is_type(sent[0], HEARTBEAT_ACK)) return;

    check(info_of(sent[0]) == info, "Heartbeat Info echoed verbatim");
    check(sent[0].header.verification_tag == PEER_TAG, "addressed with the peer's tag");
    check(sent[0].header.src_port == LOCAL_PORT && sent[0].header.des_port == PEER_PORT,
          "ports swapped back towards the sender");
    check(sent[0].chunks[0].chunk_header.flag == 0, "no flags: 3.3.6 defines none");
}

void test_oversized_info_is_not_echoed() {
    std::printf("A HEARTBEAT whose Info exceeds the path MTU:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);

    std::vector<uint8_t> info(DEFAULT_PMDCS, 0x5A);
    Access::deliver(stack, inbound(OUR_TAG, HEARTBEAT, info));

    check(Access::drain_sends(stack).empty(), "no reply: echoing it would exceed PMDCS");
    check(Access::has_association(stack, key), "and the association is untouched");
}

void test_heartbeat_probe_is_sent_when_idle() {
    std::printf("The heartbeat timer on an idle path (8.3):\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    Access::fire_heartbeat_timer(stack, key);

    auto sent = Access::drain_sends(stack);
    check(sent.size() == 1 && is_type(sent[0], HEARTBEAT), "one HEARTBEAT sent");
    if (sent.size() != 1 || !is_type(sent[0], HEARTBEAT)) return;

    check(sent[0].header.verification_tag == PEER_TAG, "addressed with the peer's tag");
    check(info_of(sent[0]).size() == HEARTBEAT_INFO_SIZE, "Heartbeat Info is the nonce and destination");
    check(read_be32(info_of(sent[0]).data()) == Access::tcb(stack, key).hb_nonce,
          "the nonce on the wire is the one recorded in the TCB");
    check(Access::tcb(stack, key).hb_outstanding, "the probe is marked outstanding");
    check(Access::timer_armed(stack, key), "and the timer is re-armed");
}

void test_no_probe_while_data_is_outstanding() {
    std::printf("The heartbeat timer on a path with unacknowledged DATA:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    Access::add_outstanding_data(stack, key);
    Access::fire_heartbeat_timer(stack, key);

    check(Access::drain_sends(stack).empty(), "no probe: T3-rtx is already testing the path");
    check(!Access::tcb(stack, key).hb_outstanding, "nothing marked outstanding");
    check(Access::timer_armed(stack, key), "the timer is still re-armed");
}

void test_matching_ack_clears_the_path() {
    std::printf("A HEARTBEAT ACK that answers our probe:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    Access::fire_heartbeat_timer(stack, key);
    auto sent = Access::drain_sends(stack);
    if (sent.size() != 1) {
        check(false, "probe sent");
        return;
    }

    Access::tcb(stack, key).error_count = 3;
    Access::deliver(stack, inbound(OUR_TAG, HEARTBEAT_ACK, info_of(sent[0])));

    const Association& assoc = Access::tcb(stack, key);
    check(!assoc.hb_outstanding, "the probe is no longer outstanding");
    check(assoc.error_count == 0, "the error count is cleared");
    check(assoc.has_srtt, "the round trip fed the RTO estimator");
    check(Access::drain_sends(stack).empty(), "a HEARTBEAT ACK is never answered");
}

void test_ack_with_a_foreign_nonce_is_ignored() {
    std::printf("A HEARTBEAT ACK carrying a nonce we never sent:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    Access::fire_heartbeat_timer(stack, key);
    auto sent = Access::drain_sends(stack);
    if (sent.size() != 1) {
        check(false, "probe sent");
        return;
    }

    Access::tcb(stack, key).error_count = 3;
    std::vector<uint8_t> forged = info_of(sent[0]);
    forged[0] ^= 0xFF;
    Access::deliver(stack, inbound(OUR_TAG, HEARTBEAT_ACK, forged));

    const Association& assoc = Access::tcb(stack, key);
    check(assoc.hb_outstanding, "the probe is still outstanding");
    check(assoc.error_count == 3, "the error count is untouched");
    check(!assoc.has_srtt, "and no round trip was measured from it");
}

void test_unsolicited_ack_is_ignored() {
    std::printf("A HEARTBEAT ACK with no probe outstanding:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);

    Access::tcb(stack, key).error_count = 2;
    sockaddr_in destination = peer_address();
    Access::deliver(stack, inbound(OUR_TAG, HEARTBEAT_ACK, heartbeat_info(0, destination)));

    check(Access::tcb(stack, key).error_count == 2, "the error count is untouched");
    check(!Access::tcb(stack, key).has_srtt, "no round trip measured");
}

void test_unanswered_probes_end_the_association() {
    std::printf("A peer that stops answering (8.1):\n");

    SCTP_Socket stack;
    stack.sctp_subscribe(Notification_Type::SCTP_ASSOC_CHANGE, true);
    Association_Key key{peer_address()};
    Access::establish(stack, key);

    // One firing to send the first probe, then one per unanswered probe until
    // the count passes the threshold.
    int threshold = Access::tcb(stack, key).error_threshold;
    for (int i = 0; i <= threshold + 1; i++) {
        Access::fire_heartbeat_timer(stack, key);
        Access::drain_sends(stack);
        if (i == 0) {
            check(Access::tcb(stack, key).error_count == 0,
                  "the first firing sends a probe and counts nothing");
        }
    }

    check(!Access::has_association(stack, key), "the association is gone once the threshold is passed");
    check(!Access::timer_armed(stack, key), "and its heartbeat timer with it");
    check(Access::drain_sends(stack).empty(), "no ABORT: an unreachable peer is not told");

    auto notifications = Access::drain_notifications(stack);
    bool lost = false;
    for (const auto& notification : notifications) {
        const auto* change = std::get_if<Assoc_Change>(&notification.payload);
        lost = lost || (change && change->state == Assoc_Change_State::COMM_LOST);
    }
    check(lost, "the upper layer is told the association was lost");
}

} // namespace

int main() {
    std::printf("Heartbeat tests (RFC 9260 8.3)\n\n");

    test_heartbeat_is_answered();
    test_oversized_info_is_not_echoed();
    test_heartbeat_probe_is_sent_when_idle();
    test_no_probe_while_data_is_outstanding();
    test_matching_ack_clears_the_path();
    test_ack_with_a_foreign_nonce_is_ignored();
    test_unsolicited_ack_is_ignored();
    test_unanswered_probes_end_the_association();

    if (failures == 0) {
        std::printf("\nALL TESTS PASSED (0 failures)\n");
        return 0;
    }
    std::printf("\n%d CHECK(S) FAILED\n", failures);
    return 1;
}
