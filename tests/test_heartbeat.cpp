// Path heartbeats (RFC 9260 8.3) and path verification (5.4): the HEARTBEAT ACK
// a peer is owed, the checks an answering HEARTBEAT ACK has to pass before it
// is believed, the per-destination timers, error counts and RTOs, and the error
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
#include <optional>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;

namespace {

bool same_transport_address(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}

constexpr uint32_t OUR_TAG = 0x0A0B0C0D;
constexpr uint32_t PEER_TAG = 0x11223344;
constexpr uint16_t PEER_PORT = 40000;
constexpr uint16_t LOCAL_PORT = 9899;

sockaddr_in address_of(const char* ip) {
    sockaddr_in src{};
    src.sin_family = AF_INET;
    src.sin_port = htons(PEER_PORT);
    sctp_parse_ipv4(ip, src.sin_addr);
    return src;
}

sockaddr_in peer_address() {
    return address_of("127.0.0.1");
}

sockaddr_in second_address() {
    return address_of("127.0.0.2");
}

sockaddr_in third_address() {
    return address_of("127.0.0.3");
}

} // namespace

struct SCTP_Socket_Test_Access {
    // An established association, with the socket's own address filled in so
    // originated packets have ports to carry.
    static void establish(SCTP_Socket& stack, const Association_Key& key) {
        stack.local_address.sin_family = AF_INET;
        stack.local_address.sin_port = htons(LOCAL_PORT);
        sctp_parse_ipv4("127.0.0.1", stack.local_address.sin_addr);

        Association assoc = stack.init_new_association(key.address);
        assoc.this_ver_tag = OUR_TAG;
        assoc.peer_ver_tag = PEER_TAG;
        assoc.state = ESTABLISHED;
        assoc.last_peer_tsn = 0;
        assoc.primary_path = key.address;
        stack.associations.insert_or_assign(key, assoc);
        stack.start_heartbeats(key, stack.associations.at(key));
    }

    static void deliver(SCTP_Socket& stack, const SCTP_Packet& packet) {
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.handle_recv_packet(wire.data(), wire.size(), peer_address());
    }

    // Further peer addresses, UNCONFIRMED, with their timers armed as at establishment.
    static void add_paths(SCTP_Socket& stack, const Association_Key& key, const std::vector<sockaddr_in>& addresses) {
        Association& assoc = stack.associations.at(key);
        stack.add_peer_addresses(key, assoc, addresses);
        stack.start_heartbeats(key, assoc);
    }

    static void fire_heartbeat_timer(SCTP_Socket& stack, const Association_Key& key, const sockaddr_in& path) {
        stack.handle_expiration(Expiration_Fallback{
            Expiration_Key{key, Expiration_Timer_Type::HEARTBEAT, path_key(path)},
            Clock::now(), 0, Deliverable{key, {}, SCTP_Packet{}}});
    }

    static void fire_heartbeat_timer(SCTP_Socket& stack, const Association_Key& key) {
        fire_heartbeat_timer(stack, key, key.address);
    }

    static void fire_t3(SCTP_Socket& stack, const Association_Key& key) {
        stack.handle_t3_expiration(key, key.address);
    }

    static std::vector<Deliverable> drain_deliverables(SCTP_Socket& stack) {
        std::vector<Deliverable> sent;
        auto now = Clock::now();
        while (auto pending = stack.sends.peek(now)) {
            sent.push_back(pending->deliverable);
            stack.sends.commit(*pending);
        }
        return sent;
    }

    static std::vector<SCTP_Packet> drain_sends(SCTP_Socket& stack) {
        std::vector<SCTP_Packet> sent;
        auto now = Clock::now();
        while (auto pending = stack.sends.peek(now)) {
            sent.push_back(pending->deliverable.packet);
            stack.sends.commit(*pending);
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

    static SCTP_Socket& api(SCTP_Socket& stack) {
        return stack;
    }

    static bool has_association(SCTP_Socket& stack, const Association_Key& key) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        return stack.associations.find(key) != stack.associations.end();
    }

    static Association& tcb(SCTP_Socket& stack, const Association_Key& key) {
        return stack.associations.at(key);
    }

    static Peer_Path& path(SCTP_Socket& stack, const Association_Key& key, const sockaddr_in& address) {
        return *find_path(stack.associations.at(key), address);
    }

    static Peer_Path& primary_path(SCTP_Socket& stack, const Association_Key& key) {
        return primary(stack.associations.at(key));
    }

    static bool timer_armed(SCTP_Socket& stack, const Association_Key& key, const sockaddr_in& path) {
        return stack.expirations.is_active(Expiration_Key{key, Expiration_Timer_Type::HEARTBEAT, path_key(path)});
    }

    static bool timer_armed(SCTP_Socket& stack, const Association_Key& key) {
        return timer_armed(stack, key, key.address);
    }

    // Whether the path's heartbeat timer falls due within `within`. Destructive:
    // every timer due by then is taken off the heap.
    static bool due_within(SCTP_Socket& stack, const Association_Key& key, const sockaddr_in& path, Clock::duration within) {
        Expiration_Key timer{key, Expiration_Timer_Type::HEARTBEAT, path_key(path)};
        for (const auto& fallback : stack.expirations.drain_expired(Clock::now() + within)) {
            if (fallback.key == timer) {
                return true;
            }
        }
        return false;
    }

    // Marks one TSN outstanding, which is what makes a destination non-idle.
    static void add_outstanding_data(SCTP_Socket& stack, const Association_Key& key) {
        Association& assoc = stack.associations.at(key);
        data_chunk_value data{assoc.next_tsn++, 0, 0, 0, {'x'}};
        stack.record_data_sent(key, key.address, data, Clock::now());
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
    check(heartbeat_info_nonce(info_of(sent[0])) == Access::primary_path(stack, key).hb_nonce,
          "the nonce on the wire is the one recorded for the path");
    check(same_transport_address(heartbeat_info_destination(info_of(sent[0])), key.address),
          "and the Info names the destination");
    check(Access::primary_path(stack, key).hb_outstanding, "the probe is marked outstanding");
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
    check(!Access::primary_path(stack, key).hb_outstanding, "nothing marked outstanding");
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
    Access::primary_path(stack, key).error_count = 3;
    Access::deliver(stack, inbound(OUR_TAG, HEARTBEAT_ACK, info_of(sent[0])));

    const Peer_Path& path = Access::primary_path(stack, key);
    check(!path.hb_outstanding, "the probe is no longer outstanding");
    check(Access::tcb(stack, key).error_count == 0, "the association error count is cleared");
    check(path.error_count == 0, "and the path's");
    check(path.has_srtt, "the round trip fed the path's RTO estimator");
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
    forged[7] ^= 0xFF;
    Access::deliver(stack, inbound(OUR_TAG, HEARTBEAT_ACK, forged));

    const Peer_Path& path = Access::primary_path(stack, key);
    check(path.hb_outstanding, "the probe is still outstanding");
    check(Access::tcb(stack, key).error_count == 3, "the error count is untouched");
    check(!path.has_srtt, "and no round trip was measured from it");
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
    check(!Access::primary_path(stack, key).has_srtt, "no round trip measured");
}

void test_unanswered_probes_end_the_association() {
    std::printf("A peer that stops answering (8.1):\n");

    SCTP_Socket stack;
    stack.sctp_subscribe(Notification_Type::SCTP_ASSOC_CHANGE, true);
    Association_Key key{peer_address()};
    Access::establish(stack, key);

    // Each round sends a probe, then lets its one-RTO deadline pass.
    int threshold = Access::tcb(stack, key).error_threshold;
    for (int i = 0; i <= threshold; i++) {
        Access::fire_heartbeat_timer(stack, key);
        if (i == 0) {
            check(Access::tcb(stack, key).error_count == 0,
                  "the firing that sends a probe counts nothing");
        }
        Access::fire_heartbeat_timer(stack, key);
        Access::drain_sends(stack);
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

// The probe the next firing of a path's timer sends, as it went to the wire.
std::optional<Deliverable> probe(SCTP_Socket& stack, const Association_Key& key, const sockaddr_in& path) {
    Access::fire_heartbeat_timer(stack, key, path);
    auto sent = Access::drain_deliverables(stack);
    if (sent.size() != 1 || !is_type(sent[0].packet, HEARTBEAT)) {
        return std::nullopt;
    }
    return sent[0];
}

// A probe sent, then left unanswered past its deadline.
void unanswered(SCTP_Socket& stack, const Association_Key& key, const sockaddr_in& path) {
    Access::fire_heartbeat_timer(stack, key, path);
    Access::fire_heartbeat_timer(stack, key, path);
    Access::drain_sends(stack);
}

// Answers a probe from the primary address, whatever path it went out on.
void acknowledge(SCTP_Socket& stack, const Deliverable& probe) {
    Access::deliver(stack, inbound(OUR_TAG, HEARTBEAT_ACK, info_of(probe.packet)));
}

std::vector<Peer_Addr_Change> address_changes(SCTP_Socket& stack) {
    std::vector<Peer_Addr_Change> out;
    for (const auto& notification : Access::drain_notifications(stack)) {
        if (const auto* change = std::get_if<Peer_Addr_Change>(&notification.payload)) {
            out.push_back(*change);
        }
    }
    return out;
}

bool reports(const std::vector<Peer_Addr_Change>& changes, const sockaddr_in& address, Peer_Addr_State state) {
    for (const auto& change : changes) {
        if (same_transport_address(change.address, address) && change.state == state) {
            return true;
        }
    }
    return false;
}

void test_unconfirmed_path_is_probed_every_rto() {
    std::printf("An UNCONFIRMED path (5.4):\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    Access::add_paths(stack, key, {second_address()});

    check(!Access::path(stack, key, second_address()).confirmed, "starts UNCONFIRMED");
    check(Access::due_within(stack, key, second_address(), Clock::duration::zero()), "is probed at once");

    auto sent = probe(stack, key, second_address());
    check(sent.has_value(), "one HEARTBEAT sent");
    if (!sent) return;
    check(same_transport_address(sent->destination, second_address()), "to that address");
    check(same_transport_address(heartbeat_info_destination(info_of(sent->packet)), second_address()),
          "with the Info naming it");
    check(!Access::due_within(stack, key, second_address(), std::chrono::milliseconds(900))
          && Access::due_within(stack, key, second_address(), std::chrono::milliseconds(1100)),
          "and probed again one RTO later, not HB.interval");
}

void test_ack_confirms_the_path_it_names() {
    std::printf("A HEARTBEAT ACK for an UNCONFIRMED path, arriving over another:\n");

    SCTP_Socket stack;
    stack.sctp_subscribe(Notification_Type::SCTP_PEER_ADDR_CHANGE, true);
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    Access::add_paths(stack, key, {second_address()});
    auto sent = probe(stack, key, second_address());
    if (!sent) {
        check(false, "probe sent");
        return;
    }
    acknowledge(stack, *sent);

    const Peer_Path& path = *find_path(Access::tcb(stack, key), second_address());
    check(path.confirmed, "the named path is CONFIRMED");
    check(path.has_srtt, "the round trip is measured for that path");
    check(!Access::primary_path(stack, key).has_srtt, "and not for the one the ACK arrived on");
    check(reports(address_changes(stack), second_address(), Peer_Addr_State::ADDR_CONFIRMED),
          "the upper layer is told it was confirmed");
    check(Access::timer_armed(stack, key, second_address())
          && !Access::due_within(stack, key, second_address(), sctp_parameters::HB_INTERVAL),
          "its timer drops to the HB.interval rate");
}

void test_confirmation_probes_are_bounded_by_hb_max_burst() {
    std::printf("Several UNCONFIRMED paths (5.4, HB.Max.Burst):\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    Access::add_paths(stack, key, {second_address(), third_address()});

    check(Access::timer_armed(stack, key, second_address()), "the first is probed");
    check(!Access::timer_armed(stack, key, third_address()), "the second waits its turn");

    auto sent = probe(stack, key, second_address());
    if (!sent) {
        check(false, "probe sent");
        return;
    }
    acknowledge(stack, *sent);
    check(Access::due_within(stack, key, third_address(), Clock::duration::zero()),
          "once the first is confirmed the second is probed at once");
}

void test_unconfirmed_path_that_never_answers() {
    std::printf("An UNCONFIRMED path that never answers:\n");

    SCTP_Socket stack;
    stack.sctp_subscribe(Notification_Type::SCTP_PEER_ADDR_CHANGE, true);
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    Access::add_paths(stack, key, {second_address(), third_address()});

    for (int i = 0; i <= sctp_parameters::PATH_MAX_RETRANS + 1; i++) {
        probe(stack, key, second_address());
    }

    const Peer_Path& path = *find_path(Access::tcb(stack, key), second_address());
    check(!path.active && !path.confirmed, "is marked inactive past Path.Max.Retrans");
    check(path.error_count == sctp_parameters::PATH_MAX_RETRANS + 1, "its error count stops there");
    check(Access::tcb(stack, key).error_count == 0, "the association error count is not touched");
    check(reports(address_changes(stack), second_address(), Peer_Addr_State::ADDR_UNREACHABLE),
          "the upper layer is told it is unreachable");
    check(Access::due_within(stack, key, third_address(), Clock::duration::zero()),
          "the next UNCONFIRMED path takes its turn");
    check(Access::timer_armed(stack, key, second_address())
          && !Access::due_within(stack, key, second_address(), sctp_parameters::HB_INTERVAL),
          "and this one falls back to the HB.interval rate");
}

void test_alternate_path_failure_and_recovery() {
    std::printf("A CONFIRMED alternate path that stops answering (8.2, 8.3):\n");

    SCTP_Socket stack;
    stack.sctp_subscribe(Notification_Type::SCTP_PEER_ADDR_CHANGE, true);
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    Access::add_paths(stack, key, {second_address()});
    if (auto sent = probe(stack, key, second_address())) {
        acknowledge(stack, *sent);
    }
    address_changes(stack);

    unanswered(stack, key, second_address());
    const Peer_Path& path = *find_path(Access::tcb(stack, key), second_address());
    check(path.error_count == 1, "an unanswered probe counts against the path");
    check(Access::tcb(stack, key).error_count == 0, "but not the association: it carries no data");
    check(path.rto == 2 * std::chrono::microseconds(sctp_parameters::RTO_INITIAL), "and backs off the path's RTO");
    check(Access::primary_path(stack, key).rto == std::chrono::microseconds(sctp_parameters::RTO_INITIAL),
          "leaving the primary's alone");

    for (int i = 0; i < sctp_parameters::PATH_MAX_RETRANS; i++) {
        unanswered(stack, key, second_address());
    }
    check(!path.active, "past Path.Max.Retrans it is inactive");
    check(reports(address_changes(stack), second_address(), Peer_Addr_State::ADDR_UNREACHABLE), "and reported");
    std::optional<Deliverable> last = probe(stack, key, second_address());
    check(last.has_value(), "it is still heartbeated");
    check(Access::has_association(stack, key), "the association survives");
    if (!last) return;

    acknowledge(stack, *last);
    check(path.active && path.error_count == 0, "an answer makes it active again");
    check(reports(address_changes(stack), second_address(), Peer_Addr_State::ADDR_AVAILABLE), "and is reported");
}

void test_unanswered_primary_probe() {
    std::printf("An unanswered probe on the primary path:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    unanswered(stack, key, key.address);

    check(Access::primary_path(stack, key).error_count == 1, "counts against the path");
    check(Access::tcb(stack, key).error_count == 1, "and the association: it is the path carrying data");
    check(Access::primary_path(stack, key).rto == 2 * std::chrono::microseconds(sctp_parameters::RTO_INITIAL),
          "and backs off its RTO");
}

void test_t3_counts_against_the_primary_path() {
    std::printf("A T3-rtx expiry (8.2):\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    Access::add_outstanding_data(stack, key);
    Access::fire_t3(stack, key);

    check(Access::primary_path(stack, key).error_count == 1, "counts against the primary path");
}

// A CONFIRMED alternate, its first probe answered.
void confirm_second_path(SCTP_Socket& stack, const Association_Key& key) {
    Access::add_paths(stack, key, {second_address()});
    if (auto sent = probe(stack, key, second_address())) {
        acknowledge(stack, *sent);
    }
}

void test_probe_deadline_is_one_rto() {
    std::printf("A probe on a CONFIRMED path (8.3, one RTO to answer):\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    probe(stack, key, key.address);

    check(!Access::due_within(stack, key, key.address, std::chrono::milliseconds(900))
          && Access::due_within(stack, key, key.address, std::chrono::milliseconds(1100)),
          "its timer runs to one RTO after it was sent");
    Access::fire_heartbeat_timer(stack, key);
    check(Access::primary_path(stack, key).error_count == 1, "and an unanswered one counts when it fires");
    check(Access::drain_sends(stack).empty(), "with no new probe before the next interval");
    check(Access::timer_armed(stack, key)
          && !Access::due_within(stack, key, key.address, sctp_parameters::HB_INTERVAL),
          "which the timer then runs to");
}

void test_answer_returns_to_the_interval() {
    std::printf("A probe answered inside its RTO:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    auto sent = probe(stack, key, key.address);
    if (!sent) {
        check(false, "probe sent");
        return;
    }
    acknowledge(stack, *sent);
    check(Access::timer_armed(stack, key)
          && !Access::due_within(stack, key, key.address, sctp_parameters::HB_INTERVAL),
          "the timer goes back to the next interval, not the deadline");
}

void test_idle_means_no_new_data_this_period() {
    std::printf("Idleness (8.3):\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    Access::add_outstanding_data(stack, key);
    Peer_Path& path = Access::primary_path(stack, key);
    path.new_data_sent_at = path.hb_period_start - std::chrono::seconds(1);

    check(probe(stack, key, key.address).has_value(),
          "DATA still outstanding from before the period does not stop a probe");
    Access::fire_heartbeat_timer(stack, key);
    Access::drain_sends(stack);
    Access::add_outstanding_data(stack, key);
    Access::fire_heartbeat_timer(stack, key);
    check(Access::drain_sends(stack).empty(), "new DATA sent within it does");
}

void test_alternate_ack_leaves_the_association_count() {
    std::printf("A HEARTBEAT ACK on a path that carries no DATA (8.1):\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    confirm_second_path(stack, key);

    Access::tcb(stack, key).error_count = 3;
    if (auto sent = probe(stack, key, second_address())) {
        acknowledge(stack, *sent);
    }
    check(Access::tcb(stack, key).error_count == 3, "does not clear the association error count");
    if (auto sent = probe(stack, key, key.address)) {
        acknowledge(stack, *sent);
    }
    check(Access::tcb(stack, key).error_count == 0, "one on the primary does");
}

void test_change_heartbeat() {
    std::printf("CHANGE HEARTBEAT (11.1.9):\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    SCTP_Socket& api = Access::api(stack);

    check(!api.sctp_change_heartbeat(key, second_address(), false), "refused for an unknown destination");
    check(api.sctp_change_heartbeat(key, key.address, false), "accepted for a known one");
    check(!Access::timer_armed(stack, key), "disabling stops the path's timer");
    Access::fire_heartbeat_timer(stack, key);
    check(Access::drain_sends(stack).empty(), "and nothing is probed");

    check(api.sctp_change_heartbeat(key, key.address, true, std::chrono::seconds(120)), "re-enabled with a new interval");
    check(Access::tcb(stack, key).hb_interval == std::chrono::seconds(120), "the interval is the association's");
    check(Access::timer_armed(stack, key)
          && !Access::due_within(stack, key, key.address, std::chrono::seconds(120)),
          "and the next probe is at least that far off");
}

void test_disabled_unconfirmed_path_gives_up_its_turn() {
    std::printf("Disabling heartbeat on an UNCONFIRMED path:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    Access::add_paths(stack, key, {second_address(), third_address()});
    Access::api(stack).sctp_change_heartbeat(key, second_address(), false);

    check(!Access::timer_armed(stack, key, second_address()), "stops its probing");
    check(Access::due_within(stack, key, third_address(), Clock::duration::zero()), "and the next path is probed");
}

void test_request_heartbeat() {
    std::printf("REQUESTHEARTBEAT (11.1.10):\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);

    check(!Access::api(stack).sctp_request_heartbeat(key, second_address()), "refused for an unknown destination");
    check(Access::api(stack).sctp_request_heartbeat(key, key.address), "accepted for a known one");
    auto sent = Access::drain_sends(stack);
    check(sent.size() == 1 && is_type(sent[0], HEARTBEAT), "a HEARTBEAT goes out at once");
    check(Access::primary_path(stack, key).hb_outstanding, "and is awaited like any other");
}

void test_set_primary() {
    std::printf("SETPRIMARY (11.1.6):\n");

    SCTP_Socket stack;
    Association_Key key{peer_address()};
    Access::establish(stack, key);
    Access::add_paths(stack, key, {second_address()});

    check(!Access::api(stack).sctp_set_primary(key, second_address()), "refused for an UNCONFIRMED destination");
    if (auto sent = probe(stack, key, second_address())) {
        acknowledge(stack, *sent);
    }
    check(Access::api(stack).sctp_set_primary(key, second_address()), "accepted once it is CONFIRMED");
    check(same_transport_address(Access::tcb(stack, key).primary_path, second_address()), "and it is the primary");
}

} // namespace

int main() {
    std::printf("Heartbeat tests (RFC 9260 5.4, 8.3)\n\n");

    test_heartbeat_is_answered();
    test_oversized_info_is_not_echoed();
    test_heartbeat_probe_is_sent_when_idle();
    test_no_probe_while_data_is_outstanding();
    test_matching_ack_clears_the_path();
    test_ack_with_a_foreign_nonce_is_ignored();
    test_unsolicited_ack_is_ignored();
    test_unanswered_probes_end_the_association();
    test_unconfirmed_path_is_probed_every_rto();
    test_ack_confirms_the_path_it_names();
    test_confirmation_probes_are_bounded_by_hb_max_burst();
    test_unconfirmed_path_that_never_answers();
    test_alternate_path_failure_and_recovery();
    test_unanswered_primary_probe();
    test_t3_counts_against_the_primary_path();
    test_probe_deadline_is_one_rto();
    test_answer_returns_to_the_interval();
    test_idle_means_no_new_data_this_period();
    test_alternate_ack_leaves_the_association_count();
    test_change_heartbeat();
    test_disabled_unconfirmed_path_gives_up_its_turn();
    test_request_heartbeat();
    test_set_primary();

    if (failures == 0) {
        std::printf("\nALL TESTS PASSED (0 failures)\n");
        return 0;
    }
    std::printf("\n%d CHECK(S) FAILED\n", failures);
    return 1;
}
