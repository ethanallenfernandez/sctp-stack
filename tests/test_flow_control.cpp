// Flow and congestion control (RFC 9260 6.1, 6.2, 6.2.1, 6.3.3, 7.2): on the
// sending side, per-association admission of new DATA and retransmissions
// against cwnd and the peer's rwnd, zero window probing, Max.Burst, cwnd growth
// and idle decay; on the receiving side, the a_rwnd we advertise, window
// updates, and dropping DATA once the receive buffer is full.
//
// transmit() does what run_sending does minus the sendto(), so nothing here
// touches the network or waits on wall-clock time.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "serialize.hpp"
#include "socket_internal.hpp"

#include <chrono>
#include <cstdio>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

using Clock = std::chrono::steady_clock;

namespace {

constexpr uint32_t OUR_TAG = 0x0A0B0C0D;
constexpr uint32_t PEER_TAG = 0x11223344;
constexpr uint16_t LOCAL_PORT = 9899;
constexpr uint32_t INITIAL_TSN = 1000;
constexpr uint32_t PEER_TSN = 5000;

sockaddr_in peer_address(uint16_t port) {
    sockaddr_in src{};
    src.sin_family = AF_INET;
    src.sin_port = htons(port);
    sctp_parse_ipv4("127.0.0.1", src.sin_addr);
    return src;
}

} // namespace

struct SCTP_Socket_Test_Access {
    static void establish(SCTP_Socket& stack, const Association_Key& key, uint32_t cwnd, uint32_t peer_rwnd) {
        stack.local_address.sin_family = AF_INET;
        stack.local_address.sin_port = htons(LOCAL_PORT);
        sctp_parse_ipv4("127.0.0.1", stack.local_address.sin_addr);

        Association assoc = stack.init_new_association(key);
        assoc.this_ver_tag = OUR_TAG;
        assoc.peer_ver_tag = PEER_TAG;
        assoc.state = ESTABLISHED;
        assoc.next_tsn = INITIAL_TSN;
        assoc.cumulative_tsn_ack = INITIAL_TSN - 1;
        assoc.last_peer_tsn = PEER_TSN - 1;
        assoc.cwnd = cwnd;
        assoc.peer_rwnd = peer_rwnd;
        assoc.data_sent_at = Clock::now();
        stack.associations.insert_or_assign(key, assoc);
    }

    static Association new_association(SCTP_Socket& stack, const Association_Key& key) {
        return stack.init_new_association(key);
    }

    static std::optional<SCTP_Packet> transmit(SCTP_Socket& stack) {
        auto pending = stack.next_packet();
        if (!pending) {
            return std::nullopt;
        }
        stack.packet_sent(*pending);
        return pending->deliverable.packet;
    }

    // What run_sending does when sendto fails: the packet stays queued.
    static std::optional<SCTP_Packet> fail_transmit(SCTP_Socket& stack) {
        auto pending = stack.next_packet();
        if (!pending) {
            return std::nullopt;
        }
        stack.requeue_bundled_sack(*pending);
        return pending->deliverable.packet;
    }

    static void start_transmission_opportunity(SCTP_Socket& stack) {
        stack.start_transmission_opportunity();
    }

    static Send_Allowances allowances(SCTP_Socket& stack) {
        return stack.send_allowances();
    }

    static void deliver_sack(SCTP_Socket& stack, uint16_t peer_port, uint32_t cumulative_tsn_ack, uint32_t a_rwnd,
                             std::vector<sack_gap_ack_block> gaps = {}, std::vector<uint32_t> duplicates = {}) {
        SCTP_Packet sack = build_sack(peer_port, LOCAL_PORT, OUR_TAG, cumulative_tsn_ack, a_rwnd, std::move(gaps), std::move(duplicates));
        std::vector<uint8_t> wire = serialize_sctp_packet(sack);
        stack.handle_recv_packet(wire.data(), wire.size(), peer_address(peer_port));
    }

    // One DATA chunk from the peer, by default with the I bit so it is
    // acknowledged at once.
    static void deliver_data(SCTP_Socket& stack, uint16_t peer_port, uint32_t tsn, size_t size, bool immediate = true) {
        SCTP_Packet packet = build_data(peer_port, LOCAL_PORT, OUR_TAG,
            {data_chunk_value{tsn, 0, 0, 0, std::vector<uint8_t>(size, 'p')}});
        packet.chunks[0].chunk_header.flag |= immediate ? DATA_IMMEDIATE_SACK_FLAG : 0;
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.handle_recv_packet(wire.data(), wire.size(), peer_address(peer_port));
    }

    // Takes everything off the send queue, windows ignored.
    static std::vector<SCTP_Packet> drain(SCTP_Socket& stack) {
        std::vector<SCTP_Packet> sent;
        while (auto pending = stack.sends.peek(Clock::now())) {
            sent.push_back(pending->deliverable.packet);
            stack.sends.commit(*pending);
        }
        return sent;
    }

    static bool retransmission_queued(SCTP_Socket& stack, const Association_Key& key) {
        return stack.sends.has_retransmission_for(key);
    }

    static void refresh_allowances(SCTP_Socket& stack) {
        stack.send_allowances();
    }

    static void fire(SCTP_Socket& stack, const Association_Key& key, Expiration_Timer_Type type) {
        stack.handle_expiration(Expiration_Fallback{
            Expiration_Key{key, type}, Clock::now(), 0, Deliverable{key, SCTP_Packet{}}});
    }

    static bool timer_armed(SCTP_Socket& stack, const Association_Key& key, Expiration_Timer_Type type) {
        return stack.expirations.is_active(Expiration_Key{key, type});
    }

    static bool send_pending(SCTP_Socket& stack) {
        return stack.sends.next_deadline().has_value();
    }

    static bool has_association(SCTP_Socket& stack, const Association_Key& key) {
        return stack.associations.find(key) != stack.associations.end();
    }

    static bool comm_lost_notified(SCTP_Socket& stack) {
        bool lost = false;
        while (auto notification = stack.notifications.dequeue()) {
            const auto* change = std::get_if<Assoc_Change>(&notification->payload);
            lost = lost || (change && change->state == Assoc_Change_State::COMM_LOST);
        }
        return lost;
    }

    static size_t queued(SCTP_Socket& stack) {
        return stack.sends.size();
    }

    static Association& tcb(SCTP_Socket& stack, const Association_Key& key) {
        return stack.associations.at(key);
    }
};

namespace {

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

using Access = SCTP_Socket_Test_Access;

// 400 bytes of user data is a 416-byte DATA chunk.
const std::vector<uint8_t> MESSAGE(400, 'x');
constexpr uint32_t CHUNK = 416;

uint32_t tsn_of(const SCTP_Packet& packet) {
    return std::get<data_chunk_value>(packet.chunks[0].chunk_value).tsn;
}

// One pass of the send loop.
int send_all(SCTP_Socket& stack) {
    Access::start_transmission_opportunity(stack);
    int sent = 0;
    while (Access::transmit(stack)) {
        ++sent;
    }
    return sent;
}

void test_cwnd_limits_new_data() {
    std::printf("Rule B: new DATA stops once flightsize reaches cwnd:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 1200, 65535);
    for (int i = 0; i < 4; ++i) {
        stack.sctp_send_data(key, MESSAGE);
    }

    int sent = 0;
    while (Access::transmit(stack)) {
        ++sent;
    }
    check(sent == 3, "three packets sent: the third breaches cwnd by less than PMDCS");
    check(bytes_in_flight(Access::tcb(stack, key)) == 3 * CHUNK, "flightsize counts every chunk sent");
    check(Access::queued(stack) == 1, "the fourth waits in the queue");
    check(!Access::send_pending(stack), "a refused packet does not keep the event loop spinning");
}

void test_rwnd_limits_new_data() {
    std::printf("Rule A and 6.2.1 B: rwnd is spent as DATA goes out:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 4380, 500);
    stack.sctp_send_data(key, MESSAGE);
    stack.sctp_send_data(key, MESSAGE);

    check(Access::transmit(stack).has_value(), "the first chunk fits the window");
    check(Access::tcb(stack, key).peer_rwnd == 500 - CHUNK, "rwnd is reduced by the chunk sent");
    check(!Access::transmit(stack).has_value(), "the second does not fit, though cwnd is open");
    check(!Access::timer_armed(stack, key, Expiration_Timer_Type::ZERO_WINDOW_PROBE),
          "no probe while DATA is in flight");

    Access::deliver_sack(stack, 40000, INITIAL_TSN, 65535);
    auto packet = Access::transmit(stack);
    check(packet && tsn_of(*packet) == INITIAL_TSN + 1, "a SACK that reopens the window releases it");
}

void test_associations_are_gated_independently() {
    std::printf("A closed window holds back only its own association:\n");

    SCTP_Socket stack;
    Association_Key closed{peer_address(40000)};
    Association_Key open{peer_address(40001)};
    Access::establish(stack, closed, 4380, 0);
    Access::establish(stack, open, 4380, 65535);
    Access::tcb(stack, closed).outstanding_data.emplace(
        INITIAL_TSN - 1, Outstanding_Data{data_chunk_value{INITIAL_TSN - 1, 0, 0, 0, {'x'}}, {}, {}, false, false, 0, false, false});
    stack.sctp_send_data(closed, MESSAGE);
    stack.sctp_send_data(open, MESSAGE);

    auto packet = Access::transmit(stack);
    check(packet && packet->header.des_port == 40001, "the open association's DATA goes first");
    check(!Access::transmit(stack).has_value(), "the closed one's stays queued");
}

void test_tsn_order_is_kept_within_an_association() {
    std::printf("A smaller later message does not overtake a refused one:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 4380, 500);
    Access::tcb(stack, key).outstanding_data.emplace(
        INITIAL_TSN - 1, Outstanding_Data{data_chunk_value{INITIAL_TSN - 1, 0, 0, 0, {'x'}}, {}, {}, false, false, 0, false, false});
    stack.sctp_send_data(key, std::vector<uint8_t>(1000, 'x'));
    stack.sctp_send_data(key, {'y'});

    check(!Access::transmit(stack).has_value(), "nothing is sent");
    check(Access::queued(stack) == 2, "both messages stay queued in order");
}

void test_zero_window_probe() {
    std::printf("Rule A: zero window probing:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 4380, 0);
    stack.sctp_send_data(key, MESSAGE);

    check(!Access::transmit(stack).has_value(), "no DATA while the window is closed");
    check(Access::timer_armed(stack, key, Expiration_Timer_Type::ZERO_WINDOW_PROBE),
          "the first probe is scheduled an RTO out");

    Access::fire(stack, key, Expiration_Timer_Type::ZERO_WINDOW_PROBE);
    auto probe = Access::transmit(stack);
    check(probe && tsn_of(*probe) == INITIAL_TSN, "the queued chunk goes out as the probe");
    check(Access::tcb(stack, key).zero_window_probing, "the association is marked as probing");
    check(Access::timer_armed(stack, key, Expiration_Timer_Type::T3_RTX), "T3-rtx backs the probe off from here");

    stack.sctp_send_data(key, MESSAGE);
    check(!Access::transmit(stack).has_value(), "only one probe is in flight");

    Association& assoc = Access::tcb(stack, key);
    uint32_t cwnd = assoc.cwnd;
    Access::deliver_sack(stack, 40000, INITIAL_TSN - 1, 0);
    Access::fire(stack, key, Expiration_Timer_Type::T3_RTX);
    check(assoc.error_count == 0, "a probe expiring while SACKs arrive is not an error");
    check(assoc.cwnd == cwnd, "probing leaves cwnd alone");
    Access::fire(stack, key, Expiration_Timer_Type::T3_RTX);
    check(assoc.error_count == 1, "one expiring with no SACK since is");

    Access::deliver_sack(stack, 40000, INITIAL_TSN, 65535);
    check(!assoc.zero_window_probing, "a SACK that opens the window ends probing");
    check(Access::transmit(stack).has_value(), "and queued DATA flows again");
}

void test_max_burst() {
    std::printf("Rule D: Max.Burst new-DATA packets per transmission opportunity:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 65535, 65535);
    for (int i = 0; i < 6; ++i) {
        stack.sctp_send_data(key, MESSAGE);
    }

    check(send_all(stack) == static_cast<int>(sctp_parameters::MAX_BURST), "Max.Burst packets go, though cwnd allows more");
    auto allowances = Access::allowances(stack);
    check(allowances.at(key).burst_spent && allowances.at(key).cwnd_open,
          "the burst is spent while cwnd itself stays open for retransmissions");
    check(!Access::transmit(stack).has_value(), "nothing more in the same opportunity");
    check(send_all(stack) == 2, "the next opportunity starts a new burst");
}

void test_initial_cwnd() {
    std::printf("7.2.1: initial cwnd for an IPv4 peer:\n");

    SCTP_Socket stack;
    Association fresh = Access::new_association(stack, Association_Key{peer_address(40000)});
    check(fresh.pmdcs == 1200 && fresh.cwnd == 4404, "min(4 * PMDCS, max(2 * PMDCS, 4404)) with a 1200-byte PMDCS");
}

void test_slow_start_grows_a_full_window() {
    std::printf("7.2.1: slow start on a fully utilized window:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 1200, 65535);
    for (int i = 0; i < 4; ++i) {
        stack.sctp_send_data(key, MESSAGE);
    }
    send_all(stack);

    Access::deliver_sack(stack, 40000, INITIAL_TSN, 65535);
    check(Access::tcb(stack, key).cwnd == 1200 + CHUNK, "cwnd grows by the bytes acknowledged");
    check(Access::tcb(stack, key).partial_bytes_acked == 0, "partial_bytes_acked is untouched");
}

void test_slow_start_increase_is_capped() {
    std::printf("7.2.1: slow start grows by at most L * PMDCS per SACK:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 1200, 65535);
    for (int i = 0; i < 3; ++i) {
        stack.sctp_send_data(key, MESSAGE);
    }
    send_all(stack);

    Access::deliver_sack(stack, 40000, INITIAL_TSN + 2, 65535);
    check(Access::tcb(stack, key).cwnd == 1200 + DEFAULT_PMDCS, "3 chunks acked, but cwnd grows by one PMDCS");
}

void test_slow_start_needs_a_full_window() {
    std::printf("7.2.1: no growth while the window is not being used:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 4404, 65535);
    stack.sctp_send_data(key, MESSAGE);
    send_all(stack);

    Access::deliver_sack(stack, 40000, INITIAL_TSN, 65535);
    check(Access::tcb(stack, key).cwnd == 4404, "cwnd is unchanged");
}

void test_slow_start_pauses_in_fast_recovery() {
    std::printf("7.2.1: no slow start growth in Fast Recovery:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 1200, 65535);
    for (int i = 0; i < 3; ++i) {
        stack.sctp_send_data(key, MESSAGE);
    }
    send_all(stack);
    Access::tcb(stack, key).in_fast_recovery = true;
    Access::tcb(stack, key).fast_recovery_exit_tsn = INITIAL_TSN + 2;

    Access::deliver_sack(stack, 40000, INITIAL_TSN, 65535);
    check(Access::tcb(stack, key).cwnd == 1200, "cwnd is unchanged");
}

void test_congestion_avoidance() {
    std::printf("7.2.2: congestion avoidance adds one PMDCS per cwnd acknowledged:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 1200, 65535);
    Association& assoc = Access::tcb(stack, key);
    assoc.ssthresh = 1000;
    for (int i = 0; i < 6; ++i) {
        stack.sctp_send_data(key, MESSAGE);
    }

    check(send_all(stack) == 3, "three chunks fill the window");
    Access::deliver_sack(stack, 40000, INITIAL_TSN, 65535);
    check(assoc.cwnd == 1200 && assoc.partial_bytes_acked == CHUNK, "first SACK: bytes counted, cwnd unchanged");

    check(send_all(stack) == 1, "one more chunk refills it");
    Access::deliver_sack(stack, 40000, INITIAL_TSN + 1, 65535);
    check(assoc.cwnd == 1200 && assoc.partial_bytes_acked == 2 * CHUNK, "second SACK: still counting");

    check(send_all(stack) == 1, "and again");
    Access::deliver_sack(stack, 40000, INITIAL_TSN + 2, 65535);
    check(assoc.cwnd == 1200 + DEFAULT_PMDCS, "a full cwnd acknowledged adds one PMDCS");
    check(assoc.partial_bytes_acked == 3 * CHUNK - 1200, "and cwnd is taken off partial_bytes_acked");
}

void test_congestion_avoidance_needs_a_full_window() {
    std::printf("7.2.2: partial_bytes_acked on a window that is not full:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 1200, 65535);
    Association& assoc = Access::tcb(stack, key);
    assoc.ssthresh = 1000;
    assoc.partial_bytes_acked = 1000;
    stack.sctp_send_data(key, MESSAGE);
    stack.sctp_send_data(key, MESSAGE);
    send_all(stack);

    Access::deliver_sack(stack, 40000, INITIAL_TSN, 65535);
    check(assoc.cwnd == 1200, "cwnd is unchanged");
    check(assoc.partial_bytes_acked == 1200, "partial_bytes_acked is capped at cwnd");

    Access::deliver_sack(stack, 40000, INITIAL_TSN + 1, 65535);
    check(assoc.partial_bytes_acked == 0, "it resets once everything sent is acknowledged");
}

std::vector<uint32_t> tsns_of(const SCTP_Packet& packet) {
    std::vector<uint32_t> tsns;
    for (const auto& chunk : packet.chunks) {
        tsns.push_back(std::get<data_chunk_value>(chunk.chunk_value).tsn);
    }
    return tsns;
}

std::optional<sack_chunk_value> last_sack(const std::vector<SCTP_Packet>& packets) {
    std::optional<sack_chunk_value> sack;
    for (const auto& packet : packets) {
        for (const auto& chunk : packet.chunks) {
            if (chunk.chunk_header.type == SACK) {
                sack = std::get<sack_chunk_value>(chunk.chunk_value);
            }
        }
    }
    return sack;
}

size_t read_message(SCTP_Socket& stack) {
    std::vector<uint8_t> buffer(RWND);
    return stack.sctp_recv_data(buffer);
}

void test_idle_cwnd_decay() {
    std::printf("7.2.1: cwnd decays while no DATA is sent:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 20000, 65535);
    Association& assoc = Access::tcb(stack, key);
    assoc.data_sent_at = Clock::now() - std::chrono::milliseconds(2500);

    Access::refresh_allowances(stack);
    check(assoc.ssthresh == 20000, "ssthresh is set to cwnd before the first decay");
    check(assoc.cwnd == 5000, "two idle RTOs halve cwnd twice");
    Access::refresh_allowances(stack);
    check(assoc.cwnd == 5000, "the elapsed RTOs are only applied once");

    assoc.data_sent_at = Clock::now() - std::chrono::milliseconds(1100);
    Access::refresh_allowances(stack);
    check(assoc.cwnd == 4 * DEFAULT_PMDCS, "cwnd stops at 4 * PMDCS");
    check(assoc.ssthresh == 20000, "ssthresh is kept through later decays");

    stack.sctp_send_data(key, MESSAGE);
    Access::transmit(stack);
    check(!assoc.idle_decaying && Clock::now() - assoc.data_sent_at < std::chrono::seconds(1),
          "sending DATA ends the idle period");
}

void test_idle_decay_never_raises_cwnd() {
    std::printf("7.2.1: idle decay never raises cwnd:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, DEFAULT_PMDCS, 65535);
    Association& assoc = Access::tcb(stack, key);
    uint32_t ssthresh = assoc.ssthresh;
    assoc.data_sent_at = Clock::now() - std::chrono::seconds(10);

    Access::refresh_allowances(stack);
    check(assoc.cwnd == DEFAULT_PMDCS, "cwnd stays at one PMDCS rather than rising to 4 * PMDCS");
    check(assoc.ssthresh == ssthresh, "and ssthresh is untouched");
}

void test_t3_marks_everything_outstanding() {
    std::printf("6.3.3 and 7.2.1: after T3-rtx, one packet in flight until an ack:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 4404, 65535);
    for (int i = 0; i < 3; ++i) {
        stack.sctp_send_data(key, MESSAGE);
    }
    send_all(stack);

    Access::fire(stack, key, Expiration_Timer_Type::T3_RTX);
    Association& assoc = Access::tcb(stack, key);
    check(assoc.cwnd == DEFAULT_PMDCS, "cwnd drops to one PMDCS");
    check(Access::retransmission_queued(stack, key), "the first retransmission is queued at once");
    check(assoc.outstanding_data.at(INITIAL_TSN + 2).pending_retransmission,
          "what did not fit is marked for retransmission");

    auto first = Access::transmit(stack);
    check(first && tsns_of(*first) == std::vector<uint32_t>({INITIAL_TSN, INITIAL_TSN + 1}),
          "the earliest chunks that fit one packet go first");
    check(!Access::transmit(stack).has_value(), "nothing more while that packet is unacknowledged");

    Access::deliver_sack(stack, 40000, INITIAL_TSN + 1, 65535);
    auto second = Access::transmit(stack);
    check(second && tsns_of(*second) == std::vector<uint32_t>({INITIAL_TSN + 2}),
          "the SACK releases the remaining marked chunk");
}

void test_marked_chunks_wait_for_cwnd() {
    std::printf("6.1 C: marked chunks go before new DATA, as cwnd allows:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 1200, 65535);
    for (int i = 0; i < 4; ++i) {
        stack.sctp_send_data(key, MESSAGE);
    }
    check(send_all(stack) == 3, "three chunks in flight");

    Association& assoc = Access::tcb(stack, key);
    assoc.cwnd = 800;
    assoc.outstanding_data.at(INITIAL_TSN + 2).pending_retransmission = true;
    check(!Access::transmit(stack).has_value(), "a marked chunk waits while flightsize is at cwnd");

    Access::deliver_sack(stack, 40000, INITIAL_TSN, 65535);
    auto packet = Access::transmit(stack);
    check(packet && tsns_of(*packet) == std::vector<uint32_t>({INITIAL_TSN + 2}),
          "once cwnd opens it goes ahead of the queued new DATA");
}

void test_fast_retransmit_on_entering_fast_recovery() {
    std::printf("7.2.4: the Fast Retransmit packet is sent on entering Fast Recovery:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 4404, 65535);
    for (int i = 0; i < 5; ++i) {
        stack.sctp_send_data(key, MESSAGE);
    }
    send_all(stack);

    Access::deliver_sack(stack, 40000, INITIAL_TSN - 1, 65535, {{2, 2}});
    Access::deliver_sack(stack, 40000, INITIAL_TSN - 1, 65535, {{2, 3}});
    check(!Access::retransmission_queued(stack, key), "nothing before the third miss indication");
    Access::deliver_sack(stack, 40000, INITIAL_TSN - 1, 65535, {{2, 4}});
    check(Access::tcb(stack, key).in_fast_recovery, "the third enters Fast Recovery");
    check(Access::retransmission_queued(stack, key), "and queues the retransmission without waiting for cwnd");
}

void test_advertised_window_tracks_the_buffer() {
    std::printf("6.2: a_rwnd is the receive buffer left over:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 4404, 65535);

    Access::deliver_data(stack, 40000, PEER_TSN, 1000);
    auto sack = last_sack(Access::drain(stack));
    check(sack && sack->a_rwnd == RWND - 1000, "1000 unread bytes are taken off the window");

    check(read_message(stack) == 1000, "the ULP reads them");
    check(Access::drain(stack).empty(), "freeing 1000 bytes is not worth a window update");

    Access::deliver_data(stack, 40000, PEER_TSN + 1, 100);
    sack = last_sack(Access::drain(stack));
    check(sack && sack->a_rwnd == RWND - 1000,
          "receiver SWS: the 900-byte opening is held back rather than advertised");
}

void test_window_update() {
    std::printf("6.2: a window update when the ULP frees a quarter of the buffer:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 4404, 65535);
    for (uint32_t i = 0; i < 3; ++i) {
        Access::deliver_data(stack, 40000, PEER_TSN + i, 20000);
    }
    auto sack = last_sack(Access::drain(stack));
    check(sack && sack->a_rwnd == RWND - 60000, "the window is nearly closed");

    read_message(stack);
    sack = last_sack(Access::drain(stack));
    check(sack && sack->a_rwnd == RWND - 40000, "reading 20000 bytes sends a SACK with the new window");
    check(sack && sack->cumulative_tsn_ack == PEER_TSN + 2, "acknowledging nothing new");
}

void test_full_buffer_drops_new_data() {
    std::printf("6.2: with the window at 0, DATA above everything received is dropped:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 4404, 65535);
    for (uint32_t i = 0; i < 3; ++i) {
        Access::deliver_data(stack, 40000, PEER_TSN + i, RWND / 3);
    }
    Access::drain(stack);

    Access::deliver_data(stack, 40000, PEER_TSN + 3, 100);
    auto sack = last_sack(Access::drain(stack));
    check(Access::tcb(stack, key).last_peer_tsn == PEER_TSN + 2, "the chunk is not accepted");
    check(sack && sack->cumulative_tsn_ack == PEER_TSN + 2 && sack->gap_ack_blocks.empty(),
          "the immediate SACK does not include it");
    check(sack && sack->a_rwnd == 0, "and reports the window as 0");
}

void test_full_buffer_prefers_the_lower_tsn() {
    std::printf("6.2: with the window at 0, a lower TSN displaces the highest one held:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 4404, 65535);
    Access::deliver_data(stack, 40000, PEER_TSN, 60000);
    Access::deliver_data(stack, 40000, PEER_TSN + 2, RWND - 60000);
    auto sack = last_sack(Access::drain(stack));
    check(sack && sack->a_rwnd == 0 && sack->gap_ack_blocks.size() == 1, "buffer full, with TSN +2 held out of order");

    Access::deliver_data(stack, 40000, PEER_TSN + 1, 10);
    Association& assoc = Access::tcb(stack, key);
    check(assoc.last_peer_tsn == PEER_TSN + 1, "the missing TSN is accepted");
    check(assoc.tsn_ooo_buffer.empty(), "the highest TSN held is dropped to make room");
    sack = last_sack(Access::drain(stack));
    check(sack && sack->cumulative_tsn_ack == PEER_TSN + 1 && sack->gap_ack_blocks.empty(),
          "the SACK no longer reports it");
}

void test_unanswered_retransmissions_end_the_association() {
    std::printf("8.1: T3-rtx expiries past Association.Max.Retrans:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 4404, 65535);
    stack.sctp_send_data(key, MESSAGE);
    Access::transmit(stack);

    for (uint16_t i = 0; i < sctp_parameters::ASSOCIATION_MAX_RETRANS; ++i) {
        Access::fire(stack, key, Expiration_Timer_Type::T3_RTX);
    }
    check(Access::has_association(stack, key), "the association survives Association.Max.Retrans expiries");
    Access::drain(stack);

    Access::fire(stack, key, Expiration_Timer_Type::T3_RTX);
    check(!Access::has_association(stack, key), "one more ends it");
    check(Access::comm_lost_notified(stack), "the ULP is told communication was lost");
    check(Access::drain(stack).empty(), "and nothing is sent, not even an ABORT");
}

void test_probe_expiries_with_sacks_do_not_end_the_association() {
    std::printf("6.1 A: a probed zero window never counts towards Association.Max.Retrans:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 4404, 0);
    stack.sctp_send_data(key, MESSAGE);
    Access::transmit(stack);
    Access::fire(stack, key, Expiration_Timer_Type::ZERO_WINDOW_PROBE);
    Access::transmit(stack);

    for (uint16_t i = 0; i < 2 * sctp_parameters::ASSOCIATION_MAX_RETRANS; ++i) {
        Access::deliver_sack(stack, 40000, INITIAL_TSN - 1, 0);
        Access::fire(stack, key, Expiration_Timer_Type::T3_RTX);
    }
    check(Access::has_association(stack, key), "the association is kept while the peer keeps answering");
}

bool immediate_sack_requested(const SCTP_Packet& packet) {
    return (packet.chunks.back().chunk_header.flag & DATA_IMMEDIATE_SACK_FLAG) != 0;
}

void test_sack_is_bundled_with_data() {
    std::printf("6.1: a delayed SACK is bundled with outgoing DATA:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 65535, 65535);
    Access::deliver_data(stack, 40000, PEER_TSN, 100, false);
    check(Access::timer_armed(stack, key, Expiration_Timer_Type::DELAYED_SACK), "the peer's DATA starts the delayed SACK timer");

    stack.sctp_send_data(key, MESSAGE);
    auto packet = Access::transmit(stack);
    check(packet && packet->chunks.size() == 2 && packet->chunks[0].chunk_header.type == SACK
              && packet->chunks[1].chunk_header.type == DATA,
          "our DATA goes out with the SACK ahead of it");
    check(packet && std::get<sack_chunk_value>(packet->chunks[0].chunk_value).cumulative_tsn_ack == PEER_TSN,
          "acknowledging the peer's DATA");
    check(!Access::timer_armed(stack, key, Expiration_Timer_Type::DELAYED_SACK), "and the delayed SACK timer is stopped");
}

void test_bundled_sack_survives_a_failed_send() {
    std::printf("A SACK bundled into a packet whose send fails is not lost:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 65535, 65535);
    Access::deliver_data(stack, 40000, PEER_TSN, 100, false);
    stack.sctp_send_data(key, MESSAGE);

    auto attempt = Access::fail_transmit(stack);
    check(attempt && attempt->chunks.front().chunk_header.type == SACK, "the SACK was bundled into the failed packet");
    auto retry = Access::drain(stack);
    check(retry.size() == 2 && retry[0].chunks.size() == 1 && retry[0].chunks[0].chunk_header.type == SACK,
          "it is queued again on its own, ahead of the DATA");
    check(retry.size() == 2 && retry[1].chunks.size() == 1 && retry[1].chunks[0].chunk_header.type == DATA,
          "and the queued DATA packet is unchanged");
}

void test_sack_that_does_not_fit_goes_alone() {
    std::printf("6.1: a SACK that would overflow the packet is sent on its own:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 65535, 65535);
    Access::deliver_data(stack, 40000, PEER_TSN, 100, false);

    stack.sctp_send_data(key, std::vector<uint8_t>(DEFAULT_PMDCS - 16, 'x'));
    auto packet = Access::transmit(stack);
    check(packet && packet->chunks.size() == 1 && packet->chunks[0].chunk_header.type == DATA,
          "a full-size DATA packet is sent unchanged");
    auto sack = last_sack(Access::drain(stack));
    check(sack && sack->cumulative_tsn_ack == PEER_TSN, "the SACK follows as its own packet");
    check(!Access::timer_armed(stack, key, Expiration_Timer_Type::DELAYED_SACK), "without waiting for the timer");
}

void test_immediate_sack_bit() {
    std::printf("6.1: the I bit on DATA that fills a window, or in SHUTDOWN-PENDING:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 1200, 65535);
    for (int i = 0; i < 3; ++i) {
        stack.sctp_send_data(key, MESSAGE);
    }
    auto first = Access::transmit(stack);
    auto second = Access::transmit(stack);
    auto third = Access::transmit(stack);
    check(first && second && !immediate_sack_requested(*first) && !immediate_sack_requested(*second),
          "not while there is room left");
    check(third && immediate_sack_requested(*third), "set on the packet that fills cwnd");

    SCTP_Socket small_window;
    Access::establish(small_window, key, 65535, CHUNK);
    small_window.sctp_send_data(key, MESSAGE);
    auto filling = Access::transmit(small_window);
    check(filling && immediate_sack_requested(*filling), "set on the packet that fills the peer's rwnd");

    SCTP_Socket closing;
    Access::establish(closing, key, 65535, 65535);
    closing.sctp_send_data(key, MESSAGE);
    Access::tcb(closing, key).state = SHUTDOWN_PENDING;
    auto last = Access::transmit(closing);
    check(last && immediate_sack_requested(*last), "set in SHUTDOWN-PENDING");
}

void test_duplicate_tsns_count_in_congestion_avoidance() {
    std::printf("7.2.2: Duplicate TSNs add to partial_bytes_acked:\n");

    SCTP_Socket stack;
    Association_Key key{peer_address(40000)};
    Access::establish(stack, key, 1200, 65535);
    Association& assoc = Access::tcb(stack, key);
    assoc.ssthresh = 1000;
    stack.sctp_send_data(key, MESSAGE);
    stack.sctp_send_data(key, MESSAGE);
    send_all(stack);
    assoc.outstanding_data.at(INITIAL_TSN).retransmitted = true;

    Access::deliver_sack(stack, 40000, INITIAL_TSN, 65535);
    check(assoc.partial_bytes_acked == CHUNK, "the acked chunk is counted");
    Access::deliver_sack(stack, 40000, INITIAL_TSN, 65535, {}, {INITIAL_TSN});
    check(assoc.partial_bytes_acked == 2 * CHUNK, "a report of it as a duplicate counts its size again");
    Access::deliver_sack(stack, 40000, INITIAL_TSN, 65535, {}, {INITIAL_TSN});
    check(assoc.partial_bytes_acked == 2 * CHUNK, "but only once");
}

} // namespace

int main() {
    std::printf("Flow and congestion control tests (RFC 9260 6.1, 6.2.1, 7.2)\n\n");

    test_cwnd_limits_new_data();
    test_rwnd_limits_new_data();
    test_associations_are_gated_independently();
    test_tsn_order_is_kept_within_an_association();
    test_zero_window_probe();
    test_max_burst();
    test_initial_cwnd();
    test_slow_start_grows_a_full_window();
    test_slow_start_increase_is_capped();
    test_slow_start_needs_a_full_window();
    test_slow_start_pauses_in_fast_recovery();
    test_congestion_avoidance();
    test_congestion_avoidance_needs_a_full_window();
    test_idle_cwnd_decay();
    test_idle_decay_never_raises_cwnd();
    test_t3_marks_everything_outstanding();
    test_marked_chunks_wait_for_cwnd();
    test_fast_retransmit_on_entering_fast_recovery();
    test_advertised_window_tracks_the_buffer();
    test_window_update();
    test_full_buffer_drops_new_data();
    test_full_buffer_prefers_the_lower_tsn();
    test_unanswered_retransmissions_end_the_association();
    test_probe_expiries_with_sacks_do_not_end_the_association();
    test_sack_is_bundled_with_data();
    test_bundled_sack_survives_a_failed_send();
    test_sack_that_does_not_fit_goes_alone();
    test_immediate_sack_bit();
    test_duplicate_tsns_count_in_congestion_avoidance();

    if (failures == 0) {
        std::printf("\nALL TESTS PASSED (0 failures)\n");
        return 0;
    }
    std::printf("\n%d CHECK(S) FAILED\n", failures);
    return 1;
}
