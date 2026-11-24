// RFC 9260 section 6: user data transfer.

#include "rfc_harness.hpp"

#include <map>
#include <set>

using namespace rfc;

namespace {

const std::vector<uint8_t> KB(1000, 'k');
constexpr uint8_t UBE = DATA_FLAG_U | DATA_FLAG_B | DATA_FLAG_E;

void deliver(SCTP_Socket& s, uint32_t tsn, std::vector<uint8_t> bytes = {'d'}, uint8_t flags = UBE, uint16_t stream = 0,
             uint16_t ssn = 0, uint8_t extra = 0, const sockaddr_in& src = addr()) {
    Access::receive(s, packet(OUR_TAG, {data_chunk(data(tsn, std::move(bytes), flags, stream, ssn), extra)}), src);
}

void sack(SCTP_Socket& s, uint32_t cumulative, uint32_t a_rwnd = RWND, std::vector<sack_gap_ack_block> gaps = {},
          const sockaddr_in& src = addr()) {
    Access::receive(s, packet(OUR_TAG, {sack_chunk(cumulative, a_rwnd, std::move(gaps))}), src);
}

std::optional<sack_chunk_value> last_sack(const Sent& sent) {
    std::optional<sack_chunk_value> found;
    for (const auto& d : sent.out) {
        if (const auto* v = find_value<sack_chunk_value>(d.packet, SACK)) {
            found = *v;
        }
    }
    return found;
}

bool sack_covers(const std::optional<sack_chunk_value>& v, uint32_t tsn) {
    return v && sack_acknowledges(*v, tsn);
}

size_t wire_size(const SCTP_Packet& p) {
    return serialize_sctp_packet(p).size();
}

void s6_states() {
    section("6 User Data Transfer: states");
    auto sends_in = [](Association_State state) {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s, state);
        a.send.outbound.push_back(Outbound_Message{0, 0, false, {'s'}, 0, 0});
        a.send.outbound_bytes = 1;
        return !Access::sent(s).data().empty();
    };
    req("9260-6-1", sends_in(ESTABLISHED) && sends_in(SHUTDOWN_PENDING) && sends_in(SHUTDOWN_RECEIVED)
            && !sends_in(COOKIE_ECHOED) && !sends_in(SHUTDOWN_SENT) && !sends_in(SHUTDOWN_ACK_SENT),
        "DATA is sent only in ESTABLISHED, SHUTDOWN-PENDING and SHUTDOWN-RECEIVED");
    auto takes_in = [](Association_State state) {
        SCTP_Socket s;
        Access::establish(s, state);
        deliver(s, PEER_TSN);
        std::vector<uint8_t> buffer(4);
        return Access::read(s, buffer) == 1;
    };
    req("9260-6-2", takes_in(ESTABLISHED) && takes_in(SHUTDOWN_PENDING) && takes_in(SHUTDOWN_SENT)
            && !takes_in(SHUTDOWN_RECEIVED) && !takes_in(SHUTDOWN_ACK_SENT),
        "DATA is accepted only in ESTABLISHED, SHUTDOWN-PENDING and SHUTDOWN-SENT");
    {
        SCTP_Socket s;
        Access::setup(s);
        deliver(s, PEER_TSN);
        auto out = Access::sent(s);
        req("9260-6-3", out.any(ABORT) && !out.any(SACK), "DATA with no TCB is out of the blue: ABORT");
        Access::receive(s, packet(OUR_TAG, {sack_chunk(5)}));
        auto sack_out = Access::sent(s);
        req("9260-6-6", sack_out.any(ABORT), "SACK with no TCB is out of the blue: ABORT");
    }
    {
        SCTP_Socket s;
        Access::establish(s, COOKIE_ECHOED);
        deliver(s, PEER_TSN);
        std::vector<uint8_t> buffer(4);
        req("9260-6-4", Access::read(s, buffer) == 0 && !Access::sent(s).any(SACK), "DATA in COOKIE-ECHOED is discarded");
    }
    auto processes_sack_in = [](Association_State state) {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s, state);
        a.send.outstanding.emplace(OUR_TSN, Outstanding_Data{data(OUR_TSN), Clock::now(), Clock::now(), false, false, 0, false, false, addr()});
        a.send.next_tsn = OUR_TSN + 1;
        sack(s, OUR_TSN);
        return a.send.outstanding.empty();
    };
    req("9260-6-5", processes_sack_in(ESTABLISHED) && processes_sack_in(SHUTDOWN_PENDING) && processes_sack_in(SHUTDOWN_RECEIVED),
        "SACK is processed in ESTABLISHED, SHUTDOWN-PENDING and SHUTDOWN-RECEIVED");
    req("9260-6-7", !processes_sack_in(COOKIE_ECHOED) && !processes_sack_in(SHUTDOWN_ACK_SENT), "and discarded in other states");
}

void s6_fragmentation_and_bundling() {
    section("6 User Data Transfer: fragmentation and bundling");
    SCTP_Socket s;
    Association_TCB& a = Access::establish(s);
    Access::send(s, std::vector<uint8_t>(5000, 'f'));
    auto chunks = Access::sent(s).data();
    req("9260-6-8", chunks.size() > 1, "a message larger than a packet is fragmented");
    req("9260-6-9", !chunks.empty() && std::all_of(chunks.begin(), chunks.end(), [&](const data_chunk_value& c) {
            return data_chunk_wire_size(c) <= amdcs(a);
        }), "each DATA chunk fits the AMDCS");

    SCTP_Socket t;
    Access::establish(t);
    deliver(t, PEER_TSN, {'x'});
    Access::sent(t);
    Access::send(t, {'y'});
    auto out = Access::sent(t);
    const Deliverable* d = out.with(DATA);
    bool control_first = d && d->packet.chunks[0].chunk_header.type == SACK;
    req("9260-6-10", control_first, "control chunks come before DATA");
    req("9260-6.10-3", control_first, "a bundled control chunk is placed first");
    req("9260-6.1-16", control_first, "a pending SACK is bundled with outbound DATA");

    SCTP_Socket r;
    Access::establish(r);
    Access::receive(r, packet(OUR_TAG, {data_chunk(data(PEER_TSN + 1, {'b'}, DATA_FLAG_U)), data_chunk(data(PEER_TSN, {'a'}, DATA_FLAG_U | DATA_FLAG_B)),
                                         data_chunk(data(PEER_TSN + 2, {'c'}, DATA_FLAG_U | DATA_FLAG_E))}));
    std::vector<uint8_t> buffer(8);
    size_t n = Access::read(r, buffer);
    req("9260-6-11", n == 3 && buffer[0] == 'a' && buffer[1] == 'b' && buffer[2] == 'c', "bundled fragments are reassembled");
}

void s6_1_rule_a() {
    section("6.1 Rule A: the peer's receive window");
    {
        SCTP_Socket s;
        Access::establish(s, ESTABLISHED, {}, 100);
        Access::send(s, KB);
        auto out = Access::sent(s);
        req("9260-6.1-1", out.data().empty(), "the transmission rules are applied to new DATA");
        req("9260-6.1-2", out.data().empty() && Access::armed(s, Expiration_Timer_Type::ZERO_WINDOW_PROBE),
            "no new DATA while rwnd is smaller than the next chunk");
        auto wait = Access::remaining(s, Expiration_Timer_Type::ZERO_WINDOW_PROBE);
        Association_TCB* a = Access::tcb(s);
        req("9260-6.1-7", wait && a && *wait <= std::chrono::duration_cast<std::chrono::milliseconds>(primary(*a).rto)
                && *wait > std::chrono::duration_cast<std::chrono::milliseconds>(primary(*a).rto) / 2,
            "the first zero window probe waits one RTO");
        Access::fire(s, Expiration_Timer_Type::ZERO_WINDOW_PROBE);
        auto probe = Access::sent(s).data();
        req("9260-6.1-5", probe.size() == 1, "a zero window probe is sent");
        auto rto_before = a ? primary(*a).rto : std::chrono::microseconds{};
        uint16_t errors = a ? a->paths.error_count : 0;
        sack(s, OUR_TSN - 1, 0);
        Access::fire(s, Expiration_Timer_Type::T3_RTX, PEER_IP);
        Access::sent(s);
        req("9260-6.1-7", a && primary(*a).rto >= rto_before * 2 - std::chrono::microseconds(1), "later probes back off exponentially");
        req("9260-6.1-6", a && a->paths.error_count == errors && primary(*a).error_count == 0,
            "an unanswered probe while SACKs arrive counts no error");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s, ESTABLISHED, {}, 100);
        primary(a).cwnd = 0;
        Access::send(s, KB);
        Access::sent(s);
        a.send.zero_window_probe_allowed = true;
        req("9260-6.1-3", Access::sent(s).data().empty(), "a zero window probe is sent only when cwnd allows");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Access::send(s, KB);
        Access::sent(s);
        sack(s, OUR_TSN - 1, 0);
        Access::send(s, KB);
        Access::sent(s);
        req("9260-6.1-4", !Access::armed(s, Expiration_Timer_Type::ZERO_WINDOW_PROBE) && a.send.outstanding.size() == 1,
            "no zero window probe while DATA is outstanding");
        req("9260-6.1-17", Access::send(s, KB) == Sctp_Status::OK && Access::sent(s).data().empty(),
            "with the window full, sends are accepted but no DATA goes out");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        primary(a).cwnd = 40000;
        primary(a).data_sent_at = Clock::now() - std::chrono::seconds(5);
        a.send.peer_rwnd = 0;
        Access::decay(s);
        req("9260-6.1-8", primary(a).cwnd < 40000 && primary(a).cwnd >= 4 * pmdcs(primary(a)),
            "while the window stays closed, cwnd still decays per 7.2.1");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s, ESTABLISHED, {}, 300);
        a.send.peer_max_rwnd = RWND;
        Access::send(s, std::vector<uint8_t>(5000, 's'));
        req("9260-6.1-9", Access::sent(s).data().empty(), "a window far below the largest offered is not filled with a sliver (SWS)");
    }
}

void s6_1_rules_b_to_d() {
    section("6.1 Rules B - D: cwnd, retransmissions first, Max.Burst");
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        primary(a).cwnd = 1500;
        for (int i = 0; i < 5; ++i) {
            Access::send(s, KB);
        }
        Access::sent(s);
        size_t flight = bytes_in_flight(a);
        req("9260-6.1-10", flight < 1500 + pmdcs(primary(a)), "outstanding DATA stays under cwnd + PMDCS - 1");
        req("9260-6.1-11", flight > 1500, "a new packet may overrun cwnd when the flight is below it");
        req("9260-6.1-12", a.send.outstanding.size() == 2, "the overrun is one packet");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Access::send(s, KB);
        Access::sent(s);
        Access::fire(s, Expiration_Timer_Type::T3_RTX, PEER_IP);
        a.send.outstanding.begin()->second.pending_retransmission = true;
        Access::send(s, KB);
        auto out = Access::sent(s).data();
        req("9260-6.1-13", !out.empty() && out[0].tsn == OUR_TSN, "chunks marked for retransmission go before new DATA");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        primary(a).cwnd = 1000000;
        for (int i = 0; i < 20; ++i) {
            Access::send(s, KB);
        }
        auto burst = Access::sent_once(s);
        req("9260-6.1-14", burst.size() <= sctp_parameters::MAX_BURST, "one transmission opportunity sends at most Max.Burst packets");
        req("9260-6.1-15", primary(a).cwnd == 1000000, "limiting the burst leaves cwnd unchanged");
    }
}

void s6_1_t3() {
    section("6.1 T3-rtx start and restart");
    SCTP_Socket s;
    Association_TCB& a = Access::establish(s);
    Access::send(s, KB);
    Access::sent(s);
    req("9260-6.1-18", Access::armed(s, Expiration_Timer_Type::T3_RTX, PEER_IP), "the first transmission starts T3-rtx");
    auto left = Access::remaining(s, Expiration_Timer_Type::T3_RTX, PEER_IP);
    req("9260-6.1-21", left && *left <= std::chrono::duration_cast<std::chrono::milliseconds>(primary(a).rto)
            && *left > std::chrono::duration_cast<std::chrono::milliseconds>(primary(a).rto) / 2,
        "T3-rtx is set to the destination's RTO");
    uint64_t before = Access::generation(s, Expiration_Timer_Type::T3_RTX, PEER_IP);
    Access::send(s, KB);
    Access::sent(s);
    req("9260-6.1-20", Access::generation(s, Expiration_Timer_Type::T3_RTX, PEER_IP) == before,
        "sending more DATA does not restart a running T3-rtx");
    primary(a).cwnd = 100000;
    for (int i = 0; i < 3; ++i) {
        Access::send(s, KB);
    }
    Access::sent(s);
    before = Access::generation(s, Expiration_Timer_Type::T3_RTX, PEER_IP);
    for (uint16_t i = 0; i < 3; ++i) {
        sack(s, OUR_TSN - 1, RWND, {{2, static_cast<uint16_t>(2 + i)}});
    }
    Access::sent(s);
    req("9260-6.1-19", Access::generation(s, Expiration_Timer_Type::T3_RTX, PEER_IP) != before,
        "retransmitting the earliest outstanding chunk restarts T3-rtx");

    size_t smallest_chunk = DATA_CHUNK_HEADER_SIZE + 4;
    req("9260-6.1-22", UINT32_MAX / smallest_chunk < (uint64_t{1} << 31), "the send window cannot span 2^31 TSNs");
}

void s6_1_ssn_window() {
    section("6.1 Ordered messages in the send window");
    SCTP_Socket s;
    Association_TCB& a = Access::establish(s, ESTABLISHED, {}, UINT32_MAX);
    primary(a).cwnd = UINT32_MAX / 2;
    for (int i = 0; i < 66000; ++i) {
        a.send.outbound.push_back(Outbound_Message{0, a.send.next_ssn[0]++, false, {'o'}, 0, 0});
        a.send.outbound_bytes += 1;
    }
    for (int pass = 0; pass < 2000 && !a.send.outbound.empty(); ++pass) {
        Access::sent(s);
    }
    std::set<uint16_t> in_flight;
    for (const auto& entry : a.send.outstanding) {
        in_flight.insert(entry.second.data.stream_seq_num);
    }
    req("9260-6.1-23", a.send.outstanding.size() <= 65535 && in_flight.size() == a.send.outstanding.size(),
        "at most 2^16 - 1 ordered messages of a stream are outstanding");
}

void s6_2_receiving() {
    section("6.2 Acknowledgement on Reception of DATA Chunks");
    {
        SCTP_Socket s;
        Access::establish(s);
        deliver(s, PEER_TSN, {'a'}, UBE, 0, 0, DATA_IMMEDIATE_SACK_FLAG);
        auto v = last_sack(Access::sent(s));
        req("9260-6.2-1", sack_covers(v, PEER_TSN), "each DATA chunk inside the window is acknowledged");
        req("9260-6.2-15", v.has_value(), "acknowledgements are sent in SACK chunks");
        req("9260-6.2-16", v && v->cumulative_tsn_ack == PEER_TSN, "Cumulative TSN Ack is the latest in-sequence TSN");
        req("9260-6.2-19", v.has_value(), "the I bit draws an immediate SACK");
    }
    {
        // TSN PEER_TSN delivered, + 1 and + 3 missing, the rest middle fragments that cannot be delivered.
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        deliver(s, PEER_TSN, KB);
        deliver(s, PEER_TSN + 2, KB, DATA_FLAG_U);
        for (uint32_t t = 4; t <= 67; ++t) {
            deliver(s, PEER_TSN + t, KB, DATA_FLAG_U);
        }
        Access::sent(s);
        deliver(s, PEER_TSN + 68, KB, DATA_FLAG_U);
        auto drop_high = Access::sent(s);
        auto v = last_sack(drop_high);
        req("9260-6.2-2", a.receive.ooo.count(PEER_TSN + 68) == 0, "with the window at 0, a TSN above the largest received is dropped");
        req("9260-6.2-4", v.has_value(), "and a SACK goes out at once");
        req("9260-6.2-5", v && !sack_covers(v, PEER_TSN + 68), "not acknowledging the dropped chunk");
        deliver(s, PEER_TSN + 3, KB, DATA_FLAG_U);
        auto drop_held = Access::sent(s);
        v = last_sack(drop_held);
        req("9260-6.2-3", a.receive.ooo.count(PEER_TSN + 3) == 1 && a.receive.ooo.count(PEER_TSN + 67) == 0,
            "a lower TSN displaces the largest held for reordering");
        req("9260-6.2-27", v && sack_covers(v, PEER_TSN + 3) && !sack_covers(v, PEER_TSN + 67), "the displaced chunk is no longer reported");
        req("9260-6.2-28", v && v->a_rwnd == Access::receive_window(s), "a_rwnd counts only what is held");
        req("9260-6.2-26", a.receive.last_peer_tsn == PEER_TSN, "nothing at or below the Cumulative TSN Ack is dropped");
        req("9260-6.2-29", a.receive.ooo.count(PEER_TSN + 2) == 1, "gap-acknowledged data is dropped only for want of space");
        req("9260-6.2-30", a.receive.ooo.count(PEER_TSN + 4) == 1, "only the highest held chunk is given up");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        for (uint32_t i = 0; i < 64; ++i) {
            deliver(s, PEER_TSN + i, KB, UBE, 0, 0, DATA_IMMEDIATE_SACK_FLAG);
        }
        Access::sent(s);
        std::vector<uint8_t> small(100);
        Access::read(s, small);
        auto out = Access::sent(s);
        req("9260-6.2-6", !out.any(SACK), "a small opening of the window is not advertised (receiver SWS)");
        std::vector<uint8_t> buffer(1000);
        size_t updates = 0;
        for (int i = 0; i < 63; ++i) {
            Access::read(s, buffer);
            updates += Access::sent(s).count(SACK);
        }
        req("9260-6.2-11", updates >= 1, "an opening window is advertised without new DATA");
        req("9260-6.2-22", updates >= 1, "the sender learns of the change in time");
        req("9260-6.2-12", updates <= 4, "without a burst of window updates");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        deliver(s, PEER_TSN);
        auto first = Access::sent(s);
        auto delay = Access::remaining(s, Expiration_Timer_Type::DELAYED_SACK);
        deliver(s, PEER_TSN + 1);
        auto second = Access::sent(s);
        req("9260-6.2-7", !first.any(SACK) && second.any(SACK), "delayed acknowledgement as in RFC 5681 4.2");
        req("9260-6.2-8", delay && *delay <= std::chrono::milliseconds(200) && second.count(SACK) == 1,
            "a SACK for every second packet, and within 200 ms");
        req("9260-6.2-9", !first.any(SACK), "not more often than that");
        req("9260-6.2-13", sctp_parameters::SACK_DELAY <= std::chrono::milliseconds(500), "SACK.Delay is not above 500 ms");
        req("9260-6.2-14", sctp_parameters::SACK_DELAY <= std::chrono::milliseconds(500), "and cannot be raised above it");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::receive(s, packet(OUR_TAG, {data_chunk(data(PEER_TSN, {'d'}, UBE)), data_chunk(data(PEER_TSN + 2, {'d'}, UBE)), data_chunk(data(PEER_TSN + 4, {'d'}, UBE))}));
        req("9260-6.2-10", Access::sent(s).count(SACK) == 1, "one packet draws at most one SACK");
    }
    {
        SCTP_Socket s;
        Access::establish(s, SHUTDOWN_SENT);
        deliver(s, PEER_TSN + 1);
        auto out = Access::sent(s);
        req("9260-6.2-18", out.any(SHUTDOWN) && out.any(SACK), "out-of-order DATA is acknowledged with a SACK, not the SHUTDOWN alone");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        deliver(s, PEER_TSN, {'a'}, UBE, 0, 0, DATA_IMMEDIATE_SACK_FLAG);
        Access::sent(s);
        deliver(s, PEER_TSN);
        auto v = last_sack(Access::sent(s));
        req("9260-6.2-20", v.has_value(), "a packet of only duplicates draws a SACK at once");
        req("9260-6.2-21", v && v->duplicate_tsns == std::vector<uint32_t>{PEER_TSN}, "reporting the duplicate");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        deliver(s, PEER_TSN, KB, DATA_FLAG_U | DATA_FLAG_B, 0, 0, DATA_IMMEDIATE_SACK_FLAG);
        auto first = last_sack(Access::sent(s));
        deliver(s, PEER_TSN + 1, KB, DATA_FLAG_U, 0, 0, DATA_IMMEDIATE_SACK_FLAG);
        auto second = last_sack(Access::sent(s));
        req("9260-6.2-23", first && second && second->a_rwnd <= first->a_rwnd, "a_rwnd does not grow until bytes are released");
        req("9260-6.2-24", first && first->a_rwnd <= RWND - 1000, "fragments held for reassembly count against it");
        req("9260-6.2-25", second && second->a_rwnd == Access::receive_window(s), "the SACK carries the current a_rwnd");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        deliver(s, PEER_TSN, {});
        auto out = Access::sent(s);
        req("9260-6.2-31", out.any(ABORT) && has_cause(*&out.with(ABORT)->packet, ABORT, CAUSE_NO_USER_DATA),
            "a DATA chunk with no user data draws ABORT with No User Data");
        SCTP_Socket t;
        Access::establish(t);
        req("9260-6.2-32", Access::send(t, {}) == Sctp_Status::EMPTY_MESSAGE, "we never send a DATA chunk without user data");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Access::send(s, KB);
        Access::send(s, KB);
        Access::sent(s);
        size_t flight = bytes_in_flight(a);
        sack(s, OUR_TSN - 1, 10000);
        req("9260-6.2.1-1", a.send.peer_rwnd == 10000 - flight, "rwnd is the a_rwnd less the bytes still in flight");
    }
}

void s6_2_gap_limit() {
    section("6.2 / 6.7 Gap Ack Blocks limited by the PMTU");
    SCTP_Socket s;
    Access::establish(s);
    Sent out;
    for (uint32_t i = 0; i < 800; i += 2) {
        deliver(s, PEER_TSN + 1 + i);
        out = Access::sent(s);
    }
    const Deliverable* last = nullptr;
    for (const auto& d : out.out) {
        if (find_chunk(d.packet, SACK)) {
            last = &d;
        }
    }
    const auto* v = last ? find_value<sack_chunk_value>(last->packet, SACK) : nullptr;
    bool fits = last && wire_size(last->packet) <= SCTP_COMMON_HEADER_SIZE + BASE_PMDCS;
    bool lowest = v && !v->gap_ack_blocks.empty() && v->gap_ack_blocks.front().start == 2;
    req("9260-6.2-17", fits && v && v->gap_ack_blocks.size() > 100, "as many Gap Ack Blocks as fit the PMTU are reported");
    req("9260-6.7-6", fits, "one SACK is sent even when the blocks do not all fit");
    req("9260-6.7-7", fits && lowest, "reporting the lowest blocks and leaving the highest TSNs unacknowledged");
}

void s6_3_rtt() {
    section("6.3 Management of the Retransmission Timer");
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Access::send(s, KB);
        Access::send(s, KB);
        Access::sent(s);
        bool one_at_a_time = a.send.rtt_measurement_tsn == OUR_TSN;
        sack(s, OUR_TSN + 1);
        bool measured = primary(a).has_srtt;
        auto first = primary(a).srtt;
        Access::send(s, KB);
        Access::sent(s);
        bool again = a.send.rtt_measurement_tsn.has_value();
        sack(s, OUR_TSN + 2);
        req("9260-6.3.1-1", measured && again && primary(a).has_srtt, "a new RTT measurement is made each round trip");
        req("9260-6.3.1-2", one_at_a_time, "at most one measurement per round trip");
        (void)first;
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Access::send(s, KB);
        Access::sent(s);
        Access::fire(s, Expiration_Timer_Type::T3_RTX, PEER_IP);
        Access::sent(s);
        sack(s, OUR_TSN);
        req("9260-6.3.1-4", !primary(a).has_srtt, "a retransmitted chunk is not measured (Karn)");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        primary(a).cwnd = 100000;
        Access::send(s, KB);
        Access::send(s, KB);
        Access::sent(s);
        a.send.outstanding.at(OUR_TSN).pending_retransmission = true;
        Access::schedule_retransmission(s);
        Access::sent(s);
        sack(s, OUR_TSN + 1);
        req("9260-6.3.1-5", !primary(a).has_srtt, "no measurement from a TSN sent before a lower one was retransmitted");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s, ESTABLISHED, {"127.0.0.2"});
        a.paths.list[1].rto = std::chrono::seconds(3);
        Access::send(s, KB);
        Access::sent(s);
        Access::fire(s, Expiration_Timer_Type::T3_RTX, PEER_IP);
        auto out = Access::sent(s);
        auto left = Access::remaining(s, Expiration_Timer_Type::T3_RTX, "127.0.0.2");
        req("9260-6.3.3-1", left && *left > std::chrono::seconds(2), "the RTO of the retransmission's destination arms T3-rtx");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        primary(a).cwnd = 100000;
        for (int i = 0; i < 4; ++i) {
            Access::send(s, KB);
        }
        Access::sent(s);
        Access::fire(s, Expiration_Timer_Type::T3_RTX, PEER_IP);
        auto first = Access::sent(s).data();
        size_t marked = 0;
        for (const auto& e : a.send.outstanding) {
            marked += e.second.pending_retransmission;
        }
        sack(s, OUR_TSN);
        auto later = Access::sent(s).data();
        req("9260-6.3.3-2", first.size() == 1 && marked == 3 && !later.empty() && later[0].tsn == OUR_TSN + 1,
            "chunks that did not fit are marked and sent as cwnd allows");
    }
}

void s6_4_multihoming() {
    section("6.4 Multi-Homed SCTP Endpoints");
    {
        SCTP_Socket s;
        Access::establish(s, ESTABLISHED, {"127.0.0.2"});
        s.sctp_set_primary(Access::key(s), addr("127.0.0.2"));
        Access::send(s, KB);
        const Deliverable* d = nullptr;
        auto out = Access::sent(s);
        d = out.with(DATA);
        req("9260-6.4-1", d && same_destination(d->destination, addr("127.0.0.2")), "DATA goes to the primary path");
    }
    {
        SCTP_Socket s;
        Access::establish(s, ESTABLISHED, {"127.0.0.2"});
        Access::receive(s, packet(OUR_TAG, {chunk(HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}})}), addr("127.0.0.2"));
        auto out = Access::sent(s);
        const Deliverable* d = out.with(HEARTBEAT_ACK);
        req("9260-6.4-2", d && same_destination(d->destination, addr("127.0.0.2")), "a reply goes back where its chunk came from");
    }
    {
        SCTP_Socket s;
        Access::establish(s, ESTABLISHED, {"127.0.0.2"});
        std::set<uint32_t> destinations;
        for (uint32_t i = 0; i < 6; ++i) {
            deliver(s, PEER_TSN + i, {'m'}, UBE, 0, 0, DATA_IMMEDIATE_SACK_FLAG, addr("127.0.0.2"));
            auto sent_d = Access::sent(s);
            for (const auto* d : sent_d.all(SACK)) {
                destinations.insert(d->destination.sin_addr.s_addr);
            }
        }
        req("9260-6.4-3", destinations.size() == 1, "SACKs for DATA from one source keep one destination");
        req("9260-6.7-2", destinations.size() == 1 && *destinations.begin() == addr("127.0.0.2").sin_addr.s_addr,
            "a SACK goes to where the last DATA came from");
    }
    {
        SCTP_Socket s;
        Access::establish(s, ESTABLISHED, {"127.0.0.2"});
        Access::send(s, KB);
        Access::sent(s);
        Access::fire(s, Expiration_Timer_Type::T3_RTX, PEER_IP);
        auto out = Access::sent(s);
        const Deliverable* d = out.with(DATA);
        req("9260-6.4-4", d && same_destination(d->destination, addr("127.0.0.2")), "timed-out DATA is retransmitted to another destination");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s, ESTABLISHED, {"127.0.0.2"});
        primary(a).cwnd = 100000;
        for (int i = 0; i < 5; ++i) {
            Access::send(s, KB);
        }
        Access::sent(s);
        s.sctp_set_primary(Access::key(s), addr("127.0.0.2"));
        for (int i = 0; i < 3; ++i) {
            sack(s, OUR_TSN - 1, RWND, {{2, static_cast<uint16_t>(2 + i)}});
        }
        auto out = Access::sent(s);
        const Deliverable* d = out.with(DATA);
        req("9260-6.4-5", d && find_value<data_chunk_value>(d->packet, DATA)->tsn == OUR_TSN && same_destination(d->destination, addr()),
            "a fast retransmission goes to the original destination");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s, ESTABLISHED, {"127.0.0.2"});
        primary(a).active = false;
        Access::send(s, KB);
        auto out = Access::sent(s);
        const Deliverable* d = out.with(DATA);
        req("9260-6.4.1-1", d && same_destination(d->destination, addr("127.0.0.2")), "with the primary inactive, DATA goes to an active alternate");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Access::add_local(s, "127.0.0.2");
        primary(a).source = ipv4("127.0.0.1");
        Access::send(s, KB);
        Access::sent(s);
        Access::fire(s, Expiration_Timer_Type::T3_RTX, PEER_IP);
        auto out = Access::sent(s);
        const Deliverable* d = out.with(DATA);
        in_addr source = d ? (d->source.s_addr != INADDR_ANY ? d->source : primary(a).source) : in_addr{};
        req("9260-6.4.1-2", d && source.s_addr == ipv4("127.0.0.2").s_addr, "a timed-out retransmission moves to the most divergent source address");
    }
}

void s6_5_6_streams() {
    section("6.5 / 6.6 Streams and Ordered Delivery");
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Sctp_Status refused = Access::send(s, {'x'}, a.send.out_streams);
        Access::send(s, {'a'}, 3);
        auto chunks = Access::sent(s).data();
        req("9260-6.5-1", refused == Sctp_Status::INVALID_STREAM && !chunks.empty()
                && std::all_of(chunks.begin(), chunks.end(), [&](const data_chunk_value& c) { return c.stream_identifier < a.send.out_streams; }),
            "every DATA chunk carries a valid stream");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::receive(s, packet(OUR_TAG, {data_chunk(data(PEER_TSN, {'i'}, UBE, 20))}));
        auto out = Access::sent(s);
        Access::fire(s, Expiration_Timer_Type::DELAYED_SACK);
        auto later = Access::sent(s);
        std::vector<uint8_t> buffer(4);
        req("9260-6.5-2", out.any(OP_ERROR) && has_cause(*&out.with(OP_ERROR)->packet, OP_ERROR, CAUSE_INVALID_STREAM_ID)
                && (sack_covers(last_sack(out), PEER_TSN) || sack_covers(last_sack(later), PEER_TSN)) && Access::read(s, buffer) == 0,
            "DATA on an invalid stream is acknowledged, reported and discarded");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        primary(a).cwnd = 100000;
        Access::send(s, {'0'}, 1);
        Access::send(s, {'1'}, 1);
        Access::send(s, {'u'}, 1, true);
        Access::send(s, {'2'}, 1);
        Access::send(s, {'z'}, 2);
        auto chunks = Access::sent(s).data();
        bool ok = chunks.size() == 5 && chunks[0].stream_seq_num == 0 && chunks[1].stream_seq_num == 1 && chunks[3].stream_seq_num == 2
            && chunks[4].stream_seq_num == 0;
        req("9260-6.5-3", ok, "each stream's SSN starts at 0");
        req("9260-6.5-4", ok, "and goes up by 1 per ordered message");
        req("9260-6.5-6", ok, "an unordered message leaves it unchanged");
        a.send.next_ssn[3] = 65535;
        Access::send(s, {'w'}, 3);
        Access::send(s, {'x'}, 3);
        auto wrap = Access::sent(s).data();
        req("9260-6.5-5", wrap.size() == 2 && wrap[0].stream_seq_num == 65535 && wrap[1].stream_seq_num == 0, "after 65535 comes 0");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        deliver(s, PEER_TSN + 1, {'b'}, DATA_FLAG_B | DATA_FLAG_E, 0, 1);
        std::vector<uint8_t> buffer(4);
        bool held = Access::read(s, buffer) == 0;
        deliver(s, PEER_TSN, {'a'}, DATA_FLAG_B | DATA_FLAG_E, 0, 0);
        size_t n1 = Access::read(s, buffer);
        char first = static_cast<char>(buffer[0]);
        size_t n2 = Access::read(s, buffer);
        req("9260-6.6-1", n1 == 1 && first == 'a' && n2 == 1 && buffer[0] == 'b', "ordered messages go up in SSN order");
        req("9260-6.6-2", held, "and are held until the gap is filled");
        deliver(s, PEER_TSN + 2, {'u'}, UBE, 0, 4242);
        req("9260-6.6-3", Access::read(s, buffer) == 1 && buffer[0] == 'u', "an unordered message's SSN is ignored");
    }
}

void s6_7_gaps() {
    section("6.7 Report Gaps in Received DATA TSNs");
    {
        SCTP_Socket s;
        Access::establish(s);
        deliver(s, PEER_TSN + 1);
        auto v = last_sack(Access::sent(s));
        req("9260-6.7-1", v && v->gap_ack_blocks.size() == 1, "a gap draws a SACK with Gap Ack Blocks at once");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        primary(a).cwnd = 100000;
        for (int i = 0; i < 5; ++i) {
            Access::send(s, KB);
        }
        Access::sent(s);
        sack(s, OUR_TSN, RWND, {{2, 2}});
        req("9260-6.7-3", a.send.outstanding.count(OUR_TSN) == 0, "cumulatively acknowledged chunks leave the transmit queue");
        req("9260-6.7-4", a.send.outstanding.at(OUR_TSN + 1).missing_reports == 1 && a.send.outstanding.at(OUR_TSN + 3).missing_reports == 0,
            "an unreported TSN below the highest acknowledged is missing");
        sack(s, OUR_TSN, RWND, {{2, 3}});
        sack(s, OUR_TSN, RWND, {{2, 4}});
        req("9260-6.7-5", a.send.outstanding.at(OUR_TSN + 1).missing_reports >= 3 && a.send.outstanding.at(OUR_TSN + 1).fast_retransmitted,
            "missing reports are counted to decide retransmission");
    }
}

void s6_8_crc() {
    section("6.8 CRC32c Checksum Calculation");
    const char* vector = "123456789";
    uint32_t crc = calculate_sctp_checksum(reinterpret_cast<const uint8_t*>(vector), 9);
    SCTP_Socket s;
    Access::establish(s);
    Access::send(s, {'c'});
    auto out = Access::sent(s);
    bool valid = !out.empty();
    for (const auto& d : out.out) {
        auto w = serialize_sctp_packet(d.packet);
        uint32_t stored = sctp_read_wire_checksum(w.data());
        sctp_clear_wire_checksum(w.data());
        valid = valid && calculate_sctp_checksum(w.data(), w.size()) == stored;
    }
    req("9260-6.8-1", crc == 0xE3069283 && valid, "every packet carries the CRC32c of its contents");
    req("9260-6.8-2", valid, "computed over the packet with the checksum field zeroed");
    SCTP_Socket r;
    Access::establish(r);
    auto w = serialize_sctp_packet(packet(OUR_TAG, {data_chunk(data(PEER_TSN, {'x'}), DATA_IMMEDIATE_SACK_FLAG)}));
    w[w.size() - 4] ^= 0x01;
    Access::receive_wire(r, w);
    std::vector<uint8_t> buffer(4);
    req("9260-6.8-3", Access::sent(r).empty(), "the checksum is checked first");
    req("9260-6.8-4", Access::read(r, buffer) == 0, "a packet failing it is treated as invalid");
}

void s6_9_fragmentation() {
    section("6.9 Fragmentation and Reassembly");
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        primary(a).cwnd = 100000;
        Access::send(s, std::vector<uint8_t>(1200, 'f'), 0, true);
        auto out = Access::sent(s);
        auto chunks = out.data();
        bool fits = !out.empty();
        for (const auto& d : out.out) {
            fits = fits && wire_size(d.packet) <= SCTP_COMMON_HEADER_SIZE + pmdcs(primary(a));
        }
        req("9260-6.9-2", chunks.size() == 2 && fits, "a message too big for the PMTU is fragmented");
        req("9260-6.9-7", fits, "counting the common and DATA chunk headers");
        req("9260-6.9-9", chunks.size() == 2, "into a series of DATA chunks");
        req("9260-6.9-10", std::all_of(chunks.begin(), chunks.end(), [&](const data_chunk_value& c) { return data_chunk_wire_size(c) <= amdcs(a); }),
            "each no larger than the AMDCS");
        req("9260-6.9-11", chunks.size() == 2 && chunks[1].tsn == chunks[0].tsn + 1, "with TSNs in sequence");
        req("9260-6.9-12", std::all_of(chunks.begin(), chunks.end(), [](const data_chunk_value& c) { return (c.flags & DATA_FLAG_U) != 0; }),
            "an unordered message has U on every fragment");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        primary(a).cwnd = 100000;
        Access::send(s, std::vector<uint8_t>(4000, 'g'));
        auto chunks = Access::sent(s).data();
        bool flags = chunks.size() >= 3;
        for (size_t i = 0; flags && i < chunks.size(); ++i) {
            uint8_t be = chunks[i].flags & (DATA_FLAG_B | DATA_FLAG_E);
            flags = be == (i == 0 ? DATA_FLAG_B : i + 1 == chunks.size() ? DATA_FLAG_E : 0);
        }
        req("9260-6.9-13", flags, "B/E are 10 on the first, 00 in the middle and 01 on the last");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s, ESTABLISHED, {"127.0.0.2"});
        a.paths.list[1].plpmtud.plpmtu = 600;
        Access::send(s, std::vector<uint8_t>(2000, 'h'));
        auto chunks = Access::sent(s).data();
        req("9260-6.9-5", !chunks.empty() && std::all_of(chunks.begin(), chunks.end(), [](const data_chunk_value& c) {
                return data_chunk_wire_size(c) <= pmdcs_of(600);
            }), "with a multihomed peer, chunks fit the smallest path (AMDCS)");
        req("9260-7.3-3", amdcs(a) == pmdcs_of(600), "the AMDCS is the smallest PMDCS over the destinations");
        req("9260-7.3-4", !chunks.empty() && data_chunk_wire_size(chunks[0]) <= pmdcs_of(600), "and sizes the fragments");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Access::send(s, std::vector<uint8_t>(1100, 'i'));
        Access::sent(s);
        primary(a).plpmtud.plpmtu = 600;
        Access::fire(s, Expiration_Timer_Type::T3_RTX, PEER_IP);
        auto out = Access::sent(s);
        const Deliverable* d = out.with(DATA);
        req("9260-6.9-6", d && d->ip_fragment, "a chunk cut before the PMTU fell is sent with IP fragmentation allowed");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        deliver(s, PEER_TSN, {'p'}, UBE);
        Access::sent(s);
        Access::send(s, std::vector<uint8_t>(pmdcs(primary(a)) - DATA_CHUNK_HEADER_SIZE, 'j'));
        auto out = Access::sent(s);
        bool fits = !out.empty();
        for (const auto& d : out.out) {
            fits = fits && wire_size(d.packet) <= SCTP_COMMON_HEADER_SIZE + pmdcs(primary(a));
        }
        req("9260-6.9-8", fits && out.any(SACK), "the space for a bundled SACK is counted");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        deliver(s, PEER_TSN + 2, {'c'}, DATA_FLAG_E);
        deliver(s, PEER_TSN, {'a'}, DATA_FLAG_B);
        deliver(s, PEER_TSN + 1, {'b'}, 0);
        std::vector<uint8_t> buffer(8);
        size_t n = Access::read(s, buffer);
        req("9260-6.9-1", n == 3, "reassembly is supported");
        req("9260-6.9-14", n == 3 && buffer[0] == 'a' && buffer[2] == 'c', "fragments are recognized by B/E and reassembled in TSN order");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        uint32_t i = 0;
        deliver(s, PEER_TSN, KB, DATA_FLAG_B);
        for (i = 1; i < 66; ++i) {
            deliver(s, PEER_TSN + i, KB, 0);
        }
        std::vector<uint8_t> buffer(100000);
        bool partial = false;
        size_t n = Access::read(s, buffer, &partial);
        req("9260-6.9-15", n > 0 && partial, "with the buffer full mid-message, part of it is delivered");
    }
}

void s6_10_bundling() {
    section("6.10 Bundling");
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        primary(a).cwnd = 100000;
        for (int i = 0; i < 30; ++i) {
            Access::send(s, std::vector<uint8_t>(100 + i * 37, 'b'));
        }
        auto out = Access::sent(s);
        bool fits = !out.empty(), increasing = true, whole = true;
        for (const auto& d : out.out) {
            auto w = serialize_sctp_packet(d.packet);
            fits = fits && w.size() <= SCTP_COMMON_HEADER_SIZE + pmdcs(primary(a));
            uint32_t previous = 0;
            bool first = true;
            for (const auto& c : d.packet.chunks) {
                if (c.chunk_header.type == DATA) {
                    uint32_t tsn = std::get<data_chunk_value>(c.chunk_value).tsn;
                    increasing = increasing && (first || tsn_gt(tsn, previous));
                    previous = tsn;
                    first = false;
                }
            }
            SCTP_Packet back = deserialize_sctp_packet(w.data(), w.size());
            whole = whole && back.chunks.size() == d.packet.chunks.size();
        }
        req("9260-6.10-1", fits, "every packet fits the PMTU");
        req("9260-6.10-2", fits, "of the primary path");
        req("9260-6.10-4", increasing, "DATA chunks in a packet are in increasing TSN order");
        req("9260-6.10-5", whole, "no packet carries a partial chunk");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::receive(s, packet(OUR_TAG, {data_chunk(data(PEER_TSN)), chunk(SHUTDOWN, shutdown_chunk_value{OUR_TSN - 1})}));
        std::vector<uint8_t> buffer(4);
        req("9260-6.10-6", Access::read(s, buffer) == 1, "chunks are processed in order: DATA ahead of a SHUTDOWN is taken");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        auto w = serialize_sctp_packet(packet(OUR_TAG, {chunk(HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}}), data_chunk(data(PEER_TSN, KB))}));
        w.resize(w.size() - 200);
        sctp_clear_wire_checksum(w.data());
        uint32_t crc = calculate_sctp_checksum(w.data(), w.size());
        std::memcpy(w.data() + SCTP_CHECKSUM_OFFSET, &crc, 4);
        Access::receive_wire(s, w);
        req("9260-6.10-7", Access::sent(s).any(HEARTBEAT_ACK), "a partial chunk is dropped, not the chunks before it");
    }
    {
        SCTP_Socket s;
        Access::establish(s, SHUTDOWN_SENT);
        Access::receive(s, packet(OUR_TAG, {chunk(SHUTDOWN_ACK, empty_chunk_value{})}));
        auto out = Access::sent(s);
        const Deliverable* d = out.with(SHUTDOWN_COMPLETE);
        req("9260-6.10-8", d && only(d->packet, SHUTDOWN_COMPLETE), "SHUTDOWN COMPLETE is never bundled");
    }
}

} // namespace

int main() {
    s6_states();
    s6_fragmentation_and_bundling();
    s6_1_rule_a();
    s6_1_rules_b_to_d();
    s6_1_t3();
    s6_1_ssn_window();
    s6_2_receiving();
    s6_2_gap_limit();
    s6_3_rtt();
    s6_4_multihoming();
    s6_5_6_streams();
    s6_7_gaps();
    s6_8_crc();
    s6_9_fragmentation();
    s6_10_bundling();
    return summary("RFC 9260 section 6");
}
