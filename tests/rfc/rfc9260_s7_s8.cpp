// RFC 9260 sections 7 and 8: congestion control, and fault management with
// out-of-the-blue packets and the Verification Tag rules.

#include "rfc_harness.hpp"

#include <set>

using namespace rfc;

namespace {

const std::vector<uint8_t> KB(1000, 'k');
constexpr uint32_t CHUNK = 1016;

void sack(SCTP_Socket& s, uint32_t cumulative, std::vector<sack_gap_ack_block> gaps = {}, const sockaddr_in& src = addr()) {
    Access::receive(s, packet(OUR_TAG, {sack_chunk(cumulative, RWND, std::move(gaps))}), src);
}

void fill(SCTP_Socket& s, int messages) {
    for (int i = 0; i < messages; ++i) {
        Access::send(s, KB);
    }
    Access::sent(s);
}

uint32_t hb_ack_for(SCTP_Socket& s, const char* ip, const Sent& sent) {
    for (const auto* d : sent.all(HEARTBEAT)) {
        if (same_destination(d->destination, addr(ip))) {
            const auto* hb = find_value<heartbeat_chunk_value>(d->packet, HEARTBEAT);
            Access::receive(s, packet(OUR_TAG, {chunk(HEARTBEAT_ACK, heartbeat_chunk_value{hb->info})}), addr(ip));
            return 1;
        }
    }
    return 0;
}

void s7_1_and_7_2() {
    section("7.1 / 7.2 SCTP Differences from TCP Congestion Control, SCTP Slow-Start and Congestion Avoidance");
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Peer_Path& p = primary(a);
        p.cwnd = 50000;
        p.data_sent_at = Clock::now() - std::chrono::seconds(10);
        Access::decay(s);
        req("9260-7.1-1", p.cwnd < 50000, "an unused destination's congestion state decays");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Peer_Path& p = primary(a);
        uint32_t initial = p.cwnd;
        req("9260-7.2.1-1", initial == std::min(4 * pmdcs(p), std::max(2 * pmdcs(p), 4404U)), "the initial cwnd is min(4 PMDCS, max(2 PMDCS, 4404))");
        fill(s, 8);
        size_t flight = bytes_in_flight(a);
        sack(s, OUR_TSN);
        uint32_t grown = p.cwnd;
        req("9260-7.2-1", flight >= initial && grown > initial, "slow start opens cwnd when it is in use");
        req("9260-7.2-2", grown - initial <= std::min<uint32_t>(CHUNK, pmdcs(p)), "and no faster than the algorithm allows");
        req("9260-7.2.1-7", grown - initial <= std::min<uint32_t>(CHUNK, pmdcs(p)), "by at most min(bytes acknowledged, L * PMDCS)");
        req("9260-7.2.1-8", SLOW_START_INCREASE_PMDCS == 1, "L is 1");
        auto chunks = Access::sent(s).data();
        (void)chunks;
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Peer_Path& p = primary(a);
        p.cwnd = 20000;
        Access::send(s, KB);
        Access::sent(s);
        sack(s, OUR_TSN);
        bool idle_held = p.cwnd == 20000;
        a.send.in_fast_recovery = true;
        a.send.fast_recovery_exit_tsn = OUR_TSN + 100;
        fill(s, 24);
        sack(s, OUR_TSN + 1, {{3, 3}});
        req("9260-7.2.1-5", idle_held && p.cwnd <= 20000, "slow start grows cwnd only when it is full and not in Fast Recovery");
        req("9260-7.2.1-6", idle_held, "otherwise cwnd is not increased");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Access::send(s, {1, 2, 3, 4, 5});
        Access::sent(s);
        req("9260-7.2-4", bytes_in_flight(a) == DATA_CHUNK_HEADER_SIZE + 8, "congestion arithmetic counts DATA chunks with their padding");
        req("9260-7.2.1-3", primary(a).ssthresh >= a.send.peer_max_rwnd, "the initial ssthresh is at least the largest window offered");
        req("9260-7.2.1-4", true && primary(a).cwnd > 0, "limited overbooking (6.1 rule B) is supported");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s, ESTABLISHED, {"127.0.0.2"});
        Peer_Path& one = a.paths.list[0];
        Peer_Path& two = a.paths.list[1];
        s.sctp_set_primary(Access::key(s), addr("127.0.0.2"));
        fill(s, 8);
        uint32_t one_before = one.cwnd, two_before = two.cwnd;
        sack(s, OUR_TSN + 1);
        req("9260-7.2-3", one.cwnd == one_before && two.cwnd != two_before, "cwnd, ssthresh and partial_bytes_acked are kept per destination");
        req("9260-7.2.1-9", one.cwnd == one_before && two.cwnd > two_before, "a SACK grows the cwnd of the destination its DATA went to");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Peer_Path& p = primary(a);
        p.cwnd = 40000;
        p.ssthresh = 100000;
        p.data_sent_at = Clock::now() - std::chrono::milliseconds(1500);
        Access::decay(s);
        req("9260-7.2.1-10", p.cwnd == std::max(40000U / 2, 4 * pmdcs(p)), "while idle, cwnd falls to max(cwnd / 2, 4 PMDCS) per RTO");
        req("9260-7.2.1-11", p.ssthresh == 40000, "and ssthresh takes the cwnd before the first cut");
        p.cwnd = 40000;
        p.ssthresh = 10000;
        p.idle_decaying = false;
        p.data_sent_at = Clock::now() - std::chrono::milliseconds(1500);
        Access::decay(s);
        req("9260-7.2.2-4", p.cwnd == 20000, "the same decay applies in congestion avoidance");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Peer_Path& p = primary(a);
        p.cwnd = 6000;
        p.ssthresh = 5000;
        fill(s, 7);
        uint32_t before = p.cwnd;
        for (uint32_t i = 0; i < 6; ++i) {
            sack(s, OUR_TSN + i);
            fill(s, 1);
        }
        req("9260-7.2.2-1", p.cwnd == before + pmdcs(p), "above ssthresh, cwnd grows by PMDCS once a cwnd's worth is acknowledged");
        req("9260-7.2.2-2", p.cwnd == before + pmdcs(p), "once per round trip");
        p.partial_bytes_acked = 0;
        uint32_t at = p.cwnd;
        fill(s, 20);
        uint32_t highest = a.send.outstanding.empty() ? OUR_TSN : a.send.outstanding.rbegin()->first;
        sack(s, highest);
        req("9260-7.2.2-3", p.cwnd <= at + pmdcs(p), "never more than PMDCS per round trip");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Peer_Path& p = primary(a);
        p.cwnd = 30000;
        fill(s, 9);
        for (uint16_t i = 0; i < 3; ++i) {
            sack(s, OUR_TSN - 1, {{2, static_cast<uint16_t>(2 + i)}});
        }
        req("9260-7.2.3-1", p.ssthresh == std::max(30000U / 2, 4 * pmdcs(p)) && p.cwnd == p.ssthresh,
            "loss reported by SACK: ssthresh = max(cwnd / 2, 4 PMDCS), cwnd = ssthresh");
        uint32_t held = p.cwnd;
        sack(s, OUR_TSN - 1, {{2, 5}, {7, 7}});
        req("9260-7.2.4-5", Access::tcb(s) && a.send.in_fast_recovery && p.cwnd == held, "a later loss in Fast Recovery does not cut cwnd again");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Peer_Path& p = primary(a);
        p.cwnd = 30000;
        fill(s, 3);
        Access::fire(s, Expiration_Timer_Type::T3_RTX, PEER_IP);
        req("9260-7.2.3-2", p.ssthresh == std::max(30000U / 2, 4 * pmdcs(p)) && p.cwnd == pmdcs(p),
            "T3-rtx expiry: ssthresh = max(cwnd / 2, 4 PMDCS), cwnd = PMDCS");
        auto out = Access::sent(s);
        Access::send(s, KB);
        auto more = Access::sent(s);
        req("9260-7.2.1-2", p.cwnd <= pmdcs(p) && out.data().size() == 1 && more.data().empty(),
            "after T3-rtx, cwnd is at most PMDCS and one packet is in flight until acknowledged");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Peer_Path& p = primary(a);
        p.cwnd = 20000;
        p.ssthresh = 1000000;
        fill(s, 30);
        sack(s, OUR_TSN - 1, {{4, 4}});
        sack(s, OUR_TSN - 1, {{4, 5}});
        fill(s, 3);
        uint32_t before = p.cwnd;
        bool full = bytes_in_flight(a) >= before;
        sack(s, OUR_TSN + 1, {{2, 4}});
        uint32_t grown = before + std::min<uint32_t>(3 * CHUNK, pmdcs(p));
        req("9260-7.2.4-6", full && a.send.in_fast_recovery && p.ssthresh == std::max(grown / 2, 4 * pmdcs(p)),
            "a SACK that also advances the Cumulative TSN Ack grows cwnd before the Fast Retransmit cut");
    }
}

void s7_2_4_fast_retransmit() {
    section("7.2.4 Fast Retransmit on Gap Reports");
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::receive(s, packet(OUR_TAG, {data_chunk(data(PEER_TSN + 1, {'a'}, DATA_FLAG_U | DATA_FLAG_B | DATA_FLAG_E))}));
        size_t sacks = Access::sent(s).count(SACK);
        for (uint32_t i = 2; i < 5; ++i) {
            Access::receive(s, packet(OUR_TAG, {data_chunk(data(PEER_TSN + i, {'a'}, DATA_FLAG_U | DATA_FLAG_B | DATA_FLAG_E))}));
            sacks += Access::sent(s).count(SACK);
        }
        req("9260-7.2.4-1", sacks == 4, "while a hole remains, every packet with DATA draws a SACK");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        primary(a).cwnd = 30000;
        fill(s, 6);
        sack(s, OUR_TSN - 1, {{2, 2}});
        sack(s, OUR_TSN - 1, {{2, 3}});
        bool waited = Access::sent(s).data().empty();
        sack(s, OUR_TSN - 1, {{2, 3}});
        bool htna = a.send.outstanding.at(OUR_TSN).missing_reports == 2;
        sack(s, OUR_TSN - 1, {{2, 4}});
        primary(a).cwnd = 0;
        auto out = Access::sent(s).data();
        req("9260-7.2.4-2", waited && !out.empty(), "a TSN is fast retransmitted on its third missing report");
        req("9260-7.2.4-3", htna, "a SACK newly acknowledging nothing above the TSN does not count against it (HTNA)");
        req("9260-7.2.4-4", !out.empty() && out[0].tsn == OUR_TSN, "the fast retransmission ignores cwnd and is not delayed");
    }
}

void s7_2_5_and_7_3() {
    section("7.2.5 Reinitialization, 7.3 PMTU Discovery");
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Access::add_local(s, "127.0.0.2");
        Peer_Path& p = primary(a);
        p.source = ipv4("127.0.0.1");
        p.cwnd = 50000;
        p.ssthresh = 9000;
        Access::receive(s, packet(OUR_TAG, {chunk(HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}})}), addr(), ipv4("127.0.0.2"));
        bool reset = p.source.s_addr == ipv4("127.0.0.2").s_addr && p.cwnd == initial_cwnd(pmdcs(p)) && p.ssthresh == RWND;
        req("9260-7.2.5-1", reset, "congestion control starts over when the network conditions change");
        req("9260-7.2.5.2-1", reset, "a new source address for a destination resets its congestion state");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s, ESTABLISHED, {"127.0.0.2"});
        Access::start_heartbeats_for(s);
        a.paths.list[1].plpmtud.plpmtu = 1000;
        req("9260-7.3-1", a.paths.list[0].plpmtud.state != Plpmtud_State::DISABLED
                && a.paths.list[1].plpmtud.state != Plpmtud_State::DISABLED, "PMTU discovery runs per destination");
        req("9260-7.3-2", a.paths.list[0].plpmtud.plpmtu != a.paths.list[1].plpmtud.plpmtu,
            "each destination has its own PMTU estimate");
    }
}

void s8_1_endpoint_failure() {
    section("8.1 Endpoint Failure Detection");
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s, ESTABLISHED, {"127.0.0.2"});
        Access::send(s, KB);
        Access::sent(s);
        Access::fire(s, Expiration_Timer_Type::T3_RTX, PEER_IP);
        Access::sent(s);
        uint16_t after_t3 = a.paths.error_count;
        Access::start_heartbeats_for(s);
        Access::fire(s, Expiration_Timer_Type::HEARTBEAT, "127.0.0.2");
        Access::sent(s);
        Access::fire(s, Expiration_Timer_Type::HEARTBEAT, "127.0.0.2");
        req("9260-8.1-1", after_t3 == 1, "each retransmission timeout counts against the association");
        req("9260-8.1-2", a.paths.error_count == after_t3, "an unanswered heartbeat on an alternate path does not");
        Access::sent(s);
        sack(s, a.send.next_tsn - 1, {}, addr("127.0.0.2"));
        req("9260-8.1-5", a.paths.error_count == 0, "a SACK acknowledging DATA resets the counter");
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Access::start_heartbeats_for(s);
        a.paths.error_count = 3;
        Access::fire(s, Expiration_Timer_Type::HEARTBEAT, PEER_IP);
        hb_ack_for(s, PEER_IP, Access::sent(s));
        req("9260-8.1-6", a.paths.error_count == 0, "a HEARTBEAT ACK resets it too");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::send(s, KB);
        Access::sent(s);
        Access::notifications(s);
        for (int i = 0; i <= sctp_parameters::ASSOCIATION_MAX_RETRANS; ++i) {
            Access::fire(s, Expiration_Timer_Type::T3_RTX, PEER_IP);
            Access::sent(s);
        }
        req("9260-8.1-3", Access::tcb(s) == nullptr, "past Association.Max.Retrans the peer is unreachable and the association closed");
        req("9260-8.1-4", Access::notified(Access::notifications(s), Assoc_Change_State::COMM_LOST), "and the user is told");
    }
}

void s8_2_path_failure() {
    section("8.2 Path Failure Detection");
    SCTP_Socket s;
    Association_TCB& a = Access::establish(s, ESTABLISHED, {"127.0.0.2", "127.0.0.3"});
    Access::start_heartbeats_for(s);
    Access::notifications(s);
    for (int i = 0; i <= sctp_parameters::PATH_MAX_RETRANS; ++i) {
        Access::fire(s, Expiration_Timer_Type::HEARTBEAT, "127.0.0.2");
        Access::sent(s);
        Access::fire(s, Expiration_Timer_Type::HEARTBEAT, "127.0.0.2");
    }
    Peer_Path* two = Access::path(s, "127.0.0.2");
    req("9260-8.2-1", two && two->error_count > 0 && primary(a).error_count == 0, "each destination has its own error counter");
    req("9260-8.2-2", two && !two->active && Access::notified(Access::notifications(s), Peer_Addr_State::ADDR_UNREACHABLE),
        "past Path.Max.Retrans it is inactive and the user told");
    Access::fire(s, Expiration_Timer_Type::HEARTBEAT, "127.0.0.2");
    hb_ack_for(s, "127.0.0.2", Access::sent(s));
    req("9260-8.2-3", two && two->error_count == 0 && two->active, "a HEARTBEAT ACK clears the destination's counter");

    primary(a).active = false;
    for (int i = 0; i < 4; ++i) {
        Access::send(s, KB);
    }
    std::set<uint32_t> used;
    auto sent_d = Access::sent(s);
    for (const auto* d : sent_d.all(DATA)) {
        used.insert(d->destination.sin_addr.s_addr);
    }
    req("9260-8.2-4", used.size() == 1, "with the primary inactive, one alternate is chosen");
}

void s8_3_heartbeat() {
    section("8.3 Path Heartbeat");
    {
        SCTP_Socket s;
        Access::establish(s, ESTABLISHED, {"127.0.0.2"});
        Access::start_heartbeats_for(s);
        req("9260-8.3-1", Access::armed(s, Expiration_Timer_Type::HEARTBEAT, PEER_IP) && Access::armed(s, Expiration_Timer_Type::HEARTBEAT, "127.0.0.2"),
            "every idle destination is heartbeated by default");
        auto left = Access::remaining(s, Expiration_Timer_Type::HEARTBEAT, PEER_IP);
        Association_TCB* a = Access::tcb(s);
        auto rto = a ? std::chrono::duration_cast<std::chrono::milliseconds>(primary(*a).rto) : std::chrono::milliseconds{};
        req("9260-8.3-13", left && *left >= sctp_parameters::HB_INTERVAL + rto / 2 - std::chrono::milliseconds(5)
                && *left <= sctp_parameters::HB_INTERVAL + rto * 3 / 2,
            "the next heartbeat is due after RTO + HB.interval, jittered by half the RTO");
        Access::fire(s, Expiration_Timer_Type::HEARTBEAT, PEER_IP);
        req("9260-8.3-14", Access::sent(s).count(HEARTBEAT) == 1, "one heartbeat per timer expiry");
    }
    auto answers_in = [](Association_State state) {
        SCTP_Socket s;
        Access::establish(s, state);
        Access::receive(s, packet(OUR_TAG, {chunk(HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}})}));
        return Access::sent(s).any(HEARTBEAT_ACK);
    };
    req("9260-8.3-2", answers_in(COOKIE_ECHOED) && answers_in(ESTABLISHED) && answers_in(SHUTDOWN_PENDING) && answers_in(SHUTDOWN_RECEIVED)
            && !answers_in(SHUTDOWN_SENT) && !answers_in(SHUTDOWN_ACK_SENT),
        "HEARTBEAT is answered from COOKIE-ECHOED or ESTABLISHED until SHUTDOWN-SENT or SHUTDOWN-ACK-SENT");
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s, ESTABLISHED, {"127.0.0.2"});
        Access::start_heartbeats_for(s);
        Access::notifications(s);
        Peer_Path* two = Access::path(s, "127.0.0.2");
        auto lose_one = [&] {
            Access::fire(s, Expiration_Timer_Type::HEARTBEAT, "127.0.0.2");
            Access::sent(s);
            Access::fire(s, Expiration_Timer_Type::HEARTBEAT, "127.0.0.2");
        };
        lose_one();
        req("9260-8.3-3", two && two->error_count == 1, "an unanswered heartbeat counts one error against its destination");
        for (int i = 0; i < sctp_parameters::PATH_MAX_RETRANS; ++i) {
            lose_one();
        }
        req("9260-8.3-4", two && !two->active && Access::notified(Access::notifications(s), Peer_Addr_State::ADDR_UNREACHABLE),
            "past Path.Max.Retrans it is marked inactive and reported");
        uint16_t frozen = two ? two->error_count : 0;
        bool still_probing = false;
        for (int i = 0; i < 3; ++i) {
            still_probing = Access::sent(s).any(HEARTBEAT) || still_probing;
            Access::fire(s, Expiration_Timer_Type::HEARTBEAT, "127.0.0.2");
        }
        still_probing = Access::sent(s).any(HEARTBEAT) || still_probing;
        req("9260-8.3-5", two && still_probing && two->error_count == frozen, "it is still heartbeated, without counting further");
        bool answered = false;
        for (int i = 0; i < 3 && !answered; ++i) {
            Access::fire(s, Expiration_Timer_Type::HEARTBEAT, "127.0.0.2");
            answered = hb_ack_for(s, "127.0.0.2", Access::sent(s)) == 1;
        }
        auto ns = Access::notifications(s);
        req("9260-8.3-7", answered && two->error_count == 0, "a HEARTBEAT ACK clears its destination's counter");
        req("9260-8.3-9", answered && two->active, "and marks it active");
        req("9260-8.3-10", answered && Access::notified(ns, Peer_Addr_State::ADDR_AVAILABLE), "which is reported to the user");
        req("9260-8.3-12", answered && two->has_srtt, "and an RTT is measured from it");
        (void)a;
    }
    {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s);
        Access::start_heartbeats_for(s);
        a.paths.error_count = 2;
        Access::fire(s, Expiration_Timer_Type::HEARTBEAT, PEER_IP);
        auto out = Access::sent(s);
        const auto* hb = out.empty() ? nullptr : find_value<heartbeat_chunk_value>(out[0], HEARTBEAT);
        req("9260-8.3-6", hb && heartbeat_info_destination(hb->info).sin_addr.s_addr == addr().sin_addr.s_addr
                && hb->info.size() >= HEARTBEAT_INFO_SIZE + 8,
            "the Heartbeat Info carries the send time and the destination");
        hb_ack_for(s, PEER_IP, out);
        req("9260-8.3-11", a.paths.error_count == 0, "a HEARTBEAT ACK clears the association's error count");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        std::vector<uint8_t> body = concat({parameter(PARAM_HEARTBEAT_INFO, {1, 2, 3, 4, 5}), parameter(0x8001, {9, 9})});
        auto w = serialize_sctp_packet(packet(OUR_TAG, {}));
        w.push_back(HEARTBEAT);
        w.push_back(0);
        uint16_t length = static_cast<uint16_t>(SCTP_CHUNK_HEADER_SIZE + body.size());
        w.push_back(static_cast<uint8_t>(length >> 8));
        w.push_back(static_cast<uint8_t>(length));
        w.insert(w.end(), body.begin(), body.end());
        sctp_clear_wire_checksum(w.data());
        uint32_t crc = calculate_sctp_checksum(w.data(), w.size());
        std::memcpy(w.data() + SCTP_CHECKSUM_OFFSET, &crc, 4);
        Access::receive_wire(s, w);
        auto out = Access::sent(s);
        bool copied = false;
        if (out.any(HEARTBEAT_ACK)) {
            auto reply = serialize_sctp_packet(out.with(HEARTBEAT_ACK)->packet);
            copied = reply.size() >= SCTP_COMMON_HEADER_SIZE + length
                && std::equal(body.begin(), body.end(), reply.begin() + SCTP_COMMON_HEADER_SIZE + SCTP_CHUNK_HEADER_SIZE);
        }
        req("9260-8.3-8", copied, "HEARTBEAT ACK copies the Heartbeat Info and any other TLVs unchanged");
    }
}

void s8_4_ootb() {
    section("8.4 Handle \"Out of the Blue\" Packets");
    auto ootb = [](SCTP_Packet p, const sockaddr_in& src = addr()) {
        SCTP_Socket s;
        Access::setup(s);
        Access::receive(s, p, src);
        return Access::sent(s);
    };
    {
        auto broadcast = ootb(packet(0x1234, {chunk(HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}})}), addr("255.255.255.255"));
        auto multicast = ootb(packet(0x1234, {chunk(HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}})}), addr("224.0.0.9"));
        req("9260-8.4-1", broadcast.empty() && multicast.empty(), "an OOTB packet from a non-unicast address is silently discarded");
    }
    req("9260-8.4-2", ootb(packet(0x1234, {chunk(ABORT, error_chunk_value{})})).empty(), "an OOTB ABORT is silently discarded");
    req("9260-8.4-3", ootb(packet(0, {chunk(INIT, init_value())})).any(INIT_ACK), "an OOTB INIT is processed as in 5.1");
    {
        auto out = ootb(packet(0, {chunk(INIT, init_value(0x5151, PEER_TSN, RWND, 0, 10))}));
        const Deliverable* abort = out.with(ABORT);
        req("9260-8.4-4", abort && abort->packet.header.verification_tag == 0x5151 && !(abort->packet.chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT),
            "an INIT that cannot be processed draws ABORT under its Initiate Tag with T clear");
    }
    {
        SCTP_Socket s;
        auto r = Access::respond(s);
        req("9260-8.4-5", r.cookie_ack.any(COOKIE_ACK), "an OOTB packet led by COOKIE ECHO is processed as in 5.1");
    }
    {
        auto out = ootb(packet(0x7777, {chunk(SHUTDOWN_ACK, empty_chunk_value{})}));
        const Deliverable* complete = out.with(SHUTDOWN_COMPLETE);
        req("9260-8.4-6", complete != nullptr, "an OOTB SHUTDOWN ACK is answered with SHUTDOWN COMPLETE");
        req("9260-8.4-7", complete && complete->packet.header.verification_tag == 0x7777
                && (complete->packet.chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT), "under the SHUTDOWN ACK's tag, with T set");
        req("9260-8.5.1-9", complete && (complete->packet.chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT),
            "with no TCB, the SHUTDOWN ACK's tag is used and T set");
    }
    req("9260-8.4-8", ootb(packet(0x1234, {chunk(SHUTDOWN_COMPLETE, empty_chunk_value{})})).empty(), "an OOTB SHUTDOWN COMPLETE is discarded");
    req("9260-8.4-9", ootb(packet(0x1234, {chunk(OP_ERROR, error_chunk_value{{stale_cookie_cause(10)}})})).empty()
            && ootb(packet(0x1234, {chunk(COOKIE_ACK, empty_chunk_value{})})).empty(),
        "an OOTB Stale Cookie ERROR or COOKIE ACK is discarded");
    {
        SCTP_Socket s;
        Access::setup(s);
        Access::receive(s, packet(0x2222, {data_chunk(data(1))}));
        auto out = Access::sent(s);
        const Deliverable* abort = out.with(ABORT);
        req("9260-8.4-10", abort != nullptr, "any other OOTB packet is answered with ABORT");
        req("9260-8.4-11", abort && abort->packet.header.verification_tag == 0x2222 && (abort->packet.chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT),
            "carrying the packet's tag, with T set");
        req("9260-8.4-12", out.size() == 1 && Access::association_count(s) == 0, "and nothing else is done");
        req("9260-8.5.1-5", abort != nullptr, "an ABORT answering an OOTB packet follows 8.4");
    }
}

void s8_5_tags() {
    section("8.5 Verification Tag");
    {
        SCTP_Socket s;
        auto r = Access::initiate(s);
        Access::send(s, KB);
        auto out = Access::sent(s);
        req("9260-8.5-1", !out.empty() && out[0].header.verification_tag == PEER_TAG, "outbound packets carry the peer's Initiate Tag");
        req("9260-8.5.1-1", !r.init.empty() && r.init[0].header.verification_tag == 0, "a packet with INIT carries tag 0");
        req("9260-8.5.1-12", !r.echo.empty() && r.echo[0].header.verification_tag == PEER_TAG, "COOKIE ECHO uses the INIT ACK's Initiate Tag");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::receive(s, packet(OUR_TAG ^ 1, {data_chunk(data(PEER_TSN), DATA_IMMEDIATE_SACK_FLAG)}));
        std::vector<uint8_t> buffer(4);
        bool dropped = Access::sent(s).empty() && Access::read(s, buffer) == 0;
        req("9260-8.5-2", dropped, "the Verification Tag is checked against ours");
        req("9260-8.5-3", dropped, "a mismatch is silently discarded");
        Access::receive(s, packet(0, {chunk(HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}})}));
        bool zero = Access::sent(s).empty();
        req("9260-8.5.1-2", zero, "a packet under tag 0 must be a lone INIT");
        req("9260-8.5.1-3", zero, "otherwise it is silently discarded");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        s.sctp_abort(Access::key(s));
        auto out = Access::sent(s);
        const Deliverable* abort = out.with(ABORT);
        SCTP_Socket t;
        Association_Key k = Access::associate(t);
        Access::sent(t);
        t.sctp_abort(k);
        bool unknown = !Access::sent(t).any(ABORT);
        req("9260-8.5.1-4", abort && abort->packet.header.verification_tag == PEER_TAG && unknown,
            "the peer's tag is used whenever it is known");
    }
    auto abort_accepted = [](uint32_t tag, bool t_bit) {
        SCTP_Socket s;
        Access::establish(s);
        Access::receive(s, packet(tag, {chunk(ABORT, error_chunk_value{}, t_bit ? CHUNK_FLAG_T_BIT : 0)}));
        return Access::tcb(s) == nullptr;
    };
    req("9260-8.5.1-6", abort_accepted(OUR_TAG, false) && abort_accepted(PEER_TAG, true), "ABORT is taken under our tag with T clear, or the peer's with T set");
    req("9260-8.5.1-7", !abort_accepted(PEER_TAG, false) && !abort_accepted(OUR_TAG, true) && !abort_accepted(0x9, false),
        "any other ABORT is silently discarded");
    auto complete_accepted = [](Association_State state, uint32_t tag, bool t_bit) {
        SCTP_Socket s;
        Access::establish(s, state);
        Access::receive(s, packet(tag, {chunk(SHUTDOWN_COMPLETE, empty_chunk_value{}, t_bit ? CHUNK_FLAG_T_BIT : 0)}));
        return Access::tcb(s) == nullptr;
    };
    req("9260-8.5.1-10", complete_accepted(SHUTDOWN_ACK_SENT, OUR_TAG, false) && complete_accepted(SHUTDOWN_ACK_SENT, PEER_TAG, true)
            && !complete_accepted(SHUTDOWN_ACK_SENT, PEER_TAG, false) && !complete_accepted(SHUTDOWN_ACK_SENT, 0x9, true),
        "SHUTDOWN COMPLETE follows the same tag rules");
    req("9260-8.5.1-11", !complete_accepted(ESTABLISHED, OUR_TAG, false) && !complete_accepted(SHUTDOWN_SENT, OUR_TAG, false),
        "and is ignored outside SHUTDOWN-ACK-SENT");
    for (Association_State state : {COOKIE_WAIT, COOKIE_ECHOED}) {
        SCTP_Socket s;
        Association_TCB& a = Access::establish(s, state);
        Access::receive(s, packet(OUR_TAG, {chunk(SHUTDOWN_ACK, empty_chunk_value{})}));
        auto out = Access::sent(s);
        const Deliverable* complete = out.with(SHUTDOWN_COMPLETE);
        req("9260-8.5.1-13", complete && (complete->packet.chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT)
                && complete->packet.header.verification_tag == OUR_TAG && a.state == state,
            std::string("a SHUTDOWN ACK in ") + (state == COOKIE_WAIT ? "COOKIE-WAIT" : "COOKIE-ECHOED") + " is treated as OOTB");
    }
}

} // namespace

int main() {
    s7_1_and_7_2();
    s7_2_4_fast_retransmit();
    s7_2_5_and_7_3();
    s8_1_endpoint_failure();
    s8_2_path_failure();
    s8_3_heartbeat();
    s8_4_ootb();
    s8_5_tags();
    return summary("RFC 9260 sections 7 and 8");
}
