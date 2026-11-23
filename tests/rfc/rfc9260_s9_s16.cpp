// RFC 9260 sections 9 to 16: termination, ICMP handling, security
// considerations, the TCB and protocol parameters.

#include "rfc_harness.hpp"

#include <set>
#include <thread>

using namespace rfc;

namespace {

const std::vector<uint8_t> KB(1000, 'k');

void shutdown_from_peer(SCTP_Socket& s, uint32_t cumulative = OUR_TSN - 1) {
    Access::receive(s, packet(OUR_TAG, {chunk(SHUTDOWN, shutdown_chunk_value{cumulative})}));
}

void s9_1_abort() {
    section("9 / 9.1 Termination, Abort of an Association");
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::close_associations(s);
        req("9260-9-1", Access::sent(s).any(ABORT) && Access::tcb(s) == nullptr, "an endpoint leaving service ends its associations");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::send(s, KB);
        std::vector<uint8_t> reason{'b', 'y', 'e'};
        s.sctp_abort(Access::key(s), reason);
        auto out = Access::sent(s);
        const Deliverable* abort = out.with(ABORT);
        req("9260-9.1-1", abort != nullptr, "aborting sends ABORT");
        req("9260-9.1-2", abort && abort->packet.header.verification_tag == PEER_TAG && out.data().empty(),
            "under the peer's tag, with no DATA bundled");
        const auto* causes = abort ? find_value<error_chunk_value>(abort->packet, ABORT) : nullptr;
        req("9260-9.1-3", causes && !causes->causes.empty() && causes->causes[0].code == CAUSE_USER_INITIATED_ABORT
                && causes->causes[0].info == reason, "a user abort carries User-Initiated Abort with the reason");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::receive(s, packet(OUR_TAG, {chunk(HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}}), data_chunk(data(PEER_TSN), DATA_IMMEDIATE_SACK_FLAG),
                                            chunk(ABORT, error_chunk_value{})}));
        req("9260-9.1-4", Access::sent(s).empty(), "a packet containing ABORT draws no response at all");
        req("9260-3.3.7-4", Access::sent(s).empty(), "not even to the chunks bundled ahead of it");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::receive(s, packet(PEER_TAG, {chunk(ABORT, error_chunk_value{})}));
        bool kept = Access::tcb(s) != nullptr;
        Access::notifications(s);
        Access::receive(s, packet(OUR_TAG, {chunk(ABORT, error_chunk_value{{error_cause{CAUSE_USER_INITIATED_ABORT, {'w', 'h', 'y'}}}})}));
        auto ns = Access::notifications(s);
        req("9260-9.1-5", kept, "an ABORT passes the 8.5.1 tag check first");
        req("9260-9.1-6", Access::tcb(s) == nullptr && Access::notified(ns, Assoc_Change_State::COMM_LOST),
            "then the association is removed and the user told");
        bool reason = std::any_of(ns.begin(), ns.end(), [](const Notification& n) {
            const auto* e = std::get_if<Remote_Error>(&n.payload);
            return e && !e->causes.empty() && e->causes[0].code == CAUSE_USER_INITIATED_ABORT && e->causes[0].info == std::vector<uint8_t>{'w', 'h', 'y'};
        });
        req("9260-9.1-7", reason, "the peer's Upper Layer Abort Reason is made available to the user");
    }
}

void s9_2_shutdown() {
    section("9.2 Shutdown of an Association");
    {
        SCTP_Socket s;
        Association& a = Access::establish(s);
        Access::send(s, KB);
        Access::sent(s);
        s.sctp_shutdown(Access::key(s));
        bool waited = !Access::sent(s).any(SHUTDOWN);
        Access::receive(s, packet(OUR_TAG, {sack_chunk(OUR_TSN)}));
        auto out = Access::sent(s);
        req("9260-9.2-20", waited, "SHUTDOWN waits until outstanding DATA is acknowledged");
        req("9260-9.2-1", out.any(SHUTDOWN) && a.state == SHUTDOWN_SENT && Access::armed(s, Expiration_Timer_Type::T2_SHUTDOWN),
            "then SHUTDOWN is sent, T2-shutdown started and SHUTDOWN-SENT entered");
        auto first = Access::remaining(s, Expiration_Timer_Type::T2_SHUTDOWN);
        Access::receive(s, packet(OUR_TAG, {data_chunk(data(PEER_TSN, {'x'}, DATA_FLAG_U | DATA_FLAG_B | DATA_FLAG_E))}));
        Access::sent(s);
        Access::fire(s, Expiration_Timer_Type::T2_SHUTDOWN);
        auto again = Access::sent(s);
        const auto* resent = again.empty() ? nullptr : find_value<shutdown_chunk_value>(again[0], SHUTDOWN);
        req("9260-9.2-2", resent && resent->cumulative_tsn_ack == PEER_TSN, "T2 expiry resends SHUTDOWN with the updated Cumulative TSN Ack");
        auto second = Access::remaining(s, Expiration_Timer_Type::T2_SHUTDOWN);
        req("9260-9.2-3", first && second && *first <= std::chrono::duration_cast<std::chrono::milliseconds>(sctp_parameters::RTO_INITIAL)
                && *second > *first, "T2-shutdown follows the 6.3 timer rules, backing off");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        s.sctp_shutdown(Access::key(s));
        Access::sent(s);
        Access::notifications(s);
        bool resends = true;
        for (int i = 0; i < sctp_parameters::ASSOCIATION_MAX_RETRANS; ++i) {
            Access::fire(s, Expiration_Timer_Type::T2_SHUTDOWN);
            resends = resends && Access::sent(s).any(SHUTDOWN);
        }
        bool alive = Access::tcb(s) != nullptr;
        Access::fire(s, Expiration_Timer_Type::T2_SHUTDOWN);
        req("9260-9.2-4", resends && alive, "SHUTDOWN is retransmitted up to Association.Max.Retrans times");
        req("9260-9.2-5", Access::tcb(s) == nullptr && Access::notified(Access::notifications(s), Assoc_Change_State::COMM_LOST),
            "then the TCB is destroyed and the peer reported unreachable");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s);
        s.sctp_shutdown(Access::key(s));
        Access::sent(s);
        Access::fire(s, Expiration_Timer_Type::T2_SHUTDOWN);
        Access::sent(s);
        uint64_t before = Access::generation(s, Expiration_Timer_Type::T2_SHUTDOWN);
        Access::receive(s, packet(OUR_TAG, {chunk(HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}})}));
        req("9260-9.2-6", a.error_count == 0 && Access::generation(s, Expiration_Timer_Type::T2_SHUTDOWN) != before,
            "any packet from the peer clears the count and restarts T2-shutdown");
        uint64_t t2 = Access::generation(s, Expiration_Timer_Type::T2_SHUTDOWN);
        Access::receive(s, packet(OUR_TAG, {data_chunk(data(PEER_TSN + 2, {'g'}, DATA_FLAG_U | DATA_FLAG_B | DATA_FLAG_E))}));
        auto out = Access::sent(s);
        req("9260-9.2-9", out.any(SHUTDOWN) && Access::generation(s, Expiration_Timer_Type::T2_SHUTDOWN) != t2,
            "in SHUTDOWN-SENT each DATA packet is answered with SHUTDOWN and T2 restarted");
        req("9260-9.2-10", out.any(SACK), "with a SACK too when there are gaps");
        req("9260-9.2-11", Access::armed(s, Expiration_Timer_Type::T5_SHUTDOWN_GUARD), "T5-shutdown-guard is running");
        auto guard = Access::remaining(s, Expiration_Timer_Type::T5_SHUTDOWN_GUARD);
        req("9260-9.2-12", guard && *guard > 5 * sctp_parameters::RTO_MAX - std::chrono::seconds(2) && *guard <= 5 * sctp_parameters::RTO_MAX,
            "set to 5 * RTO.Max");
        Access::fire(s, Expiration_Timer_Type::T5_SHUTDOWN_GUARD);
        req("9260-9.2-11", Access::sent(s).any(ABORT) && Access::tcb(s) == nullptr, "on expiry, the association is aborted");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s);
        shutdown_from_peer(s);
        Sctp_Status ignored = s.sctp_shutdown(Access::key(s));
        shutdown_from_peer(s);
        auto out = Access::sent(s);
        req("9260-9.2-13", out.any(SHUTDOWN_ACK) && a.state == SHUTDOWN_ACK_SENT && Access::armed(s, Expiration_Timer_Type::T2_SHUTDOWN),
            "with nothing outstanding, SHUTDOWN is answered with SHUTDOWN ACK, T2 started");
        Access::fire(s, Expiration_Timer_Type::T2_SHUTDOWN);
        req("9260-9.2-14", Access::sent(s).any(SHUTDOWN_ACK), "T2 expiry resends SHUTDOWN ACK");
        req("9260-9.2-7", ignored == Sctp_Status::SHUTTING_DOWN, "SHUTDOWN-RECEIVED ignores the user's shutdown but still answers SHUTDOWN");
        req("9260-9.2-21", Access::send(s, {'x'}) != Sctp_Status::OK, "new data is refused while shutting down");
        Access::notifications(s);
        for (int i = 1; i < sctp_parameters::ASSOCIATION_MAX_RETRANS; ++i) {
            Access::fire(s, Expiration_Timer_Type::T2_SHUTDOWN);
            Access::sent(s);
        }
        bool alive = Access::tcb(s) != nullptr;
        Access::fire(s, Expiration_Timer_Type::T2_SHUTDOWN);
        req("9260-9.2-15", alive, "SHUTDOWN ACK is retransmitted up to Association.Max.Retrans times");
        req("9260-9.2-16", Access::tcb(s) == nullptr && Access::notified(Access::notifications(s), Assoc_Change_State::COMM_LOST),
            "then the TCB is destroyed and the peer reported unreachable");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s);
        Access::send(s, KB);
        Access::sent(s);
        shutdown_from_peer(s);
        Sctp_Status refused = Access::send(s, {'n'});
        Access::fire(s, Expiration_Timer_Type::T3_RTX, PEER_IP);
        auto out = Access::sent(s);
        req("9260-9.2-8", out.data().size() == 1 && refused != Sctp_Status::OK && a.state == SHUTDOWN_RECEIVED,
            "with DATA outstanding, the SHUTDOWN receiver keeps retransmitting but takes no new data");
    }
    {
        SCTP_Socket s;
        Access::establish(s, SHUTDOWN_SENT);
        Access::receive(s, packet(OUR_TAG, {chunk(SHUTDOWN_ACK, empty_chunk_value{})}));
        auto out = Access::sent(s);
        req("9260-9.2-17", out.any(SHUTDOWN_COMPLETE) && Access::tcb(s) == nullptr && !Access::armed(s, Expiration_Timer_Type::T2_SHUTDOWN),
            "SHUTDOWN ACK stops T2, draws SHUTDOWN COMPLETE and removes the association");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s, ESTABLISHED);
        Access::receive(s, packet(OUR_TAG, {chunk(SHUTDOWN_COMPLETE, empty_chunk_value{})}));
        req("9260-9.2-18", a.state == ESTABLISHED && Access::tcb(s) != nullptr, "SHUTDOWN COMPLETE outside SHUTDOWN-ACK-SENT is discarded");
        SCTP_Socket t;
        Access::establish(t, SHUTDOWN_ACK_SENT);
        Access::receive(t, packet(OUR_TAG, {chunk(SHUTDOWN_COMPLETE, empty_chunk_value{})}));
        req("9260-9.2-19", Access::tcb(t) == nullptr && !Access::armed(t, Expiration_Timer_Type::T2_SHUTDOWN),
            "in SHUTDOWN-ACK-SENT it stops T2 and removes the association");
        req("9260-14.2-1", Access::association_count(t) == 0, "a CLOSED association's TCB is removed");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s, SHUTDOWN_ACK_SENT);
        Access::receive(s, packet(0, {chunk(INIT, init_value(0x4444))}));
        auto out = Access::sent(s);
        req("9260-9.2-22", out.any(SHUTDOWN_ACK) && !out.any(INIT_ACK) && a.state == SHUTDOWN_ACK_SENT,
            "an INIT in SHUTDOWN-ACK-SENT is discarded and SHUTDOWN ACK resent");
    }
    for (Association_State state : {COOKIE_WAIT, COOKIE_ECHOED}) {
        SCTP_Socket s;
        Association_Key k = Access::associate(s);
        Access::sent(s);
        Association* a = Access::tcb(s, k);
        a->state = state;
        Access::receive(s, packet(a->this_ver_tag, {chunk(SHUTDOWN_ACK, empty_chunk_value{})}));
        auto out = Access::sent(s);
        const Deliverable* complete = out.with(SHUTDOWN_COMPLETE);
        req("9260-9.2-23", complete && only(complete->packet, SHUTDOWN_COMPLETE) && complete->packet.header.verification_tag == a->this_ver_tag
                && a->state == state && Access::armed(s, Expiration_Timer_Type::T1_INIT),
            "SHUTDOWN ACK during setup draws a lone SHUTDOWN COMPLETE under its tag; T1 runs on");
        Access::receive(s, packet(a->this_ver_tag, {chunk(SHUTDOWN, shutdown_chunk_value{0})}));
        req("9260-9.2-24", Access::sent(s).empty() && a->state == state, "SHUTDOWN during setup is silently discarded");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s, SHUTDOWN_SENT);
        shutdown_from_peer(s);
        auto out = Access::sent(s);
        req("9260-9.2-25", out.any(SHUTDOWN_ACK) && a.state == SHUTDOWN_ACK_SENT && Access::armed(s, Expiration_Timer_Type::T2_SHUTDOWN),
            "crossing SHUTDOWNs: SHUTDOWN ACK, SHUTDOWN-ACK-SENT, T2 restarted");
        Access::receive(s, packet(OUR_TAG, {chunk(SHUTDOWN_ACK, empty_chunk_value{})}));
        auto done = Access::sent(s);
        req("9260-9.2-26", done.any(SHUTDOWN_COMPLETE) && Access::tcb(s) == nullptr && !Access::armed(s, Expiration_Timer_Type::T2_SHUTDOWN),
            "then SHUTDOWN ACK stops T2, draws SHUTDOWN COMPLETE and removes the association");
    }
}

// Sends one packet of the association to the peer's address, where nothing
// listens, so the kernel queues an ICMP Port Unreachable on our socket.
bool port_unreachable(SCTP_Socket& s, const SCTP_Packet& p) {
    Access::raw_send(s, p, addr());
    Access::icmp(s);
    return true;
}

void s10_icmp() {
    section("10 ICMP Handling");
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::start_heartbeats_for(s);
        Association* a = Access::tcb(s);
        auto quoted = serialize_sctp_packet(build_packet(LOCAL_PORT, PEER_PORT, PEER_TAG, HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}}));
        Access::handle_icmp_ptb(s, addr(), quoted, 1020);
        bool used = a && primary(*a).plpmtud.state == Plpmtud_State::ERROR;
        req("9260-10-1", used, "ICMP is handled by the procedures of section 10");
        req("9260-10-3", used, "the quoted packet locates the association");
        req("9260-10-6", used, "Packet Too Big is applied to PMTU discovery");
        req("9260-12.4-1", used, "the section 10 ICMP handling is implemented");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::start_heartbeats_for(s);
        Association* a = Access::tcb(s);
        auto before = a ? primary(*a).plpmtud.state : Plpmtud_State::DISABLED;
        Access::handle_icmp_ptb(s, addr("127.0.0.9"), serialize_sctp_packet(build_packet(LOCAL_PORT, PEER_PORT, PEER_TAG, HEARTBEAT, heartbeat_chunk_value{{1}})), 1020);
        bool unknown = a && primary(*a).plpmtud.state == before;
        req("9260-10-4", unknown, "an ICMP message for no association is ignored");
        Access::handle_icmp_ptb(s, addr(), serialize_sctp_packet(build_packet(LOCAL_PORT, PEER_PORT, PEER_TAG ^ 1, HEARTBEAT, heartbeat_chunk_value{{1}})), 1020);
        bool wrong_tag = a && primary(*a).plpmtud.state == before;
        req("9260-10-5", wrong_tag, "one whose Verification Tag is not the peer's is discarded");
        req("6951-5.5-1", unknown && wrong_tag, "ICMP that cannot be tied to an association or verified is discarded");
    }
    {
        SCTP_Socket s;
        Access::setup(s);
        Association_Key k = Access::associate(s);
        auto init = Access::sent(s);
        Association* a = Access::tcb(s, k);
        a->peer_address_list[0].plpmtud.state = Plpmtud_State::BASE;
        a->peer_address_list[0].plpmtud.probed_size = 1400;
        Access::handle_icmp_ptb(s, addr(), init.empty() ? std::vector<uint8_t>{} : serialize_sctp_packet(init[0]), 1020);
        req("9260-10-5", a->peer_address_list[0].plpmtud.state != Plpmtud_State::BASE,
            "with a quoted tag of 0, an INIT whose Initiate Tag is ours is accepted");
    }
    {
        SCTP_Socket s;
        bool bound = Access::bind_real(s);
        Access::establish(s);
        Access::notifications(s);
        port_unreachable(s, build_packet(LOCAL_PORT, PEER_PORT, PEER_TAG, HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}}));
        bool aborted = bound && Access::tcb(s) == nullptr && Access::notified(Access::notifications(s), Assoc_Change_State::COMM_LOST);
        req("9260-10-7", aborted, "Protocol Unreachable is an ABORT with the T bit (UDP Port Unreachable, RFC 6951 5.5)");
        req("9260-10-8", aborted, "the association is aborted on it");
        req("6951-5.5-3", aborted, "received ICMP is mapped as RFC 6951 5.5 says");
        req("6951-5.5-4", aborted, "Port Unreachable is treated as Protocol Unreachable");
    }
    {
        SCTP_Socket s;
        bool bound = Access::bind_real(s, LOCAL_PORT + 1);
        Access::setup(s);
        Access::establish(s);
        port_unreachable(s, build_packet(LOCAL_PORT, PEER_PORT, PEER_TAG ^ 0xFF, HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}}));
        req("6951-5.5-1", bound && Access::tcb(s) != nullptr, "ICMP whose quoted tag is not the peer's is silently discarded");
    }
    {
        SCTP_Socket s;
        bool bound = Access::bind_real(s, LOCAL_PORT + 2);
        Access::setup(s);
        Association_Key k = Access::associate(s);
        auto init = Access::sent(s);
        Access::notifications(s);
        if (!init.empty()) {
            port_unreachable(s, init[0]);
        }
        req("9260-10-7", bound && !Access::tcb(s, k) && Access::notified(Access::notifications(s), Assoc_Change_State::CANT_STR_ASSOC),
            "for an INIT in COOKIE-WAIT, it is handled like an ABORT");
    }
}

void s12_security() {
    section("12 Security Considerations");
    {
        SCTP_Socket s;
        auto r = Access::initiate(s, {}, false);
        req("9260-12.3-1", !r.init.empty() && only(r.init[0], INIT) && r.init[0].header.verification_tag == 0,
            "an INIT goes alone and under tag 0");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        std::vector<uint8_t> w = serialize_sctp_packet(packet(OUR_TAG, {chunk(HEARTBEAT, heartbeat_chunk_value{{1, 1, 1, 1}}),
                                                                       chunk(HEARTBEAT, heartbeat_chunk_value{{2, 2, 2, 2}}),
                                                                       data_chunk(data(PEER_TSN, {'x'}, DATA_FLAG_U | DATA_FLAG_B | DATA_FLAG_E, 20))}));
        Access::receive_wire(s, w);
        size_t control_packets = 0;
        for (const auto& d : Access::sent(s).out) {
            control_packets += std::any_of(d.packet.chunks.begin(), d.packet.chunks.end(), [](const SCTP_Chunk& c) {
                return c.chunk_header.type != DATA;
            });
        }
        req("9260-12.4-2", control_packets == 1, "replies to one packet's chunks go out in one packet");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::receive(s, packet(OUR_TAG, {sack_chunk(OUR_TSN + 5)}));
        auto out = Access::sent(s);
        req("9260-12.4-4", out.any(ABORT) && Access::tcb(s) == nullptr, "a SACK acknowledging a TSN never sent aborts the association");
    }
    {
        SCTP_Socket s;
        auto r = Access::respond(s);
        size_t init_ack = r.init_ack.empty() ? 0 : serialize_sctp_packet(r.init_ack[0]).size();
        req("9260-12.4-5", init_ack != 0 && init_ack <= SCTP_COMMON_HEADER_SIZE + 20 + 4 + STATE_COOKIE_SIZE,
            "the INIT ACK holds little more than its cookie");
    }
}

void s14_tcb_and_s16_parameters() {
    section("14 TCB Parameters, 16 Suggested SCTP Protocol Parameter Values");
    {
        std::vector<uint8_t> bytes(4096);
        random_bytes(bytes.data(), bytes.size());
        size_t ones = 0;
        for (uint8_t b : bytes) {
            ones += static_cast<size_t>(__builtin_popcount(b));
        }
        SCTP_Socket a, b;
        Access::setup(a);
        Access::setup(b);
        SCTP_Common_Header header{PEER_PORT, LOCAL_PORT, 0, 0};
        auto ca = Access::cookies(a).generate(header, init_value(), addr(), 1, 1, 0, 0);
        auto cb = Access::cookies(b).generate(header, init_value(), addr(), 1, 1, 0, 0);
        req("9260-14.1-1", ones > 4096 * 4 - 400 && ones < 4096 * 4 + 400 && ca != cb,
            "the cookie secret comes from the system's cryptographic random source");
    }
    using namespace sctp_parameters;
    using std::chrono::milliseconds;
    using std::chrono::seconds;
    bool recommended = RTO_INITIAL == seconds(1) && RTO_MIN == seconds(1) && RTO_MAX == seconds(60) && MAX_BURST == 4
        && RTO_ALPHA == 1.0 / 8 && RTO_BETA == 1.0 / 4 && VALID_COOKIE_LIFE == seconds(60) && ASSOCIATION_MAX_RETRANS == 10
        && PATH_MAX_RETRANS == 5 && MAX_INIT_RETRANSMITS == 8 && HB_INTERVAL == seconds(30) && HB_MAX_BURST == 1
        && SACK_DELAY == milliseconds(200);
    req("9260-16-1", recommended, "the protocol parameters take the recommended values");
    SCTP_Socket s;
    Association& a = Access::establish(s);
    Peer_Path& p = primary(a);
    SCTP_Socket_Test_Access::send(s, KB);
    Access::sent(s);
    p.has_srtt = true;
    p.srtt = std::chrono::microseconds(1000);
    p.rttvar = std::chrono::microseconds(100);
    Access::receive(s, packet(OUR_TAG, {sack_chunk(OUR_TSN)}));
    req("9260-16-2", p.rto >= std::chrono::duration_cast<std::chrono::microseconds>(RTO_MIN), "RTO never goes below RTO.Min");
}

} // namespace

int main() {
    s9_1_abort();
    s9_2_shutdown();
    s10_icmp();
    s12_security();
    s14_tcb_and_s16_parameters();
    return summary("RFC 9260 sections 9 to 16");
}
