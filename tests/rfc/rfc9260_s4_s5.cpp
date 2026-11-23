// RFC 9260 sections 4 and 5: the association state machine, initialization,
// collisions and restarts, State Cookies, tags and path verification.

#include "rfc_harness.hpp"
#include "crypto/hmac.hpp"

#include <set>

using namespace rfc;

namespace {

uint32_t init_tag(const Sent& sent) {
    const auto* init = sent.empty() ? nullptr : find_value<init_chunk_value>(sent[0], INIT);
    return init ? init->initiate_tag : 0;
}

void advance_cookie_clock(SCTP_Socket& s, std::chrono::seconds by) {
    Access::cookies(s).clock = [by] { return Clock::now() + by; };
}

// A cookie of ours for the peer's INIT, signed by s, with the tags given.
std::vector<uint8_t> cookie_for(SCTP_Socket& s, uint32_t local_tag, uint32_t peer_tag, uint32_t local_tie, uint32_t peer_tie) {
    SCTP_Common_Header header{PEER_PORT, LOCAL_PORT, 0, 0};
    return Access::cookies(s).generate(header, init_value(peer_tag, PEER_TSN + 100), addr(), local_tag, OUR_TSN + 100,
                                       local_tie, peer_tie);
}

void echo(SCTP_Socket& s, const std::vector<uint8_t>& cookie, uint32_t tag, std::vector<SCTP_Chunk> bundled = {},
          const sockaddr_in& src = addr()) {
    std::vector<SCTP_Chunk> chunks{chunk(COOKIE_ECHO, cookie_echo_chunk_value{cookie})};
    chunks.insert(chunks.end(), bundled.begin(), bundled.end());
    Access::receive(s, packet(tag, chunks), src);
}

void s4_state_machine() {
    section("4 SCTP Association State Diagram");
    {
        SCTP_Socket s;
        auto r = Access::respond(s);
        std::vector<uint8_t> bad = r.cookie;
        SCTP_Socket fresh;
        Access::setup(fresh);
        Access::receive(fresh, packet(0, {chunk(INIT, init_value())}));
        auto ack = Access::sent(fresh);
        const auto* v = ack.empty() ? nullptr : find_value<init_chunk_value>(ack[0], INIT_ACK);
        std::vector<uint8_t> cookie;
        if (v) {
            find_parameter(v->optional_parameters, PARAM_STATE_COOKIE, cookie);
        }
        std::vector<uint8_t> tampered = cookie;
        if (!tampered.empty()) {
            tampered[10] ^= 1;
        }
        echo(fresh, tampered, v ? v->initiate_tag : 0);
        req("9260-4-1", Access::sent(fresh).empty() && Access::association_count(fresh) == 0, "an invalid cookie is silently discarded");
        advance_cookie_clock(fresh, std::chrono::minutes(5));
        echo(fresh, cookie, v ? v->initiate_tag : 0);
        auto out = Access::sent(fresh);
        req("9260-4-2", out.any(OP_ERROR) && has_cause(*&out.with(OP_ERROR)->packet, OP_ERROR, CAUSE_STALE_COOKIE),
            "an expired cookie is answered with an ERROR");
    }
    {
        SCTP_Socket s;
        Access::associate(s);
        Access::sent(s);
        bool retransmitted = true;
        for (int i = 0; i < sctp_parameters::MAX_INIT_RETRANSMITS; ++i) {
            bool fired = Access::fire(s, Expiration_Timer_Type::T1_INIT);
            auto out = Access::sent(s);
            retransmitted = retransmitted && fired && out.any(INIT) && Access::armed(s, Expiration_Timer_Type::T1_INIT);
        }
        req("9260-4-3", retransmitted, "T1-init expiry resends INIT and restarts T1-init");
        req("9260-4-4", retransmitted && Access::tcb(s) != nullptr, "up to Max.Init.Retransmits times");
        Access::notifications(s);
        Access::fire(s, Expiration_Timer_Type::T1_INIT);
        bool gave_up = !Access::tcb(s) && !Access::sent(s).any(INIT);
        req("9260-4-5", gave_up && Access::notified(Access::notifications(s), Assoc_Change_State::CANT_STR_ASSOC),
            "then the attempt is abandoned and the user told");
    }
    {
        SCTP_Socket s;
        Access::initiate(s, {}, false);
        bool retransmitted = true;
        for (int i = 0; i < sctp_parameters::MAX_INIT_RETRANSMITS; ++i) {
            bool fired = Access::fire(s, Expiration_Timer_Type::T1_COOKIE);
            auto out = Access::sent(s);
            retransmitted = retransmitted && fired && out.any(COOKIE_ECHO) && Access::armed(s, Expiration_Timer_Type::T1_COOKIE);
        }
        req("9260-4-6", retransmitted, "T1-cookie expiry resends COOKIE ECHO and restarts T1-cookie");
        req("9260-4-7", retransmitted && Access::tcb(s) != nullptr, "up to Max.Init.Retransmits times");
        Access::notifications(s);
        Access::fire(s, Expiration_Timer_Type::T1_COOKIE);
        req("9260-4-8", !Access::tcb(s) && Access::notified(Access::notifications(s), Assoc_Change_State::CANT_STR_ASSOC),
            "then the attempt is abandoned and the user told");
    }
    {
        SCTP_Socket s;
        Access::establish(s, SHUTDOWN_SENT);
        Access::receive(s, packet(OUR_TAG, {data_chunk(data(PEER_TSN))}));
        auto out = Access::sent(s);
        req("9260-4-9", out.any(SHUTDOWN) && !Access::armed(s, Expiration_Timer_Type::DELAYED_SACK),
            "in SHUTDOWN-SENT, DATA is acknowledged at once");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s);
        Access::send(s, {'q'});
        Access::receive(s, packet(OUR_TAG, {chunk(SHUTDOWN, shutdown_chunk_value{OUR_TSN - 1})}));
        Sctp_Status refused = Access::send(s, {'n'});
        req("9260-4-10", a.state == SHUTDOWN_RECEIVED && refused != Sctp_Status::OK, "SHUTDOWN-RECEIVED refuses new sends");
        auto out = Access::sent(s);
        bool data_sent = out.data().size() == 1;
        Access::receive(s, packet(OUR_TAG, {sack_chunk(OUR_TSN)}));
        auto after = Access::sent(s);
        req("9260-4-11", data_sent && after.any(SHUTDOWN_ACK) && a.state == SHUTDOWN_ACK_SENT,
            "SHUTDOWN-RECEIVED sends what is queued, then leaves once it is acknowledged");
        req("9260-4-12", Access::send(s, {'z'}) != Sctp_Status::OK, "SHUTDOWN-ACK-SENT refuses new sends");
    }
}

void s5_establishment() {
    section("5 / 5.1 Normal Establishment of an Association");
    {
        SCTP_Socket s;
        Association_Key k = Access::associate(s);
        Sctp_Status refused = s.sctp_send_data(k, {'e'});
        auto out = Access::sent(s);
        req("9260-5-1", refused != Sctp_Status::OK && out.data().empty(), "no DATA before the association is set up");
        Association* a = Access::tcb(s, k);
        uint32_t tag = init_tag(out);
        req("9260-5.1-1", a && tag == a->this_ver_tag && tag != 0, "INIT carries our tag as its Initiate Tag");
        SCTP_Socket t;
        Access::associate(t);
        uint32_t other = init_tag(Access::sent(t));
        req("9260-5.1-2", tag != 0 && other != 0 && tag != other, "the tag is random and not 0");
        req("9260-5.1-20", a && a->cumulative_tsn_ack == a->next_tsn - 1, "the initiator's Cumulative TSN Ack Point starts at its Initial TSN - 1");
    }
    {
        SCTP_Socket s;
        auto r = Access::respond(s, init_value(), {}, addr("127.0.0.5"));
        const Deliverable* ack = r.init_ack.with(INIT_ACK);
        const auto* v = ack ? find_value<init_chunk_value>(ack->packet, INIT_ACK) : nullptr;
        req("9260-5.1-3", ack && same_destination(ack->destination, addr("127.0.0.5")), "INIT ACK goes to the INIT's source address");
        req("9260-5.1-11", ack && same_destination(ack->destination, addr("127.0.0.5")), "INIT ACK goes to the address the INIT came from");
        req("9260-5.1.2-7", ack && same_destination(ack->destination, addr("127.0.0.5")), "the packet with INIT ACK goes to the INIT's source");
        req("9260-5.1-4", ack && ack->packet.header.verification_tag == PEER_TAG && v && v->initiate_tag != 0,
            "INIT ACK is sent under Tag_A and carries our own tag");
        std::vector<uint8_t> cookie;
        req("9260-5.1-5", v && find_parameter(v->optional_parameters, PARAM_STATE_COOKIE, cookie), "INIT ACK carries a State Cookie");
    }
    {
        SCTP_Socket s;
        Access::setup(s);
        Access::receive(s, packet(0, {chunk(INIT, init_value())}));
        Access::sent(s);
        req("9260-5.1-6", Access::association_count(s) == 0, "no state is kept after sending INIT ACK");
    }
    {
        SCTP_Socket s;
        auto r = Access::initiate(s, {}, false);
        bool first = !r.echo.empty() && r.echo[0].chunks[0].chunk_header.type == COOKIE_ECHO;
        Access::receive(s, packet(OUR_TAG, {}));
        Access::send(s, {'w'});
        auto more = Access::sent(s);
        req("9260-5.1-7", first && r.echo.size() == 1 && more.empty(),
            "COOKIE ECHO comes first, and nothing else goes to the peer until COOKIE ACK");
    }
    {
        SCTP_Socket s;
        auto r = Access::respond(s, init_value(), {data_chunk(data(PEER_TSN))});
        req("9260-5.1-8", !r.cookie_ack.empty() && r.cookie_ack[0].chunks[0].chunk_header.type == COOKIE_ACK, "COOKIE ACK comes first");
        req("9260-5.1.5-5", !r.cookie_ack.empty() && r.cookie_ack[0].chunks[0].chunk_header.type == COOKIE_ACK, "COOKIE ACK is the first chunk");
        req("9260-5.1.5-6", r.cookie_ack.any(SACK), "DATA bundled with the COOKIE ECHO is acknowledged at once");
        bool order = true;
        for (const auto& d : r.cookie_ack.out) {
            if (find_chunk(d.packet, SACK) && find_chunk(d.packet, COOKIE_ACK)) {
                order = order && d.packet.chunks[0].chunk_header.type == COOKIE_ACK;
            }
        }
        req("9260-5.1.5-7", order, "a SACK bundled with COOKIE ACK comes after it");
    }
    {
        SCTP_Socket s;
        auto r = Access::initiate(s);
        auto r2 = Access::respond(s);
        bool init_alone = !r.init.empty() && only(r.init[0], INIT);
        SCTP_Socket t;
        auto resp = Access::respond(t);
        bool ack_alone = !resp.init_ack.empty() && only(resp.init_ack[0], INIT_ACK);
        req("9260-5.1-9", init_alone && ack_alone, "INIT and INIT ACK are never bundled");
        SCTP_Socket u;
        Access::setup(u);
        Access::receive(u, packet(0, {chunk(INIT, init_value()), chunk(HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}})}));
        req("9260-5.1-10", init_alone && ack_alone && Access::sent(u).empty(), "and a packet carrying INIT with other chunks is dropped");
        req("9260-12.3-2", Access::sent(u).empty(), "an INIT bundled with other chunks is silently discarded");
        SCTP_Socket v;
        Access::setup(v);
        Access::receive(v, packet(5, {chunk(INIT, init_value())}));
        req("9260-12.3-2", Access::sent(v).empty() && Access::association_count(v) == 0,
            "an INIT under a nonzero tag is silently discarded");
        (void)r2;
    }
    {
        SCTP_Socket s;
        Access::associate(s);
        Access::sent(s);
        auto first = Access::remaining(s, Expiration_Timer_Type::T1_INIT);
        Access::fire(s, Expiration_Timer_Type::T1_INIT);
        Access::sent(s);
        auto second = Access::remaining(s, Expiration_Timer_Type::T1_INIT);
        bool initial = first && *first <= sctp_parameters::RTO_INITIAL && *first > sctp_parameters::RTO_INITIAL / 2;
        bool doubled = second && *second > sctp_parameters::RTO_INITIAL * 3 / 2 && *second <= sctp_parameters::RTO_INITIAL * 2;
        req("9260-5.1-12", initial && doubled, "T1-init starts at RTO.Initial and backs off as in 6.3");
        req("9260-5.1.6-1", initial && doubled, "INIT retransmission timers follow 6.3");
        for (int i = 0; i < 7; ++i) {
            Access::fire(s, Expiration_Timer_Type::T1_INIT);
            Access::sent(s);
        }
        auto capped = Access::remaining(s, Expiration_Timer_Type::T1_INIT);
        req("9260-5.1.6-1", capped && *capped <= sctp_parameters::RTO_MAX, "and never exceed RTO.Max");
    }
    {
        SCTP_Socket s;
        auto r = Access::initiate(s, concat({parameter(PARAM_STATE_COOKIE, std::vector<uint8_t>(32, 1)), ipv4_parameter("127.0.0.2")}), false);
        bool elsewhere = false;
        for (int i = 0; i < 4; ++i) {
            Access::fire(s, Expiration_Timer_Type::T1_COOKIE);
            auto sent_d = Access::sent(s);
            for (const auto* d : sent_d.all(COOKIE_ECHO)) {
                elsewhere = elsewhere || same_destination(d->destination, addr("127.0.0.2"));
            }
        }
        req("9260-5.1-14", elsewhere, "COOKIE ECHO retransmissions use the peer's other addresses");
        (void)r;
    }
    {
        SCTP_Socket s;
        Access::associate(s);
        uint32_t tag = init_tag(Access::sent(s));
        Access::receive(s, packet(tag, {chunk(INIT_ACK, init_value(0x5A5A5A5A))}));
        auto out = Access::sent(s);
        const Deliverable* abort = out.with(ABORT);
        req("9260-5.1-15", abort != nullptr, "an INIT ACK missing its State Cookie is answered with ABORT");
        req("9260-5.1-16", abort && has_cause(abort->packet, ABORT, CAUSE_MISSING_MANDATORY_PARAM), "naming the missing parameter");
        req("9260-5.1-17", abort && abort->packet.header.verification_tag == 0x5A5A5A5A, "under the INIT ACK's Initiate Tag");
    }
    {
        SCTP_Socket s;
        Access::respond(s);
        Access::receive(s, packet(Access::tcb(s) ? Access::tcb(s)->this_ver_tag : 0, {data_chunk(data(PEER_TSN))}));
        auto first = Access::sent(s);
        req("9260-5.1-18", first.any(SACK), "the association's first DATA is acknowledged at once");
        Access::fire(s, Expiration_Timer_Type::DELAYED_SACK);
        Access::sent(s);
        Access::receive(s, packet(Access::tcb(s) ? Access::tcb(s)->this_ver_tag : 0, {data_chunk(data(PEER_TSN + 1, {'x'}, DATA_FLAG_B | DATA_FLAG_E, 0, 1))}));
        auto second = Access::sent(s);
        req("9260-5.1-19", !second.any(SACK) && Access::armed(s, Expiration_Timer_Type::DELAYED_SACK),
            "later DATA follows the delayed acknowledgement rules");
        Association* a = Access::tcb(s);
        req("9260-5.1-20", a && a->cumulative_tsn_ack == a->next_tsn - 1, "the responder's Cumulative TSN Ack Point starts at its Initial TSN - 1");
    }
}

void s5_1_1_streams() {
    section("5.1.1 Handle Stream Parameters");
    SCTP_Socket s;
    auto r = Access::initiate(s, {}, false);
    const auto* init = r.init.empty() ? nullptr : find_value<init_chunk_value>(r.init[0], INIT);
    SCTP_Socket t;
    auto resp = Access::respond(t);
    const auto* ack = resp.init_ack.empty() ? nullptr : find_value<init_chunk_value>(resp.init_ack[0], INIT_ACK);
    req("9260-5.1.1-1", init && init->out_streams && init->in_streams && ack && ack->out_streams && ack->in_streams,
        "INIT and INIT ACK both state OS and MIS");

    SCTP_Socket i;
    Access::associate(i);
    uint32_t tag = init_tag(Access::sent(i));
    Access::receive(i, packet(tag, {chunk(INIT_ACK, init_value(PEER_TAG, PEER_TSN, RWND, 10, 3, parameter(PARAM_STATE_COOKIE, {1, 2, 3, 4})))}));
    Access::sent(i);
    Access::receive(i, packet(tag, {chunk(COOKIE_ACK, empty_chunk_value{})}));
    Association* a = Access::tcb(i);
    req("9260-5.1.1-2", a && a->out_streams == 3, "the peer's MIS is checked against our OS");
    req("9260-5.1.1-3", a && a->out_streams == 3, "with MIS below our OS, MIS outbound streams are used");
    req("9260-5.1.1-4", a && Access::send(i, {'x'}, 2) == Sctp_Status::OK && Access::send(i, {'x'}, 3) == Sctp_Status::INVALID_STREAM,
        "outbound streams run from 0 to min(OS, MIS) - 1");
    SCTP_Socket j;
    Access::respond(j, init_value(PEER_TAG, PEER_TSN, RWND, 10, 4));
    Association* b = Access::tcb(j);
    req("9260-5.1.1-4", b && b->out_streams == 4, "as the responder too");
}

void s5_1_2_addresses() {
    section("5.1.2 Handle Address Parameters");
    {
        SCTP_Socket s;
        Access::respond(s, init_value(), {}, addr("127.0.0.7"));
        Association* a = Access::tcb(s, Access::key(s, "127.0.0.7"));
        req("9260-5.1.2-1", a && a->peer_address_list.size() == 1 && same_destination(a->peer_address_list[0].address, addr("127.0.0.7")),
            "with no address parameters, the source is the only destination, with the SCTP source port");
    }
    {
        SCTP_Socket s;
        Access::setup(s);
        Access::receive(s, packet(0, {chunk(INIT, init_value(PEER_TAG, PEER_TSN, RWND, 10, 10, parameter(PARAM_HOST_NAME_ADDRESS, {'h', 0, 0, 0})))}),
                        addr("127.0.0.6"));
        auto out = Access::sent(s);
        const Deliverable* abort = out.with(ABORT);
        req("9260-5.1.2-2", abort != nullptr, "a Host Name Address is answered with ABORT");
        req("9260-5.1.2-3", abort && same_destination(abort->destination, addr("127.0.0.6")), "sent to where the peer's packet came from");
        req("9260-12.2.4.1-1", abort != nullptr, "Host Name Address in INIT draws an ABORT");
    }
    {
        SCTP_Socket s;
        Access::respond(s, init_value(PEER_TAG, PEER_TSN, RWND, 10, 10, concat({ipv4_parameter("127.0.0.2"), ipv4_parameter("127.0.0.3")})));
        Association* a = Access::tcb(s);
        req("9260-5.1.2-4", a && a->peer_address_list.size() == 3, "every listed address and the source are recorded");
        Access::send(s, std::vector<uint8_t>(3000, 'm'));
        bool inside = true;
        for (const auto& d : Access::sent(s).out) {
            inside = inside && a && find_path(*a, d.destination) != nullptr;
        }
        req("9260-5.1.2-5", inside, "packets go only to those addresses");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s, ESTABLISHED, {"127.0.0.2"});
        Access::receive(s, packet(0, {chunk(INIT, init_value(0x42424242))}), addr("127.0.0.2"));
        auto out = Access::sent(s);
        const auto* v = out.empty() ? nullptr : find_value<init_chunk_value>(out[0], INIT_ACK);
        std::vector<uint8_t> raw;
        State_Cookie cookie{};
        bool decoded = v && find_parameter(v->optional_parameters, PARAM_STATE_COOKIE, raw) && deserialize_state_cookie(raw, cookie);
        req("9260-5.1.2-6", decoded && cookie.local_tie_tag != 0 && Access::association_count(s) == 1 && a.state == ESTABLISHED,
            "an INIT from an address of a known association belongs to it");
    }
    {
        SCTP_Socket s;
        std::vector<uint8_t> v6 = parameter(PARAM_IPV6_ADDRESS, std::vector<uint8_t>(16, 0x20));
        auto r = Access::respond(s, init_value(PEER_TAG, PEER_TSN, RWND, 10, 10, concat({v6, ipv4_parameter("127.0.0.2")})));
        Association* a = Access::tcb(s);
        const auto* ack = r.init_ack.empty() ? nullptr : find_value<init_chunk_value>(r.init_ack[0], INIT_ACK);
        std::vector<uint8_t> unrecognized;
        req("9260-5.1.2-8", a && a->peer_address_list.size() == 2, "every IPv4 address is used when IPv6 ones are listed too");
        req("9260-5.1.2-9", ack && !find_parameter(ack->optional_parameters, PARAM_UNRECOGNIZED, unrecognized) && !r.init_ack.any(ABORT)
                && !r.init_ack.any(OP_ERROR), "and the IPv6 ones draw no error");
    }
    {
        SCTP_Socket s;
        auto r = Access::respond(s, init_value(PEER_TAG, PEER_TSN, RWND, 10, 10, parameter(PARAM_SUPPORTED_ADDRESS_TYPES, {0, 6, 0, 0})));
        req("9260-5.1.2-10", Access::tcb(s) != nullptr, "IPv4, used to send the INIT, counts as supported though not listed");
        req("9260-5.1.2-11", !r.init_ack.any(ABORT) && !r.init_ack.any(OP_ERROR), "and draws no error indication");
    }
}

void s5_1_3_cookie() {
    section("5.1.3 Generating State Cookie");
    SCTP_Socket s;
    Access::setup(s);
    Access::receive(s, packet(0, {chunk(INIT, init_value())}));
    auto out = Access::sent(s);
    const auto* v = out.empty() ? nullptr : find_value<init_chunk_value>(out[0], INIT_ACK);
    std::vector<uint8_t> raw;
    State_Cookie cookie{};
    bool decoded = v && find_parameter(v->optional_parameters, PARAM_STATE_COOKIE, raw) && deserialize_state_cookie(raw, cookie);
    bool mac = decoded;
    for (size_t i = 0; mac && i < raw.size(); i += 7) {
        std::vector<uint8_t> flipped = raw;
        flipped[i] ^= 0x80;
        State_Cookie out_cookie{};
        uint32_t staleness = 0;
        SCTP_Common_Header header{PEER_PORT, LOCAL_PORT, v->initiate_tag, 0};
        mac = Access::cookies(s).verify(flipped, header, addr(), out_cookie, staleness) == Cookie_Result::INVALID;
    }
    req("9260-5.1.3-1", mac, "the cookie carries a MAC: any changed byte fails it");
    req("9260-5.1.3-2", decoded && cookie.created_us != 0 && cookie.lifespan_us != 0 && cookie.sctp_src_port == PEER_PORT
            && cookie.sctp_dst_port == LOCAL_PORT && cookie.peer_ver_tag == PEER_TAG && cookie.local_ver_tag == v->initiate_tag,
        "the cookie holds its timestamp, lifespan, ports and tags");

    // RFC 4231 test case 2.
    const char* key_text = "Jefe";
    const char* message = "what do ya want for nothing?";
    uint8_t digest[SHA256_DIGEST_SIZE];
    hmac_sha256(reinterpret_cast<const uint8_t*>(key_text), 4, reinterpret_cast<const uint8_t*>(message), 28, digest);
    const uint8_t expected[4] = {0x5b, 0xdc, 0xc1, 0x46};
    req("9260-5.1.3-3", std::equal(expected, expected + 4, digest), "the MAC is HMAC-SHA-256");

    SCTP_Socket t;
    std::vector<uint8_t> a = cookie_for(s, 1, 2, 0, 0);
    std::vector<uint8_t> b = cookie_for(t, 1, 2, 0, 0);
    req("9260-5.1.3-4", a.size() == b.size() && !std::equal(a.end() - STATE_COOKIE_MAC_SIZE, a.end(), b.end() - STATE_COOKIE_MAC_SIZE),
        "each endpoint signs with its own random secret");

    State_Cookie before{}, after{};
    deserialize_state_cookie(cookie_for(s, 1, 2, 0, 0), before);
    advance_cookie_clock(s, std::chrono::minutes(61));
    deserialize_state_cookie(cookie_for(s, 1, 2, 0, 0), after);
    req("9260-5.1.3-5", before.secret_generation != after.secret_generation, "the secret is changed hourly");

    bool shared_only = decoded && cookie.peer_initial_tsn == PEER_TSN && cookie.peer_a_rwnd == RWND && cookie.peer_out_streams == 10
        && cookie.peer_in_streams == 10 && cookie.local_initial_tsn == v->initial_tsn && raw.size() == STATE_COOKIE_SIZE;
    req("9260-5.1.3-6", shared_only, "the unencrypted cookie holds only what the INIT and INIT ACK already shared");
    req("9260-5.1.3-7", raw.size() <= STATE_COOKIE_SIZE, "the cookie is kept small");
}

void s5_1_4_cookie_echo() {
    section("5.1.4 State Cookie Processing");
    SCTP_Socket s;
    auto r = Access::initiate(s, {}, false);
    req("9260-5.1.4-1", r.echo.any(COOKIE_ECHO), "an INIT ACK in COOKIE-WAIT is answered at once with COOKIE ECHO");
    req("9260-5.1.4-2", Access::armed(s, Expiration_Timer_Type::T1_COOKIE), "T1-cookie is started");
    Access::fire(s, Expiration_Timer_Type::T1_COOKIE);
    req("9260-5.1.4-3", Access::sent(s).any(COOKIE_ECHO) && Access::armed(s, Expiration_Timer_Type::T1_COOKIE),
        "its expiry resends COOKIE ECHO and restarts the timer");
}

void s5_1_5_cookie_auth() {
    section("5.1.5 State Cookie Authentication");
    {
        SCTP_Socket s;
        auto r = Access::respond(s);
        SCTP_Socket fresh;
        Access::setup(fresh);
        Access::receive(fresh, packet(0, {chunk(INIT, init_value())}));
        auto ack = Access::sent(fresh);
        const auto* v = ack.empty() ? nullptr : find_value<init_chunk_value>(ack[0], INIT_ACK);
        std::vector<uint8_t> old;
        if (v) {
            find_parameter(v->optional_parameters, PARAM_STATE_COOKIE, old);
        }
        advance_cookie_clock(fresh, std::chrono::minutes(61));
        cookie_for(fresh, 1, 2, 0, 0);
        advance_cookie_clock(fresh, std::chrono::minutes(122));
        cookie_for(fresh, 1, 2, 0, 0);
        echo(fresh, old, v ? v->initiate_tag : 0);
        req("9260-5.1.5-1", Access::sent(fresh).empty() && Access::association_count(fresh) == 0,
            "a cookie signed by a retired secret is silently discarded");
        (void)r;
    }
    {
        SCTP_Socket fresh;
        Access::setup(fresh);
        Access::receive(fresh, packet(0, {chunk(INIT, init_value())}));
        auto ack = Access::sent(fresh);
        const auto* v = ack.empty() ? nullptr : find_value<init_chunk_value>(ack[0], INIT_ACK);
        std::vector<uint8_t> cookie;
        if (v) {
            find_parameter(v->optional_parameters, PARAM_STATE_COOKIE, cookie);
        }
        std::vector<uint8_t> forged = cookie;
        if (!forged.empty()) {
            forged.back() ^= 1;
        }
        echo(fresh, forged, v ? v->initiate_tag : 0, {data_chunk(data(PEER_TSN))});
        req("9260-5.1.5-2", Access::sent(fresh).empty() && Access::association_count(fresh) == 0,
            "a failed MAC discards the packet, DATA included");
        echo(fresh, cookie, (v ? v->initiate_tag : 0) ^ 1);
        bool tag = Access::sent(fresh).empty() && Access::association_count(fresh) == 0;
        SCTP_Packet wrong_port = packet(v ? v->initiate_tag : 0, {chunk(COOKIE_ECHO, cookie_echo_chunk_value{cookie})});
        wrong_port.header.src_port = PEER_PORT + 1;
        Access::receive(fresh, wrong_port);
        req("9260-5.1.5-3", tag && Access::sent(fresh).empty() && Access::association_count(fresh) == 0,
            "a cookie whose tag or ports do not match the packet is discarded");
        advance_cookie_clock(fresh, std::chrono::minutes(5));
        echo(fresh, cookie, v ? v->initiate_tag : 0, {data_chunk(data(PEER_TSN))});
        auto out = Access::sent(fresh);
        req("9260-5.1.5-4", out.any(OP_ERROR) && !out.any(SACK) && Access::association_count(fresh) == 0,
            "an expired cookie draws Stale Cookie, and its DATA is discarded");
    }
    {
        SCTP_Socket s;
        auto r = Access::initiate(s, {}, false);
        Association* a = Access::tcb(s);
        uint32_t our = a ? a->this_ver_tag : 0;
        echo(s, cookie_for(s, our, PEER_TAG, 0, 0), our);
        req("9260-5.1.5-8", a && a->state == ESTABLISHED && Access::sent(s).any(COOKIE_ACK),
            "a COOKIE ECHO for an existing association follows 5.2");
        (void)r;
    }
}

void s5_2_1_collision() {
    section("5.2.1 INIT Received in COOKIE-WAIT or COOKIE-ECHOED State");
    {
        SCTP_Socket s;
        Association_Key k = Access::associate(s);
        auto init = Access::sent(s);
        const auto* ours = init.empty() ? nullptr : find_value<init_chunk_value>(init[0], INIT);
        Access::receive(s, packet(0, {chunk(INIT, init_value(0x13131313))}));
        auto out = Access::sent(s);
        const Deliverable* d = out.with(INIT_ACK);
        const auto* ack = d ? find_value<init_chunk_value>(d->packet, INIT_ACK) : nullptr;
        req("9260-5.2.1-1", ours && ack && ack->initiate_tag == ours->initiate_tag && ack->initial_tsn == ours->initial_tsn,
            "in COOKIE-WAIT, the INIT ACK repeats our INIT's tag and TSN");
        req("9260-5.2.1-2", d != nullptr, "the destination rules are applied");
        req("9260-5.2.1-3", d && same_destination(d->destination, addr()), "INIT ACK goes only to the address the ULP gave");
        req("9260-5.2.1-5", d && same_destination(d->destination, addr()), "the INIT's source, which is that address");
        std::vector<uint8_t> raw;
        req("9260-5.2.1-10", ack && find_parameter(ack->optional_parameters, PARAM_STATE_COOKIE, raw), "a State Cookie is generated");
        Association* a = Access::tcb(s, k);
        req("9260-5.2.1-11", a && a->state == COOKIE_WAIT && Access::armed(s, Expiration_Timer_Type::T1_INIT),
            "the state is unchanged, T1-init runs on and the TCB is kept");
    }
    {
        SCTP_Socket s;
        Access::associate(s);
        Access::sent(s);
        Access::receive(s, packet(0, {chunk(INIT, init_value(0x13131313, PEER_TSN, RWND, 10, 10, ipv4_parameter(PEER_IP)))}),
                        addr("127.0.0.2"));
        auto out = Access::sent(s);
        const Deliverable* d = out.with(INIT_ACK);
        req("9260-5.2.1-4", d && same_destination(d->destination, addr()), "INIT ACK goes only to an address the INIT reported");
    }
    {
        SCTP_Socket s;
        auto r = Access::initiate(s, {}, false);
        const auto* ours = r.init.empty() ? nullptr : find_value<init_chunk_value>(r.init[0], INIT);
        Access::receive(s, packet(0, {chunk(INIT, init_value(0x13131313))}));
        auto out = Access::sent(s);
        const Deliverable* d = out.with(INIT_ACK);
        const auto* ack = d ? find_value<init_chunk_value>(d->packet, INIT_ACK) : nullptr;
        req("9260-5.2.1-6", ours && ack && ack->initiate_tag == ours->initiate_tag && ack->initial_tsn == ours->initial_tsn,
            "in COOKIE-ECHOED, the INIT ACK repeats our INIT's tag and TSN");
        std::vector<uint8_t> raw;
        State_Cookie cookie{};
        bool decoded = ack && find_parameter(ack->optional_parameters, PARAM_STATE_COOKIE, raw) && deserialize_state_cookie(raw, cookie);
        Association* a = Access::tcb(s);
        req("9260-5.2.1-12", decoded && a && cookie.local_tie_tag != 0 && cookie.local_tie_tag == a->local_tie_tag
                && cookie.peer_tie_tag == a->peer_tie_tag, "Tie-Tags are set in both the TCB and the cookie");
    }
    {
        SCTP_Socket s;
        Access::initiate(s, {}, false);
        Association* a = Access::tcb(s);
        Access::receive(s, packet(0, {chunk(INIT, init_value(0x13131313, PEER_TSN, RWND, 10, 10, ipv4_parameter("127.0.0.9")))}));
        auto out = Access::sent(s);
        const Deliverable* abort = out.with(ABORT);
        const auto* causes = abort ? find_value<error_chunk_value>(abort->packet, ABORT) : nullptr;
        req("9260-5.2.1-7", !out.any(INIT_ACK) && a && a->state == COOKIE_ECHOED, "an INIT adding an address is discarded, state unchanged");
        req("9260-5.2.1-8", abort && has_cause(abort->packet, ABORT, CAUSE_RESTART_WITH_NEW_ADDRESSES), "and answered with ABORT");
        bool listed = causes && !causes->causes.empty() && !find_ipv4_addresses(causes->causes[0].info).empty()
            && find_ipv4_addresses(causes->causes[0].info)[0] == ntohl(ipv4("127.0.0.9").s_addr);
        req("9260-5.2.1-9", listed, "the cause lists the added address");
    }
}

void s5_2_2_unexpected_init() {
    section("5.2.2 Unexpected INIT in Other States");
    {
        SCTP_Socket s;
        Association& a = Access::establish(s);
        a.out_streams = 4;
        Access::receive(s, packet(0, {chunk(INIT, init_value(0x24242424))}));
        auto out = Access::sent(s);
        const Deliverable* d = out.with(INIT_ACK);
        const auto* ack = d ? find_value<init_chunk_value>(d->packet, INIT_ACK) : nullptr;
        std::vector<uint8_t> raw;
        State_Cookie cookie{};
        bool decoded = ack && find_parameter(ack->optional_parameters, PARAM_STATE_COOKIE, raw) && deserialize_state_cookie(raw, cookie);
        req("9260-5.2.2-1", decoded, "an unexpected INIT draws INIT ACK with a State Cookie");
        req("9260-5.2.2-2", decoded, "after checking for new addresses");
        req("9260-5.2.2-5", decoded && cookie.local_tie_tag != 0 && cookie.local_tie_tag == a.local_tie_tag && cookie.peer_tie_tag == a.peer_tie_tag,
            "the current Tie-Tags go in the cookie and the TCB");
        req("9260-5.2.2-6", d && d->packet.header.verification_tag == 0x24242424, "the INIT ACK goes under the INIT's Initiate Tag");
        req("9260-5.2.2-7", ack && ack->initiate_tag != OUR_TAG && ack->initiate_tag != 0, "with a new Initiate Tag");
        req("9260-5.2.2-8", ack && ack->out_streams == 4, "and the association's other parameters, such as its outbound streams");
        req("9260-5.2.2-9", a.state == ESTABLISHED && a.this_ver_tag == OUR_TAG && a.peer_ver_tag == PEER_TAG, "the TCB is unchanged");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s);
        Access::receive(s, packet(0, {chunk(INIT, init_value(0x24242424, PEER_TSN, RWND, 10, 10, ipv4_parameter("127.0.0.8")))}));
        auto out = Access::sent(s);
        const Deliverable* abort = out.with(ABORT);
        const auto* causes = abort ? find_value<error_chunk_value>(abort->packet, ABORT) : nullptr;
        req("9260-5.2.2-3", abort && abort->packet.header.verification_tag == 0x24242424 && !out.any(INIT_ACK),
            "an INIT adding addresses draws ABORT under its Initiate Tag");
        req("9260-5.2.2-4", causes && !causes->causes.empty() && !find_ipv4_addresses(causes->causes[0].info).empty(),
            "listing the added addresses");
        req("9260-5.2.2-9", a.state == ESTABLISHED && a.peer_address_list.size() == 1, "and the TCB is unchanged");
    }
    {
        SCTP_Socket s;
        Access::setup(s);
        Access::receive(s, packet(0, {chunk(INIT, init_value())}));
        auto out = Access::sent(s);
        const auto* ack = out.empty() ? nullptr : find_value<init_chunk_value>(out[0], INIT_ACK);
        std::vector<uint8_t> raw;
        State_Cookie cookie{};
        bool decoded = ack && find_parameter(ack->optional_parameters, PARAM_STATE_COOKIE, raw) && deserialize_state_cookie(raw, cookie);
        req("9260-5.2.2-10", decoded && cookie.local_tie_tag == 0 && cookie.peer_tie_tag == 0, "with no TCB, the Tie-Tags are 0");
    }
}

void s5_2_3_to_5_2_6() {
    section("5.2.3 - 5.2.6 Unexpected INIT ACK, COOKIE ECHO with a TCB, COOKIE ACK, Stale Cookie");
    {
        SCTP_Socket s;
        Association& a = Access::establish(s);
        Access::receive(s, packet(OUR_TAG, {chunk(INIT_ACK, init_value(0x7, PEER_TSN, RWND, 10, 10, parameter(PARAM_STATE_COOKIE, {1, 2, 3, 4})))}));
        bool established = Access::sent(s).empty() && a.state == ESTABLISHED && a.peer_ver_tag == PEER_TAG;
        SCTP_Socket t;
        Access::initiate(t, {}, false);
        Association* b = Access::tcb(t);
        Access::receive(t, packet(b ? b->this_ver_tag : 0, {chunk(INIT_ACK, init_value(0x7, PEER_TSN, RWND, 10, 10, parameter(PARAM_STATE_COOKIE, {1, 2, 3, 4})))}));
        req("9260-5.2.3-1", established && Access::sent(t).empty() && b && b->peer_ver_tag == PEER_TAG,
            "an INIT ACK outside COOKIE-WAIT is discarded");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s);
        a.local_tie_tag = 0x101;
        a.peer_tie_tag = 0x202;
        std::vector<uint8_t> restart = cookie_for(s, 0x31, 0x32, 0x101, 0x202);
        advance_cookie_clock(s, std::chrono::minutes(5));
        echo(s, restart, 0x31, {data_chunk(data(PEER_TSN + 100))});
        auto out = Access::sent(s);
        req("9260-5.2.4-1", !out.any(SACK) && a.this_ver_tag == OUR_TAG && a.peer_ver_tag == PEER_TAG,
            "a stale cookie whose tags do not match is discarded, DATA included");
        req("9260-5.2.4-2", out.any(OP_ERROR) && has_cause(*&out.with(OP_ERROR)->packet, OP_ERROR, CAUSE_STALE_COOKIE),
            "and answered with Stale Cookie");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s);
        echo(s, cookie_for(s, 0x31, PEER_TAG, 0, 0), 0x31);
        bool case_c = Access::sent(s).empty() && a.this_ver_tag == OUR_TAG;
        echo(s, cookie_for(s, 0x31, 0x32, 0, 0), 0x31);
        req("9260-5.2.4-3", case_c && Access::sent(s).empty() && a.this_ver_tag == OUR_TAG && a.peer_ver_tag == PEER_TAG,
            "a cookie matching no row of Table 12 is discarded");
        req("9260-5.2.4-8", case_c, "case C: the cookie is discarded");
        req("9260-5.2.4-9", case_c && a.state == ESTABLISHED, "and the state is unchanged");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s);
        a.local_tie_tag = 0x101;
        a.peer_tie_tag = 0x202;
        primary(a).cwnd = 50000;
        primary(a).ssthresh = 7000;
        Access::notifications(s);
        echo(s, cookie_for(s, 0x31, 0x32, 0x101, 0x202), 0x31);
        auto ns = Access::notifications(s);
        Association* b = Access::tcb(s);
        req("9260-5.2.4-4", Access::notified(ns, Assoc_Change_State::RESTART) && !Access::notified(ns, Assoc_Change_State::COMM_LOST),
            "a restart is reported as RESTART, not COMMUNICATION LOST");
        req("9260-5.2.4-5", b && primary(*b).cwnd == initial_cwnd(pmdcs(primary(*b))) && primary(*b).ssthresh == RWND,
            "congestion control starts over");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s, SHUTDOWN_ACK_SENT);
        a.local_tie_tag = 0x101;
        a.peer_tie_tag = 0x202;
        echo(s, cookie_for(s, 0x31, 0x32, 0x101, 0x202), 0x31);
        auto out = Access::sent(s);
        const Deliverable* error = out.with(OP_ERROR);
        req("9260-5.2.4-6", a.this_ver_tag == OUR_TAG && out.any(SHUTDOWN_ACK) && error
                && has_cause(error->packet, OP_ERROR, CAUSE_COOKIE_WHILE_SHUTTING_DOWN),
            "a restart in SHUTDOWN-ACK-SENT resends SHUTDOWN ACK and reports Cookie Received While Shutting Down");
    }
    {
        SCTP_Socket s;
        auto r = Access::initiate(s, {}, false);
        Association* a = Access::tcb(s);
        uint32_t our = a ? a->this_ver_tag : 0;
        echo(s, cookie_for(s, our, 0x77, 0, 0), our);
        auto out = Access::sent(s);
        req("9260-5.2.4-7", a && a->state == ESTABLISHED && a->peer_ver_tag == 0x77 && out.any(COOKIE_ACK)
                && !Access::armed(s, Expiration_Timer_Type::T1_COOKIE) && !Access::armed(s, Expiration_Timer_Type::T1_INIT),
            "case B: the peer's tag is updated, T1 timers stopped, COOKIE ACK sent");
        (void)r;
    }
    {
        SCTP_Socket s;
        Access::initiate(s, {}, false);
        Association* a = Access::tcb(s);
        uint32_t our = a ? a->this_ver_tag : 0;
        echo(s, cookie_for(s, our, PEER_TAG, 0, 0), our);
        auto out = Access::sent(s);
        req("9260-5.2.4-10", a && a->state == ESTABLISHED, "case D: COOKIE-ECHOED moves to ESTABLISHED");
        req("9260-5.2.4-11", out.any(COOKIE_ACK) && !Access::armed(s, Expiration_Timer_Type::T1_COOKIE), "T1-cookie stops and COOKIE ACK is sent");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s);
        Access::notifications(s);
        Access::receive(s, packet(OUR_TAG, {chunk(COOKIE_ACK, empty_chunk_value{})}));
        req("9260-5.2.5-1", Access::sent(s).empty() && a.state == ESTABLISHED && Access::notifications(s).empty(),
            "COOKIE ACK outside COOKIE-ECHOED is silently discarded");
    }
    {
        SCTP_Socket s;
        Access::initiate(s, {}, false);
        Association* a = Access::tcb(s);
        uint32_t our = a ? a->this_ver_tag : 0;
        Access::receive(s, packet(our, {chunk(OP_ERROR, error_chunk_value{{stale_cookie_cause(10'000'000)}})}));
        auto out = Access::sent(s);
        req("9260-5.2.6-1", out.any(INIT) && a && a->state == COOKIE_WAIT, "Stale Cookie in COOKIE-ECHOED restarts the setup");
        const auto* init = out.empty() ? nullptr : find_value<init_chunk_value>(out[0], INIT);
        std::vector<uint8_t> preservative;
        bool found = init && find_parameter(init->optional_parameters, PARAM_COOKIE_PRESERVATIVE, preservative) && preservative.size() == 4;
        req("9260-5.2.6-3", found && read_be32(preservative.data()) <= 1000 + 100,
            "the Cookie Preservative asks for the measured RTT plus at most 1 s");
        SCTP_Socket t;
        Association& b = Access::establish(t);
        Access::receive(t, packet(OUR_TAG, {chunk(OP_ERROR, error_chunk_value{{stale_cookie_cause(1000)}})}));
        req("9260-5.2.6-2", !Access::sent(t).any(INIT) && b.state == ESTABLISHED, "outside COOKIE-ECHOED it is discarded");
    }
}

void s5_3_tags() {
    section("5.3.1 Verification Tag");
    bool nonzero = true;
    std::set<uint32_t> tags;
    for (int i = 0; i < 2000; ++i) {
        uint32_t tag = generate_nonzero_tag();
        nonzero = nonzero && tag != 0;
        tags.insert(tag);
    }
    req("9260-5.3.1-1", nonzero && tags.size() > 1990, "Initiate Tags are drawn from 1 to 2^32 - 1");

    SCTP_Socket s;
    auto r = Access::initiate(s);
    Association* a = Access::tcb(s);
    uint32_t tag = a ? a->this_ver_tag : 0;
    Access::send(s, std::vector<uint8_t>(2000, 'x'));
    Access::sent(s);
    Access::receive(s, packet(tag, {sack_chunk(a ? a->next_tsn - 1 : 0)}));
    Access::fire(s, Expiration_Timer_Type::HEARTBEAT, PEER_IP);
    Access::sent(s);
    req("9260-5.3.1-2", a && a->this_ver_tag == tag && a->peer_ver_tag == PEER_TAG, "the tags do not change over the association's life");
    s.sctp_abort(Access::key(s));
    Access::sent(s);
    Access::associate(s);
    uint32_t again = init_tag(Access::sent(s));
    req("9260-5.3.1-3", again != 0 && again != tag, "a new association to the same peer uses a new tag");
    (void)r;
}

void s5_4_path_verification() {
    section("5.4 Path Verification");
    {
        SCTP_Socket s;
        Association& a = Access::establish(s, ESTABLISHED, {"127.0.0.2", "127.0.0.3", "127.0.0.4"});
        for (size_t i = 1; i < a.peer_address_list.size(); ++i) {
            a.peer_address_list[i].confirmed = false;
        }
        Access::start_heartbeats_for(s);
        auto out = Access::sent(s);
        size_t to_unconfirmed = 0;
        for (const auto* d : out.all(HEARTBEAT)) {
            to_unconfirmed += !same_destination(d->destination, addr());
        }
        req("9260-5.4-1", to_unconfirmed <= sctp_parameters::HB_MAX_BURST, "at most HB.Max.Burst confirmation probes per RTO");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s, ESTABLISHED, {"127.0.0.2"});
        a.peer_address_list[1].confirmed = false;
        Access::start_heartbeats_for(s);
        Access::receive(s, packet(OUR_TAG, {data_chunk(data(PEER_TSN), DATA_IMMEDIATE_SACK_FLAG)}), addr("127.0.0.2"));
        Access::receive(s, packet(OUR_TAG, {chunk(HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}})}), addr("127.0.0.2"));
        Access::send(s, std::vector<uint8_t>(5000, 'u'));
        primary(a).active = false;
        Access::send(s, {'v'});
        bool clean = true;
        for (const auto& d : Access::sent(s).out) {
            if (same_destination(d.destination, addr("127.0.0.2"))) {
                for (const auto& c : d.packet.chunks) {
                    Chunk_Type t = c.chunk_header.type;
                    clean = clean && (t == HEARTBEAT || t == HEARTBEAT_ACK);
                }
            }
        }
        req("9260-5.4-2", clean, "nothing but HEARTBEAT and HEARTBEAT ACK goes to an UNCONFIRMED address");
    }
    {
        SCTP_Socket fresh;
        Access::setup(fresh);
        Access::receive(fresh, packet(0, {chunk(INIT, init_value(PEER_TAG, PEER_TSN, RWND, 10, 10, ipv4_parameter("127.0.0.2")))}));
        auto ack = Access::sent(fresh);
        const auto* v = ack.empty() ? nullptr : find_value<init_chunk_value>(ack[0], INIT_ACK);
        std::vector<uint8_t> cookie;
        if (v) {
            find_parameter(v->optional_parameters, PARAM_STATE_COOKIE, cookie);
        }
        echo(fresh, cookie, v ? v->initiate_tag : 0, {}, addr("127.0.0.2"));
        auto out = Access::sent(fresh);
        bool ok = !out.all(COOKIE_ACK).empty();
        for (const auto* d : out.all(COOKIE_ACK)) {
            ok = ok && (same_destination(d->destination, addr()) || find_chunk(d->packet, HEARTBEAT));
        }
        req("9260-5.4-3", ok, "a COOKIE ACK to an UNCONFIRMED address carries a HEARTBEAT");
        req("9260-5.4-4", ok, "or does not go there");
    }
    {
        SCTP_Socket s;
        Access::initiate(s, concat({parameter(PARAM_STATE_COOKIE, std::vector<uint8_t>(32, 1)), ipv4_parameter("127.0.0.2")}), false);
        bool ok = true;
        for (int i = 0; i < 4; ++i) {
            Access::fire(s, Expiration_Timer_Type::T1_COOKIE);
            auto sent_d = Access::sent(s);
            for (const auto* d : sent_d.all(COOKIE_ECHO)) {
                if (!same_destination(d->destination, addr())) {
                    ok = ok && find_chunk(d->packet, HEARTBEAT) && serialize_sctp_packet(d->packet).size() <= SCTP_COMMON_HEADER_SIZE + BASE_PMDCS;
                }
            }
        }
        req("9260-5.4-5", ok, "a COOKIE ECHO to an UNCONFIRMED address carries a HEARTBEAT and fits the PMTU");
        req("9260-5.4-6", ok, "otherwise it is not sent there");
    }
}

} // namespace

int main() {
    s4_state_machine();
    s5_establishment();
    s5_1_1_streams();
    s5_1_2_addresses();
    s5_1_3_cookie();
    s5_1_4_cookie_echo();
    s5_1_5_cookie_auth();
    s5_2_1_collision();
    s5_2_2_unexpected_init();
    s5_2_3_to_5_2_6();
    s5_3_tags();
    s5_4_path_verification();
    return summary("RFC 9260 sections 4 and 5");
}
