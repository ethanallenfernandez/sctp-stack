// ERROR causes the stack acts on or sends (RFC 9260 3.3.10): Stale Cookie
// recovery with a Cookie Preservative (5.2.6) from both ends, and Invalid
// Stream Identifier (6.5) with the stream negotiation it depends on (5.1.1).
// Packets go straight into handle_recv_packet; replies are read off the send
// queue, so no event loop runs.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "serialize.hpp"

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

namespace {

constexpr uint32_t OUR_TAG = 0x0A0B0C0D;
constexpr uint32_t PEER_TAG = 0x11223344;
constexpr uint16_t PEER_PORT = 40000;
constexpr uint16_t OUR_PORT = 9899;

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

Association_Key peer_key() {
    sockaddr_in src{};
    src.sin_family = AF_INET;
    src.sin_port = htons(PEER_PORT);
    sctp_parse_ipv4("127.0.0.1", src.sin_addr);
    return Association_Key{src};
}

SCTP_Chunk init_chunk(Chunk_Type type, uint16_t os, uint16_t mis, std::vector<uint8_t> params = {}) {
    return {{type, 0, 0}, init_chunk_value{PEER_TAG, 65535, os, mis, 1000, std::move(params)}};
}

SCTP_Chunk data(uint32_t tsn, uint16_t stream) {
    return {{DATA, 0, 0}, data_chunk_value{tsn, stream, 0, 0, {'x'}}};
}

std::vector<uint8_t> param(uint16_t type, std::vector<uint8_t> value) {
    std::vector<uint8_t> out;
    append_parameter(out, type, value.data(), value.size());
    return out;
}

const SCTP_Chunk* first_chunk(const std::vector<SCTP_Packet>& sent, Chunk_Type type) {
    for (const auto& packet : sent) {
        for (const auto& chunk : packet.chunks) {
            if (chunk.chunk_header.type == type) return &chunk;
        }
    }
    return nullptr;
}

} // namespace

struct SCTP_Socket_Test_Access {
    SCTP_Socket stack;

    SCTP_Socket_Test_Access() {
        stack.local_address.sin_port = htons(OUR_PORT);
    }

    Association& add(Association_State state) {
        Association assoc = stack.init_new_association(peer_key());
        assoc.state = state;
        assoc.this_ver_tag = OUR_TAG;
        assoc.peer_ver_tag = state == COOKIE_WAIT ? 0 : PEER_TAG;
        assoc.last_peer_tsn = 0;
        return stack.associations.insert_or_assign(peer_key(), assoc).first->second;
    }

    Association* find() {
        auto it = stack.associations.find(peer_key());
        return it == stack.associations.end() ? nullptr : &it->second;
    }

    void receive(uint32_t tag, std::vector<SCTP_Chunk> chunks) {
        SCTP_Packet packet;
        packet.header = {PEER_PORT, OUR_PORT, tag, 0};
        packet.chunks = std::move(chunks);
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.handle_recv_packet(wire.data(), wire.size(), peer_key().address);
    }

    std::vector<SCTP_Packet> drain_sends() {
        std::vector<SCTP_Packet> out;
        auto now = std::chrono::steady_clock::now();
        while (auto pending = stack.sends.peek(now)) {
            out.push_back(pending->deliverable.packet);
            stack.sends.commit(pending->priority);
        }
        return out;
    }

    void set_cookie_clock(std::function<std::chrono::steady_clock::time_point()> clock) {
        stack.cookie_authorizer.clock = std::move(clock);
    }

    void schedule_t1_cookie() {
        stack.schedule_expiration(Expiration_Key{peer_key(), Expiration_Timer_Type::T1_COOKIE},
                                  std::chrono::steady_clock::now() + std::chrono::seconds(10),
                                  Deliverable{peer_key(), SCTP_Packet{}});
    }

    bool t1_cookie_active() {
        return stack.expirations.is_active(Expiration_Key{peer_key(), Expiration_Timer_Type::T1_COOKIE});
    }

    static Association from_cookie(const State_Cookie& cookie) {
        SCTP_Socket stack;
        return stack.init_new_association(cookie, peer_key());
    }
};

namespace {

using Harness = SCTP_Socket_Test_Access;

error_chunk_value stale_error(uint32_t staleness_us) {
    return error_chunk_value{{error_cause{CAUSE_STALE_COOKIE,
        {static_cast<uint8_t>(staleness_us >> 24), static_cast<uint8_t>(staleness_us >> 16),
         static_cast<uint8_t>(staleness_us >> 8), static_cast<uint8_t>(staleness_us)}}}};
}

void test_initiator_stale_recovery() {
    std::printf("Initiator: Stale Cookie -> new INIT with Cookie Preservative (5.2.6):\n");

    Harness h;
    h.add(COOKIE_ECHOED).cookie_retransmits = 3;
    h.schedule_t1_cookie();

    h.receive(OUR_TAG, {{{OP_ERROR, 0, 0}, stale_error(1500)}});
    Association* assoc = h.find();
    check(assoc && assoc->state == COOKIE_WAIT, "back to COOKIE_WAIT");
    check(assoc && assoc->peer_ver_tag == 0 && assoc->cookie_retransmits == 0 && assoc->stale_cookie_retries == 1,
          "peer tag and retransmit counters reset, one retry counted");
    check(!h.t1_cookie_active(), "T1-cookie stopped");

    std::vector<SCTP_Packet> sent = h.drain_sends();
    const SCTP_Chunk* init = first_chunk(sent, INIT);
    check(init != nullptr && sent.size() == 1, "exactly one packet sent: the INIT");
    if (!init) return;
    check(sent[0].header.verification_tag == 0 && sent[0].header.des_port == PEER_PORT, "INIT header: tag 0, to the peer");
    const auto& value = std::get<init_chunk_value>(init->chunk_value);
    check(value.initiate_tag == OUR_TAG, "same Initiate Tag as before");

    // 1500 us rounds up to 2 ms; plus min(2 ms, 1 s) of margin = 4 ms.
    std::vector<uint8_t> preservative;
    check(find_parameter(value.optional_parameters, PARAM_COOKIE_PRESERVATIVE, preservative)
              && preservative == std::vector<uint8_t>{0, 0, 0, 4},
          "Cookie Preservative suggests 4 ms");
}

void test_initiator_gives_up() {
    std::printf("Initiator: retries are bounded:\n");

    Harness h;
    h.add(COOKIE_ECHOED).stale_cookie_retries = 2;   // MAX_STALE_COOKIE_RETRIES
    h.receive(OUR_TAG, {{{OP_ERROR, 0, 0}, stale_error(1500)}});
    check(h.find() == nullptr, "association removed once retries run out");
    check(first_chunk(h.drain_sends(), INIT) == nullptr, "no further INIT");
}

void test_malformed_stale_cause() {
    std::printf("Initiator: malformed Stale Cookie cause:\n");

    Harness h;
    h.add(COOKIE_ECHOED);
    h.receive(OUR_TAG, {{{OP_ERROR, 0, 0}, error_chunk_value{{error_cause{CAUSE_STALE_COOKIE, {0, 1}}}}}});
    check(h.find() && h.find()->state == COOKIE_ECHOED, "a 2-byte staleness is not acted on");
    check(h.drain_sends().empty(), "and nothing is sent");
}

void test_responder_stale_and_preservative() {
    std::printf("Responder: stale COOKIE ECHO, then an INIT with a Cookie Preservative:\n");

    Harness h;
    auto base = std::chrono::steady_clock::now();
    auto offset = std::chrono::microseconds(0);
    h.set_cookie_clock([&] { return base + offset; });

    h.receive(0, {init_chunk(INIT, 1, 1)});
    std::vector<SCTP_Packet> first_reply = h.drain_sends();
    const SCTP_Chunk* init_ack = first_chunk(first_reply, INIT_ACK);
    check(init_ack != nullptr, "INIT answered with INIT ACK");
    if (!init_ack) return;
    std::vector<uint8_t> cookie;
    find_parameter(std::get<init_chunk_value>(init_ack->chunk_value).optional_parameters, PARAM_STATE_COOKIE, cookie);

    offset = std::chrono::microseconds(sctp_parameters::VALID_COOKIE_LIFE) + std::chrono::microseconds(2500);
    State_Cookie decoded{};
    deserialize_state_cookie(cookie, decoded);
    h.receive(decoded.local_ver_tag, {{{COOKIE_ECHO, 0, 0}, cookie_echo_chunk_value{cookie}}});
    check(h.find() == nullptr, "stale COOKIE ECHO creates no association");

    std::vector<SCTP_Packet> sent = h.drain_sends();
    const SCTP_Chunk* error = first_chunk(sent, OP_ERROR);
    check(error != nullptr, "ERROR sent");
    if (error) {
        const auto& causes = std::get<error_chunk_value>(error->chunk_value).causes;
        check(sent[0].header.verification_tag == PEER_TAG, "addressed with the INIT's Initiate Tag");
        check(causes.size() == 1 && causes[0].code == CAUSE_STALE_COOKIE
                  && causes[0].info == std::vector<uint8_t>{0x00, 0x00, 0x09, 0xC4},
              "Stale Cookie with Measure of Staleness 2500 us");
    }

    h.receive(0, {init_chunk(INIT, 1, 1, param(PARAM_COOKIE_PRESERVATIVE, {0x00, 0x00, 0x13, 0x88}))});   // 5000 ms
    std::vector<SCTP_Packet> second_reply = h.drain_sends();
    init_ack = first_chunk(second_reply, INIT_ACK);
    check(init_ack != nullptr, "INIT with Cookie Preservative answered");
    if (!init_ack) return;
    find_parameter(std::get<init_chunk_value>(init_ack->chunk_value).optional_parameters, PARAM_STATE_COOKIE, cookie);
    deserialize_state_cookie(cookie, decoded);
    check(decoded.lifespan_us == 65'000'000, "cookie lifespan extended by 5 s");
}

void test_stream_negotiation() {
    std::printf("Stream negotiation (5.1.1):\n");

    State_Cookie cookie{};
    cookie.local_out_streams = 4;
    cookie.local_in_streams = 4;
    cookie.peer_out_streams = 2;
    cookie.peer_in_streams = 9;
    Association from_cookie = Harness::from_cookie(cookie);
    check(from_cookie.in_streams == 2, "responder: in = min(our MIS 4, peer OS 2)");
    check(from_cookie.out_streams == 4, "responder: out = min(our OS 4, peer MIS 9)");

    Harness h;
    h.add(COOKIE_WAIT);
    h.receive(OUR_TAG, {init_chunk(INIT_ACK, 5, 5, param(PARAM_STATE_COOKIE, std::vector<uint8_t>(96, 0)))});
    Association* assoc = h.find();
    check(assoc && assoc->state == COOKIE_ECHOED && assoc->in_streams == 1 && assoc->out_streams == 1,
          "initiator: INIT ACK offering 5/5 negotiates down to our 1/1");

    Harness zero_ack;
    zero_ack.add(COOKIE_WAIT);
    zero_ack.receive(OUR_TAG, {init_chunk(INIT_ACK, 0, 5, param(PARAM_STATE_COOKIE, std::vector<uint8_t>(96, 0)))});
    std::vector<SCTP_Packet> zero_ack_sent = zero_ack.drain_sends();
    check(!zero_ack.find(), "INIT ACK with OS 0 destroys the TCB (3.3.3)");
    check(zero_ack_sent.size() == 1 && zero_ack_sent[0].chunks[0].chunk_header.type == ABORT,
          "and is aborted");

    Harness zero_init;
    zero_init.receive(0, {init_chunk(INIT, 1, 0)});
    std::vector<SCTP_Packet> zero_init_sent = zero_init.drain_sends();
    check(zero_init_sent.size() == 1 && zero_init_sent[0].chunks[0].chunk_header.type == ABORT,
          "INIT with MIS 0 is aborted (3.3.2)");
}

void test_invalid_stream() {
    std::printf("Invalid Stream Identifier (6.5):\n");

    Harness h;
    h.add(ESTABLISHED);
    h.receive(OUR_TAG, {data(1, 0), data(2, 5), data(3, 0)});
    Association* assoc = h.find();
    check(assoc && assoc->ulp_buffer.size() == 2, "valid-stream DATA on either side is delivered");
    check(assoc && assoc->last_peer_tsn == 3, "the invalid chunk's TSN is still acknowledged");

    std::vector<SCTP_Packet> sent = h.drain_sends();
    const SCTP_Chunk* error = first_chunk(sent, OP_ERROR);
    check(error != nullptr, "ERROR sent");
    if (error) {
        const auto& causes = std::get<error_chunk_value>(error->chunk_value).causes;
        check(causes.size() == 1 && causes[0].code == CAUSE_INVALID_STREAM_ID
                  && causes[0].info == std::vector<uint8_t>{0x00, 0x05, 0x00, 0x00},
              "cause 1: stream 5, reserved 0");
    }

    Harness ooo;
    ooo.add(ESTABLISHED);
    ooo.receive(OUR_TAG, {data(3, 0), data(2, 7)});
    check(first_chunk(ooo.drain_sends(), OP_ERROR) != nullptr, "reported when it arrives out of order");
    ooo.receive(OUR_TAG, {data(1, 0)});
    assoc = ooo.find();
    check(assoc && assoc->ulp_buffer.size() == 2 && assoc->last_peer_tsn == 3,
          "gap filled: TSNs 1 and 3 delivered, 2 skipped");
    check(first_chunk(ooo.drain_sends(), OP_ERROR) == nullptr, "not reported again when drained");

    ooo.receive(OUR_TAG, {data(2, 7)});
    check(first_chunk(ooo.drain_sends(), OP_ERROR) == nullptr, "a duplicate is not reported again");
}

} // namespace

int main() {
    test_initiator_stale_recovery();
    test_initiator_gives_up();
    test_malformed_stale_cause();
    test_responder_stale_and_preservative();
    test_stream_negotiation();
    test_invalid_stream();

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
