// ABORT sent for a zero Initiate Tag (RFC 9260 3.3.2, 3.3.3). Packets are fed
// straight into handle_recv_packet and the reply is read off the send queue, so
// no event loop or socket I/O runs.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "serialize.hpp"

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

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
    struct Result {
        bool has_association;
        std::vector<SCTP_Packet> sent;
        std::vector<Notification> notifications;
    };

    // A local abort of an association carrying queued DATA.
    static Result abort_local(Association_State state, const std::vector<uint8_t>& reason) {
        SCTP_Socket stack;
        sockaddr_in src = peer_address();
        Association_Key key{src};

        stack.local_address.sin_family = AF_INET;
        stack.local_address.sin_port = htons(LOCAL_PORT);
        sctp_parse_ipv4("127.0.0.1", stack.local_address.sin_addr);

        Association assoc = stack.init_new_association(key);
        assoc.this_ver_tag = OUR_TAG;
        assoc.peer_ver_tag = state == COOKIE_WAIT ? 0 : PEER_TAG;
        assoc.state = state;
        stack.associations.insert_or_assign(key, assoc);

        stack.sctp_send_data(key, {'h', 'i'});
        stack.sctp_abort(key, reason);

        return collect(stack, key);
    }

    // state == nullptr means no TCB at all.
    static Result deliver_to(const Association_State* state, SCTP_Packet packet) {
        SCTP_Socket stack;
        stack.sctp_subscribe(Notification_Type::SCTP_REMOTE_ERROR, true);
        sockaddr_in src = peer_address();
        Association_Key key{src};
        if (state) {
            Association assoc = stack.init_new_association(key);
            assoc.this_ver_tag = OUR_TAG;
            assoc.peer_ver_tag = *state == COOKIE_WAIT ? 0 : PEER_TAG;
            assoc.state = *state;
            assoc.last_peer_tsn = 0;
            stack.associations.insert_or_assign(key, assoc);
        }

        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.handle_recv_packet(wire.data(), wire.size(), src);

        return collect(stack, key);
    }

    static Result deliver(SCTP_Packet packet, bool with_cookie_wait_tcb) {
        SCTP_Socket stack;
        sockaddr_in src = peer_address();
        Association_Key key{src};
        if (with_cookie_wait_tcb) {
            Association assoc = stack.init_new_association(key);
            assoc.this_ver_tag = OUR_TAG;
            assoc.state = COOKIE_WAIT;
            stack.associations.insert_or_assign(key, assoc);
        }

        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.handle_recv_packet(wire.data(), wire.size(), src);

        return collect(stack, key);
    }

    static Result collect(SCTP_Socket& stack, const Association_Key& key) {
        Result result{};
        result.has_association = stack.associations.find(key) != stack.associations.end();
        auto now = std::chrono::steady_clock::now();
        while (auto pending = stack.sends.peek(now)) {
            result.sent.push_back(pending->deliverable.packet);
            stack.sends.commit(pending->priority);
        }
        while (auto notification = stack.notifications.dequeue()) {
            result.notifications.push_back(*notification);
        }
        return result;
    }
};

namespace {

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

using Access = SCTP_Socket_Test_Access;

SCTP_Packet init(uint32_t initiate_tag, uint16_t streams = 1) {
    SCTP_Packet packet;
    packet.header = {PEER_PORT, LOCAL_PORT, 0, 0};
    packet.chunks.push_back({{INIT, 0, 0}, init_chunk_value{initiate_tag, RWND, streams, streams, 1000, {}}});
    return packet;
}

SCTP_Packet init_ack(uint32_t initiate_tag, uint16_t streams = 1) {
    std::vector<uint8_t> parameters;
    std::vector<uint8_t> cookie(STATE_COOKIE_SIZE, 0x5A);
    append_parameter(parameters, PARAM_STATE_COOKIE, cookie.data(), cookie.size());

    SCTP_Packet packet;
    packet.header = {PEER_PORT, LOCAL_PORT, OUR_TAG, 0};
    packet.chunks.push_back({{INIT_ACK, 0, 0}, init_chunk_value{initiate_tag, RWND, streams, streams, 2000, std::move(parameters)}});
    return packet;
}

bool is_abort(const SCTP_Packet& packet) {
    return !packet.chunks.empty() && packet.chunks[0].chunk_header.type == ABORT;
}

void test_init_zero_tag() {
    std::printf("INIT with a zero Initiate Tag:\n");

    auto r = Access::deliver(init(0), false);
    check(r.sent.size() == 1 && is_abort(r.sent[0]), "one ABORT sent, and no INIT ACK");
    check(!r.has_association, "no TCB created");
    if (r.sent.size() != 1 || !is_abort(r.sent[0])) return;

    const SCTP_Packet& abort = r.sent[0];
    check((abort.chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT) != 0, "T bit set: there is no TCB to address it from");
    check(abort.header.verification_tag == 0, "tag reflected from the INIT, which carried 0");
    check(abort.header.des_port == PEER_PORT && abort.header.src_port == LOCAL_PORT, "ABORT goes back to the sender");

    const auto& causes = std::get<error_chunk_value>(abort.chunks[0].chunk_value).causes;
    check(causes.size() == 1 && causes[0].code == CAUSE_INVALID_MANDATORY_PARAM && causes[0].info.empty(),
          "one Invalid Mandatory Parameter cause, with no cause-specific information");

    std::vector<uint8_t> wire = serialize_sctp_packet(abort);
    std::vector<uint8_t> want = {
        0x06, 0x01, 0x00, 0x08,   // ABORT, T bit, length 8
        0x00, 0x07, 0x00, 0x04,   // cause 7, length 4
    };
    check(wire.size() == SCTP_COMMON_HEADER_SIZE + want.size()
              && std::equal(want.begin(), want.end(), wire.begin() + SCTP_COMMON_HEADER_SIZE),
          "ABORT bytes match RFC 9260 3.3.7 layout");
}

void test_init_ack_zero_tag() {
    std::printf("INIT ACK with a zero Initiate Tag:\n");

    auto r = Access::deliver(init_ack(0), true);
    check(!r.has_association, "TCB destroyed");
    check(r.sent.size() == 1 && is_abort(r.sent[0]), "one ABORT sent, and no COOKIE ECHO");
    if (r.sent.size() == 1 && is_abort(r.sent[0])) {
        const SCTP_Packet& abort = r.sent[0];
        check((abort.chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT) != 0, "T bit set");
        check(abort.header.verification_tag == OUR_TAG, "tag reflected from the INIT ACK, which echoed ours");
    }

    check(r.notifications.size() == 1, "one notification");
    if (r.notifications.size() == 1) {
        const auto* change = std::get_if<Assoc_Change>(&r.notifications[0].payload);
        check(change && change->state == Assoc_Change_State::CANT_STR_ASSOC,
              "the handshake is reported as never started, not as a lost association");
    }
}

void test_valid_tags_still_work() {
    std::printf("A nonzero Initiate Tag is untouched:\n");

    auto r = Access::deliver(init(PEER_TAG), false);
    check(r.sent.size() == 1 && !r.sent[0].chunks.empty() && r.sent[0].chunks[0].chunk_header.type == INIT_ACK,
          "INIT is answered with an INIT ACK");

    r = Access::deliver(init_ack(PEER_TAG), true);
    check(r.has_association, "INIT ACK leaves the TCB in place");
    check(r.sent.size() == 1 && !r.sent[0].chunks.empty() && r.sent[0].chunks[0].chunk_header.type == COOKIE_ECHO,
          "and is answered with a COOKIE ECHO");
}

void test_user_initiated_abort() {
    std::printf("sctp_abort on an established association:\n");

    std::vector<uint8_t> reason = {'b', 'y', 'e'};
    auto r = Access::abort_local(ESTABLISHED, reason);
    check(!r.has_association, "TCB destroyed");
    check(r.sent.size() == 1 && is_abort(r.sent[0]), "the queued DATA is gone and only the ABORT is sent");
    if (r.sent.size() != 1 || !is_abort(r.sent[0])) return;

    const SCTP_Packet& abort = r.sent[0];
    check((abort.chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT) == 0, "T bit clear: the tag is the peer's, not a reflection");
    check(abort.header.verification_tag == PEER_TAG, "addressed with the peer's tag");
    check(abort.header.src_port == LOCAL_PORT && abort.header.des_port == PEER_PORT,
          "ports come from the association, not from an inbound packet");

    const auto& causes = std::get<error_chunk_value>(abort.chunks[0].chunk_value).causes;
    check(causes.size() == 1 && causes[0].code == CAUSE_USER_INITIATED_ABORT && causes[0].info == reason,
          "one User-Initiated Abort cause carrying the upper layer's reason");

    check(r.notifications.empty(), "the caller is not notified of an abort it asked for");
}

void test_abort_before_a_peer_tag_exists() {
    std::printf("sctp_abort in COOKIE_WAIT:\n");

    auto r = Access::abort_local(COOKIE_WAIT, {});
    check(!r.has_association, "TCB destroyed");
    check(r.sent.empty(), "nothing sent: no tag the peer would accept it under");
}

const Association_State ESTABLISHED_STATE = ESTABLISHED;
const Association_State COOKIE_ECHOED_STATE = COOKIE_ECHOED;

SCTP_Packet inbound(uint32_t tag, std::vector<SCTP_Chunk> chunks) {
    SCTP_Packet packet;
    packet.header = {PEER_PORT, LOCAL_PORT, tag, 0};
    packet.chunks = std::move(chunks);
    return packet;
}

SCTP_Chunk abort_chunk(bool t_bit, std::vector<error_cause> causes = {}) {
    return {{ABORT, static_cast<uint8_t>(t_bit ? CHUNK_FLAG_T_BIT : 0), 0}, error_chunk_value{std::move(causes)}};
}

bool lost(const Access::Result& r) {
    for (const auto& notification : r.notifications) {
        const auto* change = std::get_if<Assoc_Change>(&notification.payload);
        if (change && change->state == Assoc_Change_State::COMM_LOST) return true;
    }
    return false;
}

void test_receiving_abort() {
    std::printf("Receiving an ABORT (8.5.1 B):\n");

    auto r = Access::deliver_to(&ESTABLISHED_STATE, inbound(OUR_TAG, {abort_chunk(false)}));
    check(!r.has_association, "T clear and our tag: accepted, association gone");
    check(r.sent.empty(), "9.1: nothing is sent in answer to an ABORT");
    check(lost(r), "COMM_LOST reported");

    r = Access::deliver_to(&ESTABLISHED_STATE, inbound(PEER_TAG, {abort_chunk(true)}));
    check(!r.has_association, "T set and the peer's tag: accepted");

    r = Access::deliver_to(&ESTABLISHED_STATE, inbound(OUR_TAG, {abort_chunk(true)}));
    check(r.has_association, "T set but our own tag: discarded");

    r = Access::deliver_to(&ESTABLISHED_STATE, inbound(PEER_TAG, {abort_chunk(false)}));
    check(r.has_association, "T clear but the peer's tag: discarded");

    r = Access::deliver_to(&ESTABLISHED_STATE, inbound(0x99999999, {abort_chunk(false)}));
    check(r.has_association, "an unrelated tag: discarded");

    r = Access::deliver_to(nullptr, inbound(OUR_TAG, {abort_chunk(false)}));
    check(r.sent.empty(), "an ABORT with no TCB is silently discarded, never answered");
}

void test_abort_while_forming() {
    std::printf("Receiving an ABORT in COOKIE_ECHOED:\n");

    auto r = Access::deliver_to(&COOKIE_ECHOED_STATE,
                                inbound(OUR_TAG, {abort_chunk(false, {error_cause{CAUSE_PROTOCOL_VIOLATION, {'n', 'o'}}})}));
    check(!r.has_association, "association gone");
    check(!lost(r), "reported as never started, not as a lost association");

    bool reported = false;
    for (const auto& notification : r.notifications) {
        const auto* error = std::get_if<Remote_Error>(&notification.payload);
        reported = reported || (error && error->causes.size() == 1
                                && error->causes[0].code == CAUSE_PROTOCOL_VIOLATION);
    }
    check(reported, "the peer's causes are passed up as SCTP_REMOTE_ERROR");
}

void test_abort_suppresses_replies() {
    std::printf("An ABORT bundled ahead of chunks that would otherwise reply:\n");

    // 0x40: unrecognized, report it. Alone it draws an ERROR; behind an ABORT it must not.
    SCTP_Chunk unknown{{static_cast<Chunk_Type>(0x40), 0, 0}, unknown_chunk_value{{0xAA, 0xBB, 0xCC}}};
    SCTP_Chunk data{{DATA, 0, 0}, data_chunk_value{1, 0, 0, 0, {'x'}}};

    auto r = Access::deliver_to(&ESTABLISHED_STATE, inbound(OUR_TAG, {unknown, data}));
    check(r.sent.size() == 1, "without the ABORT, the packet draws a reply");

    r = Access::deliver_to(&ESTABLISHED_STATE, inbound(OUR_TAG, {abort_chunk(false), unknown, data}));
    check(!r.has_association, "association gone");
    check(r.sent.empty(), "no ERROR and no SACK once the ABORT is processed");
}

void test_ootb() {
    std::printf("Out of the blue packets (8.4):\n");

    SCTP_Chunk sack{{SACK, 0, 0}, sack_chunk_value{5, RWND, 0, 0, {}, {}}};
    auto r = Access::deliver_to(nullptr, inbound(0x77777777, {sack}));
    check(r.sent.size() == 1 && is_abort(r.sent[0]), "a SACK with no TCB draws an ABORT");
    if (r.sent.size() == 1 && is_abort(r.sent[0])) {
        check((r.sent[0].chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT) != 0, "T bit set");
        check(r.sent[0].header.verification_tag == 0x77777777, "the tag is reflected verbatim");
        check(std::get<error_chunk_value>(r.sent[0].chunks[0].chunk_value).causes.empty(), "no cause is required");
    }

    r = Access::deliver_to(nullptr, inbound(OUR_TAG, {{{COOKIE_ACK, 0, 0}, empty_chunk_value{}}}));
    check(r.sent.empty(), "a COOKIE ACK is discarded, not aborted");

    r = Access::deliver_to(nullptr, inbound(OUR_TAG, {{{SHUTDOWN_COMPLETE, 0, 0}, empty_chunk_value{}}}));
    check(r.sent.empty(), "a SHUTDOWN COMPLETE is discarded");

    SCTP_Chunk stale{{OP_ERROR, 0, 0}, error_chunk_value{{error_cause{CAUSE_STALE_COOKIE, {0, 0, 0, 1}}}}};
    r = Access::deliver_to(nullptr, inbound(OUR_TAG, {stale}));
    check(r.sent.empty(), "a Stale Cookie ERROR is discarded");

    SCTP_Chunk other{{OP_ERROR, 0, 0}, error_chunk_value{{error_cause{CAUSE_PROTOCOL_VIOLATION, {}}}}};
    r = Access::deliver_to(nullptr, inbound(OUR_TAG, {other}));
    check(r.sent.size() == 1 && is_abort(r.sent[0]), "any other ERROR still draws an ABORT");
}

void test_no_user_data() {
    std::printf("DATA with no user data (3.3.1):\n");

    SCTP_Chunk empty{{DATA, 0, 0}, data_chunk_value{7, 0, 0, 0, {}}};
    auto r = Access::deliver_to(&ESTABLISHED_STATE, inbound(OUR_TAG, {empty}));
    check(!r.has_association, "association gone");
    check(r.sent.size() == 1 && is_abort(r.sent[0]), "one ABORT sent, and no SACK");
    if (r.sent.size() != 1 || !is_abort(r.sent[0])) return;

    check((r.sent[0].chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT) == 0, "T bit clear: we held a TCB");
    check(r.sent[0].header.verification_tag == PEER_TAG, "addressed with the peer's tag");

    const auto& causes = std::get<error_chunk_value>(r.sent[0].chunks[0].chunk_value).causes;
    check(causes.size() == 1 && causes[0].code == CAUSE_NO_USER_DATA
              && causes[0].info == std::vector<uint8_t>{0, 0, 0, 7},
          "one No User Data cause carrying the offending TSN");
    check(lost(r), "COMM_LOST reported");
}

void test_zero_streams() {
    std::printf("Zero streams (3.3.2):\n");

    auto r = Access::deliver(init(PEER_TAG, 0), false);
    check(r.sent.size() == 1 && is_abort(r.sent[0]), "INIT advertising zero streams draws an ABORT");
    if (r.sent.size() == 1 && is_abort(r.sent[0])) {
        check((r.sent[0].chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT) == 0,
              "T bit clear: the Initiate Tag came from the chunk, not the header");
        check(r.sent[0].header.verification_tag == PEER_TAG, "addressed with the peer's Initiate Tag");
        const auto& causes = std::get<error_chunk_value>(r.sent[0].chunks[0].chunk_value).causes;
        check(causes.size() == 1 && causes[0].code == CAUSE_INVALID_MANDATORY_PARAM, "Invalid Mandatory Parameter");
    }

    r = Access::deliver(init_ack(PEER_TAG, 0), true);
    check(!r.has_association, "INIT ACK advertising zero streams destroys the TCB");
    check(r.sent.size() == 1 && is_abort(r.sent[0]), "and draws an ABORT");
}

} // namespace

int main() {
    test_init_zero_tag();
    test_init_ack_zero_tag();
    test_valid_tags_still_work();
    test_user_initiated_abort();
    test_abort_before_a_peer_tag_exists();
    test_receiving_abort();
    test_abort_while_forming();
    test_abort_suppresses_replies();
    test_ootb();
    test_no_user_data();
    test_zero_streams();

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
