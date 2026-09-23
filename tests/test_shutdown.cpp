// Graceful shutdown (RFC 9260 9.2): the step from SHUTDOWN-PENDING or
// SHUTDOWN-RECEIVED to sending SHUTDOWN or SHUTDOWN ACK once everything sent
// has been cumulatively acknowledged.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "serialize.hpp"

#include <algorithm>
#include <cstdio>
#include <string>
#include <tuple>
#include <vector>

namespace {

constexpr uint32_t OUR_TAG = 0x0A0B0C0D;
constexpr uint32_t PEER_TAG = 0x11223344;
constexpr uint16_t PEER_PORT = 40000;
constexpr uint16_t LOCAL_PORT = 9899;
constexpr uint32_t NEXT_TSN = 5000;
constexpr uint32_t LAST_PEER_TSN = 7000;
constexpr uint32_t TIE_TAG_LOCAL = 0x7A7A0001;
constexpr uint32_t TIE_TAG_PEER = 0x7A7A0002;
constexpr uint32_t NEW_LOCAL_TAG = 0x0E0E0E0E;
constexpr uint32_t NEW_PEER_TAG = 0x0F0F0F0F;

sockaddr_in peer_address() {
    sockaddr_in src{};
    src.sin_family = AF_INET;
    src.sin_port = htons(PEER_PORT);
    sctp_parse_ipv4("127.0.0.1", src.sin_addr);
    return src;
}

SCTP_Packet data_packet_at(uint32_t tsn) {
    SCTP_Packet packet;
    packet.chunks.push_back({{DATA, 0, 0}, data_chunk_value{tsn, 0, 0, 0, {'h', 'i'}}});
    return packet;
}

} // namespace

struct SCTP_Socket_Test_Access {
    struct Result {
        Association_State state;
        std::vector<SCTP_Packet> sent;
        bool t2_armed;
        bool heartbeat_armed;
        size_t delivered;
        size_t outstanding;
        bool has_association;
        bool t3_armed;
        bool t5_armed;
        bool any_timer;
        bool gap_ack_kept;
        uint16_t error_count;
        std::chrono::microseconds rto;
        uint32_t peer_tag;
        std::vector<Notification> notifications;
    };

    struct Stack {
        SCTP_Socket socket;
        Association_Key key{peer_address()};

        Stack(Association_State state, uint32_t cumulative_tsn_ack) {
            socket.local_address.sin_family = AF_INET;
            socket.local_address.sin_port = htons(LOCAL_PORT);
            sctp_parse_ipv4("127.0.0.1", socket.local_address.sin_addr);

            Association assoc = socket.init_new_association(key);
            assoc.this_ver_tag = OUR_TAG;
            assoc.peer_ver_tag = PEER_TAG;
            assoc.state = state;
            assoc.next_tsn = NEXT_TSN;
            assoc.cumulative_tsn_ack = cumulative_tsn_ack;
            assoc.last_peer_tsn = LAST_PEER_TSN;
            socket.associations.insert_or_assign(key, assoc);
            socket.schedule_heartbeat(key, assoc.rto);
        }

        void add_outstanding(uint32_t tsn, bool gap_acked) {
            auto now = std::chrono::steady_clock::now();
            data_chunk_value data{tsn, 0, 0, 0, {'h', 'i'}};
            socket.associations.at(key).outstanding_data.emplace(tsn, Outstanding_Data{data, now, now, false, gap_acked, 0, false, false});
        }

        Result collect() {
            Result result{};
            auto it = socket.associations.find(key);
            result.has_association = it != socket.associations.end();
            if (result.has_association) {
                result.state = it->second.state;
                result.outstanding = it->second.outstanding_data.size();
                auto gap = it->second.outstanding_data.find(NEXT_TSN - 1);
                result.gap_ack_kept = gap != it->second.outstanding_data.end() && gap->second.gap_acked;
                result.error_count = it->second.error_count;
                result.rto = it->second.rto;
                result.peer_tag = it->second.peer_ver_tag;
            }
            result.delivered = socket.receives.messages(key);
            auto now = std::chrono::steady_clock::now();
            while (auto pending = socket.sends.peek(now)) {
                result.sent.push_back(pending->deliverable.packet);
                socket.sends.commit(pending->priority);
            }
            result.t2_armed = socket.expirations.is_active(Expiration_Key{key, Expiration_Timer_Type::T2_SHUTDOWN});
            result.t3_armed = socket.expirations.is_active(Expiration_Key{key, Expiration_Timer_Type::T3_RTX});
            result.t5_armed = socket.expirations.is_active(Expiration_Key{key, Expiration_Timer_Type::T5_SHUTDOWN_GUARD});
            result.heartbeat_armed = socket.expirations.is_active(Expiration_Key{key, Expiration_Timer_Type::HEARTBEAT});
            while (auto notification = socket.notifications.dequeue()) {
                result.notifications.push_back(*notification);
            }
            return result;
        }
    };

    static Result advance(Association_State state, uint32_t cumulative_tsn_ack) {
        Stack stack(state, cumulative_tsn_ack);
        stack.socket.do_next_shutdown_step(stack.key);
        return stack.collect();
    }

    static Result advance_at_wrap() {
        Stack stack(SHUTDOWN_PENDING, 0xFFFFFFFF);
        stack.socket.associations.at(stack.key).next_tsn = 0;
        stack.socket.do_next_shutdown_step(stack.key);
        return stack.collect();
    }

    static Result sack(Association_State state, uint32_t cumulative_tsn_ack, uint32_t sacked) {
        Stack stack(state, cumulative_tsn_ack);
        SCTP_Packet packet;
        packet.header = {PEER_PORT, LOCAL_PORT, OUR_TAG, 0};
        packet.chunks.push_back({{SACK, 0, 0}, sack_chunk_value{sacked, RWND, 0, 0, {}, {}}});
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.socket.handle_recv_packet(wire.data(), wire.size(), peer_address());
        return stack.collect();
    }

    // state == nullptr means no TCB at all.
    static Result deliver_tagged(const Association_State* state, SCTP_Packet packet, uint32_t tag, uint16_t error_count = 0) {
        Stack stack(state ? *state : ESTABLISHED, NEXT_TSN - 1);
        if (state) {
            stack.socket.associations.at(stack.key).error_count = error_count;
        } else {
            stack.socket.associations.erase(stack.key);
            stack.socket.expirations.cancel_all(stack.key);
        }
        packet.header = {PEER_PORT, LOCAL_PORT, tag, 0};
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.socket.handle_recv_packet(wire.data(), wire.size(), peer_address());
        return stack.collect();
    }

    static Result deliver(Association_State state, SCTP_Packet packet) {
        return deliver_tagged(&state, std::move(packet), OUR_TAG);
    }

    // A COOKIE ECHO whose cookie this stack really minted, as Table 12 sees it.
    static Result cookie_echo(Association_State state, uint32_t local_tag, uint32_t peer_tag, uint32_t local_tie_tag, uint32_t peer_tie_tag) {
        Stack stack(state, NEXT_TSN - 1);
        Association& assoc = stack.socket.associations.at(stack.key);
        assoc.local_tie_tag = TIE_TAG_LOCAL;
        assoc.peer_tie_tag = TIE_TAG_PEER;

        SCTP_Common_Header init_header{PEER_PORT, LOCAL_PORT, 0, 0};
        init_chunk_value init{peer_tag, RWND, 1, 1, 9000, {}};
        std::vector<uint8_t> cookie = stack.socket.cookie_authorizer.generate(
            init_header, init, peer_address(), local_tag, NEXT_TSN, local_tie_tag, peer_tie_tag);

        SCTP_Packet packet;
        packet.header = {PEER_PORT, LOCAL_PORT, local_tag, 0};
        packet.chunks.push_back({{COOKIE_ECHO, 0, 0}, cookie_echo_chunk_value{cookie}});
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.socket.handle_recv_packet(wire.data(), wire.size(), peer_address());
        return stack.collect();
    }

    // DATA arrives, then the association ends before the application reads it.
    static std::pair<Result, size_t> read_after_teardown(Association_State state, SCTP_Packet ending, uint32_t tag) {
        Stack stack(state, NEXT_TSN - 1);
        std::vector<uint8_t> wire;
        for (SCTP_Packet packet : {data_packet_at(LAST_PEER_TSN + 1), std::move(ending)}) {
            packet.header = {PEER_PORT, LOCAL_PORT, tag, 0};
            wire = serialize_sctp_packet(packet);
            stack.socket.handle_recv_packet(wire.data(), wire.size(), peer_address());
        }
        Result result = stack.collect();
        std::vector<uint8_t> buffer(16);
        size_t read = stack.socket.sctp_recv_data_from(stack.key, buffer);
        Association_Key from{};
        size_t read_any = stack.socket.sctp_recv_data(buffer, &from);
        return {result, read + read_any};
    }

    static Result user_shutdown(Association_State state) {
        Stack stack(state, NEXT_TSN - 1);
        stack.socket.enqueue_packet(Deliverable{stack.key, SCTP_Packet{{}, {{{INIT, 0, 0}, init_chunk_value{}}}}});
        stack.socket.schedule_expiration(Expiration_Key{stack.key, Expiration_Timer_Type::T1_INIT},
            std::chrono::steady_clock::now() + std::chrono::seconds(1), Deliverable{});
        stack.socket.sctp_shutdown(stack.key);
        Result result = stack.collect();
        result.any_timer = stack.socket.expirations.has_any_for(stack.key);
        return result;
    }

    // NEXT_TSN-1 is outstanding, so a SHUTDOWN that does not ack it leaves the
    // association in SHUTDOWN-RECEIVED.
    static Result shutdowns_received(Association_State state, bool subscribed, std::vector<uint32_t> cumulative_tsn_acks) {
        Stack stack(state, NEXT_TSN - 2);
        stack.add_outstanding(NEXT_TSN - 1, false);
        stack.socket.sctp_subscribe(Notification_Type::SCTP_SHUTDOWN_EVENT, subscribed);
        for (uint32_t ack : cumulative_tsn_acks) {
            SCTP_Packet packet;
            packet.header = {PEER_PORT, LOCAL_PORT, OUR_TAG, 0};
            packet.chunks.push_back({{SHUTDOWN, 0, 0}, shutdown_chunk_value{ack}});
            std::vector<uint8_t> wire = serialize_sctp_packet(packet);
            stack.socket.handle_recv_packet(wire.data(), wire.size(), peer_address());
        }
        return stack.collect();
    }

    // Enters SHUTDOWN-SENT, then lets a heartbeat arrive; reports whether T5 was
    // rearmed by it.
    static std::pair<Result, bool> t5_after_activity() {
        Stack stack(SHUTDOWN_PENDING, NEXT_TSN - 1);
        stack.socket.do_next_shutdown_step(stack.key);
        Expiration_Key t5{stack.key, Expiration_Timer_Type::T5_SHUTDOWN_GUARD};
        uint64_t before = stack.socket.expirations.generation_of(t5);
        SCTP_Packet packet;
        packet.header = {PEER_PORT, LOCAL_PORT, OUR_TAG, 0};
        packet.chunks.push_back({{HEARTBEAT, 0, 0}, heartbeat_chunk_value{{1, 2, 3, 4}}});
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.socket.handle_recv_packet(wire.data(), wire.size(), peer_address());
        bool untouched = stack.socket.expirations.generation_of(t5) == before;
        return {stack.collect(), untouched};
    }

    static Result t5_expires(Association_State state) {
        Stack stack(state, NEXT_TSN - 1);
        stack.socket.handle_expiration(Expiration_Fallback{
            Expiration_Key{stack.key, Expiration_Timer_Type::T5_SHUTDOWN_GUARD}, std::chrono::steady_clock::now(), 0, Deliverable{}});
        return stack.collect();
    }

    static Result t2_expires(Association_State state, uint16_t error_count) {
        Stack stack(state, NEXT_TSN - 1);
        Association& assoc = stack.socket.associations.at(stack.key);
        assoc.error_count = error_count;
        assoc.last_peer_tsn = LAST_PEER_TSN + 5;
        stack.socket.expirations.cancel_all(stack.key);
        stack.socket.handle_expiration(Expiration_Fallback{
            Expiration_Key{stack.key, Expiration_Timer_Type::T2_SHUTDOWN}, std::chrono::steady_clock::now(), 0, Deliverable{}});
        return stack.collect();
    }

    // Three TSNs outstanding: NEXT_TSN-3 and NEXT_TSN-2 below the SHUTDOWN's
    // Cumulative TSN Ack, NEXT_TSN-1 gap-acked above it.
    static Result shutdown_with_outstanding(Association_State state, uint32_t shutdown_cumulative_tsn_ack) {
        Stack stack(state, NEXT_TSN - 4);
        stack.add_outstanding(NEXT_TSN - 3, false);
        stack.add_outstanding(NEXT_TSN - 2, false);
        stack.add_outstanding(NEXT_TSN - 1, true);
        SCTP_Packet packet;
        packet.header = {PEER_PORT, LOCAL_PORT, OUR_TAG, 0};
        packet.chunks.push_back({{SHUTDOWN, 0, 0}, shutdown_chunk_value{shutdown_cumulative_tsn_ack}});
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.socket.handle_recv_packet(wire.data(), wire.size(), peer_address());
        return stack.collect();
    }

    static Result data_sent_then_t3(Association_State state) {
        Stack stack(state, NEXT_TSN - 1);
        data_chunk_value data{NEXT_TSN, 0, 0, 0, {'h', 'i'}};
        stack.socket.associations.at(stack.key).next_tsn = NEXT_TSN + 1;
        stack.socket.record_data_sent(stack.key, data, std::chrono::steady_clock::now());
        stack.socket.handle_t3_expiration(stack.key);
        return stack.collect();
    }

    static Result heartbeat_expires(Association_State state) {
        Stack stack(state, NEXT_TSN - 1);
        stack.socket.expirations.cancel(Expiration_Key{stack.key, Expiration_Timer_Type::HEARTBEAT});
        stack.socket.handle_heartbeat_expiration(stack.key);
        return stack.collect();
    }

    static size_t recv_from(Association_State state) {
        Stack stack(state, NEXT_TSN - 1);
        stack.socket.receives.push(stack.key, {'h', 'i'});
        std::vector<uint8_t> buffer(16);
        return stack.socket.sctp_recv_data_from(stack.key, buffer);
    }

    static Result send_data(Association_State state) {
        Stack stack(state, NEXT_TSN - 1);
        stack.socket.sctp_send_data(stack.key, {'h', 'i'});
        Result result = stack.collect();
        result.state = stack.socket.associations.at(stack.key).next_tsn == NEXT_TSN ? state : ESTABLISHED;
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

bool only_chunk(const Access::Result& r, Chunk_Type type) {
    return r.sent.size() == 1 && r.sent[0].chunks.size() == 1
        && r.sent[0].chunks[0].chunk_header.type == type
        && r.sent[0].header.verification_tag == PEER_TAG;
}

void test_pending_all_acked_sends_shutdown() {
    std::printf("SHUTDOWN-PENDING with everything acked:\n");
    auto r = Access::advance(SHUTDOWN_PENDING, NEXT_TSN - 1);
    check(only_chunk(r, SHUTDOWN), "a lone SHUTDOWN goes out under the peer's tag");
    check(!r.sent.empty() && std::get<shutdown_chunk_value>(r.sent[0].chunks[0].chunk_value).cumulative_tsn_ack == LAST_PEER_TSN,
          "Cumulative TSN Ack is the last in-sequence TSN received");
    check(r.state == SHUTDOWN_SENT, "moves to SHUTDOWN-SENT");
    check(r.t2_armed, "T2-shutdown is armed");
    check(!r.heartbeat_armed, "heartbeats stop");
}

void test_pending_unacked_waits() {
    std::printf("SHUTDOWN-PENDING with a TSN not yet acked:\n");
    auto r = Access::advance(SHUTDOWN_PENDING, NEXT_TSN - 2);
    check(r.sent.empty(), "nothing is sent");
    check(r.state == SHUTDOWN_PENDING, "stays in SHUTDOWN-PENDING");
    check(!r.t2_armed, "T2-shutdown is not armed");
    check(r.heartbeat_armed, "heartbeats continue");
}

void test_received_all_acked_sends_shutdown_ack() {
    std::printf("SHUTDOWN-RECEIVED with everything acked:\n");
    auto r = Access::advance(SHUTDOWN_RECEIVED, NEXT_TSN - 1);
    check(only_chunk(r, SHUTDOWN_ACK), "a lone SHUTDOWN ACK goes out under the peer's tag");
    check(r.state == SHUTDOWN_ACK_SENT, "moves to SHUTDOWN-ACK-SENT");
    check(r.t2_armed, "T2-shutdown is armed");
}

void test_other_states_untouched() {
    std::printf("States with no shutdown to advance:\n");
    for (Association_State state : {ESTABLISHED, SHUTDOWN_SENT, SHUTDOWN_ACK_SENT}) {
        auto r = Access::advance(state, NEXT_TSN - 1);
        check(r.sent.empty() && r.state == state && !r.t2_armed, "state " + std::to_string(state) + " is left alone");
    }
}

void test_tsn_wrap() {
    std::printf("next_tsn at 0:\n");
    check(Access::advance_at_wrap().state == SHUTDOWN_SENT, "a cumulative ack of 2^32-1 covers next_tsn 0");
}

void test_sack_completes_pending() {
    std::printf("SACK arriving in SHUTDOWN-PENDING:\n");
    auto r = Access::sack(SHUTDOWN_PENDING, NEXT_TSN - 2, NEXT_TSN - 1);
    check(only_chunk(r, SHUTDOWN), "the SACK that acks the last TSN triggers SHUTDOWN");
    check(r.state == SHUTDOWN_SENT, "moves to SHUTDOWN-SENT");

    r = Access::sack(SHUTDOWN_RECEIVED, NEXT_TSN - 2, NEXT_TSN - 1);
    check(only_chunk(r, SHUTDOWN_ACK), "in SHUTDOWN-RECEIVED it triggers SHUTDOWN ACK");

    r = Access::sack(ESTABLISHED, NEXT_TSN - 2, NEXT_TSN - 1);
    check(r.sent.empty() && r.state == ESTABLISHED, "in ESTABLISHED it triggers nothing");
}

void test_no_user_data_while_shutting_down() {
    std::printf("User sends while shutting down (9.2, 4 notes 5 and 7):\n");
    for (Association_State state : {SHUTDOWN_PENDING, SHUTDOWN_SENT, SHUTDOWN_RECEIVED, SHUTDOWN_ACK_SENT}) {
        auto r = Access::send_data(state);
        check(r.sent.empty() && r.state == state, "state " + std::to_string(state) + " rejects the send and assigns no TSN");
    }
}

SCTP_Packet data_packet(uint32_t tsn) {
    SCTP_Packet packet;
    packet.chunks.push_back({{DATA, 0, 0}, data_chunk_value{tsn, 0, 0, 0, {'h', 'i'}}});
    return packet;
}

SCTP_Packet single(Chunk_Type type, Chunk_Value_Type value, uint8_t flag = 0) {
    SCTP_Packet packet;
    packet.chunks.push_back({{type, flag, 0}, std::move(value)});
    return packet;
}

bool reported(const Access::Result& r, Assoc_Change_State state) {
    return std::any_of(r.notifications.begin(), r.notifications.end(), [&](const Notification& n) {
        return n.type == Notification_Type::SCTP_ASSOC_CHANGE && std::get<Assoc_Change>(n.payload).state == state;
    });
}

SCTP_Packet heartbeat_packet() {
    SCTP_Packet packet;
    packet.chunks.push_back({{HEARTBEAT, 0, 0}, heartbeat_chunk_value{{1, 2, 3, 4}}});
    return packet;
}

std::string name(Association_State state) {
    switch (state) {
        case ESTABLISHED: return "ESTABLISHED";
        case SHUTDOWN_PENDING: return "SHUTDOWN-PENDING";
        case SHUTDOWN_SENT: return "SHUTDOWN-SENT";
        case SHUTDOWN_RECEIVED: return "SHUTDOWN-RECEIVED";
        case SHUTDOWN_ACK_SENT: return "SHUTDOWN-ACK-SENT";
        default: return std::to_string(state);
    }
}

void test_data_transmission_continues() {
    std::printf("Outstanding DATA while shutting down (6, 9.2):\n");
    for (Association_State state : {SHUTDOWN_PENDING, SHUTDOWN_RECEIVED}) {
        auto r = Access::data_sent_then_t3(state);
        check(r.outstanding == 1, name(state) + ": DATA reaching the wire is recorded as outstanding");
        check(r.sent.size() == 1 && r.sent[0].chunks.size() == 1 && r.sent[0].chunks[0].chunk_header.type == DATA,
              name(state) + ": T3-rtx expiry retransmits it");
    }
    for (Association_State state : {SHUTDOWN_SENT, SHUTDOWN_ACK_SENT}) {
        auto r = Access::data_sent_then_t3(state);
        check(r.outstanding == 0 && r.sent.empty(), name(state) + ": no DATA is tracked or retransmitted");
    }
}

void test_data_reception() {
    std::printf("DATA received while shutting down (6):\n");
    auto r = Access::deliver(SHUTDOWN_PENDING, data_packet(LAST_PEER_TSN + 1));
    check(r.delivered == 1, "SHUTDOWN-PENDING delivers it");
    check(r.sent.empty(), "SHUTDOWN-PENDING may delay the SACK");

    r = Access::deliver(SHUTDOWN_SENT, data_packet(LAST_PEER_TSN + 1));
    check(r.delivered == 1, "SHUTDOWN-SENT delivers it");
    check(only_chunk(r, SHUTDOWN), "SHUTDOWN-SENT acknowledges it without delay, with a SHUTDOWN");

    for (Association_State state : {SHUTDOWN_RECEIVED, SHUTDOWN_ACK_SENT}) {
        r = Access::deliver(state, data_packet(LAST_PEER_TSN + 1));
        check(r.delivered == 0 && r.sent.empty(), name(state) + " discards it");
    }
}

void test_receive_buffer_readable() {
    std::printf("Reading received data while shutting down:\n");
    for (Association_State state : {SHUTDOWN_PENDING, SHUTDOWN_SENT, SHUTDOWN_RECEIVED, SHUTDOWN_ACK_SENT}) {
        check(Access::recv_from(state) == 2, name(state) + ": sctp_recv_data_from returns it");
    }
}

void test_heartbeats() {
    std::printf("Heartbeats while shutting down (8.3):\n");
    for (Association_State state : {SHUTDOWN_PENDING, SHUTDOWN_RECEIVED}) {
        auto r = Access::heartbeat_expires(state);
        check(r.sent.size() == 1 && r.sent[0].chunks[0].chunk_header.type == HEARTBEAT && r.heartbeat_armed,
              name(state) + ": an idle path is still probed and the timer rearmed");
    }
    for (Association_State state : {SHUTDOWN_SENT, SHUTDOWN_ACK_SENT}) {
        auto r = Access::heartbeat_expires(state);
        check(r.sent.empty() && !r.heartbeat_armed, name(state) + ": probing has stopped");
    }

    auto r = Access::deliver(SHUTDOWN_PENDING, heartbeat_packet());
    check(r.sent.size() == 1 && r.sent[0].chunks[0].chunk_header.type == HEARTBEAT_ACK, "SHUTDOWN-PENDING answers a HEARTBEAT");
    for (Association_State state : {SHUTDOWN_SENT, SHUTDOWN_ACK_SENT}) {
        r = Access::deliver(state, heartbeat_packet());
        check(r.sent.empty(), name(state) + " no longer answers a HEARTBEAT");
    }
}

void test_receive_shutdown() {
    std::printf("SHUTDOWN received (9.2):\n");
    SCTP_Packet shutdown = single(SHUTDOWN, shutdown_chunk_value{NEXT_TSN - 1});

    for (Association_State state : {ESTABLISHED, SHUTDOWN_PENDING, SHUTDOWN_RECEIVED}) {
        auto r = Access::deliver(state, shutdown);
        check(only_chunk(r, SHUTDOWN_ACK), name(state) + ", nothing outstanding: SHUTDOWN ACK goes out");
        check(r.state == SHUTDOWN_ACK_SENT && r.t2_armed, name(state) + ": moves to SHUTDOWN-ACK-SENT with T2 armed");
    }

    auto r = Access::shutdown_with_outstanding(ESTABLISHED, NEXT_TSN - 2);
    check(r.state == SHUTDOWN_RECEIVED, "with DATA still outstanding it moves to SHUTDOWN-RECEIVED");
    check(r.sent.empty(), "and sends nothing yet");
    check(r.outstanding == 1, "TSNs up to the Cumulative TSN Ack are no longer outstanding");
    check(r.gap_ack_kept, "a gap-acked TSN is not reneged by the missing Gap Ack Block");
    check(!r.t3_armed, "T3-rtx stops: what remains is gap-acked (6.3.2 R2)");

    r = Access::shutdown_with_outstanding(ESTABLISHED, NEXT_TSN - 1);
    check(only_chunk(r, SHUTDOWN_ACK) && r.state == SHUTDOWN_ACK_SENT, "a Cumulative TSN Ack covering everything draws SHUTDOWN ACK");
    check(!r.t3_armed, "T3-rtx stops");

    r = Access::shutdown_with_outstanding(ESTABLISHED, NEXT_TSN - 5);
    check(r.state == SHUTDOWN_RECEIVED && r.outstanding == 3, "a stale Cumulative TSN Ack acks nothing but still moves the state");

    r = Access::deliver(ESTABLISHED, single(SHUTDOWN, shutdown_chunk_value{NEXT_TSN}));
    check(!r.has_association && reported(r, Assoc_Change_State::COMM_LOST), "a Cumulative TSN Ack beyond anything sent aborts (12.3)");
    check(r.sent.size() == 1 && r.sent[0].chunks[0].chunk_header.type == ABORT
          && std::get<error_chunk_value>(r.sent[0].chunks[0].chunk_value).causes.at(0).code == CAUSE_PROTOCOL_VIOLATION,
          "with a Protocol Violation cause");

    r = Access::deliver(SHUTDOWN_SENT, shutdown);
    check(only_chunk(r, SHUTDOWN_ACK), "SHUTDOWN-SENT (simultaneous close): SHUTDOWN ACK goes out");
    check(r.state == SHUTDOWN_ACK_SENT && r.t2_armed, "SHUTDOWN-SENT: moves to SHUTDOWN-ACK-SENT, T2 restarted");

    r = Access::deliver(SHUTDOWN_ACK_SENT, shutdown);
    check(only_chunk(r, SHUTDOWN_ACK) && r.state == SHUTDOWN_ACK_SENT, "SHUTDOWN-ACK-SENT: SHUTDOWN ACK is resent");

    for (Association_State state : {COOKIE_WAIT, COOKIE_ECHOED}) {
        r = Access::deliver(state, shutdown);
        check(r.sent.empty() && r.state == state, name(state) + ": silently discarded");
    }
}

void test_receive_shutdown_ack() {
    std::printf("SHUTDOWN ACK received (9.2, 8.5.1 C):\n");
    for (Association_State state : {SHUTDOWN_SENT, SHUTDOWN_ACK_SENT}) {
        auto r = Access::deliver(state, single(SHUTDOWN_ACK, empty_chunk_value{}));
        check(only_chunk(r, SHUTDOWN_COMPLETE), name(state) + ": SHUTDOWN COMPLETE goes out under the peer's tag");
        check(!r.sent.empty() && (r.sent[0].chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT) == 0, name(state) + ": with the T bit clear");
        check(!r.has_association && !r.t2_armed && !r.heartbeat_armed, name(state) + ": the association and its timers are gone");
        check(reported(r, Assoc_Change_State::SHUTDOWN_COMP), name(state) + ": SHUTDOWN_COMP is reported");
    }
    for (Association_State state : {ESTABLISHED, SHUTDOWN_PENDING, SHUTDOWN_RECEIVED}) {
        auto r = Access::deliver(state, single(SHUTDOWN_ACK, empty_chunk_value{}));
        check(r.sent.empty() && r.has_association && r.state == state, name(state) + ": discarded");
    }
}

void test_receive_shutdown_complete() {
    std::printf("SHUTDOWN COMPLETE received (9.2, 8.5.1 C):\n");
    auto r = Access::deliver(SHUTDOWN_ACK_SENT, single(SHUTDOWN_COMPLETE, empty_chunk_value{}));
    check(!r.has_association && !r.t2_armed, "SHUTDOWN-ACK-SENT: the association and its timers are gone");
    check(r.sent.empty(), "nothing is sent in reply");
    check(reported(r, Assoc_Change_State::SHUTDOWN_COMP), "SHUTDOWN_COMP is reported");

    for (Association_State state : {ESTABLISHED, SHUTDOWN_PENDING, SHUTDOWN_SENT, SHUTDOWN_RECEIVED}) {
        r = Access::deliver(state, single(SHUTDOWN_COMPLETE, empty_chunk_value{}));
        check(r.has_association && r.state == state && r.notifications.empty(), name(state) + ": ignored");
    }
}

const SCTP_Chunk* find_chunk(const SCTP_Packet& packet, Chunk_Type type) {
    for (const auto& chunk : packet.chunks) {
        if (chunk.chunk_header.type == type) {
            return &chunk;
        }
    }
    return nullptr;
}

void test_t2_expiry() {
    std::printf("T2-shutdown expiry (9.2, 6.3.3):\n");
    auto r = Access::t2_expires(SHUTDOWN_SENT, 0);
    check(only_chunk(r, SHUTDOWN), "SHUTDOWN-SENT: SHUTDOWN is resent");
    check(!r.sent.empty() && std::get<shutdown_chunk_value>(r.sent[0].chunks[0].chunk_value).cumulative_tsn_ack == LAST_PEER_TSN + 5,
          "carrying the Cumulative TSN Ack as it stands now");
    check(r.error_count == 1 && r.rto == std::chrono::seconds(2), "the error count rises and the RTO backs off");
    check(r.t2_armed, "T2 is rearmed");

    r = Access::t2_expires(SHUTDOWN_ACK_SENT, 0);
    check(only_chunk(r, SHUTDOWN_ACK) && r.t2_armed, "SHUTDOWN-ACK-SENT: SHUTDOWN ACK is resent and T2 rearmed");

    for (Association_State state : {SHUTDOWN_SENT, SHUTDOWN_ACK_SENT}) {
        r = Access::t2_expires(state, sctp_parameters::ASSOCIATION_MAX_RETRANS);
        check(!r.has_association && r.sent.empty() && reported(r, Assoc_Change_State::COMM_LOST),
              name(state) + ": past Association.Max.Retrans the TCB goes, with COMM_LOST and no ABORT");
    }

    r = Access::t2_expires(ESTABLISHED, 0);
    check(r.sent.empty() && r.error_count == 0, "a stale T2 in ESTABLISHED does nothing");
}

void test_shutdown_sent_activity() {
    std::printf("Packets arriving in SHUTDOWN-SENT (9.2):\n");
    Association_State sent = SHUTDOWN_SENT;
    auto r = Access::deliver_tagged(&sent, heartbeat_packet(), OUR_TAG, 4);
    check(r.error_count == 0 && r.t2_armed, "any packet clears the retransmission count and restarts T2");

    r = Access::deliver_tagged(&sent, heartbeat_packet(), OUR_TAG ^ 1, 4);
    check(r.error_count == 4, "a packet failing the tag check does not");

    r = Access::deliver(SHUTDOWN_SENT, data_packet(LAST_PEER_TSN + 1));
    check(only_chunk(r, SHUTDOWN) && r.t2_armed, "in-sequence DATA: a lone SHUTDOWN, T2 restarted");
    check(!r.sent.empty() && std::get<shutdown_chunk_value>(r.sent[0].chunks[0].chunk_value).cumulative_tsn_ack == LAST_PEER_TSN + 1,
          "its Cumulative TSN Ack covers the new DATA");

    r = Access::deliver(SHUTDOWN_SENT, data_packet(LAST_PEER_TSN + 2));
    const SCTP_Chunk* sack = r.sent.size() == 1 ? find_chunk(r.sent[0], SACK) : nullptr;
    check(sack && find_chunk(r.sent[0], SHUTDOWN), "DATA leaving a gap: SHUTDOWN and SACK in one packet");
    check(sack && std::get<sack_chunk_value>(sack->chunk_value).gap_ack_blocks.size() == 1, "the SACK carries the gap");

    r = Access::deliver(SHUTDOWN_SENT, data_packet(LAST_PEER_TSN));
    sack = r.sent.size() == 1 ? find_chunk(r.sent[0], SACK) : nullptr;
    check(sack && find_chunk(r.sent[0], SHUTDOWN), "duplicate DATA: SHUTDOWN and SACK in one packet");
    check(sack && std::get<sack_chunk_value>(sack->chunk_value).duplicate_tsns == std::vector<uint32_t>{LAST_PEER_TSN},
          "the SACK reports the duplicate");
}

void test_shutdown_complete_tags() {
    std::printf("SHUTDOWN COMPLETE verification tag (8.5.1 C):\n");
    Association_State ack_sent = SHUTDOWN_ACK_SENT;
    auto r = Access::deliver_tagged(&ack_sent, single(SHUTDOWN_COMPLETE, empty_chunk_value{}, CHUNK_FLAG_T_BIT), PEER_TAG);
    check(!r.has_association && reported(r, Assoc_Change_State::SHUTDOWN_COMP), "T bit set with the peer's tag: accepted");

    r = Access::deliver_tagged(&ack_sent, single(SHUTDOWN_COMPLETE, empty_chunk_value{}, CHUNK_FLAG_T_BIT), OUR_TAG);
    check(r.has_association, "T bit set with our tag: discarded");

    r = Access::deliver_tagged(&ack_sent, single(SHUTDOWN_COMPLETE, empty_chunk_value{}), PEER_TAG);
    check(r.has_association, "T bit clear with the peer's tag: discarded");
}

void test_ootb_shutdown_ack() {
    std::printf("SHUTDOWN ACK out of the blue (8.4, 8.5.1 E, 9.2):\n");
    constexpr uint32_t OLD_TAG = 0x55667788;
    auto r = Access::deliver_tagged(nullptr, single(SHUTDOWN_ACK, empty_chunk_value{}), OLD_TAG);
    check(r.sent.size() == 1 && r.sent[0].chunks.size() == 1 && r.sent[0].chunks[0].chunk_header.type == SHUTDOWN_COMPLETE,
          "no TCB: answered with a lone SHUTDOWN COMPLETE");
    check(!r.sent.empty() && r.sent[0].header.verification_tag == OLD_TAG && (r.sent[0].chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT),
          "no TCB: the tag is reflected and the T bit set");

    for (Association_State state : {COOKIE_WAIT, COOKIE_ECHOED}) {
        r = Access::deliver_tagged(&state, single(SHUTDOWN_ACK, empty_chunk_value{}), OLD_TAG);
        check(r.sent.size() == 1 && r.sent[0].header.verification_tag == OLD_TAG
              && r.sent[0].chunks[0].chunk_header.type == SHUTDOWN_COMPLETE
              && (r.sent[0].chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT),
              name(state) + ": answered as out of the blue");
        check(r.has_association && r.state == state, name(state) + ": the handshake carries on");
    }

    SCTP_Packet with_abort = single(SHUTDOWN_ACK, empty_chunk_value{});
    with_abort.chunks.push_back({{ABORT, 0, 0}, error_chunk_value{}});
    r = Access::deliver_tagged(nullptr, with_abort, OLD_TAG);
    check(r.sent.empty(), "an ABORT later in the packet outranks the SHUTDOWN ACK");
}

void test_sack_acking_unsent() {
    std::printf("SACK acknowledging a TSN never sent (12.3):\n");
    auto r = Access::deliver(ESTABLISHED, single(SACK, sack_chunk_value{NEXT_TSN, RWND, 0, 0, {}, {}}));
    check(!r.has_association && reported(r, Assoc_Change_State::COMM_LOST), "a Cumulative TSN Ack past the last TSN sent aborts");
    check(r.sent.size() == 1 && r.sent[0].chunks[0].chunk_header.type == ABORT
          && std::get<error_chunk_value>(r.sent[0].chunks[0].chunk_value).causes.at(0).code == CAUSE_PROTOCOL_VIOLATION,
          "with a Protocol Violation cause");

    r = Access::deliver(ESTABLISHED, single(SACK, sack_chunk_value{NEXT_TSN - 3, RWND, 1, 0, {{2, 3}}, {}}));
    check(!r.has_association, "a Gap Ack Block reaching past the last TSN sent aborts");

    r = Access::deliver(ESTABLISHED, single(SACK, sack_chunk_value{NEXT_TSN - 3, RWND, 1, 0, {{1, 2}}, {}}));
    check(r.has_association, "a Gap Ack Block ending on the last TSN sent is fine");
}

SCTP_Packet init_packet() {
    return single(INIT, init_chunk_value{NEW_PEER_TAG, RWND, 1, 1, 9000, {}});
}

void test_handshake_chunks_while_shutting_down() {
    std::printf("Handshake chunks while shutting down (9.2, 5.2.2, 5.2.4):\n");
    Association_State ack_sent = SHUTDOWN_ACK_SENT;
    auto r = Access::deliver_tagged(&ack_sent, init_packet(), 0);
    check(only_chunk(r, SHUTDOWN_ACK), "INIT in SHUTDOWN-ACK-SENT: discarded, SHUTDOWN ACK resent under the peer's tag");
    check(r.state == SHUTDOWN_ACK_SENT, "INIT in SHUTDOWN-ACK-SENT: state unchanged");

    Association_State sent = SHUTDOWN_SENT;
    r = Access::deliver_tagged(&sent, init_packet(), 0);
    check(r.sent.size() == 1 && r.sent[0].chunks[0].chunk_header.type == INIT_ACK && r.state == SHUTDOWN_SENT,
          "INIT in SHUTDOWN-SENT: answered with an INIT ACK, state unchanged");

    r = Access::cookie_echo(SHUTDOWN_ACK_SENT, NEW_LOCAL_TAG, NEW_PEER_TAG, TIE_TAG_LOCAL, TIE_TAG_PEER);
    const SCTP_Packet* shutdown_ack = nullptr;
    const SCTP_Packet* error = nullptr;
    for (const auto& packet : r.sent) {
        switch (packet.chunks.at(0).chunk_header.type) {
            case SHUTDOWN_ACK: shutdown_ack = &packet; break;
            case OP_ERROR: error = &packet; break;
            default: break;
        }
    }
    check(r.sent.size() == 2 && shutdown_ack && error, "peer restart in SHUTDOWN-ACK-SENT: SHUTDOWN ACK and ERROR, nothing else");
    check(shutdown_ack && shutdown_ack->header.verification_tag == PEER_TAG, "the SHUTDOWN ACK goes under the old peer tag");
    check(error && error->header.verification_tag == NEW_PEER_TAG
          && std::get<error_chunk_value>(error->chunks[0].chunk_value).causes.at(0).code == CAUSE_COOKIE_WHILE_SHUTTING_DOWN,
          "the ERROR carries Cookie Received While Shutting Down under the restarted peer's tag");
    check(r.state == SHUTDOWN_ACK_SENT && r.peer_tag == PEER_TAG && r.notifications.empty(),
          "no new association is set up");

    for (Association_State state : {SHUTDOWN_PENDING, SHUTDOWN_SENT, SHUTDOWN_RECEIVED}) {
        r = Access::cookie_echo(state, OUR_TAG, NEW_PEER_TAG, 0, 0);
        check(r.state == state && r.peer_tag == NEW_PEER_TAG, name(state) + ": collision keeps the shutdown and takes the new peer tag");
        check(r.sent.size() == 1 && r.sent[0].chunks[0].chunk_header.type == COOKIE_ACK && r.sent[0].header.verification_tag == NEW_PEER_TAG,
              name(state) + ": COOKIE ACK under the new peer tag");
    }

    r = Access::cookie_echo(COOKIE_ECHOED, OUR_TAG, NEW_PEER_TAG, 0, 0);
    check(r.state == ESTABLISHED && reported(r, Assoc_Change_State::COMM_UP), "COOKIE-ECHOED: collision still establishes");
}

void test_data_outlives_association() {
    std::printf("Received data outlives the association:\n");
    SCTP_Packet shutdown_ack;
    shutdown_ack.chunks.push_back({{SHUTDOWN_ACK, 0, 0}, empty_chunk_value{}});
    auto [r, read] = Access::read_after_teardown(SHUTDOWN_SENT, shutdown_ack, OUR_TAG);
    check(!r.has_association && reported(r, Assoc_Change_State::SHUTDOWN_COMP), "SHUTDOWN ACK completes the shutdown and removes the association");
    check(read == 2, "the DATA that preceded it can still be read");

    SCTP_Packet abort;
    abort.chunks.push_back({{ABORT, 0, 0}, error_chunk_value{}});
    std::tie(r, read) = Access::read_after_teardown(ESTABLISHED, abort, OUR_TAG);
    check(!r.has_association && read == 2, "so can DATA delivered before an ABORT");
}

void test_user_shutdown() {
    std::printf("SHUTDOWN primitive (9.2, and as Linux before COMMUNICATION UP):\n");
    for (Association_State state : {COOKIE_WAIT, COOKIE_ECHOED}) {
        auto r = Access::user_shutdown(state);
        check(!r.has_association, name(state) + ": the TCB is dropped");
        check(r.sent.empty(), name(state) + ": nothing goes to the peer, and the queued INIT is purged");
        check(!r.any_timer, name(state) + ": no timer survives, T1 included");
        check(r.notifications.empty(), name(state) + ": no notification");
    }

    auto r = Access::user_shutdown(ESTABLISHED);
    check(r.has_association && r.state == SHUTDOWN_SENT, "ESTABLISHED with nothing outstanding goes straight to SHUTDOWN-SENT");

    for (Association_State state : {SHUTDOWN_PENDING, SHUTDOWN_SENT, SHUTDOWN_RECEIVED, SHUTDOWN_ACK_SENT}) {
        r = Access::user_shutdown(state);
        bool only_init = r.sent.size() == 1 && r.sent[0].chunks[0].chunk_header.type == INIT;
        check(r.has_association && r.state == state && only_init, name(state) + ": ignored");
    }
}

size_t shutdown_events(const Access::Result& r) {
    return std::count_if(r.notifications.begin(), r.notifications.end(), [](const Notification& n) {
        return n.type == Notification_Type::SCTP_SHUTDOWN_EVENT && std::holds_alternative<Shutdown_Event>(n.payload);
    });
}

void test_shutdown_event() {
    std::printf("SCTP_SHUTDOWN_EVENT (RFC 6458 6.1.5, as Linux):\n");
    for (Association_State state : {ESTABLISHED, SHUTDOWN_PENDING}) {
        auto r = Access::shutdowns_received(state, true, {NEXT_TSN - 1});
        check(shutdown_events(r) == 1, name(state) + ": the peer's SHUTDOWN is reported");
    }
    auto r = Access::shutdowns_received(ESTABLISHED, false, {NEXT_TSN - 1});
    check(shutdown_events(r) == 0, "off by default");

    r = Access::shutdowns_received(ESTABLISHED, true, {NEXT_TSN - 2, NEXT_TSN - 2});
    check(r.state == SHUTDOWN_RECEIVED && shutdown_events(r) == 1, "a repeated SHUTDOWN is not reported again");

    r = Access::shutdowns_received(SHUTDOWN_SENT, true, {NEXT_TSN - 1});
    check(shutdown_events(r) == 0, "a crossing SHUTDOWN in SHUTDOWN-SENT is not reported");

    r = Access::shutdowns_received(ESTABLISHED, true, {NEXT_TSN});
    check(!r.has_association && shutdown_events(r) == 0, "a SHUTDOWN that aborts the association is not reported");
}

void test_t5_guard() {
    std::printf("T5-shutdown-guard (9.2, as Linux):\n");
    auto r = Access::advance(SHUTDOWN_PENDING, NEXT_TSN - 1);
    check(r.state == SHUTDOWN_SENT && r.t5_armed, "armed on entering SHUTDOWN-SENT");
    r = Access::advance(SHUTDOWN_RECEIVED, NEXT_TSN - 1);
    check(r.state == SHUTDOWN_ACK_SENT && !r.t5_armed, "not armed by the receiver of the SHUTDOWN");

    auto [after, untouched] = Access::t5_after_activity();
    check(after.t5_armed && untouched, "a packet from the peer restarts T2 but not T5");

    for (Association_State state : {SHUTDOWN_SENT, SHUTDOWN_ACK_SENT}) {
        r = Access::t5_expires(state);
        check(r.sent.size() == 1 && r.sent[0].chunks.size() == 1 && r.sent[0].chunks[0].chunk_header.type == ABORT
              && r.sent[0].header.verification_tag == PEER_TAG
              && (r.sent[0].chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT) == 0
              && std::get<error_chunk_value>(r.sent[0].chunks[0].chunk_value).causes.empty(),
              name(state) + ": expiry sends an ABORT under the peer's tag, with no cause");
        check(!r.has_association && !r.t2_armed && reported(r, Assoc_Change_State::COMM_LOST),
              name(state) + ": and the association goes, reported as COMM_LOST");
    }

    r = Access::t5_expires(ESTABLISHED);
    check(r.has_association && r.sent.empty(), "a stale T5 in ESTABLISHED does nothing");
}

} // namespace

int main() {
    test_pending_all_acked_sends_shutdown();
    test_pending_unacked_waits();
    test_received_all_acked_sends_shutdown_ack();
    test_other_states_untouched();
    test_tsn_wrap();
    test_sack_completes_pending();
    test_no_user_data_while_shutting_down();
    test_data_transmission_continues();
    test_data_reception();
    test_receive_buffer_readable();
    test_heartbeats();
    test_receive_shutdown();
    test_receive_shutdown_ack();
    test_receive_shutdown_complete();
    test_t2_expiry();
    test_shutdown_sent_activity();
    test_shutdown_complete_tags();
    test_ootb_shutdown_ack();
    test_sack_acking_unsent();
    test_handshake_chunks_while_shutting_down();
    test_data_outlives_association();
    test_user_shutdown();
    test_shutdown_event();
    test_t5_guard();

    if (failures) {
        std::printf("\n%d check(s) FAILED\n", failures);
        return 1;
    }
    std::printf("\nAll shutdown tests passed\n");
    return 0;
}
