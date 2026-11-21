// ULP notifications: the Notification_Queue on its own, then the events the
// stack produces for ERROR chunks and association lifecycle changes.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include <sctp/notification_queue.hpp>
#include "serialize.hpp"

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>
#include "support.hpp"

namespace {

constexpr uint32_t OUR_TAG = 0x0A0B0C0D;
constexpr uint32_t PEER_TAG = 0x11223344;
constexpr uint16_t PEER_PORT = 40000;

Association_Key peer_key() {
    sockaddr_in src{};
    src.sin_family = AF_INET;
    src.sin_port = htons(PEER_PORT);
    sctp_parse_ipv4("127.0.0.1", src.sin_addr);
    return Association_Key{src};
}

Notification event(Notification_Type type) {
    if (type == Notification_Type::SCTP_ASSOC_CHANGE) {
        return Notification{type, peer_key(), Assoc_Change{Assoc_Change_State::COMM_UP}};
    }
    return Notification{type, peer_key(), Remote_Error{{error_cause{CAUSE_PROTOCOL_VIOLATION, {}}}}};
}

bool is_assoc_change(const std::optional<Notification>& n, Assoc_Change_State state) {
    return n && n->type == Notification_Type::SCTP_ASSOC_CHANGE
        && std::get<Assoc_Change>(n->payload).state == state;
}

} // namespace

struct SCTP_Socket_Test_Access {
    static void add_association(SCTP_Socket& stack, Association_State state) {
        Association_Key key = peer_key();
        Association assoc = stack.init_new_association(key.address);
        assoc.state = state;
        assoc.this_ver_tag = OUR_TAG;
        assoc.peer_ver_tag = PEER_TAG;
        assoc.primary_path = key.address;
        stack.associations.insert_or_assign(key, assoc);
    }

    static void set_state(SCTP_Socket& stack, Association_State state) {
        stack.associations.at(peer_key()).state = state;
    }

    static bool has_association(SCTP_Socket& stack) {
        return stack.associations.count(peer_key()) != 0;
    }

    static size_t queued_sends(SCTP_Socket& stack) {
        return stack.sends.size();
    }

    static void receive(SCTP_Socket& stack, error_chunk_value error) {
        SCTP_Packet packet;
        packet.header = {PEER_PORT, 9899, OUR_TAG, 0};
        packet.chunks.push_back({{OP_ERROR, 0, 0}, std::move(error)});
        stack.local_address.sin_port = htons(9899);
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.handle_recv_packet(wire.data(), wire.size(), peer_key().address);
    }
};

namespace {

using Access = SCTP_Socket_Test_Access;

void test_queue_order() {
    std::printf("Ordering:\n");
    Notification_Queue queue;

    queue.enqueue(event(Notification_Type::SCTP_ASSOC_CHANGE));
    queue.enqueue(event(Notification_Type::SCTP_REMOTE_ERROR));
    queue.enqueue(event(Notification_Type::SCTP_ASSOC_CHANGE));

    auto a = queue.dequeue();
    auto b = queue.dequeue();
    auto c = queue.dequeue();
    check(a && b && c, "three events dequeued");
    if (a && b && c) {
        check(a->type == Notification_Type::SCTP_ASSOC_CHANGE && b->type == Notification_Type::SCTP_REMOTE_ERROR
                  && c->type == Notification_Type::SCTP_ASSOC_CHANGE,
              "FIFO order");
    }
    check(!queue.dequeue(), "empty queue returns nullopt");
}

void test_remote_error() {
    std::printf("ERROR chunk -> REMOTE_ERROR:\n");

    SCTP_Socket stack;
    Access::add_association(stack, ESTABLISHED);

    error_chunk_value error;
    error.causes.push_back({CAUSE_INVALID_STREAM_ID, {0x00, 0x05, 0x00, 0x00}});
    error.causes.push_back({0x0100, {0xAB}});   // no RFC 9260 meaning; still passed up
    Access::receive(stack, error);

    auto n = stack.sctp_recv_notification();
    check(n && n->type == Notification_Type::SCTP_REMOTE_ERROR, "one REMOTE_ERROR");
    if (n && n->type == Notification_Type::SCTP_REMOTE_ERROR) {
        const auto& causes = std::get<Remote_Error>(n->payload).causes;
        check(n->src == peer_key(), "keyed on the sender");
        check(causes.size() == 2 && causes[0].code == CAUSE_INVALID_STREAM_ID
                  && causes[0].info == std::vector<uint8_t>{0x00, 0x05, 0x00, 0x00}
                  && causes[1].code == 0x0100,
              "all causes, raw, including an unknown code");
    }
    check(!stack.sctp_recv_notification(), "nothing else queued");
    check(Access::has_association(stack), "association untouched");
    check(Access::queued_sends(stack) == 0, "nothing sent back");

    Access::receive(stack, error_chunk_value{});
    check(!stack.sctp_recv_notification(), "ERROR with no causes is not reported");
}

void test_error_while_echoed() {
    std::printf("ERROR in COOKIE_ECHOED:\n");

    SCTP_Socket stack;
    Access::add_association(stack, COOKIE_ECHOED);

    Access::receive(stack, error_chunk_value{{error_cause{CAUSE_PROTOCOL_VIOLATION, {}}}});
    check(Access::has_association(stack), "a non-stale ERROR does not end the handshake");
    auto n = stack.sctp_recv_notification();
    check(n && n->type == Notification_Type::SCTP_REMOTE_ERROR, "it is reported as REMOTE_ERROR");

    bool retried_quietly = true;
    for (int i = 0; i < 2; ++i) {   // MAX_STALE_COOKIE_RETRIES
        Access::receive(stack, error_chunk_value{{error_cause{CAUSE_STALE_COOKIE, {0, 0, 0, 1}}}});
        retried_quietly = retried_quietly && Access::has_association(stack) && !stack.sctp_recv_notification();
        Access::set_state(stack, COOKIE_ECHOED);   // as if the retried handshake reached COOKIE ECHO again
    }
    check(retried_quietly, "Stale Cookie retries the handshake without notifying");
    Access::receive(stack, error_chunk_value{{error_cause{CAUSE_STALE_COOKIE, {0, 0, 0, 1}}}});
    check(!Access::has_association(stack), "once retries run out, Stale Cookie ends the handshake");
    n = stack.sctp_recv_notification();
    check(is_assoc_change(n, Assoc_Change_State::CANT_STR_ASSOC), "reported as CANT_STR_ASSOC");
    check(!stack.sctp_recv_notification(), "and not also as REMOTE_ERROR");
}

void test_handshake_comm_up() {
    std::printf("Handshake -> COMM_UP:\n");

    SCTP_Socket client;
    SCTP_Socket server;
    if (!client.sctp_bind("127.0.0.1", 47101) || !server.sctp_bind("127.0.0.1", 47102)
            || !client.sctp_run() || !server.sctp_run()) {
        check(false, "sockets bound and running");
        return;
    }

    Association_Key key;
    client.sctp_associate("127.0.0.1", 47102, key);
    auto client_event = notification_wait(client, 5000);
    auto server_event = notification_wait(server, 5000);
    check(is_assoc_change(client_event, Assoc_Change_State::COMM_UP), "initiator gets COMM_UP");
    check(client_event && client_event->src == key, "keyed on the association");
    check(is_assoc_change(server_event, Assoc_Change_State::COMM_UP), "responder gets COMM_UP");
    check(!notification_wait(client, 100) && !notification_wait(server, 100), "exactly one each");

    client.sctp_close();
    server.sctp_close();
}

} // namespace

int main() {
    test_queue_order();
    test_remote_error();
    test_error_while_echoed();
    test_handshake_comm_up();

    return report();
}
