// What each API call returns when it cannot do what was asked.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "socket_internal.hpp"

#include <cstdio>
#include <string>
#include <vector>

namespace {

constexpr uint16_t STACK_PORT = 39901;
constexpr uint16_t SILENT_PORT = 39902;

sockaddr_in address(const char* ip, uint16_t port) {
    sockaddr_in out{};
    out.sin_family = AF_INET;
    out.sin_port = htons(port);
    sctp_parse_ipv4(ip, out.sin_addr);
    return out;
}

} // namespace

struct SCTP_Socket_Test_Access {
    static Association_Key insert(SCTP_Socket& stack, Association_State state) {
        Association_Key key = peer_key(address("127.0.0.1", 5000), 5000);
        Association assoc = stack.init_new_association(key.address);
        assoc.state = state;
        assoc.peer_ver_tag = 0x01020304;
        stack.associations.insert_or_assign(key, assoc);
        return key;
    }

    static Receive_Queue& receives(SCTP_Socket& stack) {
        return stack.receives;
    }

    static void set_state(SCTP_Socket& stack, const Association_Key& key, Association_State state) {
        stack.associations.at(key).state = state;
    }
};

namespace {

using Access = SCTP_Socket_Test_Access;

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

void expect(Sctp_Status got, Sctp_Status want, const std::string& what) {
    check(got == want, what);
}

void test_associate() {
    std::printf("Associate:\n");
    SCTP_Socket stack;
    Association_Key key;
    expect(stack.sctp_associate("127.0.0.1", 5000, key), Sctp_Status::NOT_RUNNING, "before run");
    if (!stack.sctp_bind("127.0.0.1", STACK_PORT) || !stack.sctp_run()) {
        check(false, "stack started");
        return;
    }
    expect(stack.sctp_associate("256.0.0.1", 5000, key), Sctp_Status::INVALID_ADDRESS, "to a malformed address");
    stack.sctp_close(0);
}

void test_before_established() {
    std::printf("An association still in COOKIE-WAIT:\n");
    sctp_socket_t silent = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in silent_at = address("127.0.0.1", SILENT_PORT);
    if (silent == INVALID_SOCKET || bind(silent, reinterpret_cast<sockaddr*>(&silent_at), sizeof(silent_at)) != 0) {
        check(false, "silent peer socket");
        return;
    }
    SCTP_Socket stack;
    stack.sctp_set_linger(0);
    if (!stack.sctp_bind("127.0.0.1", STACK_PORT) || !stack.sctp_run()) {
        check(false, "stack started");
        sctp_close_socket(silent);
        return;
    }

    Association_Key key;
    expect(stack.sctp_associate("127.0.0.1", SILENT_PORT, key), Sctp_Status::OK, "associate");
    Association_Key again;
    expect(stack.sctp_associate("127.0.0.1", SILENT_PORT, again), Sctp_Status::ASSOCIATION_EXISTS, "associate to the same peer again");
    expect(stack.sctp_associate("127.0.0.1", SILENT_PORT, again, SILENT_PORT + 1), Sctp_Status::ASSOCIATION_EXISTS,
           "even through another UDP port");
    expect(stack.sctp_send_data(key, {1, 2, 3}), Sctp_Status::NOT_ESTABLISHED, "send");
    expect(stack.sctp_request_heartbeat(key, key.address), Sctp_Status::NOT_ESTABLISHED, "request a heartbeat");
    expect(stack.await_established_association(key, 50), Sctp_Status::TIMED_OUT, "await");
    expect(stack.sctp_shutdown(key), Sctp_Status::OK, "shutdown drops the TCB");

    expect(stack.sctp_send_data(key, {1, 2, 3}), Sctp_Status::NO_ASSOCIATION, "send once it is gone");
    expect(stack.sctp_abort(key), Sctp_Status::NO_ASSOCIATION, "abort once it is gone");
    expect(stack.sctp_shutdown(key), Sctp_Status::NO_ASSOCIATION, "shutdown once it is gone");
    expect(stack.sctp_change_heartbeat(key, key.address, false), Sctp_Status::NO_ASSOCIATION, "change heartbeat once it is gone");
    expect(stack.sctp_set_primary(key, key.address), Sctp_Status::NO_ASSOCIATION, "set primary once it is gone");
    stack.sctp_close(0);
    sctp_close_socket(silent);
}

void test_oversized_message() {
    std::printf("A message larger than the send buffer:\n");
    SCTP_Socket stack;
    Association_Key key = Access::insert(stack, ESTABLISHED);
    expect(stack.sctp_send_data(key, std::vector<uint8_t>(2 * SEND_BUFFER)), Sctp_Status::OK, "is taken when nothing is queued");
    expect(stack.sctp_send_data(key, {1}), Sctp_Status::QUEUE_FULL, "and fills it");
}

void test_unread_data_outlives_its_association() {
    std::printf("Unread data from an ended association:\n");
    SCTP_Socket stack;
    Association_Key key = Access::insert(stack, ESTABLISHED);
    Access::receives(stack).push(key, std::vector<uint8_t>(100, 7));
    stack.sctp_abort(key);
    check(Access::receives(stack).buffered_bytes(key) == 0, "no longer counts against the window under its key");
    Access::insert(stack, ESTABLISHED);
    std::vector<uint8_t> buffer(200);
    check(stack.sctp_recv_data_from(key, buffer) == 100, "and is still read, ahead of the new association's");
}

void test_established() {
    std::printf("An ESTABLISHED association:\n");
    SCTP_Socket stack;
    Association_Key key = Access::insert(stack, ESTABLISHED);
    sockaddr_in stranger = address("127.0.0.9", 5000);

    expect(stack.sctp_send_data(key, {}), Sctp_Status::EMPTY_MESSAGE, "send an empty message");
    expect(stack.sctp_send_data(key, {1}, LOCAL_OUT_STREAMS), Sctp_Status::INVALID_STREAM, "send on a stream not negotiated");
    expect(stack.sctp_send_data(key, {1}, LOCAL_OUT_STREAMS - 1), Sctp_Status::OK, "send on the last stream");
    expect(stack.sctp_send_data(key, std::vector<uint8_t>(SEND_BUFFER)), Sctp_Status::QUEUE_FULL,
           "send past the send buffer");
    expect(stack.sctp_send_data(key, std::vector<uint8_t>(SEND_BUFFER - 1)), Sctp_Status::OK, "send up to it");
    expect(stack.sctp_send_data(key, {1}), Sctp_Status::QUEUE_FULL, "send once it is full");
    expect(stack.sctp_change_heartbeat(key, stranger, false), Sctp_Status::UNKNOWN_DESTINATION, "change heartbeat of a stranger");
    expect(stack.sctp_request_heartbeat(key, stranger), Sctp_Status::UNKNOWN_DESTINATION, "request a heartbeat of a stranger");
    expect(stack.sctp_set_primary(key, stranger), Sctp_Status::UNKNOWN_DESTINATION, "make a stranger primary");

    Access::set_state(stack, key, SHUTDOWN_PENDING);
    expect(stack.sctp_send_data(key, {1}), Sctp_Status::SHUTTING_DOWN, "send in SHUTDOWN-PENDING");
    expect(stack.sctp_shutdown(key), Sctp_Status::SHUTTING_DOWN, "shutdown in SHUTDOWN-PENDING");
    Access::set_state(stack, key, SHUTDOWN_SENT);
    expect(stack.sctp_request_heartbeat(key, key.address), Sctp_Status::SHUTTING_DOWN, "request a heartbeat in SHUTDOWN-SENT");
    expect(stack.sctp_abort(key), Sctp_Status::OK, "abort");
}

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    test_associate();
    test_before_established();
    test_established();
    test_oversized_message();
    test_unread_data_outlives_its_association();

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
