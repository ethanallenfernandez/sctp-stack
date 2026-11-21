// Graceful shutdown end to end (RFC 9260 9.2): two stacks over loopback, real
// event loops, no packet injected by hand.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>

#include <chrono>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "support.hpp"

using Clock = std::chrono::steady_clock;

struct SCTP_Socket_Test_Access {
    static size_t association_count(SCTP_Socket& stack) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        return stack.associations.size();
    }
};

namespace {

using Access = SCTP_Socket_Test_Access;

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

bool start(SCTP_Socket& stack, int port) {
    return stack.sctp_bind("127.0.0.1", port) && stack.sctp_run();
}

bool await_notification(SCTP_Socket& stack, Notification_Type type, Assoc_Change_State state, int timeout_ms = 5000) {
    auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    while (Clock::now() < deadline) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
        auto n = notification_wait(stack, static_cast<int>(std::max<int64_t>(remaining.count(), 1)));
        if (!n || n->type != type) {
            continue;
        }
        const auto* change = std::get_if<Assoc_Change>(&n->payload);
        if (type != Notification_Type::SCTP_ASSOC_CHANGE || (change && change->state == state)) {
            return true;
        }
    }
    return false;
}

std::vector<uint8_t> message(char side, int i) {
    std::string text = std::string(1, side) + std::to_string(i);
    return std::vector<uint8_t>(text.begin(), text.end());
}

// Reads until `count` messages have arrived or the deadline passes.
std::vector<std::string> read_all(SCTP_Socket& stack, const Association_Key& from, size_t count, int timeout_ms = 5000) {
    std::vector<std::string> received;
    auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    std::vector<uint8_t> buffer(64);
    while (received.size() < count && Clock::now() < deadline) {
        size_t n = stack.sctp_recv_data_from(from, buffer);
        if (n == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        received.emplace_back(buffer.begin(), buffer.begin() + static_cast<long>(n));
    }
    return received;
}

bool in_order(const std::vector<std::string>& received, char side, size_t count) {
    if (received.size() != count) {
        return false;
    }
    for (size_t i = 0; i < count; ++i) {
        if (received[i] != std::string(1, side) + std::to_string(i)) {
            return false;
        }
    }
    return true;
}

// a and b are started, associated and established; returns a's key for b and b's for a.
bool pair_up(SCTP_Socket& a, int a_port, SCTP_Socket& b, int b_port, Association_Key& a_to_b, Association_Key& b_to_a) {
    if (!start(a, a_port) || !start(b, b_port)) {
        return false;
    }
    a.sctp_associate("127.0.0.1", b_port, a_to_b);
    b_to_a = a.get_this_association_key();
    return await_established(a, a_to_b, 3000) == Sctp_Status::OK
        && await_established(b, b_to_a, 3000) == Sctp_Status::OK;
}

void test_shutdown_delivers_everything() {
    std::printf("SHUTDOWN with DATA queued in both directions:\n");
    constexpr int MESSAGES = 50;
    SCTP_Socket a, b;
    Association_Key a_to_b{}, b_to_a{};
    if (!pair_up(a, 39711, b, 39712, a_to_b, b_to_a)) {
        check(false, "association established"); return;
    }

    for (int i = 0; i < MESSAGES; ++i) {
        b.sctp_send_data(b_to_a, message('b', i));
    }
    for (int i = 0; i < MESSAGES; ++i) {
        a.sctp_send_data(a_to_b, message('a', i));
    }
    a.sctp_shutdown(a_to_b);
    a.sctp_send_data(a_to_b, message('x', 0));

    check(await_notification(a, Notification_Type::SCTP_ASSOC_CHANGE, Assoc_Change_State::SHUTDOWN_COMP),
          "the initiator reports SHUTDOWN_COMP");
    check(await_notification(b, Notification_Type::SCTP_ASSOC_CHANGE, Assoc_Change_State::SHUTDOWN_COMP),
          "the peer reports SHUTDOWN_COMP");
    check(Access::association_count(a) == 0 && Access::association_count(b) == 0, "both associations are gone");

    check(in_order(read_all(b, b_to_a, MESSAGES), 'a', MESSAGES),
          "every message queued before the SHUTDOWN reached the peer, in order");
    check(in_order(read_all(a, a_to_b, MESSAGES), 'b', MESSAGES),
          "every message the peer had queued reached the initiator, in order");
    std::vector<uint8_t> buffer(64);
    check(b.sctp_recv_data_from(b_to_a, buffer) == 0, "a send made after SHUTDOWN was refused");
}

void test_close_aborts() {
    std::printf("sctp_close:\n");
    SCTP_Socket a, b;
    Association_Key a_to_b{}, b_to_a{};
    if (!pair_up(a, 39717, b, 39718, a_to_b, b_to_a)) {
        check(false, "association established"); return;
    }

    auto started = Clock::now();
    a.sctp_close();
    check(Clock::now() - started < std::chrono::milliseconds(500), "close does not wait for a shutdown");
    check(await_notification(b, Notification_Type::SCTP_ASSOC_CHANGE, Assoc_Change_State::COMM_LOST),
          "the peer is aborted, and reports COMM_LOST");
}

void test_close_mid_handshake() {
    std::printf("sctp_close before the association is up:\n");
    SCTP_Socket a;
    if (!start(a, 39719)) {
        check(false, "stack started"); return;
    }
    Association_Key key;
    a.sctp_associate("127.0.0.1", 39720, key);

    auto started = Clock::now();
    a.sctp_close();
    check(Clock::now() - started < std::chrono::milliseconds(500),
          "a COOKIE-WAIT association is dropped at once rather than waited on");
}

} // namespace

int main() {
    test_shutdown_delivers_everything();
    test_close_aborts();
    test_close_mid_handshake();

    if (failures) {
        std::printf("\n%d check(s) FAILED\n", failures);
        return 1;
    }
    std::printf("\nAll graceful shutdown tests passed\n");
    return 0;
}
