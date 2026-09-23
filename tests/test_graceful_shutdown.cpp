// Graceful shutdown end to end (RFC 9260 9.2): two stacks over loopback, real
// event loops, no packet injected by hand.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "serialize.hpp"

#include <chrono>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using Clock = std::chrono::steady_clock;

struct SCTP_Socket_Test_Access {
    static size_t association_count(SCTP_Socket& stack) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        return stack.associations.size();
    }

    // Leaves the UDP socket bound but stops anything answering on it.
    static void silence(SCTP_Socket& stack) {
        stack.running.store(false);
        stack.wake_event_loop();
        stack.event_loop_thread.join();
    }

    // Whatever reached a silenced stack's socket, in arrival order.
    static std::vector<SCTP_Packet> drain_socket(SCTP_Socket& stack) {
        std::vector<SCTP_Packet> packets;
        uint8_t buffer[2048];
        for (;;) {
            int n = recvfrom(stack.udp_socket, reinterpret_cast<char*>(buffer), sizeof(buffer), 0, nullptr, nullptr);
            if (n <= 0) {
                return packets;
            }
            packets.push_back(deserialize_sctp_packet(buffer, static_cast<size_t>(n)));
        }
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
        auto n = stack.sctp_recv_notification(static_cast<int>(std::max<int64_t>(remaining.count(), 1)));
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

bool await_empty(SCTP_Socket& stack, int timeout_ms = 5000) {
    auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    while (Access::association_count(stack) != 0 && Clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return Access::association_count(stack) == 0;
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
    a_to_b = a.sctp_associate("127.0.0.1", b_port);
    b_to_a = a.get_this_association_key();
    return a.await_established_association(a_to_b, 3000) == 0
        && b.await_established_association(b_to_a, 3000) == 0;
}

void test_shutdown_delivers_everything() {
    std::printf("SHUTDOWN with DATA queued in both directions:\n");
    constexpr int MESSAGES = 50;
    SCTP_Socket a, b;
    Association_Key a_to_b{}, b_to_a{};
    if (!pair_up(a, 39711, b, 39712, a_to_b, b_to_a)) {
        check(false, "association established"); return;
    }
    b.sctp_subscribe(Notification_Type::SCTP_SHUTDOWN_EVENT, true);

    for (int i = 0; i < MESSAGES; ++i) {
        b.sctp_send_data(b_to_a, message('b', i));
    }
    for (int i = 0; i < MESSAGES; ++i) {
        a.sctp_send_data(a_to_b, message('a', i));
    }
    a.sctp_shutdown(a_to_b);
    a.sctp_send_data(a_to_b, message('x', 0));

    check(await_notification(b, Notification_Type::SCTP_SHUTDOWN_EVENT, Assoc_Change_State::COMM_UP),
          "the peer is told a shutdown has begun");
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

void test_close_is_graceful() {
    std::printf("sctp_close shuts associations down gracefully:\n");
    SCTP_Socket a, b;
    Association_Key a_to_b{}, b_to_a{};
    if (!pair_up(a, 39713, b, 39714, a_to_b, b_to_a)) {
        check(false, "association established"); return;
    }
    for (int i = 0; i < 10; ++i) {
        a.sctp_send_data(a_to_b, message('a', i));
    }

    auto started = Clock::now();
    a.sctp_close();
    auto took = Clock::now() - started;
    check(took < std::chrono::seconds(2), "close returns once the shutdown completes, well inside the linger");
    check(await_notification(b, Notification_Type::SCTP_ASSOC_CHANGE, Assoc_Change_State::SHUTDOWN_COMP),
          "the peer sees a graceful SHUTDOWN_COMP, not an ABORT");
    check(await_empty(b), "the peer's association is gone");
    check(in_order(read_all(b, b_to_a, 10), 'a', 10), "data sent just before close still arrives");
}

void test_close_aborts_after_linger() {
    std::printf("sctp_close with an unresponsive peer:\n");
    SCTP_Socket a, b;
    Association_Key a_to_b{}, b_to_a{};
    if (!pair_up(a, 39715, b, 39716, a_to_b, b_to_a)) {
        check(false, "association established"); return;
    }
    Access::silence(b);

    auto started = Clock::now();
    a.sctp_close(300);
    auto took = Clock::now() - started;
    check(took >= std::chrono::milliseconds(300) && took < std::chrono::seconds(2), "close waits out the linger and no longer");

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto packets = Access::drain_socket(b);
    bool shutdown_first = !packets.empty() && packets.front().chunks.at(0).chunk_header.type == SHUTDOWN;
    const SCTP_Chunk* last = packets.empty() ? nullptr : &packets.back().chunks.at(0);
    bool aborted = last && last->chunk_header.type == ABORT
        && std::get<error_chunk_value>(last->chunk_value).causes.size() == 1
        && std::get<error_chunk_value>(last->chunk_value).causes[0].code == CAUSE_USER_INITIATED_ABORT;
    check(shutdown_first, "a SHUTDOWN was tried first");
    check(aborted, "then an ABORT with User-Initiated Abort reached the wire before the loop stopped");
}

void test_close_with_zero_linger() {
    std::printf("sctp_close with a linger of 0:\n");
    SCTP_Socket a, b;
    Association_Key a_to_b{}, b_to_a{};
    if (!pair_up(a, 39717, b, 39718, a_to_b, b_to_a)) {
        check(false, "association established"); return;
    }
    a.sctp_set_linger(0);

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
    a.sctp_associate("127.0.0.1", 39720);

    auto started = Clock::now();
    a.sctp_close();
    check(Clock::now() - started < std::chrono::milliseconds(500),
          "a COOKIE-WAIT association is dropped at once rather than waited on");
}

} // namespace

int main() {
    test_shutdown_delivers_everything();
    test_close_is_graceful();
    test_close_aborts_after_linger();
    test_close_with_zero_linger();
    test_close_mid_handshake();

    if (failures) {
        std::printf("\n%d check(s) FAILED\n", failures);
        return 1;
    }
    std::printf("\nAll graceful shutdown tests passed\n");
    return 0;
}
