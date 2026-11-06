// The calls that wait: receive, await, a send into a full buffer, and the
// linger in sctp_close. Each must return as soon as its condition holds, not on
// a polling interval, and must not outlast what it waits on.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include <sctp/receive_queue.hpp>
#include "socket_internal.hpp"

#include <chrono>
#include <cstdio>
#include <future>
#include <string>
#include <thread>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;
using std::chrono::milliseconds;

constexpr uint16_t A_PORT = 39951;
constexpr uint16_t B_PORT = 39952;
constexpr uint16_t SILENT_PORT = 39953;

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

template <typename F>
auto timed(F f) {
    auto start = Clock::now();
    auto result = f();
    return std::make_pair(result, Clock::now() - start);
}

Association_Key key(uint16_t port) {
    sockaddr_in at{};
    at.sin_family = AF_INET;
    at.sin_port = htons(port);
    sctp_parse_ipv4("127.0.0.1", at.sin_addr);
    return Association_Key{at};
}

void test_receive_queue_waits() {
    std::printf("Receive_Queue reads with a timeout:\n");
    Receive_Queue queue;
    uint8_t buffer[16];

    auto [none, waited] = timed([&] { return queue.read_any(buffer, sizeof buffer, milliseconds(50)); });
    check(!none && waited >= milliseconds(50), "nothing arrives: returns empty after the timeout");

    auto pusher = std::async(std::launch::async, [&] {
        std::this_thread::sleep_for(milliseconds(50));
        queue.push(key(1), {1, 2, 3});
    });
    auto [read, took] = timed([&] { return queue.read_from(key(1), buffer, sizeof buffer, milliseconds(5000)); });
    pusher.wait();
    check(read && read->bytes == 3 && took < milliseconds(1000), "a push wakes the reader");

    auto closer = std::async(std::launch::async, [&] {
        std::this_thread::sleep_for(milliseconds(50));
        queue.close();
    });
    auto [closed, until] = timed([&] { return queue.read_any(buffer, sizeof buffer, milliseconds(5000)); });
    closer.wait();
    check(!closed && until < milliseconds(1000), "close() wakes it too");
}

void test_await_sees_the_tcb_go() {
    std::printf("await on an association that is dropped:\n");
    sctp_socket_t silent = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in silent_at = key(SILENT_PORT).address;
    SCTP_Socket stack;
    stack.sctp_set_linger(0);
    if (silent == INVALID_SOCKET || bind(silent, reinterpret_cast<sockaddr*>(&silent_at), sizeof(silent_at)) != 0
            || !stack.sctp_bind("127.0.0.1", A_PORT) || !stack.sctp_run()) {
        check(false, "started");
        return;
    }
    Association_Key id;
    stack.sctp_associate("127.0.0.1", SILENT_PORT, id);
    auto dropper = std::async(std::launch::async, [&] {
        std::this_thread::sleep_for(milliseconds(50));
        stack.sctp_shutdown(id);
    });
    auto [status, took] = timed([&] { return stack.await_established_association(id, 5000); });
    dropper.wait();
    check(status == Sctp_Status::NO_ASSOCIATION && took < milliseconds(1000),
          "sctp_shutdown of the COOKIE-WAIT TCB ends the wait at once");
    stack.sctp_close(0);
    sctp_close_socket(silent);
}

void test_blocking_calls_between_stacks() {
    std::printf("Between two stacks:\n");
    SCTP_Socket a, b;
    a.sctp_set_linger(0);
    b.sctp_set_linger(0);
    if (!a.sctp_bind("127.0.0.1", A_PORT) || !a.sctp_run() || !b.sctp_bind("127.0.0.1", B_PORT) || !b.sctp_run()) {
        check(false, "started");
        return;
    }
    Association_Key a_to_b;
    a.sctp_associate("127.0.0.1", B_PORT, a_to_b);
    auto [up, took] = timed([&] { return a.await_established_association(a_to_b, 3000); });
    check(up == Sctp_Status::OK && took < milliseconds(1000), "await returns once ESTABLISHED");
    Association_Key b_to_a = key(A_PORT);
    check(b.await_established_association(b_to_a, 3000) == Sctp_Status::OK, "and on the other side");

    std::vector<uint8_t> buffer(SEND_BUFFER);
    auto sender = std::async(std::launch::async, [&] {
        std::this_thread::sleep_for(milliseconds(50));
        return a.sctp_send_data(a_to_b, {'h', 'i'});
    });
    auto [bytes, waited] = timed([&] { return b.sctp_recv_data_from(b_to_a, buffer, nullptr, nullptr, 5000); });
    check(sender.get() == Sctp_Status::OK && bytes == 2 && waited < milliseconds(1000), "a receive waits for the message");

    // B does not read, so its window closes after RWND and the rest stays queued.
    const std::vector<uint8_t> half(SEND_BUFFER / 2);
    check(a.sctp_send_data(a_to_b, std::vector<uint8_t>(SEND_BUFFER)) == Sctp_Status::OK, "the send buffer filled");
    std::this_thread::sleep_for(milliseconds(100));
    check(a.sctp_send_data(a_to_b, half) == Sctp_Status::QUEUE_FULL, "without a timeout, a send is refused");
    auto drainer = std::async(std::launch::async, [&] {
        std::this_thread::sleep_for(milliseconds(50));
        size_t total = 0;
        while (total < SEND_BUFFER + half.size()) {
            size_t n = b.sctp_recv_data_from(b_to_a, buffer, nullptr, nullptr, 2000);
            if (n == 0) break;
            total += n;
        }
        return total;
    });
    auto [room, after] = timed([&] { return a.sctp_send_data(a_to_b, half, 0, false, 5000); });
    check(room == Sctp_Status::OK && after < milliseconds(3000), "with one, it waits until reading frees room");
    check(drainer.get() == SEND_BUFFER + half.size(), "and all of it arrives");

    auto reader = std::async(std::launch::async, [&] {
        std::vector<uint8_t> unread(1);
        return timed([&] { return a.sctp_recv_data(unread, nullptr, nullptr, nullptr, 5000); });
    });
    std::this_thread::sleep_for(milliseconds(50));
    auto started = Clock::now();
    a.sctp_close(5000);
    auto closing = Clock::now() - started;
    auto [nothing, blocked] = reader.get();
    check(closing < milliseconds(1000), "close with a linger returns once the shutdown completes");
    check(nothing == 0 && blocked < milliseconds(1000), "and wakes a blocked receive");
    b.sctp_close(0);
}

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    test_receive_queue_waits();
    test_await_sees_the_tcb_go();
    test_blocking_calls_between_stacks();

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
