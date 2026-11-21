// End-to-end event-loop sleep and wakeup tests.

#include <sctp/socket.hpp>

#include <chrono>
#include <cstdio>
#include <ctime>
#include <string>
#include <thread>

namespace {

using Clock = std::chrono::steady_clock;

int failures = 0;

void check(bool condition, const std::string& description) {
    std::printf(
        "  [%s] %s\n", condition ? "PASS" : "FAIL",
        description.c_str());
    if (!condition) {
        ++failures;
    }
}

void test_idle_loop_sleeps_and_close_wakes_it() {
    std::printf("Idle event loop blocks in poll:\n");

    SCTP_Socket stack;
    if (!stack.sctp_bind("127.0.0.1", 0) || !stack.sctp_run()) {
        check(false, "started an idle socket");
        return;
    }

    std::clock_t cpu_started = std::clock();
    auto wall_started = Clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(350));
    auto wall_elapsed = Clock::now() - wall_started;
    std::clock_t cpu_elapsed = std::clock() - cpu_started;

    double cpu_seconds =
        static_cast<double>(cpu_elapsed) / CLOCKS_PER_SEC;
    double wall_seconds =
        std::chrono::duration<double>(wall_elapsed).count();
    check(
        cpu_seconds < wall_seconds * 0.4,
        "idle loop did not consume a CPU core");

    auto close_started = Clock::now();
    stack.sctp_close();
    auto close_elapsed = std::chrono::duration_cast<
        std::chrono::milliseconds>(Clock::now() - close_started);
    check(
        close_elapsed < std::chrono::milliseconds(250),
        "close promptly woke an indefinitely blocked poll");
}

} // namespace

int main() {
    test_idle_loop_sleeps_and_close_wakes_it();

    std::printf(
        "\n%s (%d failure%s)\n",
        failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
        failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
