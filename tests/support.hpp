#ifndef SCTP_TESTS_SUPPORT_HPP
#define SCTP_TESTS_SUPPORT_HPP

// Polling waits for the tests. The library's calls never block.

#include <sctp/socket.hpp>

#include <chrono>
#include <optional>
#include <thread>
#include <vector>

template <typename Predicate>
bool wait_until(Predicate done, int timeout_ms) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (!done()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return true;
}

// An empty message passes every state check before it is refused, so
// EMPTY_MESSAGE means ESTABLISHED, and nothing is sent. NO_ASSOCIATION once a
// TCB that was there has gone; otherwise the last refusal, on timeout.
inline Sctp_Status await_established(SCTP_Socket& socket, const Association_Key& key, int timeout_ms) {
    Sctp_Status status = Sctp_Status::NO_ASSOCIATION;
    bool seen = false;
    wait_until([&] {
        status = socket.sctp_send_data(key, {});
        if (status == Sctp_Status::EMPTY_MESSAGE) {
            status = Sctp_Status::OK;
            return true;
        }
        if (status != Sctp_Status::NO_ASSOCIATION) {
            seen = true;
            return false;
        }
        return seen;
    }, timeout_ms);
    return status;
}

// Retries while the send buffer is full.
inline Sctp_Status send_wait(SCTP_Socket& socket, const Association_Key& key, const std::vector<uint8_t>& data, uint16_t stream, bool unordered, int timeout_ms, uint32_t ppid = 0) {
    Sctp_Status status;
    wait_until([&] {
        status = socket.sctp_send_data(key, data, stream, unordered, ppid);
        return status != Sctp_Status::QUEUE_FULL;
    }, timeout_ms);
    return status;
}

inline size_t recv_wait(SCTP_Socket& socket, std::vector<uint8_t>& buffer, Association_Key* key, bool* partial, uint16_t* stream, int timeout_ms, uint32_t* ppid = nullptr) {
    size_t n = 0;
    wait_until([&] { return (n = socket.sctp_recv_data(buffer, key, partial, stream, ppid)) != 0; }, timeout_ms);
    return n;
}

inline size_t recv_from_wait(SCTP_Socket& socket, const Association_Key& key, std::vector<uint8_t>& buffer, bool* partial, uint16_t* stream, int timeout_ms, uint32_t* ppid = nullptr) {
    size_t n = 0;
    wait_until([&] { return (n = socket.sctp_recv_data_from(key, buffer, partial, stream, ppid)) != 0; }, timeout_ms);
    return n;
}

inline std::optional<Notification> notification_wait(SCTP_Socket& socket, int timeout_ms) {
    std::optional<Notification> notification;
    wait_until([&] { return (notification = socket.sctp_recv_notification()).has_value(); }, timeout_ms);
    return notification;
}

#endif
