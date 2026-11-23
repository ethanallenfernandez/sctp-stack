#ifndef SCTP_TESTS_SUPPORT_HPP
#define SCTP_TESTS_SUPPORT_HPP

// Checks, polling waits and a hand-driven peer for the tests. The library's
// calls never block.

#include <sctp/socket.hpp>
#include "protocol/serialize.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <optional>
#include <string>
#include <thread>
#include <variant>
#include <vector>

inline int failures = 0;

inline void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    failures += !cond;
}

// main's exit status.
inline int report() {
    std::printf("\n%s (%d failure%s)\n", failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}

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

// The association a peer started, from the COMM UP that announced it. Id 0 on
// timeout. Notifications before it are dropped.
inline Association_Key accepted_association(SCTP_Socket& socket, int timeout_ms) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        std::optional<Notification> n = notification_wait(socket, static_cast<int>(std::max<int64_t>(remaining.count(), 1)));
        if (!n) {
            return {};
        }
        const auto* change = std::get_if<Assoc_Change>(&n->payload);
        if (change && change->state == Assoc_Change_State::COMM_UP) {
            return n->src;
        }
    }
}

// SCTP over UDP by hand, from 127.0.0.1 at open's port to the stack at
// stack_port. Each SCTP port is its UDP port.
struct Raw_Peer {
    uint32_t tag = 0;
    uint32_t initial_tsn = 0;
    sctp_socket_t socket = INVALID_SOCKET;
    sockaddr_in self{};
    sockaddr_in stack_address{};
    uint32_t stack_tag = 0;

    ~Raw_Peer() { close(); }

    static sockaddr_in loopback(uint16_t port) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return address;
    }

    bool open(uint16_t port, uint16_t stack_port) {
        self = loopback(port);
        stack_address = loopback(stack_port);
        socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socket == INVALID_SOCKET || ::bind(socket, reinterpret_cast<sockaddr*>(&self), sizeof(self)) == SOCKET_ERROR
                || !sctp_set_nonblocking(socket)) {
            close();
            return false;
        }
        return true;
    }

    void close() {
        if (socket != INVALID_SOCKET) {
            sctp_close_socket(socket);
            socket = INVALID_SOCKET;
        }
    }

    void send(const SCTP_Packet& packet) {
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        ::sendto(socket, reinterpret_cast<const char*>(wire.data()), wire.size(), 0,
                 reinterpret_cast<const sockaddr*>(&stack_address), sizeof(stack_address));
    }

    // The next packet led by a chunk of type, or by any chunk without one.
    bool receive_until(std::optional<Chunk_Type> type, SCTP_Packet& packet, std::chrono::steady_clock::time_point deadline,
                       std::vector<uint8_t>* raw = nullptr) {
        while (std::chrono::steady_clock::now() < deadline) {
            uint8_t buffer[4096];
            int received = ::recvfrom(socket, reinterpret_cast<char*>(buffer), sizeof(buffer), 0, nullptr, nullptr);
            if (received > 0) {
                try {
                    SCTP_Packet candidate = deserialize_sctp_packet(buffer, static_cast<size_t>(received));
                    if (!type || (!candidate.chunks.empty() && candidate.chunks[0].chunk_header.type == *type)) {
                        packet = std::move(candidate);
                        if (raw != nullptr) {
                            raw->assign(buffer, buffer + received);
                        }
                        return true;
                    }
                } catch (const std::exception&) {
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return false;
    }

    bool recv(SCTP_Packet& packet) {
        return receive_until(std::nullopt, packet, std::chrono::steady_clock::now() + std::chrono::seconds(2));
    }

    SCTP_Packet packet(Chunk_Type type) const {
        SCTP_Packet result;
        result.header = {ntohs(self.sin_port), ntohs(stack_address.sin_port), type == INIT ? 0 : stack_tag, 0};
        return result;
    }

    void send_chunk(Chunk_Type type, Chunk_Value_Type value) {
        SCTP_Packet out = packet(type);
        out.chunks.push_back(SCTP_Chunk{{type, 0, 0}, std::move(value)});
        send(out);
    }

    void send_cookie_ack() {
        send_chunk(COOKIE_ACK, empty_chunk_value{});
    }

    // The stack associates with us, up to its COOKIE ECHO.
    bool begin_initiator_handshake(SCTP_Socket& stack, Association_Key& key, SCTP_Packet& cookie_echo, std::vector<uint8_t>* raw = nullptr) {
        stack.sctp_associate("127.0.0.1", ntohs(self.sin_port), key);
        SCTP_Packet init;
        if (!receive_until(INIT, init, std::chrono::steady_clock::now() + std::chrono::seconds(1))) {
            return false;
        }
        stack_tag = std::get<init_chunk_value>(init.chunks[0].chunk_value).initiate_tag;

        // The stack drops an INIT ACK with no State Cookie. Contents are
        // opaque to the initiator, so filler is enough - and keeping it fixed
        // lets a test assert the echo is byte-identical.
        std::vector<uint8_t> parameters;
        std::vector<uint8_t> filler(STATE_COOKIE_SIZE, 0xA5);
        append_parameter(parameters, PARAM_STATE_COOKIE, filler.data(), filler.size());
        send_chunk(INIT_ACK, init_chunk_value{tag, RWND, 1, 1, initial_tsn, std::move(parameters)});
        return receive_until(COOKIE_ECHO, cookie_echo, std::chrono::steady_clock::now() + std::chrono::seconds(1), raw);
    }

    bool establish_initiator(SCTP_Socket& stack, Association_Key& key) {
        SCTP_Packet cookie_echo;
        if (!begin_initiator_handshake(stack, key, cookie_echo)) {
            return false;
        }
        send_cookie_ack();
        return await_established(stack, key, 1000) == Sctp_Status::OK;
    }

    bool establish_responder(SCTP_Socket& stack, Association_Key& key) {
        send_chunk(INIT, init_chunk_value{tag, RWND, 1, 1, initial_tsn, {}});
        SCTP_Packet init_ack;
        if (!receive_until(INIT_ACK, init_ack, std::chrono::steady_clock::now() + std::chrono::seconds(1))) {
            return false;
        }
        const auto& init_ack_value = std::get<init_chunk_value>(init_ack.chunks[0].chunk_value);
        stack_tag = init_ack_value.initiate_tag;

        // Must come back byte for byte: the stateless responder has nothing
        // else to rebuild the association from.
        std::vector<uint8_t> cookie;
        if (!find_parameter(init_ack_value.optional_parameters, PARAM_STATE_COOKIE, cookie)) {
            return false;
        }
        send_chunk(COOKIE_ECHO, cookie_echo_chunk_value{cookie});
        SCTP_Packet cookie_ack;
        if (!receive_until(COOKIE_ACK, cookie_ack, std::chrono::steady_clock::now() + std::chrono::seconds(1))) {
            return false;
        }
        key = accepted_association(stack, 1000);
        return key != Association_Key{} && await_established(stack, key, 1000) == Sctp_Status::OK;
    }

    // One single-chunk message per TSN, on stream 0 in TSN order.
    void send_data_packet(const std::vector<uint32_t>& tsns, uint8_t flags = 0) {
        SCTP_Packet data = packet(DATA);
        for (uint32_t tsn : tsns) {
            data_chunk_value value{tsn, 0, static_cast<uint16_t>(tsn - initial_tsn), 0, {static_cast<uint8_t>(tsn)}};
            data.chunks.push_back(SCTP_Chunk{{DATA, static_cast<uint8_t>(DATA_FLAG_B | DATA_FLAG_E | flags), 0}, std::move(value)});
        }
        send(data);
    }

    void send_sack(uint32_t cumulative, std::vector<sack_gap_ack_block> gaps) {
        send_chunk(SACK, sack_chunk_value{cumulative, RWND, std::move(gaps), {}});
    }
};

#endif
