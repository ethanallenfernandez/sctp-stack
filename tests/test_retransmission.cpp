// End-to-end T3-rtx tests.
//
// A raw UDP peer completes the SCTP handshake, then controls which DATA chunks
// are acknowledged. This exercises the public SCTP_Socket API, wire codec,
// event loop, SACK processing, and retransmission timer together.

#include <sctp/socket.hpp>
#include "serialize.hpp"
#include "checksum.hpp"

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

constexpr uint16_t STACK_PORT = 19911;
constexpr uint16_t PEER_PORT = 19912;
constexpr uint32_t PEER_TAG = 0xA1B2C3D4;
constexpr uint32_t PEER_TSN = 0x10203040;

int failures = 0;

void check(bool condition, const std::string& description) {
    std::printf("  [%s] %s\n",
                condition ? "PASS" : "FAIL", description.c_str());
    if (!condition) {
        ++failures;
    }
}

struct RawPeer {
    sctp_socket_t socket = INVALID_SOCKET;
    sockaddr_in stack_address{};
    sockaddr_in self{};
    uint32_t stack_tag = 0;

    bool open() {
        socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socket == INVALID_SOCKET) {
            return false;
        }

        self.sin_family = AF_INET;
        self.sin_port = htons(PEER_PORT);
        sctp_parse_ipv4("127.0.0.1", self.sin_addr);
        if (::bind(socket, reinterpret_cast<sockaddr*>(&self), sizeof(self))
                == SOCKET_ERROR) {
            return false;
        }
        if (!sctp_set_nonblocking(socket)) {
            return false;
        }

        stack_address.sin_family = AF_INET;
        stack_address.sin_port = htons(STACK_PORT);
        sctp_parse_ipv4("127.0.0.1", stack_address.sin_addr);
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
        ::sendto(socket, reinterpret_cast<const char*>(wire.data()),
                 wire.size(), 0,
                 reinterpret_cast<const sockaddr*>(&stack_address),
                 sizeof(stack_address));
    }

    bool receive_until(
            Chunk_Type type,
            SCTP_Packet& packet,
            Clock::time_point deadline) {
        while (Clock::now() < deadline) {
            uint8_t buffer[2048];
            sockaddr_in from{};
            socklen_t from_length = sizeof(from);
            int received = ::recvfrom(
                socket, reinterpret_cast<char*>(buffer), sizeof(buffer), 0,
                reinterpret_cast<sockaddr*>(&from), &from_length);
            if (received > 0) {
                try {
                    SCTP_Packet candidate = deserialize_sctp_packet(
                        buffer, static_cast<size_t>(received));
                    if (!candidate.chunks.empty()
                            && candidate.chunks[0].chunk_header.type == type) {
                        packet = std::move(candidate);
                        return true;
                    }
                } catch (const std::exception&) {
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return false;
    }

    bool complete_handshake(SCTP_Socket& stack) {
        SCTP_Packet init;
        if (!receive_until(
                INIT, init, Clock::now() + std::chrono::seconds(1))) {
            return false;
        }

        const auto& init_value =
            std::get<init_chunk_value>(init.chunks[0].chunk_value);
        stack_tag = init_value.initiate_tag;

        SCTP_Packet init_ack;
        init_ack.header.src_port = PEER_PORT;
        init_ack.header.des_port = STACK_PORT;
        init_ack.header.verification_tag = stack_tag;
        init_ack.chunks.push_back(SCTP_Chunk{
            .chunk_header = {
                .type = INIT_ACK,
                .flag = 0,
                .length = 0,
            },
            .chunk_value = init_chunk_value{
                .initiate_tag = PEER_TAG,
                .a_rwnd = RWND,
                .out_streams = 1,
                .in_streams = 1,
                .initial_tsn = PEER_TSN,
                .optional_parameters = {},
            },
        });
        send(init_ack);

        SCTP_Packet cookie_echo;
        if (!receive_until(
                COOKIE_ECHO, cookie_echo,
                Clock::now() + std::chrono::seconds(1))) {
            return false;
        }

        SCTP_Packet cookie_ack;
        cookie_ack.header.src_port = PEER_PORT;
        cookie_ack.header.des_port = STACK_PORT;
        cookie_ack.header.verification_tag = stack_tag;
        cookie_ack.chunks.push_back(SCTP_Chunk{
            .chunk_header = {
                .type = COOKIE_ACK,
                .flag = 0,
                .length = 0,
            },
            .chunk_value = cookie_ack_chunk_value{},
        });
        send(cookie_ack);

        Association_Key key{self};
        return stack.await_established_association(key, 1000) == 0;
    }

    void send_sack(
            uint32_t cumulative_tsn,
            const std::vector<sack_gap_ack_block>& gaps) {
        std::vector<uint8_t> wire(28 + gaps.size() * 4, 0);
        auto put16 = [&](size_t offset, uint16_t value) {
            wire[offset] = static_cast<uint8_t>(value >> 8);
            wire[offset + 1] = static_cast<uint8_t>(value);
        };
        auto put32 = [&](size_t offset, uint32_t value) {
            wire[offset] = static_cast<uint8_t>(value >> 24);
            wire[offset + 1] = static_cast<uint8_t>(value >> 16);
            wire[offset + 2] = static_cast<uint8_t>(value >> 8);
            wire[offset + 3] = static_cast<uint8_t>(value);
        };

        put16(0, PEER_PORT);
        put16(2, STACK_PORT);
        put32(4, stack_tag);
        wire[12] = static_cast<uint8_t>(SACK);
        wire[13] = 0;
        put16(14, static_cast<uint16_t>(16 + gaps.size() * 4));
        put32(16, cumulative_tsn);
        put32(20, RWND);
        put16(24, static_cast<uint16_t>(gaps.size()));
        put16(26, 0);
        size_t offset = 28;
        for (const auto& gap : gaps) {
            put16(offset, gap.start);
            put16(offset + 2, gap.end);
            offset += 4;
        }

        uint32_t checksum =
            calculate_sctp_checksum(wire.data(), wire.size());
        wire[8] = static_cast<uint8_t>(checksum);
        wire[9] = static_cast<uint8_t>(checksum >> 8);
        wire[10] = static_cast<uint8_t>(checksum >> 16);
        wire[11] = static_cast<uint8_t>(checksum >> 24);

        ::sendto(socket, reinterpret_cast<const char*>(wire.data()),
                 wire.size(), 0,
                 reinterpret_cast<const sockaddr*>(&stack_address),
                 sizeof(stack_address));
    }

    void acknowledge(uint32_t cumulative_tsn) {
        send_sack(cumulative_tsn, {});
    }
};

bool setup(SCTP_Socket& stack, RawPeer& peer, Association_Key& key) {
    if (!peer.open()) {
        return false;
    }
    if (!stack.sctp_bind("127.0.0.1", STACK_PORT)
            || !stack.sctp_run()) {
        return false;
    }
    key = stack.sctp_associate("127.0.0.1", PEER_PORT);
    return peer.complete_handshake(stack);
}

void test_t3_retransmits_lost_data() {
    std::printf("T3-rtx retransmits the earliest outstanding DATA:\n");
    SCTP_Socket stack;
    RawPeer peer;
    Association_Key key{};
    if (!setup(stack, peer, key)) {
        check(false, "completed raw-peer handshake");
        peer.close();
        return;
    }

    stack.sctp_send_data(key, {'l', 'o', 's', 't'});
    SCTP_Packet first;
    bool got_first = peer.receive_until(
        DATA, first, Clock::now() + std::chrono::seconds(1));
    check(got_first, "received initial DATA");
    if (!got_first) {
        peer.close();
        return;
    }

    auto first_received = Clock::now();
    SCTP_Packet retry;
    bool got_retry = peer.receive_until(
        DATA, retry, first_received + std::chrono::milliseconds(1600));
    check(got_retry, "received DATA retransmission after RTO.Initial");
    if (got_retry) {
        const auto& first_data =
            std::get<data_chunk_value>(first.chunks[0].chunk_value);
        const auto& retry_data =
            std::get<data_chunk_value>(retry.chunks[0].chunk_value);
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - first_received);
        check(retry_data.tsn == first_data.tsn,
              "retransmission preserves the original TSN");
        check(retry_data.user_data == first_data.user_data,
              "retransmission preserves the original payload");
        check(elapsed >= std::chrono::milliseconds(850),
              "T3-rtx did not fire prematurely");

        auto first_retry_received = Clock::now();
        SCTP_Packet second_retry;
        bool got_second_retry = peer.receive_until(
            DATA, second_retry,
            first_retry_received + std::chrono::milliseconds(2600));
        check(got_second_retry,
              "received another retransmission after backed-off RTO");
        if (got_second_retry) {
            auto backed_off_elapsed =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now() - first_retry_received);
            check(backed_off_elapsed >= std::chrono::milliseconds(1800),
                  "T3 expiration doubled the destination RTO");
        }
        peer.acknowledge(retry_data.tsn);
    }
    peer.close();
}

void test_sack_stops_t3() {
    std::printf("A cumulative SACK stops T3-rtx:\n");
    SCTP_Socket stack;
    RawPeer peer;
    Association_Key key{};
    if (!setup(stack, peer, key)) {
        check(false, "completed raw-peer handshake");
        peer.close();
        return;
    }

    stack.sctp_send_data(key, {'a', 'c', 'k'});
    SCTP_Packet data_packet;
    bool got_data = peer.receive_until(
        DATA, data_packet, Clock::now() + std::chrono::seconds(1));
    check(got_data, "received initial DATA");
    if (!got_data) {
        peer.close();
        return;
    }

    uint32_t tsn =
        std::get<data_chunk_value>(data_packet.chunks[0].chunk_value).tsn;
    peer.acknowledge(tsn);

    SCTP_Packet unexpected;
    bool retransmitted = peer.receive_until(
        DATA, unexpected, Clock::now() + std::chrono::milliseconds(1250));
    check(!retransmitted, "no DATA retransmission after acknowledgement");
    peer.close();
}

void test_new_data_does_not_restart_running_t3() {
    std::printf("Sending more DATA does not restart a running T3-rtx:\n");
    SCTP_Socket stack;
    RawPeer peer;
    Association_Key key{};
    if (!setup(stack, peer, key)) {
        check(false, "completed raw-peer handshake");
        peer.close();
        return;
    }

    stack.sctp_send_data(key, {'o', 'n', 'e'});
    SCTP_Packet first;
    bool got_first = peer.receive_until(
        DATA, first, Clock::now() + std::chrono::seconds(1));
    check(got_first, "received first DATA");
    if (!got_first) {
        peer.close();
        return;
    }

    uint32_t first_tsn =
        std::get<data_chunk_value>(first.chunks[0].chunk_value).tsn;
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    stack.sctp_send_data(key, {'t', 'w', 'o'});
    SCTP_Packet second;
    bool got_second = peer.receive_until(
        DATA, second, Clock::now() + std::chrono::milliseconds(300));
    check(got_second, "received second DATA");

    SCTP_Packet retry;
    bool got_retry = peer.receive_until(
        DATA, retry, Clock::now() + std::chrono::milliseconds(650));
    check(got_retry, "original T3 deadline remained active");
    if (got_retry) {
        const auto& retry_data =
            std::get<data_chunk_value>(retry.chunks[0].chunk_value);
        check(retry_data.tsn == first_tsn,
              "timeout retransmitted the earliest outstanding TSN");
        peer.acknowledge(
            std::get<data_chunk_value>(second.chunks[0].chunk_value).tsn);
    }
    peer.close();
}

void test_sack_restarts_t3_for_remaining_data() {
    std::printf("Acknowledging the earliest TSN restarts T3-rtx:\n");
    SCTP_Socket stack;
    RawPeer peer;
    Association_Key key{};
    if (!setup(stack, peer, key)) {
        check(false, "completed raw-peer handshake");
        peer.close();
        return;
    }

    stack.sctp_send_data(key, {'o', 'n', 'e'});
    stack.sctp_send_data(key, {'t', 'w', 'o'});
    SCTP_Packet first;
    SCTP_Packet second;
    bool got_both =
        peer.receive_until(
            DATA, first, Clock::now() + std::chrono::seconds(1))
        && peer.receive_until(
            DATA, second, Clock::now() + std::chrono::seconds(1));
    check(got_both, "received two initial DATA chunks");
    if (!got_both) {
        peer.close();
        return;
    }

    uint32_t first_tsn =
        std::get<data_chunk_value>(first.chunks[0].chunk_value).tsn;
    uint32_t second_tsn =
        std::get<data_chunk_value>(second.chunks[0].chunk_value).tsn;
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    peer.acknowledge(first_tsn);
    auto acknowledged_at = Clock::now();

    SCTP_Packet premature;
    bool fired_old_deadline = peer.receive_until(
        DATA, premature,
        acknowledged_at + std::chrono::milliseconds(600));
    check(!fired_old_deadline, "old T3 deadline was cancelled");

    SCTP_Packet retry;
    bool got_retry = peer.receive_until(
        DATA, retry,
        acknowledged_at + std::chrono::milliseconds(2300));
    check(got_retry, "remaining DATA retransmitted from restarted T3");
    if (got_retry) {
        const auto& value =
            std::get<data_chunk_value>(retry.chunks[0].chunk_value);
        check(value.tsn == second_tsn,
              "restart retransmits the earliest remaining TSN");
        peer.acknowledge(second_tsn);
    }
    peer.close();
}

void test_gap_ack_reneging_restarts_t3() {
    std::printf("Reneging a Gap Ack restarts a stopped T3-rtx:\n");
    SCTP_Socket stack;
    RawPeer peer;
    Association_Key key{};
    if (!setup(stack, peer, key)) {
        check(false, "completed raw-peer handshake");
        peer.close();
        return;
    }

    stack.sctp_send_data(key, {'o', 'n', 'e'});
    stack.sctp_send_data(key, {'t', 'w', 'o'});
    SCTP_Packet first;
    SCTP_Packet second;
    bool got_both =
        peer.receive_until(
            DATA, first, Clock::now() + std::chrono::seconds(1))
        && peer.receive_until(
            DATA, second, Clock::now() + std::chrono::seconds(1));
    check(got_both, "received two initial DATA chunks");
    if (!got_both) {
        peer.close();
        return;
    }

    uint32_t first_tsn =
        std::get<data_chunk_value>(first.chunks[0].chunk_value).tsn;
    uint32_t second_tsn =
        std::get<data_chunk_value>(second.chunks[0].chunk_value).tsn;
    uint32_t cumulative = first_tsn - 1;
    peer.send_sack(cumulative, {{1, 2}});
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    peer.send_sack(cumulative, {{1, 1}});

    SCTP_Packet retry;
    bool got_retry = peer.receive_until(
        DATA, retry, Clock::now() + std::chrono::milliseconds(1500));
    check(got_retry, "reneged DATA was retransmitted");
    if (got_retry) {
        const auto& value =
            std::get<data_chunk_value>(retry.chunks[0].chunk_value);
        check(value.tsn == second_tsn,
              "only the reneged TSN was retransmitted");
        peer.acknowledge(second_tsn);
    }
    peer.close();
}

} // namespace

int main() {
    test_t3_retransmits_lost_data();
    std::printf("\n");
    test_sack_stops_t3();
    std::printf("\n");
    test_new_data_does_not_restart_running_t3();
    std::printf("\n");
    test_sack_restarts_t3_for_remaining_data();
    std::printf("\n");
    test_gap_ack_reneging_restarts_t3();

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
