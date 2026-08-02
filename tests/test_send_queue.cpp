// End-to-end local-send failure recovery.
//
// Uses the public send API and a real UDP receiver. The test first makes the
// stack's UDP socket invalid, verifies that the queued DATA is retained, then
// installs a working socket and verifies that the same TSN reaches the peer.

#include "serialize.hpp"
#include <sctp/platform.hpp>
#include <sctp/socket.hpp>

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

static int failures = 0;

static void check(bool condition, const std::string& description) {
    std::printf(
        "  [%s] %s\n", condition ? "PASS" : "FAIL",
        description.c_str());
    if (!condition) {
        ++failures;
    }
}

struct SCTP_Socket_Test_Access {
    static Association_Key add_established_association(
            SCTP_Socket& stack, const sockaddr_in& peer,
            uint32_t initial_tsn) {
        Association association{};
        association.state = ESTABLISHED;
        association.peer_ver_tag = 0x10203040;
        association.next_tsn = initial_tsn;
        association.rto = sctp_parameters::RTO_INITIAL;

        Association_Key key{peer};
        {
            std::lock_guard<std::mutex> lock(stack.associations_mutex);
            stack.associations.insert_or_assign(key, association);
        }
        stack.local_address.sin_family = AF_INET;
        stack.local_address.sin_port = htons(19001);
        return key;
    }

    static void invalidate_socket(SCTP_Socket& stack) {
        if (stack.udp_socket != INVALID_SOCKET) {
            sctp_close_socket(stack.udp_socket);
            stack.udp_socket = INVALID_SOCKET;
        }
    }

    static void install_socket(SCTP_Socket& stack, sctp_socket_t socket) {
        stack.udp_socket = socket;
    }

    static void attempt_send(SCTP_Socket& stack) {
        stack.run_sending();
    }

    static size_t pending_packets(SCTP_Socket& stack) {
        std::lock_guard<std::mutex> lock(stack.sending_queue_mutex);
        return stack.control_queue.size()
            + stack.retransmission_queue.size()
            + stack.new_data_queue.size();
    }

    static uint32_t pending_data_tsn(SCTP_Socket& stack) {
        std::lock_guard<std::mutex> lock(stack.sending_queue_mutex);
        const auto& data = std::get<data_chunk_value>(
            stack.new_data_queue.front()
                .packet.chunks.front().chunk_value);
        return data.tsn;
    }

    static void enqueue(
            SCTP_Socket& stack, Deliverable packet,
            Send_Priority priority) {
        stack.enqueue_packet(std::move(packet), priority);
    }

    static std::vector<uint32_t> retransmission_tsns(
            SCTP_Socket& stack) {
        std::lock_guard<std::mutex> lock(stack.sending_queue_mutex);
        std::vector<uint32_t> result;
        if (stack.retransmission_queue.empty()) {
            return result;
        }
        for (const auto& chunk :
             stack.retransmission_queue.front().packet.chunks) {
            if (chunk.chunk_header.type == DATA) {
                result.push_back(
                    std::get<data_chunk_value>(chunk.chunk_value).tsn);
            }
        }
        return result;
    }

    static void remove_acked_retransmissions(
            SCTP_Socket& stack, const Association_Key& key,
            const sack_chunk_value& sack) {
        stack.remove_retransmissions(key, sack);
    }
};

static SCTP_Chunk make_data_chunk(
        uint32_t tsn, std::vector<uint8_t> payload) {
    return SCTP_Chunk{
        .chunk_header = {
            .type = DATA,
            .flag = 0,
            .length = 0,
        },
        .chunk_value = data_chunk_value{
            .tsn = tsn,
            .stream_identifier = 0,
            .stream_seq_num = 0,
            .payload_protocal = 0,
            .user_data = std::move(payload),
        },
    };
}

static SCTP_Packet receive_packet(sctp_socket_t receiver) {
    uint8_t buffer[512]{};
    sockaddr_in source{};
    socklen_t source_length = sizeof(source);
    int received = recvfrom(
        receiver, reinterpret_cast<char*>(buffer), sizeof(buffer), 0,
        reinterpret_cast<sockaddr*>(&source), &source_length);
    if (received <= 0) {
        return {};
    }
    return deserialize_sctp_packet(
        buffer, static_cast<size_t>(received));
}

static void test_failed_send_retains_reserved_tsn() {
    std::printf("Local send failure retains the DATA TSN:\n");

    sctp_socket_t receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    check(receiver != INVALID_SOCKET, "created UDP receiver");
    if (receiver == INVALID_SOCKET) {
        return;
    }
    timeval receive_timeout{};
    receive_timeout.tv_sec = 1;
    setsockopt(
        receiver, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<const char*>(&receive_timeout),
        sizeof(receive_timeout));

    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = 0;
    sctp_parse_ipv4("127.0.0.1", peer.sin_addr);
    check(
        bind(receiver, reinterpret_cast<const sockaddr*>(&peer), sizeof(peer))
            != SOCKET_ERROR,
        "bound UDP receiver");
    socklen_t peer_length = sizeof(peer);
    check(
        getsockname(
            receiver, reinterpret_cast<sockaddr*>(&peer), &peer_length)
            != SOCKET_ERROR,
        "resolved UDP receiver address");

    SCTP_Socket stack;
    constexpr uint32_t INITIAL_TSN = 0xFFFFFFFE;
    Association_Key key = SCTP_Socket_Test_Access::add_established_association(
        stack, peer, INITIAL_TSN);
    stack.sctp_send_data(key, {'r', 'e', 't', 'r', 'y'});
    uint32_t reserved_tsn =
        SCTP_Socket_Test_Access::pending_data_tsn(stack);

    SCTP_Socket_Test_Access::invalidate_socket(stack);
    SCTP_Socket_Test_Access::attempt_send(stack);
    check(
        SCTP_Socket_Test_Access::pending_packets(stack) == 1,
        "failed send leaves DATA in the queue");
    check(
        SCTP_Socket_Test_Access::pending_data_tsn(stack) == reserved_tsn,
        "failed send preserves the reserved TSN");

    sctp_socket_t replacement = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    check(replacement != INVALID_SOCKET, "created replacement UDP socket");
    if (replacement == INVALID_SOCKET) {
        sctp_close_socket(receiver);
        return;
    }
    SCTP_Socket_Test_Access::install_socket(stack, replacement);
    std::this_thread::sleep_for(std::chrono::milliseconds(15));
    SCTP_Socket_Test_Access::attempt_send(stack);

    uint8_t buffer[256]{};
    sockaddr_in source{};
    socklen_t source_length = sizeof(source);
    int received = recvfrom(
        receiver, reinterpret_cast<char*>(buffer), sizeof(buffer), 0,
        reinterpret_cast<sockaddr*>(&source), &source_length);
    check(received > 0, "peer received DATA after local recovery");
    if (received > 0) {
        SCTP_Packet packet = deserialize_sctp_packet(
            buffer, static_cast<size_t>(received));
        const auto& data = std::get<data_chunk_value>(
            packet.chunks.front().chunk_value);
        check(data.tsn == INITIAL_TSN, "recovery transmitted the original TSN");
        check(
            data.user_data == std::vector<uint8_t>({'r', 'e', 't', 'r', 'y'}),
            "recovery transmitted the original payload");
    }
    check(
        SCTP_Socket_Test_Access::pending_packets(stack) == 0,
        "successful send removes DATA from the queue");

    sctp_close_socket(receiver);
}

static void test_send_priority_order() {
    std::printf("Control and retransmission send priority:\n");

    sctp_socket_t receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    check(receiver != INVALID_SOCKET, "created priority-test receiver");
    if (receiver == INVALID_SOCKET) {
        return;
    }
    timeval receive_timeout{};
    receive_timeout.tv_sec = 1;
    setsockopt(
        receiver, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<const char*>(&receive_timeout),
        sizeof(receive_timeout));

    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = 0;
    sctp_parse_ipv4("127.0.0.1", peer.sin_addr);
    bind(
        receiver, reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
    socklen_t peer_length = sizeof(peer);
    getsockname(
        receiver, reinterpret_cast<sockaddr*>(&peer), &peer_length);

    SCTP_Socket stack;
    Association_Key key = SCTP_Socket_Test_Access::add_established_association(
        stack, peer, 200);
    stack.sctp_send_data(key, {'n', 'e', 'w'});

    SCTP_Packet retransmission;
    retransmission.header.src_port = 19001;
    retransmission.header.des_port = ntohs(peer.sin_port);
    retransmission.header.verification_tag = 0x10203040;
    retransmission.chunks.push_back(
        make_data_chunk(199, {'r', 'e', 't', 'r', 'y'}));
    SCTP_Socket_Test_Access::enqueue(
        stack, Deliverable{key, std::move(retransmission)},
        Send_Priority::RETRANSMISSION);

    SCTP_Packet control;
    control.header.src_port = 19001;
    control.header.des_port = ntohs(peer.sin_port);
    control.header.verification_tag = 0x10203040;
    control.chunks.push_back(SCTP_Chunk{
        .chunk_header = {
            .type = COOKIE_ACK,
            .flag = 0,
            .length = 0,
        },
        .chunk_value = cookie_ack_chunk_value{},
    });
    SCTP_Socket_Test_Access::enqueue(
        stack, Deliverable{key, std::move(control)},
        Send_Priority::CONTROL);

    SCTP_Socket_Test_Access::attempt_send(stack);
    SCTP_Socket_Test_Access::attempt_send(stack);
    SCTP_Socket_Test_Access::attempt_send(stack);

    SCTP_Packet first = receive_packet(receiver);
    SCTP_Packet second = receive_packet(receiver);
    SCTP_Packet third = receive_packet(receiver);
    check(
        !first.chunks.empty()
            && first.chunks.front().chunk_header.type == COOKIE_ACK,
        "control traffic was sent first");
    check(
        !second.chunks.empty()
            && second.chunks.front().chunk_header.type == DATA
            && std::get<data_chunk_value>(
                second.chunks.front().chunk_value).tsn == 199,
        "retransmitted DATA was sent second");
    check(
        !third.chunks.empty()
            && third.chunks.front().chunk_header.type == DATA
            && std::get<data_chunk_value>(
                third.chunks.front().chunk_value).tsn == 200,
        "new DATA was sent last");

    sctp_close_socket(receiver);
}

static void test_sack_trims_retransmission_queue() {
    std::printf("SACK cleanup of queued retransmissions:\n");

    SCTP_Socket stack;
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(19002);
    sctp_parse_ipv4("127.0.0.1", peer.sin_addr);
    Association_Key key{peer};

    SCTP_Packet retransmission;
    retransmission.chunks.push_back(make_data_chunk(100, {'a'}));
    retransmission.chunks.push_back(make_data_chunk(101, {'b'}));
    SCTP_Socket_Test_Access::enqueue(
        stack, Deliverable{key, std::move(retransmission)},
        Send_Priority::RETRANSMISSION);

    sack_chunk_value first_sack{};
    first_sack.cumulative_tsn_ack = 100;
    SCTP_Socket_Test_Access::remove_acked_retransmissions(
        stack, key, first_sack);
    check(
        SCTP_Socket_Test_Access::retransmission_tsns(stack)
            == std::vector<uint32_t>({101}),
        "cumulative SACK removed only acknowledged queued DATA");

    sack_chunk_value second_sack{};
    second_sack.cumulative_tsn_ack = 101;
    SCTP_Socket_Test_Access::remove_acked_retransmissions(
        stack, key, second_sack);
    check(
        SCTP_Socket_Test_Access::retransmission_tsns(stack).empty(),
        "fully acknowledged retransmission packet was discarded");
}

int main() {
    test_failed_send_retains_reserved_tsn();
    std::printf("\n");
    test_send_priority_order();
    std::printf("\n");
    test_sack_trims_retransmission_queue();

    std::printf(
        "\n%s (%d failure%s)\n",
        failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
        failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
