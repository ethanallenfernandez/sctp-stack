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
#include "support.hpp"

namespace {

using Clock = std::chrono::steady_clock;

constexpr uint16_t STACK_PORT = 19911;
constexpr uint16_t PEER_PORT = 19912;
constexpr uint32_t PEER_TAG = 0xA1B2C3D4;
constexpr uint32_t PEER_TSN = 0x10203040;

bool setup(SCTP_Socket& stack, Raw_Peer& peer, Association_Key& key) {
    return peer.open(PEER_PORT, STACK_PORT) && stack.sctp_bind("127.0.0.1", STACK_PORT) && stack.sctp_run()
        && peer.establish_initiator(stack, key);
}

void test_t3_retransmits_lost_data() {
    std::printf("T3-rtx retransmits the earliest outstanding DATA:\n");
    SCTP_Socket stack;
    Raw_Peer peer{PEER_TAG, PEER_TSN};
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
        peer.send_sack(retry_data.tsn, {});
    }
    peer.close();
}

void test_sack_stops_t3() {
    std::printf("A cumulative SACK stops T3-rtx:\n");
    SCTP_Socket stack;
    Raw_Peer peer{PEER_TAG, PEER_TSN};
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
    peer.send_sack(tsn, {});

    SCTP_Packet unexpected;
    bool retransmitted = peer.receive_until(
        DATA, unexpected, Clock::now() + std::chrono::milliseconds(1250));
    check(!retransmitted, "no DATA retransmission after acknowledgement");
    peer.close();
}

void test_new_data_does_not_restart_running_t3() {
    std::printf("Sending more DATA does not restart a running T3-rtx:\n");
    SCTP_Socket stack;
    Raw_Peer peer{PEER_TAG, PEER_TSN};
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
        peer.send_sack(
            std::get<data_chunk_value>(second.chunks[0].chunk_value).tsn, {});
    }
    peer.close();
}

// The two messages may arrive bundled or apart, depending on how quickly the
// event loop picks up the first.
std::vector<uint32_t> receive_data_tsns(Raw_Peer& peer, size_t count) {
    std::vector<uint32_t> tsns;
    SCTP_Packet packet;
    while (tsns.size() < count && peer.receive_until(DATA, packet, Clock::now() + std::chrono::seconds(1))) {
        for (const auto& chunk : packet.chunks) {
            tsns.push_back(std::get<data_chunk_value>(chunk.chunk_value).tsn);
        }
    }
    return tsns;
}

void test_sack_restarts_t3_for_remaining_data() {
    std::printf("Acknowledging the earliest TSN restarts T3-rtx:\n");
    SCTP_Socket stack;
    Raw_Peer peer{PEER_TAG, PEER_TSN};
    Association_Key key{};
    if (!setup(stack, peer, key)) {
        check(false, "completed raw-peer handshake");
        peer.close();
        return;
    }

    stack.sctp_send_data(key, {'o', 'n', 'e'});
    stack.sctp_send_data(key, {'t', 'w', 'o'});
    std::vector<uint32_t> tsns = receive_data_tsns(peer, 2);
    bool got_both = tsns.size() == 2;
    check(got_both, "received two initial DATA chunks");
    if (!got_both) {
        peer.close();
        return;
    }

    uint32_t first_tsn = tsns[0];
    uint32_t second_tsn = tsns[1];
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    peer.send_sack(first_tsn, {});
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
        peer.send_sack(second_tsn, {});
    }
    peer.close();
}

void test_gap_ack_reneging_restarts_t3() {
    std::printf("Reneging a Gap Ack restarts a stopped T3-rtx:\n");
    SCTP_Socket stack;
    Raw_Peer peer{PEER_TAG, PEER_TSN};
    Association_Key key{};
    if (!setup(stack, peer, key)) {
        check(false, "completed raw-peer handshake");
        peer.close();
        return;
    }

    stack.sctp_send_data(key, {'o', 'n', 'e'});
    stack.sctp_send_data(key, {'t', 'w', 'o'});
    std::vector<uint32_t> tsns = receive_data_tsns(peer, 2);
    bool got_both = tsns.size() == 2;
    check(got_both, "received two initial DATA chunks");
    if (!got_both) {
        peer.close();
        return;
    }

    uint32_t first_tsn = tsns[0];
    uint32_t second_tsn = tsns[1];
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
        peer.send_sack(second_tsn, {});
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

    return report();
}
