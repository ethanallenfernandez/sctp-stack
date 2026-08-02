// End-to-end coverage for the Tier 1 handshake and DATA reliability rules.

#include <sctp/socket.hpp>
#include "serialize.hpp"

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

using Clock = std::chrono::steady_clock;

struct SCTP_Socket_Test_Access {
    static bool has_association(
            SCTP_Socket& stack, const Association_Key& key) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        return stack.associations.find(key) != stack.associations.end();
    }

    static void exhaust_cookie_timer(
            SCTP_Socket& stack, const Association_Key& key,
            const Deliverable& retry) {
        {
            std::lock_guard<std::mutex> lock(stack.associations_mutex);
            stack.associations.at(key).cookie_retransmits =
                sctp_parameters::MAX_INIT_RETRANSMITS;
        }
        stack.enqueue_packet(retry, Send_Priority::RETRANSMISSION);
        stack.handle_expiration(Expiration_Fallback{
            Expiration_Key{key, Expiration_Timer_Type::T1_COOKIE},
            Clock::now(), 0, retry});
    }

    static bool association_work_is_gone(
            SCTP_Socket& stack, const Association_Key& key) {
        {
            std::lock_guard<std::mutex> lock(stack.associations_mutex);
            if (stack.associations.find(key) != stack.associations.end()) {
                return false;
            }
        }
        {
            std::lock_guard<std::mutex> lock(stack.expiration_queue_mutex);
            for (const auto& expiration : stack.active_expirations) {
                if (expiration.first.location == key) {
                    return false;
                }
            }
        }
        std::lock_guard<std::mutex> lock(stack.sending_queue_mutex);
        auto contains = [&](std::queue<Deliverable> queue) {
            while (!queue.empty()) {
                if (queue.front().location == key) {
                    return true;
                }
                queue.pop();
            }
            return false;
        };
        return !contains(stack.control_queue)
            && !contains(stack.retransmission_queue)
            && !contains(stack.new_data_queue);
    }

    static Association association(
            SCTP_Socket& stack, const Association_Key& key) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        return stack.associations.at(key);
    }

    static void set_next_tsn(
            SCTP_Socket& stack, const Association_Key& key, uint32_t tsn) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        Association& association = stack.associations.at(key);
        association.next_tsn = tsn;
        association.cumulative_tsn_ack = tsn - 1;
    }

    static Association_Key add_test_association(
            SCTP_Socket& stack, uint32_t cumulative_tsn_ack) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(29999);
        sctp_parse_ipv4("127.0.0.1", address.sin_addr);
        Association_Key key{address};
        Association association = stack.init_new_association(key);
        association.state = ESTABLISHED;
        association.peer_ver_tag = 0x10203040;
        association.cumulative_tsn_ack = cumulative_tsn_ack;
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        stack.associations.insert_or_assign(key, std::move(association));
        return key;
    }

    static void add_outstanding(
            SCTP_Socket& stack, const Association_Key& key, uint32_t tsn,
            size_t payload_size = 1, bool gap_acked = false,
            uint16_t missing_reports = 0) {
        auto now = Clock::now();
        data_chunk_value data{
            .tsn = tsn,
            .stream_identifier = 0,
            .stream_seq_num = 0,
            .payload_protocal = 0,
            .user_data = std::vector<uint8_t>(payload_size, 0x5a)};
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        stack.associations.at(key).outstanding_data.insert_or_assign(
            tsn, Outstanding_Data{
                data, now, now, false, gap_acked, missing_reports,
                false, false});
    }

    static void process_sack(
            SCTP_Socket& stack, const Association_Key& key,
            uint32_t cumulative,
            std::vector<sack_gap_ack_block> gaps) {
        SCTP_Chunk chunk{
            .chunk_header = {.type = SACK, .flag = 0, .length = 0},
            .chunk_value = sack_chunk_value{
                .cumulative_tsn_ack = cumulative,
                .a_rwnd = RWND,
                .number_of_gap_ack_blocks =
                    static_cast<uint16_t>(gaps.size()),
                .number_of_duplicate_tsns = 0,
                .gap_ack_blocks = std::move(gaps),
                .duplicate_tsns = {}}};
        stack.handle_sack(SCTP_Common_Header{}, chunk, key.address);
    }

    static void enter_fast_recovery(
            SCTP_Socket& stack, const Association_Key& key,
            uint32_t exit_tsn) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        Association& association = stack.associations.at(key);
        association.in_fast_recovery = true;
        association.fast_recovery_exit_tsn = exit_tsn;
    }

    static uint16_t missing_reports(
            SCTP_Socket& stack, const Association_Key& key, uint32_t tsn) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        return stack.associations.at(key).outstanding_data.at(tsn)
            .missing_reports;
    }

    static size_t queued_fast_chunks(SCTP_Socket& stack) {
        std::lock_guard<std::mutex> lock(stack.sending_queue_mutex);
        return stack.retransmission_queue.empty()
            ? 0 : stack.retransmission_queue.front().packet.chunks.size();
    }

    static size_t pending_fast_chunks(
            SCTP_Socket& stack, const Association_Key& key) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        size_t count = 0;
        for (const auto& entry : stack.associations.at(key).outstanding_data) {
            count += entry.second.pending_retransmission ? 1 : 0;
        }
        return count;
    }

    static uint64_t t3_generation(
            SCTP_Socket& stack, const Association_Key& key) {
        std::lock_guard<std::mutex> lock(stack.expiration_queue_mutex);
        auto timer = stack.active_expirations.find(
            Expiration_Key{key, Expiration_Timer_Type::T3_RTX});
        return timer == stack.active_expirations.end() ? 0 : timer->second;
    }
};

namespace {

constexpr uint16_t STACK_PORT = 19921;
constexpr uint16_t PEER_PORT = 19922;
constexpr uint32_t PEER_TAG = 0x10203040;
constexpr uint32_t PEER_TSN = 0x55667788;
constexpr uint8_t DATA_I_BIT = 0x08;

int failures = 0;

void check(bool condition, const std::string& description) {
    std::printf("  [%s] %s\n", condition ? "PASS" : "FAIL",
                description.c_str());
    if (!condition) {
        ++failures;
    }
}

struct RawPeer {
    sctp_socket_t socket = INVALID_SOCKET;
    sockaddr_in self{};
    sockaddr_in stack_address{};
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
                == SOCKET_ERROR || !sctp_set_nonblocking(socket)) {
            close();
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

    bool receive_until(Chunk_Type type, SCTP_Packet& packet,
                       Clock::time_point deadline,
                       std::vector<uint8_t>* raw = nullptr) {
        while (Clock::now() < deadline) {
            uint8_t buffer[4096];
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

    SCTP_Packet packet(Chunk_Type type) const {
        SCTP_Packet result;
        result.header.src_port = PEER_PORT;
        result.header.des_port = STACK_PORT;
        result.header.verification_tag = type == INIT ? 0 : stack_tag;
        return result;
    }

    void send_cookie_ack() {
        SCTP_Packet ack = packet(COOKIE_ACK);
        ack.chunks.push_back(SCTP_Chunk{
            .chunk_header = {.type = COOKIE_ACK, .flag = 0, .length = 0},
            .chunk_value = cookie_ack_chunk_value{}});
        send(ack);
    }

    bool begin_initiator_handshake(
            SCTP_Socket& stack, Association_Key& key,
            SCTP_Packet& cookie_echo, std::vector<uint8_t>* raw = nullptr) {
        key = stack.sctp_associate("127.0.0.1", PEER_PORT);
        SCTP_Packet init;
        if (!receive_until(INIT, init, Clock::now() + std::chrono::seconds(1))) {
            return false;
        }
        stack_tag = std::get<init_chunk_value>(
            init.chunks[0].chunk_value).initiate_tag;
        SCTP_Packet ack = packet(INIT_ACK);
        ack.chunks.push_back(SCTP_Chunk{
            .chunk_header = {.type = INIT_ACK, .flag = 0, .length = 0},
            .chunk_value = init_chunk_value{
                .initiate_tag = PEER_TAG,
                .a_rwnd = RWND,
                .out_streams = 1,
                .in_streams = 1,
                .initial_tsn = PEER_TSN,
                .optional_parameters = {1, 2, 3, 4}}});
        send(ack);
        return receive_until(COOKIE_ECHO, cookie_echo,
                             Clock::now() + std::chrono::seconds(1), raw);
    }

    bool establish_initiator(SCTP_Socket& stack, Association_Key& key) {
        SCTP_Packet cookie_echo;
        if (!begin_initiator_handshake(stack, key, cookie_echo)) {
            return false;
        }
        send_cookie_ack();
        return stack.await_established_association(key, 1000) == 0;
    }

    bool establish_responder(SCTP_Socket& stack, Association_Key& key) {
        SCTP_Packet init = packet(INIT);
        init.header.verification_tag = 0;
        init.chunks.push_back(SCTP_Chunk{
            .chunk_header = {.type = INIT, .flag = 0, .length = 0},
            .chunk_value = init_chunk_value{
                .initiate_tag = PEER_TAG,
                .a_rwnd = RWND,
                .out_streams = 1,
                .in_streams = 1,
                .initial_tsn = PEER_TSN,
                .optional_parameters = {}}});
        send(init);
        SCTP_Packet init_ack;
        if (!receive_until(INIT_ACK, init_ack,
                           Clock::now() + std::chrono::seconds(1))) {
            return false;
        }
        stack_tag = std::get<init_chunk_value>(
            init_ack.chunks[0].chunk_value).initiate_tag;
        SCTP_Packet echo = packet(COOKIE_ECHO);
        echo.chunks.push_back(SCTP_Chunk{
            .chunk_header = {.type = COOKIE_ECHO, .flag = 0, .length = 0},
            .chunk_value = cookie_echo_chunk_value{.cookie_data = {}}});
        send(echo);
        SCTP_Packet cookie_ack;
        if (!receive_until(COOKIE_ACK, cookie_ack,
                           Clock::now() + std::chrono::seconds(1))) {
            return false;
        }
        key = Association_Key{self};
        return stack.await_established_association(key, 1000) == 0;
    }

    void send_data_packet(
            const std::vector<uint32_t>& tsns, uint8_t flags = 0) {
        SCTP_Packet data = packet(DATA);
        for (uint32_t tsn : tsns) {
            data.chunks.push_back(SCTP_Chunk{
                .chunk_header = {.type = DATA, .flag = flags, .length = 0},
                .chunk_value = data_chunk_value{
                    .tsn = tsn,
                    .stream_identifier = 0,
                    .stream_seq_num = 0,
                    .payload_protocal = 0,
                    .user_data = {static_cast<uint8_t>(tsn)}}});
        }
        send(data);
    }

    void send_sack(uint32_t cumulative,
                   std::vector<sack_gap_ack_block> gaps) {
        SCTP_Packet sack = packet(SACK);
        sack.chunks.push_back(SCTP_Chunk{
            .chunk_header = {.type = SACK, .flag = 0, .length = 0},
            .chunk_value = sack_chunk_value{
                .cumulative_tsn_ack = cumulative,
                .a_rwnd = RWND,
                .number_of_gap_ack_blocks =
                    static_cast<uint16_t>(gaps.size()),
                .number_of_duplicate_tsns = 0,
                .gap_ack_blocks = std::move(gaps),
                .duplicate_tsns = {}}});
        send(sack);
    }
};

bool start(SCTP_Socket& stack, RawPeer& peer) {
    return peer.open() && stack.sctp_bind("127.0.0.1", STACK_PORT)
        && stack.sctp_run();
}

void test_t1_cookie() {
    std::printf("T1-cookie retransmission and cancellation:\n");
    SCTP_Socket stack;
    RawPeer peer;
    Association_Key key{};
    check(start(stack, peer), "started raw UDP endpoints");
    SCTP_Packet cookie_echo;
    std::vector<uint8_t> first_wire;
    bool began = peer.begin_initiator_handshake(
        stack, key, cookie_echo, &first_wire);
    check(began, "received initial COOKIE ECHO");
    if (!began) {
        peer.close();
        return;
    }

    SCTP_Packet retry;
    std::vector<uint8_t> retry_wire;
    auto sent_at = Clock::now();
    bool retried = peer.receive_until(
        COOKIE_ECHO, retry, sent_at + std::chrono::milliseconds(1400),
        &retry_wire);
    check(retried, "lost COOKIE ACK caused a retry after RTO.Initial");
    check(retry_wire == first_wire,
          "COOKIE ECHO retransmission is byte-for-byte unchanged");

    peer.send_cookie_ack();
    check(stack.await_established_association(key, 1000) == 0,
          "COOKIE ACK established the association");
    SCTP_Packet unexpected;
    check(!peer.receive_until(COOKIE_ECHO, unexpected,
                              Clock::now() + std::chrono::milliseconds(2200)),
          "COOKIE ACK cancelled the backed-off retry");
    peer.close();
}

void test_t1_cookie_exhaustion() {
    std::printf("T1-cookie exhaustion cleanup:\n");
    SCTP_Socket stack;
    RawPeer peer;
    Association_Key key{};
    check(start(stack, peer), "started raw UDP endpoints");
    SCTP_Packet echo;
    bool began = peer.begin_initiator_handshake(stack, key, echo);
    check(began, "association reached COOKIE_ECHOED");
    if (began) {
        SCTP_Socket_Test_Access::exhaust_cookie_timer(
            stack, key, Deliverable{key, echo});
        check(!SCTP_Socket_Test_Access::has_association(stack, key),
              "eighth retry exhaustion removed the association");
        check(SCTP_Socket_Test_Access::association_work_is_gone(stack, key),
              "exhaustion purged timers and queued packets");
    }
    peer.close();
}

void test_delayed_sack_packet_counting() {
    std::printf("Packet-granular delayed SACK:\n");
    SCTP_Socket stack;
    RawPeer peer;
    Association_Key key{};
    check(start(stack, peer) && peer.establish_responder(stack, key),
          "established raw responder association");

    auto first_sent = Clock::now();
    peer.send_data_packet({PEER_TSN});
    SCTP_Packet sack;
    check(!peer.receive_until(SACK, sack,
                              first_sent + std::chrono::milliseconds(120)),
          "first ordinary packet was not acknowledged immediately");
    check(peer.receive_until(SACK, sack,
                             first_sent + std::chrono::milliseconds(450)),
          "first ordinary packet was acknowledged by the 200 ms timer");

    peer.send_data_packet({PEER_TSN + 1});
    check(!peer.receive_until(SACK, sack,
                              Clock::now() + std::chrono::milliseconds(80)),
          "new delayed-SACK interval started after timer delivery");
    auto second_sent = Clock::now();
    peer.send_data_packet({PEER_TSN + 2});
    check(peer.receive_until(SACK, sack,
                             second_sent + std::chrono::milliseconds(150)),
          "second unacknowledged packet triggered an immediate SACK");

    auto bundled_sent = Clock::now();
    peer.send_data_packet({PEER_TSN + 3, PEER_TSN + 4});
    check(!peer.receive_until(SACK, sack,
                              bundled_sent + std::chrono::milliseconds(120)),
          "two DATA chunks in one packet counted as one packet");
    check(peer.receive_until(SACK, sack,
                             bundled_sent + std::chrono::milliseconds(450)),
          "bundled DATA was eventually acknowledged by the timer");
    peer.close();
}

void test_immediate_sack_conditions() {
    std::printf("Immediate SACK conditions:\n");
    SCTP_Socket stack;
    RawPeer peer;
    Association_Key key{};
    check(start(stack, peer) && peer.establish_responder(stack, key),
          "established raw responder association");
    SCTP_Packet sack;

    peer.send_data_packet({PEER_TSN}, DATA_I_BIT);
    check(peer.receive_until(SACK, sack,
                             Clock::now() + std::chrono::milliseconds(150)),
          "DATA I-bit triggered an immediate SACK");
    peer.send_data_packet({PEER_TSN});
    check(peer.receive_until(SACK, sack,
                             Clock::now() + std::chrono::milliseconds(150)),
          "duplicate-only packet triggered an immediate SACK");
    peer.send_data_packet({PEER_TSN + 2});
    check(peer.receive_until(SACK, sack,
                             Clock::now() + std::chrono::milliseconds(150)),
          "out-of-order packet triggered an immediate SACK");
    peer.send_data_packet({PEER_TSN + 1});
    check(peer.receive_until(SACK, sack,
                             Clock::now() + std::chrono::milliseconds(150)),
          "gap-filling packet triggered an immediate SACK");
    check(!peer.receive_until(SACK, sack,
                              Clock::now() + std::chrono::milliseconds(280)),
          "immediate SACKs left no delayed timer duplicate");
    peer.close();
}

void test_fast_retransmit(uint32_t first_tsn, const std::string& label) {
    std::printf("Fast retransmit %s:\n", label.c_str());
    SCTP_Socket stack;
    RawPeer peer;
    Association_Key key{};
    check(start(stack, peer) && peer.establish_initiator(stack, key),
          "established raw initiator association");
    SCTP_Socket_Test_Access::set_next_tsn(stack, key, first_tsn);

    for (uint8_t value = 0; value < 5; ++value) {
        stack.sctp_send_data(key, {'d', value});
    }
    std::vector<SCTP_Packet> sent;
    for (size_t i = 0; i < 5; ++i) {
        SCTP_Packet packet;
        if (peer.receive_until(DATA, packet,
                               Clock::now() + std::chrono::seconds(1))) {
            sent.push_back(std::move(packet));
        }
    }
    check(sent.size() == 5, "received five original DATA chunks");

    peer.send_sack(first_tsn - 1, {{2, 2}});
    peer.send_sack(first_tsn - 1, {{2, 3}});
    SCTP_Packet retry;
    check(!peer.receive_until(DATA, retry,
                              Clock::now() + std::chrono::milliseconds(120)),
          "two missing reports did not retransmit DATA");

    auto third_report = Clock::now();
    peer.send_sack(first_tsn - 1, {{2, 4}});
    bool retransmitted = peer.receive_until(
        DATA, retry, third_report + std::chrono::milliseconds(300));
    check(retransmitted, "third missing report retransmitted promptly");
    if (retransmitted) {
        const auto& data = std::get<data_chunk_value>(
            retry.chunks[0].chunk_value);
        check(data.tsn == first_tsn, "fast retransmit retained the TSN");
        check(data.user_data == std::vector<uint8_t>({'d', 0}),
              "fast retransmit retained the payload");
    }

    Association during = SCTP_Socket_Test_Access::association(stack, key);
    check(during.in_fast_recovery, "sender entered Fast Recovery");
    check(during.cwnd == during.ssthresh
              && during.ssthresh >= 4 * during.pmdcs,
          "Fast Recovery applied the RFC congestion reduction");
    check(during.fast_recovery_exit_tsn == first_tsn + 4,
          "Fast Recovery recorded the highest outstanding TSN");

    peer.send_sack(first_tsn - 1, {{2, 5}});
    check(!peer.receive_until(DATA, retry,
                              Clock::now() + std::chrono::milliseconds(250)),
          "a DATA chunk was not fast-retransmitted twice");
    peer.send_sack(first_tsn + 4, {});
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    Association after = SCTP_Socket_Test_Access::association(stack, key);
    check(!after.in_fast_recovery,
          "cumulative ACK at the exit TSN ended Fast Recovery");
    peer.close();
}

void test_htna_reneging_and_pmtu() {
    std::printf("HTNA, reneging, PMTU packing, and T3 interaction:\n");

    {
        SCTP_Socket stack;
        Association_Key key =
            SCTP_Socket_Test_Access::add_test_association(stack, 9);
        SCTP_Socket_Test_Access::add_outstanding(stack, key, 10);
        SCTP_Socket_Test_Access::add_outstanding(stack, key, 11);
        SCTP_Socket_Test_Access::add_outstanding(stack, key, 12);
        SCTP_Socket_Test_Access::process_sack(stack, key, 9, {{3, 3}});
        check(SCTP_Socket_Test_Access::missing_reports(stack, key, 10) == 1
                  && SCTP_Socket_Test_Access::missing_reports(stack, key, 11) == 1,
              "HTNA counted only missing TSNs below newly acknowledged TSN 12");
        SCTP_Socket_Test_Access::process_sack(stack, key, 9, {{3, 3}});
        check(SCTP_Socket_Test_Access::missing_reports(stack, key, 10) == 1
                  && SCTP_Socket_Test_Access::missing_reports(stack, key, 11) == 1,
              "repeated Gap Ack without a new acknowledgment did not add reports");
    }

    {
        SCTP_Socket stack;
        Association_Key key =
            SCTP_Socket_Test_Access::add_test_association(stack, 9);
        SCTP_Socket_Test_Access::add_outstanding(stack, key, 10);
        SCTP_Socket_Test_Access::add_outstanding(stack, key, 11, 1, true);
        SCTP_Socket_Test_Access::process_sack(stack, key, 9, {});
        check(SCTP_Socket_Test_Access::missing_reports(stack, key, 11) == 1,
              "reneging contributed exactly one missing report");
        check(SCTP_Socket_Test_Access::t3_generation(stack, key) != 0,
              "reneging started a stopped T3-rtx timer");
    }

    {
        SCTP_Socket stack;
        Association_Key key =
            SCTP_Socket_Test_Access::add_test_association(stack, 9);
        SCTP_Socket_Test_Access::add_outstanding(stack, key, 10);
        SCTP_Socket_Test_Access::add_outstanding(stack, key, 11);
        SCTP_Socket_Test_Access::add_outstanding(stack, key, 12, 1, true);
        SCTP_Socket_Test_Access::enter_fast_recovery(stack, key, 20);
        SCTP_Socket_Test_Access::process_sack(stack, key, 10, {{2, 2}});
        check(SCTP_Socket_Test_Access::missing_reports(stack, key, 11) == 1,
              "cumulative advance in Fast Recovery counted every reported hole");
    }

    {
        SCTP_Socket stack;
        Association_Key key =
            SCTP_Socket_Test_Access::add_test_association(stack, 9);
        SCTP_Socket_Test_Access::add_outstanding(stack, key, 10, 700, false, 2);
        SCTP_Socket_Test_Access::add_outstanding(stack, key, 11, 700, false, 2);
        SCTP_Socket_Test_Access::add_outstanding(stack, key, 12, 700, false, 2);
        SCTP_Socket_Test_Access::add_outstanding(stack, key, 13);
        uint64_t old_t3 = SCTP_Socket_Test_Access::t3_generation(stack, key);
        SCTP_Socket_Test_Access::process_sack(stack, key, 9, {{4, 4}});
        check(SCTP_Socket_Test_Access::queued_fast_chunks(stack) == 1,
              "fast retransmit packed only one 700-byte DATA chunk into PMDCS");
        check(SCTP_Socket_Test_Access::pending_fast_chunks(stack, key) == 2,
              "overflow DATA remained pending in the retransmission scheduler");
        check(SCTP_Socket_Test_Access::t3_generation(stack, key) > old_t3,
              "fast retransmitting the lowest outstanding TSN restarted T3-rtx");
    }
}

} // namespace

int main() {
    test_t1_cookie();
    test_t1_cookie_exhaustion();
    test_delayed_sack_packet_counting();
    test_immediate_sack_conditions();
    test_fast_retransmit(0x01020304, "without wraparound");
    test_fast_retransmit(0xFFFFFFFE, "across TSN wraparound");
    test_htna_reneging_and_pmtu();

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
