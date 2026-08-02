#include <sctp/socket.hpp>
#include "serialize.hpp"
#include <sctp/platform.hpp>
#include <sctp/utils.hpp>
#include <iostream>
#include <string_view>
#include <string>
#include <mutex>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <cstddef>
#include <algorithm>
#include <chrono>
#include <climits>
#include <random>
#include <unordered_map>
#include "checksum.hpp"

namespace {

struct Expiration_Policy {
    Expiration_Timer_Type timer_type;
    std::chrono::milliseconds initial_timeout;
};

const std::unordered_map<Chunk_Type, std::vector<Expiration_Policy>> EXPIRE_HANDLERS{
    {INIT, {{Expiration_Timer_Type::T1_INIT, std::chrono::seconds(1)}}},
    {COOKIE_ECHO, {{Expiration_Timer_Type::T1_COOKIE, std::chrono::seconds(1)}}},
    {DATA, {{Expiration_Timer_Type::T3_RTX, std::chrono::milliseconds(0)}}},
};

constexpr std::chrono::microseconds CLOCK_GRANULARITY{1000};
constexpr std::chrono::milliseconds SEND_RETRY_DELAY{10};
constexpr uint32_t DEFAULT_PMDCS = 1200;
constexpr size_t MAX_RECEIVE_BATCH = 64;
constexpr uint8_t DATA_IMMEDIATE_SACK_FLAG = 0x08;

bool has_unacknowledged_data(const Association& assoc) {
    return std::any_of(
        assoc.outstanding_data.begin(),
        assoc.outstanding_data.end(),
        [](const auto& entry) {
            return !entry.second.gap_acked;
        }
    );
}

bool sack_acknowledges(const sack_chunk_value& sack, uint32_t tsn) {
    if (tsn_lte(tsn, sack.cumulative_tsn_ack)) {
        return true;
    }
    uint32_t offset = tsn - sack.cumulative_tsn_ack;
    if (offset > UINT16_MAX) {
        return false;
    }
    return std::any_of(
        sack.gap_ack_blocks.begin(),
        sack.gap_ack_blocks.end(),
        [offset](const sack_gap_ack_block& block) {
            return offset >= block.start && offset <= block.end;
        }
    );
}

} // namespace

SCTP_Socket::SCTP_Socket() : udp_socket(INVALID_SOCKET) {
    if (!sctp_platform_startup()) {
        std::cout << "Socket subsystem initialization failed" << std::endl;
        return;
    }
    platform_started = true;

    udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (udp_socket == INVALID_SOCKET) {
        std::cout << "Error creating socket: " << sctp_error_string() << std::endl;
        sctp_platform_cleanup();
        platform_started = false;
        return;
    }
    std::cout << "Socket created successfully" << std::endl;
}

bool SCTP_Socket::sctp_bind(std::string_view ip_address, int port) {
    sockaddr_in service{};
    service.sin_family = AF_INET;
    if (!sctp_parse_ipv4(ip_address, service.sin_addr)) {
        std::cout << "Invalid IPv4 address: " << ip_address << std::endl;
        return false;
    }
    service.sin_port = htons(port);

    if (bind(udp_socket, (const sockaddr *)&service, sizeof(service)) == SOCKET_ERROR) {
        std::cout << "Error binding socket: " << sctp_error_string() << std::endl;
        sctp_close_socket(udp_socket);
        udp_socket = INVALID_SOCKET;
        sctp_platform_cleanup();
        platform_started = false;
        return false;
    }
    local_address = service;
    std::cout << "Socket bound successfully" << std::endl;
    return true;
}

SCTP_Socket::~SCTP_Socket() {
    sctp_close();
}

bool SCTP_Socket::sctp_run() {
    if (running.load() || udp_socket == INVALID_SOCKET) {
        return false;
    }

    if (!sctp_set_nonblocking(udp_socket)) {
        std::cout << "Error setting non-blocking mode: " << sctp_error_string() << std::endl;
        return false;
    }

    if (!initialize_wakeup_sockets()) {
        std::cout << "Error creating event-loop wakeup sockets: "
                  << sctp_error_string() << std::endl;
        return false;
    }

    running.store(true);
    try {
        event_loop_thread = std::thread(&SCTP_Socket::event_loop, this);
    } catch (...) {
        running.store(false);
        close_wakeup_sockets();
        throw;
    }
    return true;
}

void SCTP_Socket::sctp_close() {
    running.store(false);
    if (event_loop_thread.joinable()) {
        wake_event_loop();
        event_loop_thread.join();
    }
    {
        std::lock_guard<std::mutex> expiration_lock(expiration_queue_mutex);
        while (!expiration_queue.empty()) {
            expiration_queue.pop();
        }
        active_expirations.clear();
    }
    {
        std::lock_guard<std::mutex> sending_lock(sending_queue_mutex);
        control_queue = {};
        retransmission_queue = {};
        new_data_queue = {};
        next_send_attempt = {};
    }
    close_wakeup_sockets();
    if (udp_socket != INVALID_SOCKET) {
        sctp_close_socket(udp_socket);
        udp_socket = INVALID_SOCKET;
    }
    if (platform_started) {
        sctp_platform_cleanup();
        platform_started = false;
        std::cout << "Socket closed successfully" << std::endl;
    }
}

Association_Key SCTP_Socket::sctp_associate(std::string_view ip_address, int port) {
    if (!running.load()) {
        throw std::runtime_error("Socket is not running");
    }

    sockaddr_in to_location{};
    to_location.sin_family = AF_INET;
    if (!sctp_parse_ipv4(ip_address, to_location.sin_addr)) {
        throw std::runtime_error("Invalid IPv4 address");
    }
    to_location.sin_port =  htons(port);

    Association_Key key{to_location};
    Association assoc = init_new_association(key);

    std::unique_lock<std::mutex> assoc_lock(associations_mutex);
    associations.insert_or_assign(key, assoc);
    assoc_lock.unlock();

    SCTP_Packet init_packet = INIT_PACKET;
    // Header fields are host byte order; the serializer converts. sin_port is
    // already network order, so it needs ntohs, not htons.
    init_packet.header.src_port = ntohs(local_address.sin_port);
    init_packet.header.des_port = static_cast<uint16_t>(port);
    init_packet.header.verification_tag = 0;   // RFC 9260 §8.5, packet carries INIT
    init_packet.header.checksum = 0;
    init_packet.chunks[0].chunk_value = init_chunk_value {
        .initiate_tag = assoc.this_ver_tag,
        .a_rwnd = RWND,
        .out_streams = 1,
        .in_streams = 1,
        .initial_tsn = assoc.next_tsn,
        .optional_parameters = {}
    };

    Deliverable init_deliv{key, init_packet};

    enqueue_packet(std::move(init_deliv));

    return key;
}

namespace {

// Seeded from the full entropy of random_device rather than a single 32-bit
// draw. NOTE: mt19937 is not cryptographically secure - its state is
// recoverable from enough observed output, so a determined attacker can predict
// future tags. Move this to the OS CSPRNG when implementing the state cookie.
std::mt19937& tag_rng() {
    static thread_local std::mt19937 gen = [] {
        std::random_device rd;
        std::seed_seq seq{rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()};
        return std::mt19937(seq);
    }();
    return gen;
}

uint32_t random_u32() {
    return std::uniform_int_distribution<uint32_t>(0, UINT32_MAX)(tag_rng());
}

uint32_t random_verification_tag() {
    return std::uniform_int_distribution<uint32_t>(1, UINT32_MAX)(tag_rng());
}

} // namespace

Association SCTP_Socket::init_new_association(const Association_Key& key) {
    Association result{};

    result.primary_path = key.address;
    result.state = COOKIE_WAIT;

    result.this_ver_tag = random_verification_tag();
    result.next_tsn = random_u32();
    result.cumulative_tsn_ack = result.next_tsn - 1;
    result.rto = sctp_parameters::RTO_INITIAL;
    result.pmdcs = DEFAULT_PMDCS;
    result.cwnd = std::min(4U * result.pmdcs, std::max(2U * result.pmdcs, 4380U));
    result.ssthresh = RWND;

    return result;
}

void SCTP_Socket::remove_association(const Association_Key& key) {
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        associations.erase(key);
    }
    cancel_expirations(key);
    purge_queued_packets(key);
}

int SCTP_Socket::await_established_association(const Association_Key& association_id, int timeout_ms) {
    int waited_ms = 0;
    const int sleep_interval_ms = 10;

    while (waited_ms < timeout_ms) {
        std::unique_lock<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(association_id);
        if (it != associations.end() && it->second.state == ESTABLISHED) {
            return 0;
        }
        assoc_lock.unlock();

        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_interval_ms));
        waited_ms += sleep_interval_ms;
    }

    return -1;
}

void SCTP_Socket::sctp_send_data(const sockaddr_in& association_id, const std::vector<uint8_t>& data) {
    Association_Key key{association_id};
    sctp_send_data(key, data);
}

void SCTP_Socket::sctp_send_data(const Association_Key& association_id, const std::vector<uint8_t>& data) {
    std::unique_lock<std::mutex> assoc_lock(associations_mutex);
    auto it = associations.find(association_id);
    if (it == associations.end() || (it->second.state != ESTABLISHED && it->second.state != SHUTDOWN_PENDING && it->second.state != SHUTDOWN_RECEIVED)) {
        return;
    }

    SCTP_Packet data_packet;
    data_packet.header.src_port = ntohs(local_address.sin_port);
    data_packet.header.des_port = ntohs(association_id.address.sin_port);
    data_packet.header.verification_tag = it->second.peer_ver_tag;

    data_packet.chunks.push_back(SCTP_Chunk{
        .chunk_header = {
            .type = DATA,
            .flag = 0,
            .length = 0   // recomputed by serialize_chunk from the encoded body
        },
        .chunk_value = data_chunk_value {
            .tsn = it->second.next_tsn++,
            .stream_identifier = 0,
            .stream_seq_num = 0,
            .payload_protocal = 0,
            .user_data = data
        }
    });
    assoc_lock.unlock();

    Deliverable data_deliv{association_id, data_packet};

    enqueue_packet(std::move(data_deliv), Send_Priority::NEW_DATA);
}

size_t SCTP_Socket::sctp_recv_data(std::vector<uint8_t>& buffer, Association_Key* out_association_id) {
    std::unique_lock<std::mutex> assoc_lock(associations_mutex);
    for (auto& [key, assoc] : associations) {
        if ((assoc.state != ESTABLISHED && assoc.state != SHUTDOWN_PENDING && assoc.state != SHUTDOWN_RECEIVED)) {
            continue;
        }
        if (assoc.ulp_buffer.empty()) {
            continue;
        }

        auto key_copy = key;
        std::vector<uint8_t> data = assoc.ulp_buffer.front();
        assoc.ulp_buffer.pop();
        assoc_lock.unlock();

        size_t to_copy = std::min(buffer.size(), data.size());
        std::memcpy(const_cast<uint8_t*>(buffer.data()), data.data(), to_copy);
        if (out_association_id) {
            *out_association_id = key_copy;
        }
        return to_copy;
    }
    return 0;
}

size_t SCTP_Socket::sctp_recv_data_from(const sockaddr_in& association_id, std::vector<uint8_t>& buffer) {
    Association_Key key{association_id};
    return sctp_recv_data_from(key, buffer);
}

size_t SCTP_Socket::sctp_recv_data_from(const Association_Key& association_id, std::vector<uint8_t>& buffer) {
    std::unique_lock<std::mutex> assoc_lock(associations_mutex);
    auto it = associations.find(association_id);
    if (it == associations.end() || (it->second.state != ESTABLISHED && it->second.state != SHUTDOWN_PENDING && it->second.state != SHUTDOWN_RECEIVED)) {
        return 0;
    }

    Association& assoc = it->second;
    if (assoc.ulp_buffer.empty()) {
        return 0;
    }

    std::vector<uint8_t> data = assoc.ulp_buffer.front();
    assoc.ulp_buffer.pop();
    assoc_lock.unlock();

    size_t to_copy = std::min(buffer.size(), data.size());
    std::memcpy(const_cast<uint8_t*>(buffer.data()), data.data(), to_copy);
    return to_copy;
}

Association_Key SCTP_Socket::get_this_association_key() {
    return Association_Key{local_address};
}

void SCTP_Socket::event_loop() {
    while (running.load()) {
        sctp_pollfd descriptors[2]{};
        descriptors[0].fd = udp_socket;
        descriptors[0].events = SCTP_POLL_READ;
        descriptors[1].fd = wakeup_reader;
        descriptors[1].events = SCTP_POLL_READ;

        int ready = sctp_poll(descriptors, 2, next_poll_timeout());
        if (ready == SOCKET_ERROR) {
            int err = sctp_last_error();
            if (sctp_error_interrupted(err)) {
                continue;
            }
            std::cout << "Error polling socket: " << sctp_error_string(err) << std::endl;
            running.store(false);
            break;
        }

        if ((descriptors[1].revents & SCTP_POLL_READ) != 0) {
            drain_wakeup();
        }
        if ((descriptors[1].revents & (SCTP_POLL_ERROR | SCTP_POLL_FATAL)) != 0) {
            std::cout << "Event-loop wakeup poll reported an error" << std::endl;
            running.store(false);
            break;
        }
        if (!running.load()) {
            break;
        }

        if ((descriptors[0].revents & (SCTP_POLL_READ | SCTP_POLL_ERROR)) != 0) {
            run_receiving();
        }
        if ((descriptors[0].revents & SCTP_POLL_FATAL) != 0) {
            std::cout << "Socket poll reported a fatal error" << std::endl;
            running.store(false);
            break;
        }

        run_expire();
        run_sending();
    }
}

void SCTP_Socket::run_expire() {
    std::vector<Expiration_Fallback> expired;
    {
        std::lock_guard<std::mutex> expiration_lock(expiration_queue_mutex);
        auto now = std::chrono::steady_clock::now();
        while (!expiration_queue.empty() && expiration_queue.top().expiration <= now) {
            Expiration_Fallback fallback = expiration_queue.top();
            expiration_queue.pop();

            auto active = active_expirations.find(fallback.key);
            if (active == active_expirations.end() || active->second != fallback.generation) {
                continue;
            }
            active_expirations.erase(active);
            expired.push_back(std::move(fallback));
        }
    }

    for (const auto& fallback : expired) {
        try {
            handle_expiration(fallback);
        } catch (const std::exception& e) {
            std::cout << "Error handling timer expiration: " << e.what() << std::endl;
        } catch (...) {
            std::cout << "Error handling timer expiration" << std::endl;
        }
    }
}

void SCTP_Socket::run_sending() {
    Deliverable deliverable;
    Send_Priority priority = Send_Priority::CONTROL;
    {
        std::lock_guard<std::mutex> sending_lock(sending_queue_mutex);
        if (std::chrono::steady_clock::now() < next_send_attempt) {
            return;
        }
        if (!control_queue.empty()) {
            deliverable = control_queue.front();
        } else if (!retransmission_queue.empty()) {
            priority = Send_Priority::RETRANSMISSION;
            deliverable = retransmission_queue.front();
        } else if (!new_data_queue.empty()) {
            priority = Send_Priority::NEW_DATA;
            deliverable = new_data_queue.front();
        } else {
            return;
        }
    }

    if (!handle_send_packet(deliverable)) {
        std::lock_guard<std::mutex> sending_lock(sending_queue_mutex);
        next_send_attempt = std::chrono::steady_clock::now() + SEND_RETRY_DELAY;
        return;
    }

    {
        std::lock_guard<std::mutex> sending_lock(sending_queue_mutex);
        if (priority == Send_Priority::CONTROL) {
            control_queue.pop();
        } else if (priority == Send_Priority::RETRANSMISSION) {
            retransmission_queue.pop();
        } else {
            new_data_queue.pop();
        }
        next_send_attempt = {};
    }
    schedule_expirations_after_send(deliverable, std::chrono::steady_clock::now());
    if (priority == Send_Priority::RETRANSMISSION) {
        schedule_pending_retransmission(deliverable.location);
    }
}

void SCTP_Socket::run_receiving() {
    for (size_t received_packets = 0; received_packets < MAX_RECEIVE_BATCH; ++received_packets) {
        uint8_t buffer[RWND];
        sockaddr_in src{};
        socklen_t src_len = sizeof(src);
        int n = recvfrom(udp_socket, reinterpret_cast<char*>(buffer), sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&src), &src_len);
        if (n == SOCKET_ERROR) {
            int err = sctp_last_error();
            if (!sctp_error_would_block(err)) {
                std::cout << "Error receiving packet: " << sctp_error_string(err) << std::endl;
            }
            return;
        }
        if (n == 0) {
            return;
        }
        try {
            handle_recv_packet(buffer, static_cast<size_t>(n), src);
        } catch (const std::exception& e) {
            std::cout << "Error handling packet: " << e.what() << std::endl;
        }
    }
}

void SCTP_Socket::enqueue_packet(Deliverable deliverable, Send_Priority priority) {
    {
        std::lock_guard<std::mutex> sending_lock(sending_queue_mutex);
        if (priority == Send_Priority::CONTROL) {
            control_queue.push(std::move(deliverable));
        } else if (priority == Send_Priority::RETRANSMISSION) {
            retransmission_queue.push(std::move(deliverable));
        } else {
            new_data_queue.push(std::move(deliverable));
        }
    }
    wake_event_loop();
}

bool SCTP_Socket::initialize_wakeup_sockets() {
    close_wakeup_sockets();

    wakeup_reader = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (wakeup_reader == INVALID_SOCKET) {
        return false;
    }
    wakeup_writer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (wakeup_writer == INVALID_SOCKET) {
        int err = sctp_last_error();
        close_wakeup_sockets();
        sctp_set_last_error(err);
        return false;
    }

    sockaddr_in wakeup_address{};
    wakeup_address.sin_family = AF_INET;
    wakeup_address.sin_port = 0;
    if (!sctp_parse_ipv4("127.0.0.1", wakeup_address.sin_addr)
            || bind(
                wakeup_reader,
                reinterpret_cast<const sockaddr*>(&wakeup_address),
                sizeof(wakeup_address)) == SOCKET_ERROR) {
        int err = sctp_last_error();
        close_wakeup_sockets();
        sctp_set_last_error(err);
        return false;
    }

    socklen_t address_length = sizeof(wakeup_address);
    if (getsockname(
            wakeup_reader,
            reinterpret_cast<sockaddr*>(&wakeup_address),
            &address_length) == SOCKET_ERROR
            || connect(
                wakeup_writer,
                reinterpret_cast<const sockaddr*>(&wakeup_address),
                sizeof(wakeup_address)) == SOCKET_ERROR
            || !sctp_set_nonblocking(wakeup_reader)
            || !sctp_set_nonblocking(wakeup_writer)) {
        int err = sctp_last_error();
        close_wakeup_sockets();
        sctp_set_last_error(err);
        return false;
    }
    return true;
}

void SCTP_Socket::close_wakeup_sockets() {
    if (wakeup_reader != INVALID_SOCKET) {
        sctp_close_socket(wakeup_reader);
        wakeup_reader = INVALID_SOCKET;
    }
    if (wakeup_writer != INVALID_SOCKET) {
        sctp_close_socket(wakeup_writer);
        wakeup_writer = INVALID_SOCKET;
    }
}

void SCTP_Socket::wake_event_loop() {
    if (wakeup_writer == INVALID_SOCKET) {
        return;
    }

    const char byte = 1;
    int sent = send(wakeup_writer, &byte, 1, 0);
    if (sent == SOCKET_ERROR && !sctp_error_would_block(sctp_last_error())) {
        std::cout << "Error waking event loop: " << sctp_error_string() << std::endl;
    }
}

void SCTP_Socket::drain_wakeup() {
    char buffer[64];
    while (recv(wakeup_reader, buffer, sizeof(buffer), 0) > 0) {}
    int err = sctp_last_error();
    if (!sctp_error_would_block(err)) {
        std::cout << "Error draining event-loop wakeup: " << sctp_error_string(err) << std::endl;
    }
}

int SCTP_Socket::next_poll_timeout() {
    auto now = std::chrono::steady_clock::now();
    bool have_deadline = false;
    auto deadline = std::chrono::steady_clock::time_point::max();

    {
        std::lock_guard<std::mutex> sending_lock(sending_queue_mutex);
        bool have_queued_packet = !control_queue.empty() || !retransmission_queue.empty() || !new_data_queue.empty();
        if (have_queued_packet) {
            if (next_send_attempt <= now) {
                return 0;
            }
            have_deadline = true;
            deadline = next_send_attempt;
        }
    }

    {
        std::lock_guard<std::mutex> expiration_lock(expiration_queue_mutex);
        while (!expiration_queue.empty()) {
            const Expiration_Fallback& fallback = expiration_queue.top();
            auto active = active_expirations.find(fallback.key);
            if (active != active_expirations.end() && active->second == fallback.generation) {
                if (!have_deadline || fallback.expiration < deadline) {
                    have_deadline = true;
                    deadline = fallback.expiration;
                }
                break;
            }
            expiration_queue.pop();
        }
    }

    if (!have_deadline) {
        return -1;
    }
    if (deadline <= now) {
        return 0;
    }

    auto remaining = deadline - now;
    auto milliseconds = std::chrono::ceil<std::chrono::milliseconds>(
        std::chrono::duration_cast<std::chrono::milliseconds>(remaining)
    );

    if (milliseconds.count() > INT_MAX) {
        return INT_MAX;
    }
    return static_cast<int>(milliseconds.count());
}

void SCTP_Socket::purge_queued_packets(const Association_Key& location) {
    std::lock_guard<std::mutex> sending_lock(sending_queue_mutex);
    auto purge = [&](std::queue<Deliverable>& queue) {
        std::queue<Deliverable> retained;
        while (!queue.empty()) {
            Deliverable packet = std::move(queue.front());
            queue.pop();
            if (!(packet.location == location)) {
                retained.push(std::move(packet));
            }
        }
        queue = std::move(retained);
    };
    purge(control_queue);
    purge(retransmission_queue);
    purge(new_data_queue);
}

void SCTP_Socket::remove_retransmissions(const Association_Key& location, const sack_chunk_value& sack) {
    std::lock_guard<std::mutex> sending_lock(sending_queue_mutex);
    std::queue<Deliverable> retained;
    while (!retransmission_queue.empty()) {
        Deliverable packet = std::move(retransmission_queue.front());
        retransmission_queue.pop();
        if (packet.location == location) {
            auto& chunks = packet.packet.chunks;
            chunks.erase(
                std::remove_if(
                    chunks.begin(),
                    chunks.end(),
                    [&](const SCTP_Chunk& chunk) {
                        return chunk.chunk_header.type == DATA && sack_acknowledges(sack, std::get<data_chunk_value>(chunk.chunk_value).tsn);
                    }
                ),
                chunks.end()
            );
        }
        if (!packet.packet.chunks.empty()) {
            retained.push(std::move(packet));
        }
    }
    retransmission_queue = std::move(retained);
}

void SCTP_Socket::remove_retransmissions(const Association_Key& location, Chunk_Type type) {
    std::lock_guard<std::mutex> sending_lock(sending_queue_mutex);
    std::queue<Deliverable> retained;
    while (!retransmission_queue.empty()) {
        Deliverable packet = std::move(retransmission_queue.front());
        retransmission_queue.pop();
        if (packet.location == location) {
            auto& chunks = packet.packet.chunks;
            chunks.erase(
                std::remove_if(
                    chunks.begin(),
                    chunks.end(),
                    [&](const SCTP_Chunk& chunk) {
                        return chunk.chunk_header.type == type;
                    }
                ),
                chunks.end()
            );
        }
        if (!packet.packet.chunks.empty()) {
            retained.push(std::move(packet));
        }
    }
    retransmission_queue = std::move(retained);
}

bool SCTP_Socket::handle_send_packet(const Deliverable& deliverable) {
    std::vector<uint8_t> serialized_packet = serialize_sctp_packet(deliverable.packet);
    const char* data = reinterpret_cast<const char*>(serialized_packet.data());
    const sockaddr* to = reinterpret_cast<const sockaddr*>(&deliverable.location.address);
    int sent = sendto(udp_socket, data, serialized_packet.size(), 0, to, sizeof(deliverable.location.address));

    if (sent == SOCKET_ERROR || static_cast<size_t>(sent) != serialized_packet.size()) {
        std::cout << "Error sending packet: " << sctp_error_string() << std::endl;
        return false;
    }
    return true;
}

void SCTP_Socket::schedule_expirations_after_send( const Deliverable& deliverable, std::chrono::steady_clock::time_point sent_at) {
    bool sent_data = false;
    for (const auto& chunk : deliverable.packet.chunks) {
        auto handlers = EXPIRE_HANDLERS.find(chunk.chunk_header.type);
        if (handlers == EXPIRE_HANDLERS.end()) {
            continue;
        }

        for (const auto& policy : handlers->second) {
            if (policy.timer_type == Expiration_Timer_Type::T3_RTX) {
                record_data_sent(deliverable.location, std::get<data_chunk_value>(chunk.chunk_value), sent_at);
                sent_data = true;
                continue;
            }

            auto delay = policy.initial_timeout;
            if (policy.timer_type == Expiration_Timer_Type::T1_INIT || policy.timer_type == Expiration_Timer_Type::T1_COOKIE) {
                std::lock_guard<std::mutex> assoc_lock(associations_mutex);
                auto association = associations.find(deliverable.location);
                Association_State expected_state = policy.timer_type == Expiration_Timer_Type::T1_INIT ? COOKIE_WAIT : COOKIE_ECHOED;
                if (association == associations.end() || association->second.state != expected_state) {
                    continue;
                }

                uint16_t retransmits = policy.timer_type == Expiration_Timer_Type::T1_INIT ? association->second.init_retransmits : association->second.cookie_retransmits;
                for (uint16_t i = 0; i < retransmits && delay < sctp_parameters::RTO_MAX; ++i) {
                    delay = std::min(delay * 2, sctp_parameters::RTO_MAX);
                }
            }

            schedule_expiration(Expiration_Key{deliverable.location, policy.timer_type}, sent_at + delay, deliverable);
        }
    }

    if (sent_data) {
        start_t3_if_stopped(deliverable.location);
    }
}

void SCTP_Socket::schedule_expiration(const Expiration_Key& key, std::chrono::steady_clock::time_point expiration, const Deliverable& retry) {
    {
        std::lock_guard<std::mutex> expiration_lock(expiration_queue_mutex);
        uint64_t generation = next_expiration_generation++;
        active_expirations.insert_or_assign(key, generation);
        expiration_queue.push(Expiration_Fallback{key, expiration, generation, retry});
    }
    wake_event_loop();
}

void SCTP_Socket::cancel_expiration(const Expiration_Key& key) {
    {
        std::lock_guard<std::mutex> expiration_lock(expiration_queue_mutex);
        active_expirations.erase(key);
    }
    wake_event_loop();
}

void SCTP_Socket::cancel_expirations( const Association_Key& location) {
    {
        std::lock_guard<std::mutex> expiration_lock(expiration_queue_mutex);
        for (auto it = active_expirations.begin();
             it != active_expirations.end();) {
            if (it->first.location == location) {
                it = active_expirations.erase(it);
            } else {
                ++it;
            }
        }
    }
    wake_event_loop();
}

void SCTP_Socket::handle_expiration(const Expiration_Fallback& fallback) {
    if (fallback.key.type == Expiration_Timer_Type::T3_RTX) {
        handle_t3_expiration(fallback.key.location);
        return;
    }
    if (fallback.key.type == Expiration_Timer_Type::DELAYED_SACK) {
        handle_delayed_sack_expiration(fallback.key.location);
        return;
    }
    if (fallback.key.type != Expiration_Timer_Type::T1_INIT && fallback.key.type != Expiration_Timer_Type::T1_COOKIE) {
        return;
    }

    bool should_retry = false;
    bool exhausted = false;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(fallback.key.location);
        bool is_init = fallback.key.type == Expiration_Timer_Type::T1_INIT;
        Association_State expected_state = is_init ? COOKIE_WAIT : COOKIE_ECHOED;
        if (association == associations.end() || association->second.state != expected_state) {
            return;
        }

        uint16_t& retransmits = is_init ? association->second.init_retransmits : association->second.cookie_retransmits;
        if (retransmits >= sctp_parameters::MAX_INIT_RETRANSMITS) {
            associations.erase(association);
            exhausted = true;
        } else {
            ++retransmits;
            should_retry = true;
        }
    }

    if (exhausted) {
        cancel_expirations(fallback.key.location);
        purge_queued_packets(fallback.key.location);
        std::cout << "Association failed after handshake retransmissions" << std::endl;
    } else if (should_retry) {
        enqueue_packet(fallback.retry, Send_Priority::RETRANSMISSION);
    }
}

void SCTP_Socket::record_data_sent(const Association_Key& location, const data_chunk_value& data, std::chrono::steady_clock::time_point sent_at) {
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    auto association = associations.find(location);
    if (association == associations.end() || association->second.state != ESTABLISHED) {
        return;
    }

    Association& assoc = association->second;
    auto outstanding = assoc.outstanding_data.find(data.tsn);
    if (outstanding == assoc.outstanding_data.end()) {
        assoc.outstanding_data.emplace(
            data.tsn,
            Outstanding_Data{data, sent_at, sent_at, false, false, 0, false, false}
        );
        if (!assoc.has_rtt_measurement_tsn) {
            assoc.has_rtt_measurement_tsn = true;
            assoc.rtt_measurement_tsn = data.tsn;
        }
        return;
    }

    outstanding->second.last_sent = sent_at;
    outstanding->second.retransmitted = true;
    outstanding->second.gap_acked = false;
    if (assoc.has_rtt_measurement_tsn && tsn_lte(data.tsn, assoc.rtt_measurement_tsn)) {
        assoc.has_rtt_measurement_tsn = false;
    }
}

void SCTP_Socket::start_t3_if_stopped(const Association_Key& location) {
    Expiration_Key key{location, Expiration_Timer_Type::T3_RTX};
    {
        std::lock_guard<std::mutex> expiration_lock(expiration_queue_mutex);
        if (active_expirations.find(key) != active_expirations.end()) {
            return;
        }
    }
    restart_t3(location);
}

void SCTP_Socket::restart_t3(const Association_Key& location) {
    std::chrono::microseconds rto;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(location);
        if (association == associations.end() || !has_unacknowledged_data(association->second)) {
            cancel_expiration(Expiration_Key{location, Expiration_Timer_Type::T3_RTX});
            return;
        }
        rto = association->second.rto;
    }

    schedule_expiration(
        Expiration_Key{location, Expiration_Timer_Type::T3_RTX},
        std::chrono::steady_clock::now() + rto,
        Deliverable{location, SCTP_Packet{}}
    );
}

void SCTP_Socket::handle_t3_expiration(const Association_Key& location) {
    Deliverable retransmission;
    bool have_data = false;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(location);
        if (association == associations.end() || association->second.state != ESTABLISHED || !has_unacknowledged_data(association->second)) {
            return;
        }

        Association& assoc = association->second;
        assoc.ssthresh = std::max(assoc.cwnd / 2, 4U * assoc.pmdcs);
        assoc.cwnd = assoc.pmdcs;
        assoc.partial_bytes_acked = 0;
        assoc.rto = std::min(assoc.rto * 2, std::chrono::duration_cast<std::chrono::microseconds>(sctp_parameters::RTO_MAX));
        ++assoc.error_count;

        std::vector<std::pair<uint32_t, Outstanding_Data*>> ordered;
        ordered.reserve(assoc.outstanding_data.size());
        for (auto& entry : assoc.outstanding_data) {
            ordered.push_back({entry.first, &entry.second});
        }
        std::sort(
            ordered.begin(),
            ordered.end(),
            [&](const auto& lhs, const auto& rhs) {
                return static_cast<uint32_t>(lhs.first - assoc.cumulative_tsn_ack) < static_cast<uint32_t>(rhs.first - assoc.cumulative_tsn_ack);
            }
        );

        SCTP_Packet packet;
        packet.header.src_port = ntohs(local_address.sin_port);
        packet.header.des_port = ntohs(location.address.sin_port);
        packet.header.verification_tag = assoc.peer_ver_tag;
        size_t packet_size = SCTP_COMMON_HEADER_SIZE;
        for (const auto& [tsn, outstanding] : ordered) {
            if (outstanding->gap_acked) {
                continue;
            }
            size_t chunk_size = 16 + outstanding->data.user_data.size();
            chunk_size = (chunk_size + 3) & ~size_t{3};
            if (!packet.chunks.empty()
                    && packet_size + chunk_size
                        > SCTP_COMMON_HEADER_SIZE + assoc.pmdcs) {
                break;
            }
            packet.chunks.push_back(SCTP_Chunk{
                .chunk_header = {
                    .type = DATA,
                    .flag = 0,
                    .length = 0,
                },
                .chunk_value = outstanding->data,
            });
            packet_size += chunk_size;
            (void)tsn;
        }

        retransmission = Deliverable{location, std::move(packet)};
        have_data = !retransmission.packet.chunks.empty();
    }

    if (have_data) {
        enqueue_packet(std::move(retransmission), Send_Priority::RETRANSMISSION);
    }
}

void SCTP_Socket::handle_recv_packet(const uint8_t* data, size_t n, const sockaddr_in& src) {
    if (n < SCTP_COMMON_HEADER_SIZE) {
        return;
    }

    uint32_t received_checksum = sctp_read_wire_checksum(data);

    std::vector<uint8_t> data_copy(data, data + n);
    sctp_clear_wire_checksum(data_copy.data());

    uint32_t calculated_checksum = calculate_sctp_checksum(data_copy.data(), data_copy.size());

    if (calculated_checksum != received_checksum) {
        std::cout << "Dropped packet with invalid checksum. Received: " << received_checksum
                  << ", Calculated: " << calculated_checksum << std::endl;
        return;
    }

    SCTP_Packet in_pkt;
    try {
        in_pkt = deserialize_sctp_packet(data, n);
    } catch (const std::exception& e) {
        std::cout << "Dropped malformed packet: " << e.what() << std::endl;
        return;
    }

    if (!validate_verification_tag(in_pkt, src)) {
        std::cout << "Dropped packet with bad verification tag" << std::endl;
        return;
    }

    for (size_t i{}; i < in_pkt.chunks.size(); i++) {
        switch(in_pkt.chunks[i].chunk_header.type) {
            case INIT:
                std::cout << "Recieved INIT" << std::endl;
                SCTP_Socket::handle_init(in_pkt.header, in_pkt.chunks[i], src);
                break;
            case INIT_ACK:
                std::cout << "Recieved INIT_ACK" << std::endl;
                SCTP_Socket::handle_init_ack(in_pkt.header, in_pkt.chunks[i], src);
                break;
            case COOKIE_ECHO:
                std::cout << "Recieved COOKIE_ECHO" << std::endl;
                SCTP_Socket::handle_cookie_echo(in_pkt.header, in_pkt.chunks[i], src);
                break;
            case COOKIE_ACK:
                std::cout << "Recieved COOKIE_ACK" << std::endl;
                SCTP_Socket::handle_cookie_ack(in_pkt.header, in_pkt.chunks[i], src);
                break;
            case DATA:
                break;
            case SACK:
                SCTP_Socket::handle_sack(in_pkt.header, in_pkt.chunks[i], src);
                break;
            default:
                break;
        }
    }
    handle_data_packet(in_pkt, src);
}

bool SCTP_Socket::validate_verification_tag(const SCTP_Packet& pkt, const sockaddr_in& src) {
    if (pkt.chunks.empty()) {
        return false;
    }

    if (pkt.chunks[0].chunk_header.type == INIT) {
        return pkt.header.verification_tag == 0;
    }

    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    auto it = associations.find(Association_Key{src});
    if (it == associations.end()) {
        return false;
    }
    return pkt.header.verification_tag == it->second.this_ver_tag;
}

void SCTP_Socket::handle_init(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src) {
    std::unique_lock<std::mutex> assoc_lock(associations_mutex);
    Association_Key assoc_key{src};
    if (associations.find(assoc_key) != associations.end()) {
        return;
    }

    Association new_assoc = init_new_association(assoc_key);
    new_assoc.last_peer_tsn = std::get<init_chunk_value>(chunk.chunk_value).initial_tsn - 1;
    new_assoc.peer_ver_tag = std::get<init_chunk_value>(chunk.chunk_value).initiate_tag;
    new_assoc.peer_rwnd = std::get<init_chunk_value>(chunk.chunk_value).a_rwnd;
    associations.insert_or_assign(assoc_key, new_assoc);

    SCTP_Packet init_ack_packet;

    init_ack_packet.header.src_port = header.des_port;
    init_ack_packet.header.des_port = header.src_port;

    init_ack_packet.header.verification_tag = new_assoc.peer_ver_tag;

    init_ack_packet.chunks.push_back(SCTP_Chunk{
        .chunk_header = {
            .type = INIT_ACK,
            .flag = 0,
            .length = 0   // recomputed by serialize_chunk
        },
        .chunk_value = init_chunk_value {
            .initiate_tag = new_assoc.this_ver_tag,
            .a_rwnd = RWND,
            .out_streams = 1,
            .in_streams = 1,
            .initial_tsn = new_assoc.next_tsn,
            .optional_parameters = {}
        }
    });

    assoc_lock.unlock();

    Deliverable init_ack_deliv{src, init_ack_packet};

    enqueue_packet(std::move(init_ack_deliv));
}

void SCTP_Socket::handle_init_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src) {
    std::unique_lock<std::mutex> assoc_lock(associations_mutex);
    Association_Key assoc_key{src};
    auto it = associations.find(assoc_key);
    if (it == associations.end() || it->second.state != COOKIE_WAIT) {
        return;
    }

    Association& assoc = it->second;
    assoc.last_peer_tsn = std::get<init_chunk_value>(chunk.chunk_value).initial_tsn - 1;
    assoc.peer_ver_tag = std::get<init_chunk_value>(chunk.chunk_value).initiate_tag;
    assoc.peer_rwnd = std::get<init_chunk_value>(chunk.chunk_value).a_rwnd;
    assoc.state = COOKIE_ECHOED;
    uint32_t peer_tag = assoc.peer_ver_tag;
    assoc_lock.unlock();
    cancel_expiration(Expiration_Key{assoc_key, Expiration_Timer_Type::T1_INIT});
    remove_retransmissions(assoc_key, INIT);

    SCTP_Packet cookie_echo_packet;

    cookie_echo_packet.header.src_port = header.des_port;
    cookie_echo_packet.header.des_port = header.src_port;

    cookie_echo_packet.header.verification_tag = peer_tag;

    cookie_echo_packet.chunks.push_back(SCTP_Chunk{
        .chunk_header = {
            .type = COOKIE_ECHO,
            .flag = 0,
            .length = 0   // recomputed by serialize_chunk
        },
        .chunk_value = cookie_echo_chunk_value {
            .cookie_data = {}
        }
    });

    Deliverable cookie_echo_deliv{src, cookie_echo_packet};

    enqueue_packet(std::move(cookie_echo_deliv));
}

void SCTP_Socket::handle_cookie_echo(
        const SCTP_Common_Header& header,
        const SCTP_Chunk&,
        const sockaddr_in& src) {
    std::unique_lock<std::mutex> assoc_lock(associations_mutex);
    Association_Key assoc_key{src};
    auto it = associations.find(assoc_key);
    if (it == associations.end() || it->second.state != COOKIE_WAIT) {
        return;
    }

    Association& assoc = it->second;
    assoc.state = ESTABLISHED;
    uint32_t peer_tag = assoc.peer_ver_tag;
    assoc_lock.unlock();

    SCTP_Packet cookie_ack_packet;

    cookie_ack_packet.header.src_port = header.des_port;
    cookie_ack_packet.header.des_port = header.src_port;
    cookie_ack_packet.header.verification_tag = peer_tag;

    cookie_ack_packet.chunks.push_back(SCTP_Chunk{
        .chunk_header = {
            .type = COOKIE_ACK,
            .flag = 0,
            .length = 0   // recomputed by serialize_chunk
        },
        .chunk_value = cookie_ack_chunk_value {}
    });

    Deliverable cookie_ack_deliv{src, cookie_ack_packet};

    enqueue_packet(std::move(cookie_ack_deliv));
}
void SCTP_Socket::handle_cookie_ack(const SCTP_Common_Header&, const SCTP_Chunk&, const sockaddr_in& src) {
    std::unique_lock<std::mutex> assoc_lock(associations_mutex);
    Association_Key assoc_key{src};
    auto it = associations.find(assoc_key);
    if (it == associations.end() || it->second.state != COOKIE_ECHOED) {
        return;
    }

    Association& assoc = it->second;
    assoc.state = ESTABLISHED;
    assoc_lock.unlock();
    cancel_expiration(
        Expiration_Key{assoc_key, Expiration_Timer_Type::T1_COOKIE});
    remove_retransmissions(assoc_key, COOKIE_ECHO);
}

void SCTP_Socket::update_rto(Association& assoc, std::chrono::microseconds measurement) {
    if (!assoc.has_srtt) {
        assoc.srtt = measurement;
        assoc.rttvar = measurement / 2;
        assoc.has_srtt = true;
    } else {
        using Floating_Microseconds = std::chrono::duration<double, std::micro>;
        Floating_Microseconds previous_srtt{assoc.srtt};
        Floating_Microseconds previous_rttvar{assoc.rttvar};
        Floating_Microseconds new_rtt_measurement{measurement};
        Floating_Microseconds deviation = previous_srtt > new_rtt_measurement ? previous_srtt - new_rtt_measurement : new_rtt_measurement - previous_srtt;


        // RTTVAR is calculated first so both formulas use the previous value of SRTT.
        Floating_Microseconds new_rttvar = (1.0 - sctp_parameters::RTO_BETA) * previous_rttvar + sctp_parameters::RTO_BETA * deviation;
        Floating_Microseconds new_srtt = (1.0 - sctp_parameters::RTO_ALPHA) * previous_srtt + sctp_parameters::RTO_ALPHA * new_rtt_measurement;

        assoc.rttvar = std::chrono::duration_cast<std::chrono::microseconds>(new_rttvar);
        assoc.srtt = std::chrono::duration_cast<std::chrono::microseconds>(new_srtt);
    }

    if (assoc.rttvar.count() == 0) {
        assoc.rttvar = CLOCK_GRANULARITY;
    }
    assoc.rto = std::clamp(
        assoc.srtt + assoc.rttvar * 4,
        std::chrono::duration_cast<std::chrono::microseconds>(sctp_parameters::RTO_MIN),
        std::chrono::duration_cast<std::chrono::microseconds>(sctp_parameters::RTO_MAX)
    );
}

void SCTP_Socket::handle_sack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src) {
    (void)header;
    const auto& sack = std::get<sack_chunk_value>(chunk.chunk_value);
    Association_Key key{src};
    bool stop = false;
    bool restart = false;
    bool start = false;
    bool schedule_fast_retransmission = false;
    bool fast_retransmits_lowest = false;

    { // Scope for association lock
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(key);
        if (association == associations.end() || (association->second.state != ESTABLISHED && association->second.state != SHUTDOWN_PENDING && association->second.state != SHUTDOWN_RECEIVED)) {
            return;
        }

        Association& assoc = association->second;
        if (tsn_lt(sack.cumulative_tsn_ack, assoc.cumulative_tsn_ack)) {
            return;
        }
        uint32_t previous_cumulative_tsn_ack = assoc.cumulative_tsn_ack;
        bool cumulative_ack_advanced =
            tsn_gt(sack.cumulative_tsn_ack, previous_cumulative_tsn_ack);

        bool have_earliest = false;
        uint32_t earliest_tsn = 0;
        uint32_t earliest_distance = 0;
        for (const auto& [tsn, outstanding] : assoc.outstanding_data) {
            if (outstanding.gap_acked) {
                continue;
            }
            uint32_t distance = tsn - assoc.cumulative_tsn_ack;
            if (!have_earliest || distance < earliest_distance) {
                have_earliest = true;
                earliest_tsn = tsn;
                earliest_distance = distance;
            }
        }
        bool earliest_acknowledged = have_earliest && sack_acknowledges(sack, earliest_tsn);

        bool newly_acknowledged = false;
        bool reneged = false;
        std::vector<uint32_t> reneged_tsns;
        bool have_htna = false;
        uint32_t htna = 0;
        bool have_highest_reported = false;
        uint32_t highest_reported = sack.cumulative_tsn_ack;
        auto now = std::chrono::steady_clock::now();

        for (const auto& [tsn, outstanding] : assoc.outstanding_data) {
            bool acknowledged = sack_acknowledges(sack, tsn);
            if (acknowledged && !outstanding.gap_acked) {
                if (!have_htna || tsn_gt(tsn, htna)) {
                    htna = tsn;
                    have_htna = true;
                }
            }
            if (acknowledged
                    && (!have_highest_reported
                        || tsn_gt(tsn, highest_reported))) {
                highest_reported = tsn;
                have_highest_reported = true;
            }
        }

        for (auto it = assoc.outstanding_data.begin(); it != assoc.outstanding_data.end();) {
            uint32_t tsn = it->first;
            Outstanding_Data& outstanding = it->second;
            bool acknowledged = sack_acknowledges(sack, tsn);
            bool cumulatively_acknowledged = tsn_lte(tsn, sack.cumulative_tsn_ack);

            if (acknowledged && !outstanding.gap_acked) {
                newly_acknowledged = true;
                if (assoc.has_rtt_measurement_tsn && tsn == assoc.rtt_measurement_tsn && !outstanding.retransmitted) {
                    update_rto(assoc, std::chrono::duration_cast<std::chrono::microseconds>(now - outstanding.first_sent));
                    assoc.has_rtt_measurement_tsn = false;
                }
            }

            if (cumulatively_acknowledged) {
                it = assoc.outstanding_data.erase(it);
                continue;
            }

            if (acknowledged) {
                outstanding.gap_acked = true;
            } else if (outstanding.gap_acked) {
                outstanding.gap_acked = false;
                reneged = true;
                reneged_tsns.push_back(tsn);
                if (!outstanding.fast_retransmitted) {
                    ++outstanding.missing_reports;
                }
            }
            ++it;
        }

        assoc.cumulative_tsn_ack = sack.cumulative_tsn_ack;
        if (newly_acknowledged) {
            assoc.error_count = 0;
        }

        for (auto& [tsn, outstanding] : assoc.outstanding_data) {
            if (outstanding.gap_acked || outstanding.fast_retransmitted) {
                continue;
            }

            bool was_reneged = std::find(
                reneged_tsns.begin(), reneged_tsns.end(), tsn)
                != reneged_tsns.end();
            bool reported_missing = false;
            if (assoc.in_fast_recovery && cumulative_ack_advanced) {
                reported_missing = have_highest_reported
                    && tsn_lt(tsn, highest_reported);
            } else {
                reported_missing = have_htna && tsn_lt(tsn, htna);
            }

            // Reneging was already counted once while applying the Gap Ack
            // state transition above.
            if (reported_missing && !was_reneged) {
                ++outstanding.missing_reports;
            }
            if (outstanding.missing_reports >= 3) {
                outstanding.fast_retransmitted = true;
                outstanding.pending_retransmission = true;
                schedule_fast_retransmission = true;
            }
        }

        if (schedule_fast_retransmission) {
            auto lowest = assoc.outstanding_data.find(earliest_tsn);
            fast_retransmits_lowest = have_earliest
                && lowest != assoc.outstanding_data.end()
                && lowest->second.pending_retransmission;

            if (!assoc.in_fast_recovery) {
                assoc.ssthresh = std::max(assoc.cwnd / 2, 4U * assoc.pmdcs);
                assoc.cwnd = assoc.ssthresh;
                assoc.partial_bytes_acked = 0;

                bool have_exit = false;
                uint32_t exit_tsn = 0;
                for (const auto& [tsn, outstanding] : assoc.outstanding_data) {
                    (void)outstanding;
                    if (!have_exit || tsn_gt(tsn, exit_tsn)) {
                        have_exit = true;
                        exit_tsn = tsn;
                    }
                }
                if (have_exit) {
                    assoc.in_fast_recovery = true;
                    assoc.fast_recovery_exit_tsn = exit_tsn;
                }
            }
        }

        if (assoc.in_fast_recovery
                && tsn_gte(sack.cumulative_tsn_ack,
                           assoc.fast_recovery_exit_tsn)) {
            assoc.in_fast_recovery = false;
        }

        if (!assoc.has_rtt_measurement_tsn) {
            bool found = false;
            uint32_t candidate_tsn = 0;
            uint32_t candidate_distance = 0;
            for (const auto& [tsn, outstanding] : assoc.outstanding_data) {
                if (outstanding.gap_acked || outstanding.retransmitted) {
                    continue;
                }
                bool ambiguous = std::any_of(
                    assoc.outstanding_data.begin(),
                    assoc.outstanding_data.end(),
                    [&](const auto& other) {
                        return other.second.retransmitted && tsn_lte(other.first, tsn) && other.second.last_sent >= outstanding.first_sent;
                    });
                if (ambiguous) {
                    continue;
                }
                uint32_t distance = tsn - assoc.cumulative_tsn_ack;
                if (!found || distance < candidate_distance) {
                    found = true;
                    candidate_tsn = tsn;
                    candidate_distance = distance;
                }
            }
            if (found) {
                assoc.has_rtt_measurement_tsn = true;
                assoc.rtt_measurement_tsn = candidate_tsn;
            }
        }

        size_t outstanding_bytes = 0;
        for (const auto& [tsn, outstanding] : assoc.outstanding_data) {
            if (!outstanding.gap_acked) {
                size_t chunk_size = 16 + outstanding.data.user_data.size();
                outstanding_bytes += (chunk_size + 3) & ~size_t{3};
            }
            (void)tsn;
        }
        assoc.peer_rwnd = outstanding_bytes >= sack.a_rwnd ? 0 : sack.a_rwnd - static_cast<uint32_t>(outstanding_bytes);

        if (!has_unacknowledged_data(assoc)) {
            stop = true;
        } else if (earliest_acknowledged || fast_retransmits_lowest) {
            restart = true;
        } else if (reneged) {
            start = true;
        }
    }

    Expiration_Key timer{key, Expiration_Timer_Type::T3_RTX};
    remove_retransmissions(key, sack);
    if (schedule_fast_retransmission) {
        schedule_pending_retransmission(key);
    }
    if (stop) {
        cancel_expiration(timer);
    } else if (restart) {
        restart_t3(key);
    } else if (start) {
        start_t3_if_stopped(key);
    }
}

void SCTP_Socket::schedule_pending_retransmission(
        const Association_Key& key) {
    Deliverable retransmission;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(key);
        if (association == associations.end()) {
            return;
        }

        Association& assoc = association->second;
        std::vector<std::pair<uint32_t, Outstanding_Data*>> ordered;
        for (auto& entry : assoc.outstanding_data) {
            if (entry.second.pending_retransmission) {
                ordered.push_back({entry.first, &entry.second});
            }
        }
        std::sort(ordered.begin(), ordered.end(), [&](const auto& lhs, const auto& rhs) {
            return static_cast<uint32_t>(lhs.first - assoc.cumulative_tsn_ack)
                < static_cast<uint32_t>(rhs.first - assoc.cumulative_tsn_ack);
        });

        SCTP_Packet packet;
        packet.header.src_port = ntohs(local_address.sin_port);
        packet.header.des_port = ntohs(key.address.sin_port);
        packet.header.verification_tag = assoc.peer_ver_tag;
        size_t packet_size = SCTP_COMMON_HEADER_SIZE;
        for (const auto& [tsn, outstanding] : ordered) {
            size_t chunk_size = (16 + outstanding->data.user_data.size() + 3)
                & ~size_t{3};
            if (!packet.chunks.empty()
                    && packet_size + chunk_size
                        > SCTP_COMMON_HEADER_SIZE + assoc.pmdcs) {
                break;
            }
            packet.chunks.push_back(SCTP_Chunk{
                .chunk_header = {.type = DATA, .flag = 0, .length = 0},
                .chunk_value = outstanding->data,
            });
            outstanding->pending_retransmission = false;
            packet_size += chunk_size;
            (void)tsn;
        }
        if (packet.chunks.empty()) {
            return;
        }
        retransmission = Deliverable{key, std::move(packet)};
    }
    enqueue_packet(std::move(retransmission), Send_Priority::RETRANSMISSION);
}

SCTP_Packet SCTP_Socket::build_sack(
        const Association_Key& key, Association& assoc) {
    std::vector<uint16_t> offsets;
    offsets.reserve(assoc.tsn_ooo_buffer.size());
    for (const auto& [tsn, data] : assoc.tsn_ooo_buffer) {
        uint32_t offset = tsn - assoc.last_peer_tsn;
        if (offset > 0 && offset <= UINT16_MAX) {
            offsets.push_back(static_cast<uint16_t>(offset));
        }
        (void)data;
    }
    std::sort(offsets.begin(), offsets.end());
    offsets.erase(std::unique(offsets.begin(), offsets.end()), offsets.end()); // Should not be necessary, but nonetheless...

    std::vector<sack_gap_ack_block> gaps;
    for (uint16_t offset : offsets) {
        if (gaps.empty() || static_cast<uint32_t>(gaps.back().end) + 1 != offset) {
            gaps.push_back({offset, offset});
        } else {
            gaps.back().end = offset;
        }
    }

    SCTP_Packet sack_packet;
    sack_packet.header.src_port = ntohs(local_address.sin_port);
    sack_packet.header.des_port = ntohs(key.address.sin_port);
    sack_packet.header.verification_tag = assoc.peer_ver_tag;
    sack_packet.chunks.push_back(SCTP_Chunk{
        .chunk_header = {
            .type = SACK,
            .flag = 0,
            .length = 0,
        },
        .chunk_value = sack_chunk_value{
            .cumulative_tsn_ack = assoc.last_peer_tsn,
            .a_rwnd = RWND, // Need to track available receive window for the peer
            .number_of_gap_ack_blocks = static_cast<uint16_t>(gaps.size()),
            .number_of_duplicate_tsns = static_cast<uint16_t>(assoc.duplicate_tsns.size()),
            .gap_ack_blocks = std::move(gaps),
            .duplicate_tsns = std::move(assoc.duplicate_tsns),
        },
    });
    assoc.duplicate_tsns.clear();
    assoc.delayed_sack_packet_count = 0;
    return sack_packet;
}

void SCTP_Socket::send_sack(const Association_Key& key) {
    SCTP_Packet sack_packet;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(key);
        if (association == associations.end()
                || association->second.state != ESTABLISHED) {
            return;
        }
        sack_packet = build_sack(key, association->second);
    }
    cancel_expiration(
        Expiration_Key{key, Expiration_Timer_Type::DELAYED_SACK});
    enqueue_packet(Deliverable{key, std::move(sack_packet)});
}

void SCTP_Socket::handle_delayed_sack_expiration(
        const Association_Key& location) {
    send_sack(location);
}

void SCTP_Socket::handle_data_packet(
        const SCTP_Packet& packet, const sockaddr_in& src) {
    Association_Key assoc_key{src};
    bool have_data = false;
    bool send_immediately = false;
    bool start_delayed_timer = false;

    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(assoc_key);
        if (it == associations.end() || it->second.state != ESTABLISHED) {
            return;
        }

        Association& assoc = it->second;
        bool hole_existed = !assoc.tsn_ooo_buffer.empty();
        bool saw_duplicate = false;

        for (const auto& chunk : packet.chunks) {
            if (chunk.chunk_header.type != DATA) {
                continue;
            }
            have_data = true;
            send_immediately = send_immediately
                || (chunk.chunk_header.flag & DATA_IMMEDIATE_SACK_FLAG) != 0;
            const auto& data = std::get<data_chunk_value>(chunk.chunk_value);
            uint32_t tsn = data.tsn;
            if (tsn == assoc.last_peer_tsn + 1) {
                assoc.last_peer_tsn = tsn;
                assoc.ulp_buffer.push(data.user_data);
                read_ooo_buffer(assoc);
            } else if (tsn_lt(assoc.last_peer_tsn + 1, tsn)) {
                auto inserted = assoc.tsn_ooo_buffer.emplace(tsn, data);
                if (!inserted.second) {
                    assoc.duplicate_tsns.push_back(tsn);
                    saw_duplicate = true;
                }
            } else {
                assoc.duplicate_tsns.push_back(tsn);
                saw_duplicate = true;
            }
        }

        if (!have_data) {
            return;
        }
        send_immediately = send_immediately || saw_duplicate
            || hole_existed || !assoc.tsn_ooo_buffer.empty();
        if (!send_immediately) {
            ++assoc.delayed_sack_packet_count;
            send_immediately = assoc.delayed_sack_packet_count >= 2;
            start_delayed_timer = !send_immediately;
        }
    }

    if (send_immediately) {
        send_sack(assoc_key);
    } else if (start_delayed_timer) {
        schedule_expiration(
            Expiration_Key{assoc_key, Expiration_Timer_Type::DELAYED_SACK},
            std::chrono::steady_clock::now() + sctp_parameters::SACK_DELAY,
            Deliverable{assoc_key, SCTP_Packet{}});
    }
}

void SCTP_Socket::read_ooo_buffer(Association& assoc) {
    uint32_t tsn = assoc.last_peer_tsn + 1;
    while (assoc.tsn_ooo_buffer.find(tsn) != assoc.tsn_ooo_buffer.end()) {
        assoc.ulp_buffer.push(assoc.tsn_ooo_buffer[tsn].user_data);
        assoc.tsn_ooo_buffer.erase(tsn);
        tsn++;
    }
    assoc.last_peer_tsn = tsn - 1;
}
