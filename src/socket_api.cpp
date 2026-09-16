// SCTP_Socket lifecycle and the public API surface: construction, bind, run,
// close, association setup (RFC 9260 5.1) and the send/receive entry points
// the application calls. Everything here runs on the caller's thread, not the
// event loop.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "socket_internal.hpp"

#include <chrono>
#include <iostream>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

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

    if (!wakeup.open()) {
        std::cout << "Error creating event-loop wakeup sockets: "
                  << sctp_error_string() << std::endl;
        return false;
    }

    running.store(true);
    try {
        event_loop_thread = std::thread(&SCTP_Socket::event_loop, this);
    } catch (...) {
        running.store(false);
        wakeup.close();
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
    expirations.clear();
    sends.clear();
    wakeup.close();
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

Association SCTP_Socket::init_new_association(const Association_Key& key) {
    Association result{};

    result.primary_path = key.address;
    result.state = COOKIE_WAIT;

    do {
        generate_random(result.this_ver_tag);
    } while (result.this_ver_tag == 0); // 0 tag reserved by INIT
    generate_random(result.next_tsn);
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
    sends.purge(key);
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
