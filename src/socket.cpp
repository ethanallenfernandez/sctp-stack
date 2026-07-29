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
#include <random>
#include "checksum.hpp"

SCTP_Socket::SCTP_Socket() : udp_socket(INVALID_SOCKET) {
    if (!sctp_platform_startup()) {
        std::cout << "Socket subsystem initialization failed" << std::endl;
        return;
    }

    udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (udp_socket == INVALID_SOCKET) {
        std::cout << "Error creating socket: " << sctp_error_string() << std::endl;
        sctp_platform_cleanup();
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
    running.store(true);

    if (!sctp_set_nonblocking(udp_socket)) {
        std::cout << "Error setting non-blocking mode: " << sctp_error_string() << std::endl;
        running.store(false);
        return false;
    }

    event_loop_thread = std::thread(&SCTP_Socket::event_loop, this);
    return true;
}

void SCTP_Socket::sctp_close() {
    running.store(false);
    if (event_loop_thread.joinable()) {
        event_loop_thread.join();
    }
    if (udp_socket != INVALID_SOCKET) {
        sctp_close_socket(udp_socket);
        udp_socket = INVALID_SOCKET;
    }
    sctp_platform_cleanup();
    std::cout << "Socket closed successfully" << std::endl;
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

    std::unique_lock<std::mutex> sending_lock(sending_queue_mutex);
    sending_queue.push(init_deliv);
    sending_lock.unlock();

    return key;
}

namespace {

// Seeded from the full entropy of random_device rather than a single 32-bit
// draw. NOTE: mt19937 is not cryptographically secure — its state is
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

    return result;
}

void SCTP_Socket::remove_association(const Association_Key& key) {
    std::unique_lock<std::mutex> assoc_lock(associations_mutex);
    associations.erase(key);
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
    if (it == associations.end() || it->second.state != ESTABLISHED) {
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

    std::unique_lock<std::mutex> sending_lock(sending_queue_mutex);
    sending_queue.push(data_deliv);
    sending_lock.unlock();
}

size_t SCTP_Socket::sctp_recv_data(std::vector<uint8_t>& buffer, Association_Key* out_association_id) {
    std::unique_lock<std::mutex> assoc_lock(associations_mutex);
    for (auto& [key, assoc] : associations) {
        if (assoc.state != ESTABLISHED) {
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
    if (it == associations.end() || it->second.state != ESTABLISHED) {
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
    while (running) {
        SCTP_Packet pkt;
        std::unique_lock<std::mutex> sending_lock(sending_queue_mutex);
        if (!sending_queue.empty()) {
            handle_send_packet(sending_queue.front());
            sending_queue.pop();
        }
        sending_lock.unlock();

        uint8_t buffer[RWND];
        sockaddr_in src{};
        socklen_t src_len = sizeof(src);
        int n = recvfrom(udp_socket, reinterpret_cast<char*>(buffer), sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&src), &src_len);
        if (n > 0) {
            try {
                handle_recv_packet(buffer, static_cast<size_t>(n), src);
            } catch (const std::exception& e) {
                std::cout << "Error handling packet: " << e.what() << std::endl;
            }
        }
    }
}

void SCTP_Socket::handle_send_packet(const Deliverable& deliverable) {
    std::vector<uint8_t> serialized_packet = serialize_sctp_packet(deliverable.packet);
    const char* data = reinterpret_cast<const char*>(serialized_packet.data());
    const sockaddr* to = reinterpret_cast<const sockaddr*>(&deliverable.location.address);
    sendto(udp_socket, data, serialized_packet.size(), 0, to, sizeof(deliverable.location.address));
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
                SCTP_Socket::handle_data(in_pkt.header, in_pkt.chunks[i], src);
                break;
        }
    }
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

    std::unique_lock<std::mutex> sending_lock(sending_queue_mutex);
    sending_queue.push(init_ack_deliv);
    sending_lock.unlock();
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
    assoc.state = COOKIE_ECHOED;
    uint32_t peer_tag = assoc.peer_ver_tag;
    assoc_lock.unlock();

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

    std::unique_lock<std::mutex> sending_lock(sending_queue_mutex);
    sending_queue.push(cookie_echo_deliv);
    sending_lock.unlock();
}

void SCTP_Socket::handle_cookie_echo(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src) {
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

    std::unique_lock<std::mutex> sending_lock(sending_queue_mutex);
    sending_queue.push(cookie_ack_deliv);
    sending_lock.unlock();
}
void SCTP_Socket::handle_cookie_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src) {
    std::unique_lock<std::mutex> assoc_lock(associations_mutex);
    Association_Key assoc_key{src};
    auto it = associations.find(assoc_key);
    if (it == associations.end() || it->second.state != COOKIE_ECHOED) {
        return;
    }

    Association& assoc = it->second;
    assoc.state = ESTABLISHED;
    assoc_lock.unlock();
}
void SCTP_Socket::handle_data(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src) {
    std::unique_lock<std::mutex> assoc_lock(associations_mutex);
    Association_Key assoc_key{src};
    auto it = associations.find(assoc_key);
    if (it == associations.end() || it->second.state != ESTABLISHED) {
        return;
    }

    Association& assoc = it->second;
    uint32_t tsn = std::get<data_chunk_value>(chunk.chunk_value).tsn;
    if (tsn == assoc.last_peer_tsn + 1) {
        assoc.last_peer_tsn = tsn;
        assoc.ulp_buffer.push(std::get<data_chunk_value>(chunk.chunk_value).user_data);
        read_ooo_buffer(assoc);
    } else if (tsn_lt(assoc.last_peer_tsn + 1, tsn)) {
        assoc.tsn_ooo_buffer[tsn] = std::get<data_chunk_value>(chunk.chunk_value);
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