// SCTP_Socket lifecycle and the public API surface: construction, bind, run,
// close, association setup (RFC 9260 5.1) and the send/receive entry points
// the application calls. Everything here runs on the caller's thread, not the
// event loop.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "serialize.hpp"
#include "builders.hpp"
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
    notifications.close();
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

    // sin_port is already network order, so the builder's host-order ports need
    // ntohs, not htons.
    enqueue_packet(Deliverable{key, build_init(
        ntohs(local_address.sin_port),
        ntohs(key.address.sin_port),
        assoc.this_ver_tag,
        assoc.next_tsn
    )});
    return key;
}

Association SCTP_Socket::init_new_association(const Association_Key& key) {
    Association result{};

    result.primary_path = key.address;
    result.state = COOKIE_WAIT;

    result.this_ver_tag = generate_nonzero_tag();
    generate_random(result.next_tsn);
    result.cumulative_tsn_ack = result.next_tsn - 1;
    // Upper bounds until the INIT ACK narrows them (5.1.1).
    result.out_streams = LOCAL_OUT_STREAMS;
    result.in_streams = LOCAL_MAX_IN_STREAMS;
    result.rto = sctp_parameters::RTO_INITIAL;
    result.error_threshold = sctp_parameters::ASSOCIATION_MAX_RETRANS;
    result.pmdcs = DEFAULT_PMDCS;
    result.cwnd = std::min(4U * result.pmdcs, std::max(2U * result.pmdcs, 4380U));
    result.ssthresh = RWND;

    return result;
}

Association SCTP_Socket::init_new_association(const State_Cookie& cookie, const Association_Key& key) {
    Association result{};

    result.primary_path = key.address;
    result.state = ESTABLISHED;

    result.this_ver_tag = cookie.local_ver_tag;
    result.peer_ver_tag = cookie.peer_ver_tag;
    result.next_tsn = cookie.local_initial_tsn;
    result.cumulative_tsn_ack = cookie.local_initial_tsn - 1;
    result.last_peer_tsn = cookie.peer_initial_tsn - 1;
    result.peer_rwnd = cookie.peer_a_rwnd;
    // RFC 9260 5.1.1: each direction gets the smaller of what the two ends offered.
    result.out_streams = std::min(cookie.local_out_streams, cookie.peer_in_streams);
    result.in_streams = std::min(cookie.local_in_streams, cookie.peer_out_streams);

    result.rto = sctp_parameters::RTO_INITIAL;
    result.error_threshold = sctp_parameters::ASSOCIATION_MAX_RETRANS;
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

void SCTP_Socket::notify_assoc_change(const Association_Key& key, Assoc_Change_State state) {
    notifications.enqueue(Notification{Notification_Type::SCTP_ASSOC_CHANGE, key, 0, Assoc_Change{state}});
}

std::optional<Notification> SCTP_Socket::sctp_recv_notification(int timeout_ms) {
    if (timeout_ms <= 0) {
        return notifications.dequeue();
    }
    return notifications.wait_dequeue(std::chrono::milliseconds(timeout_ms));
}

void SCTP_Socket::sctp_subscribe(Notification_Type type, bool on) {
    notifications.set_subscribed(type, on);
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

    SCTP_Packet data_packet = build_data(
        ntohs(local_address.sin_port),
        ntohs(association_id.address.sin_port),
        it->second.peer_ver_tag,
        {data_chunk_value{
            .tsn = it->second.next_tsn++,
            .stream_identifier = 0,
            .stream_seq_num = 0,
            .payload_protocal = 0,
            .user_data = data
        }}
    );
    assoc_lock.unlock();

    Deliverable data_deliv{association_id, std::move(data_packet)};

    enqueue_packet(std::move(data_deliv), Send_Priority::NEW_DATA);
}

void SCTP_Socket::sctp_abort(const sockaddr_in& association_id, const std::vector<uint8_t>& reason) {
    Association_Key key{association_id};
    sctp_abort(key, reason);
}

void SCTP_Socket::sctp_abort(const Association_Key& association_id, const std::vector<uint8_t>& reason) {
    uint32_t peer_tag;
    size_t budget;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(association_id);
        if (it == associations.end()) {
            return;
        }
        peer_tag = it->second.peer_ver_tag;
        budget = it->second.pmdcs;
    }

    // Purge first so it drops the queued DATA that MUST NOT accompany the ABORT
    remove_association(association_id);

    // In COOKIE_WAIT there is no tag the peer would accept the ABORT under.
    if (peer_tag == 0) {
        return;
    }

    std::vector<uint8_t> abort_reason = reason;
    abort_reason.resize(std::min(abort_reason.size(), budget - 2 * SCTP_CHUNK_HEADER_SIZE));

    enqueue_packet(Deliverable{
        association_id,
        build_abort(
            ntohs(local_address.sin_port),
            ntohs(association_id.address.sin_port),
            peer_tag,
            false,
            {error_cause{CAUSE_USER_INITIATED_ABORT, std::move(abort_reason)}}
        )
    });
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
