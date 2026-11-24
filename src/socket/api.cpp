// SCTP_Socket lifecycle and the public API surface: construction, bind, run,
// close, association setup and the send/receive entry points
// the application calls. Everything here runs on the caller's thread, not the
// event loop.

#include <sctp/socket.hpp>
#include <sctp/platform/compat.hpp>
#include "protocol/serialize.hpp"
#include "protocol/builders.hpp"
#include "socket/internal.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <mutex>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {
    sctp_socket_t open_udp_socket() {
        sctp_socket_t udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udp == INVALID_SOCKET) {
            std::cerr << "Error creating socket: " << sctp_error_string() << std::endl;
            return udp;
        }
        if (!sctp_set_nonblocking(udp)) {
            std::cerr << "Error setting non-blocking mode: " << sctp_error_string() << std::endl;
            sctp_close_socket(udp);
            return INVALID_SOCKET;
        }
        if (!sctp_set_dont_fragment(udp, true)) {
            std::cerr << "Error setting DF: " << sctp_error_string() << std::endl;
        }
#ifdef __linux__
        if (!sctp_enable_icmp_errors(udp)) {
            std::cerr << "Error enabling ICMP errors: " << sctp_error_string() << std::endl;
        }
#endif
        return udp;
    }
}

SCTP_Socket::SCTP_Socket() : udp_socket(INVALID_SOCKET) {
    if (!sctp_platform_startup()) {
        std::cerr << "Socket subsystem initialization failed" << std::endl;
        return;
    }
    platform_started = true;

    udp_socket = open_udp_socket();
    if (udp_socket == INVALID_SOCKET) {
        sctp_platform_cleanup();
        platform_started = false;
    }
}

bool SCTP_Socket::sctp_bind(std::string_view ip_address, int port) {
    return sctp_bindx({std::string(ip_address)}, port);
}

bool SCTP_Socket::sctp_bindx(const std::vector<std::string>& ip_addresses, int port) {
    if (udp_socket == INVALID_SOCKET || ip_addresses.empty() || running.load()) {
        return false;
    }
    std::vector<sockaddr_in> addresses;
    for (const std::string& ip_address : ip_addresses) {
        sockaddr_in service{};
        service.sin_family = AF_INET;
        service.sin_port = htons(port);
        if (!sctp_parse_ipv4(ip_address, service.sin_addr)) {
            return false;
        }
        if (service.sin_addr.s_addr == INADDR_ANY && ip_addresses.size() > 1) {
            return false;
        }
        addresses.push_back(service);
    }

    auto fail = [&](const char* what) {
        std::cerr << what << sctp_error_string() << std::endl;
        for (const Local_Address& other : other_local_addresses) {
            sctp_close_socket(other.socket);
        }
        other_local_addresses.clear();
        sctp_close_socket(udp_socket);
        udp_socket = INVALID_SOCKET;
        sctp_platform_cleanup();
        platform_started = false;
        return false;
    };

    if (bind(udp_socket, reinterpret_cast<const sockaddr*>(&addresses[0]), sizeof(addresses[0])) == SOCKET_ERROR) {
        return fail("Error binding socket: ");
    }
    socklen_t length = sizeof(local_address);
    if (getsockname(udp_socket, reinterpret_cast<sockaddr*>(&local_address), &length) == SOCKET_ERROR) {
        return fail("Error reading bound address: ");
    }
    for (auto address = addresses.begin() + 1; address != addresses.end(); ++address) {
        address->sin_port = local_address.sin_port;
        sctp_socket_t other = open_udp_socket();
        if (other == INVALID_SOCKET) {
            return fail("Error creating socket: ");
        }
        other_local_addresses.push_back(Local_Address{*address, other});
        if (bind(other, reinterpret_cast<const sockaddr*>(&*address), sizeof(*address)) == SOCKET_ERROR) {
            return fail("Error binding socket: ");
        }
    }
    return true;
}

std::vector<in_addr> SCTP_Socket::advertised_addresses() const {
    if (other_local_addresses.empty()) {
        return {};
    }
    std::vector<in_addr> addresses{local_address.sin_addr};
    for (const Local_Address& other : other_local_addresses) {
        addresses.push_back(other.address.sin_addr);
    }
    return addresses;
}

SCTP_Socket::~SCTP_Socket() {
    sctp_close();
}

bool SCTP_Socket::sctp_run() {
    if (running.load() || udp_socket == INVALID_SOCKET) {
        return false;
    }

    if (!wakeup.open()) {
        std::cerr << "Error creating event-loop wakeup sockets: " << sctp_error_string() << std::endl;
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
    if (running.load()) {
        close_associations();
    }
    running.store(false);
    if (event_loop_thread.joinable()) {
        wake_event_loop();
        event_loop_thread.join();
    }
    expirations.clear();
    sends.clear();
    receives.clear();
    wakeup.close();
    if (udp_socket != INVALID_SOCKET) {
        sctp_close_socket(udp_socket);
        udp_socket = INVALID_SOCKET;
    }
    for (const Local_Address& other : other_local_addresses) {
        sctp_close_socket(other.socket);
    }
    other_local_addresses.clear();
    if (platform_started) {
        sctp_platform_cleanup();
        platform_started = false;
    }
}

// The event loop keeps running until the ABORTs are on the wire.
void SCTP_Socket::close_associations() {
    std::vector<Association_Key> keys;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        keys = associations | std::views::keys | std::ranges::to<std::vector>();
    }
    for (const auto& key : keys) {
        sctp_abort(key);
    }
    auto drain_deadline = std::chrono::steady_clock::now() + CLOSE_DRAIN_TIMEOUT;
    while (sends.size() != 0 && std::chrono::steady_clock::now() < drain_deadline) {
        std::this_thread::sleep_for(CLOSE_POLL_INTERVAL);
    }
}

Sctp_Status SCTP_Socket::sctp_associate(std::string_view ip_address, int sctp_port, Association_Key& out_association_id, std::optional<int> udp_port) {
    if (!running.load()) {
        return Sctp_Status::NOT_RUNNING;
    }

    sockaddr_in udp_address{};
    udp_address.sin_family = AF_INET;
    if (!sctp_parse_ipv4(ip_address, udp_address.sin_addr)) {
        return Sctp_Status::INVALID_ADDRESS;
    }
    udp_address.sin_port = htons(udp_port.value_or(sctp_port));
    uint16_t peer_sctp_port = static_cast<uint16_t>(sctp_port);

    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    if (associations.contains(association_at(peer_key(udp_address, peer_sctp_port)))) {
        return Sctp_Status::ASSOCIATION_EXISTS;
    }
    Association_Key key{next_association_id++};
    Association_TCB& assoc = associations.emplace(key, init_new_association(udp_address, peer_sctp_port)).first->second;
    add_peer_addresses(key, assoc, {udp_address});
    enqueue_packet(Deliverable{key, assoc.paths.primary, build_init(ntohs(local_address.sin_port), assoc.peer.sctp_port,
        assoc.peer.this_ver_tag, assoc.send.next_tsn, 0, advertised_addresses())});
    out_association_id = key;
    return Sctp_Status::OK;
}

Association_TCB SCTP_Socket::init_new_association(const sockaddr_in& udp_address, uint16_t peer_sctp_port) {
    Association_TCB result{};
    result.peer.sctp_port = peer_sctp_port;

    result.paths.list = {make_path(udp_address, true)};
    result.paths.primary = udp_address;

    result.peer.this_ver_tag = generate_nonzero_tag();
    generate_random(result.send.next_tsn);
    result.send.cumulative_tsn_ack = result.send.next_tsn - 1;
    result.send.out_streams = LOCAL_OUT_STREAMS;
    result.receive.in_streams = LOCAL_MAX_IN_STREAMS;
    result.send.next_ssn.assign(result.send.out_streams, 0);
    return result;
}

// The cookie's other addresses are left to add_peer_addresses, which indexes them.
Association_TCB SCTP_Socket::init_new_association(const State_Cookie& cookie) {
    Association_TCB result = init_new_association(cookie_source(cookie), cookie.sctp_src_port);
    result.state = ESTABLISHED;
    result.peer.this_ver_tag = cookie.local_ver_tag;
    result.peer.peer_ver_tag = cookie.peer_ver_tag;
    result.send.next_tsn = cookie.local_initial_tsn;
    result.send.cumulative_tsn_ack = cookie.local_initial_tsn - 1;
    result.receive.last_peer_tsn = cookie.peer_initial_tsn - 1;
    result.send.peer_rwnd = cookie.peer_a_rwnd;
    result.send.peer_max_rwnd = cookie.peer_a_rwnd;
    result.send.out_streams = std::min(cookie.local_out_streams, cookie.peer_in_streams);
    result.receive.in_streams = std::min(cookie.local_in_streams, cookie.peer_out_streams);
    result.send.next_ssn.assign(result.send.out_streams, 0);
    return result;
}

Association_TCB* SCTP_Socket::find_tcb(const Association_Key& key) {
    auto it = associations.find(key);
    return it == associations.end() ? nullptr : &it->second;
}

Association_Key SCTP_Socket::association_at(const Peer_Key& peer) {
    auto found = peer_addresses.find(peer);
    return found == peer_addresses.end() ? Association_Key{} : found->second;
}

void SCTP_Socket::add_peer_addresses(const Association_Key& key, Association_TCB& assoc, const std::vector<sockaddr_in>& addresses) {
    for (const sockaddr_in& address : addresses) {
        if (find_path(assoc, address) == nullptr) {
            assoc.paths.list.push_back(make_path(address, false));
        }
        peer_addresses.emplace(peer_key(address, assoc.peer.sctp_port), key);
    }
}

void SCTP_Socket::record_arrival(const Association_Key& key, const sockaddr_in& src, in_addr local) {
    Association_TCB* assoc = find_tcb(key);
    if (Peer_Path* path = assoc ? find_path(*assoc, src) : nullptr) {
        path->udp_address.sin_port = src.sin_port;
        path->source = local;
    }
}

// An address another association already held stays that association's.
void SCTP_Socket::forget_peer_addresses(const Association_Key& key, const Association_TCB& assoc) {
    for (const Peer_Path& path : assoc.paths.list) {
        auto found = peer_addresses.find(peer_key(path.udp_address, assoc.peer.sctp_port));
        if (found != peer_addresses.end() && found->second == key) {
            peer_addresses.erase(found);
        }
    }
}

void SCTP_Socket::remove_association(const Association_Key& key, std::optional<Assoc_Change_State> state) {
    if (Association_TCB* assoc = find_tcb(key)) {
        abandon_partial_delivery(key, assoc->receive);
        forget_peer_addresses(key, *assoc);
        associations.erase(key);
    }
    cancel_expirations(key);
    sends.purge(key);
    if (state) {
        notify_assoc_change(key, *state);
    }
}

void SCTP_Socket::notify_assoc_change(const Association_Key& key, Assoc_Change_State state) {
    notifications.enqueue(Notification{Notification_Type::SCTP_ASSOC_CHANGE, key, Assoc_Change{state}});
}

void SCTP_Socket::abandon_partial_delivery(const Association_Key& key, const TCB_Receive_Side& receive) {
    if (receive.reassembly.open && receive.reassembly.partially_delivered) {
        receives.abandon_open(key);
    }
}

void SCTP_Socket::notify_peer_addr_change(const Association_Key& key, const sockaddr_in& address, Peer_Addr_State state) {
    sockaddr_in transport_address = address;
    if (const Association_TCB* assoc = find_tcb(key)) {
        transport_address.sin_port = htons(assoc->peer.sctp_port);
    }
    notifications.enqueue(Notification{Notification_Type::SCTP_PEER_ADDR_CHANGE, key, Peer_Addr_Change{transport_address, state}});
}

namespace {
    Sctp_Status refusal_in(Association_State state) {
        return is_forming(state) ? Sctp_Status::NOT_ESTABLISHED : Sctp_Status::SHUTTING_DOWN;
    }
}

Sctp_Status SCTP_Socket::sctp_change_heartbeat(const Association_Key& association_id, const sockaddr_in& destination, bool enabled, std::optional<std::chrono::milliseconds> interval) {
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    Association_TCB* assoc = find_tcb(association_id);
    if (assoc == nullptr) {
        return Sctp_Status::NO_ASSOCIATION;
    }
    Peer_Path* changed = find_path(*assoc, destination);
    if (changed == nullptr) {
        return Sctp_Status::UNKNOWN_DESTINATION;
    }
    changed->hb_enabled = enabled;
    if (interval) {
        assoc->paths.hb_interval = *interval;
    }
    if (!transmits_data(assoc->state)) {
        return Sctp_Status::OK;
    }

    auto now = std::chrono::steady_clock::now();
    for (Peer_Path& path : assoc->paths.list) {
        if (&path != changed && !interval) {
            continue;
        }
        if (!path.hb_outstanding) {
            plan_next_probe(*assoc, path, now);
            if (probes_for_confirmation(*assoc, path)) {
                path.hb_next = now;
            }
        }
        arm_heartbeat(association_id, *assoc, path);
    }
    arm_confirmation_probes(association_id, *assoc);
    return Sctp_Status::OK;
}

Sctp_Status SCTP_Socket::sctp_request_heartbeat(const Association_Key& association_id, const sockaddr_in& destination) {
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    Association_TCB* assoc = find_tcb(association_id);
    if (assoc == nullptr) {
        return Sctp_Status::NO_ASSOCIATION;
    }
    Peer_Path* path = find_path(*assoc, destination);
    if (path == nullptr) {
        return Sctp_Status::UNKNOWN_DESTINATION;
    }
    if (!transmits_data(assoc->state)) {
        return refusal_in(assoc->state);
    }
    enqueue_packet(build_probe(association_id, *assoc, *path));
    arm_heartbeat(association_id, *assoc, *path);
    return Sctp_Status::OK;
}

Sctp_Status SCTP_Socket::sctp_set_primary(const Association_Key& association_id, const sockaddr_in& destination) {
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    Association_TCB* assoc = find_tcb(association_id);
    if (assoc == nullptr) {
        return Sctp_Status::NO_ASSOCIATION;
    }
    const Peer_Path* path = find_path(*assoc, destination);
    if (path == nullptr) {
        return Sctp_Status::UNKNOWN_DESTINATION;
    }
    if (!path->confirmed) {
        return Sctp_Status::UNCONFIRMED_DESTINATION;
    }
    assoc->paths.primary = path->udp_address;
    return Sctp_Status::OK;
}

std::optional<Notification> SCTP_Socket::sctp_recv_notification() {
    return notifications.dequeue();
}

Sctp_Status SCTP_Socket::sctp_send_data(const Association_Key& association_id, const std::vector<uint8_t>& data, uint16_t stream, bool unordered, uint32_t ppid) {
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    Association_TCB* assoc = find_tcb(association_id);
    if (assoc == nullptr) {
        return Sctp_Status::NO_ASSOCIATION;
    }
    if (assoc->state != ESTABLISHED) {
        return refusal_in(assoc->state);
    }
    if (data.empty()) {
        return Sctp_Status::EMPTY_MESSAGE;
    }
    if (stream >= assoc->send.out_streams) {
        return Sctp_Status::INVALID_STREAM;
    }
    if (!assoc->send.outbound.empty() && assoc->send.outbound_bytes + data.size() > SEND_BUFFER) {
        return Sctp_Status::QUEUE_FULL;
    }
    uint16_t ssn = unordered ? 0 : assoc->send.next_ssn[stream]++;
    assoc->send.outbound.push_back(Outbound_Message{stream, ssn, unordered, data, 0, ppid});
    assoc->send.outbound_bytes += data.size();
    wake_event_loop();
    return Sctp_Status::OK;
}

// The association is removed before the ABORT is queued so the purge drops the
// DATA that must not accompany it. In COOKIE_WAIT there is no peer tag to send
// the ABORT under, so the association simply goes.
Sctp_Status SCTP_Socket::sctp_abort(const Association_Key& association_id, const std::vector<uint8_t>& reason) {
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    Association_TCB* assoc = find_tcb(association_id);
    if (assoc == nullptr) {
        return Sctp_Status::NO_ASSOCIATION;
    }
    uint32_t peer_tag = assoc->peer.peer_ver_tag;
    sockaddr_in destination = data_path(*assoc).udp_address;
    size_t room = amdcs(*assoc) - 2 * SCTP_CHUNK_HEADER_SIZE;
    std::vector<uint8_t> abort_reason(reason.begin(), reason.begin() + static_cast<long>(std::min(reason.size(), room)));
    SCTP_Packet abort = packet_to(*assoc, ABORT, error_chunk_value{{error_cause{CAUSE_USER_INITIATED_ABORT, std::move(abort_reason)}}});

    remove_association(association_id);

    if (peer_tag != 0) {
        enqueue_packet(Deliverable{association_id, destination, std::move(abort)});
    }
    return Sctp_Status::OK;
}

size_t SCTP_Socket::sctp_recv_data(std::vector<uint8_t>& buffer, Association_Key* out_association_id, bool* out_partial, uint16_t* out_stream, uint32_t* out_ppid) {
    return finish_read(receives.read_any(buffer.data(), buffer.size()), out_association_id, out_partial, out_stream, out_ppid);
}

size_t SCTP_Socket::sctp_recv_data_from(const Association_Key& association_id, std::vector<uint8_t>& buffer, bool* out_partial, uint16_t* out_stream, uint32_t* out_ppid) {
    return finish_read(receives.read_from(association_id, buffer.data(), buffer.size()), nullptr, out_partial, out_stream, out_ppid);
}

size_t SCTP_Socket::finish_read(const std::optional<Receive_Queue::Read>& read, Association_Key* out_association_id, bool* out_partial, uint16_t* out_stream, uint32_t* out_ppid) {
    if (!read) {
        return 0;
    }
    if (out_association_id) {
        *out_association_id = read->key;
    }
    if (out_partial) {
        *out_partial = read->partial;
    }
    if (out_stream) {
        *out_stream = read->stream;
    }
    if (out_ppid) {
        *out_ppid = read->ppid;
    }
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    maybe_send_window_update(read->key);
    return read->bytes;
}

// An association still forming has nothing to close gracefully: as on Linux, it
// is dropped without a word to the peer and without a notification.
Sctp_Status SCTP_Socket::sctp_shutdown(const Association_Key& association_id) {
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    Association_TCB* assoc = find_tcb(association_id);
    if (assoc == nullptr) {
        return Sctp_Status::NO_ASSOCIATION;
    }
    if (is_forming(assoc->state)) {
        remove_association(association_id);
        return Sctp_Status::OK;
    }
    if (assoc->state != ESTABLISHED) {
        return Sctp_Status::SHUTTING_DOWN;
    }
    assoc->state = SHUTDOWN_PENDING;
    do_next_shutdown_step(association_id);
    return Sctp_Status::OK;
}
