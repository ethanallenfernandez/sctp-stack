// The event loop thread: poll() over the UDP sockets and the wakeup pair, drain
// expired timers, send one queued packet per pass, receive in batches. Also the
// wrappers that wake the loop after touching the send or expiration queues.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "serialize.hpp"
#include "socket_internal.hpp"

#include <algorithm>
#include <chrono>
#include <climits>
#include <iostream>
#include <mutex>
#include <ranges>
#include <stdexcept>
#include <vector>

void SCTP_Socket::event_loop() {
    std::vector<Local_Address> locals{Local_Address{local_address, udp_socket}};
    locals.append_range(other_local_addresses);
    std::vector<sctp_pollfd> descriptors(1 + locals.size());
    auto polled_locals = std::views::zip(descriptors | std::views::drop(1), locals);
    while (running.load()) {
        descriptors[0] = sctp_pollfd{};
        descriptors[0].fd = wakeup.poll_handle();
        descriptors[0].events = SCTP_POLL_READ;
        for (auto&& [descriptor, local] : polled_locals) {
            descriptor = sctp_pollfd{};
            descriptor.fd = local.socket;
            descriptor.events = SCTP_POLL_READ;
        }

        int ready = sctp_poll(descriptors.data(), descriptors.size(), next_poll_timeout());
        if (ready == SOCKET_ERROR) {
            int err = sctp_last_error();
            if (sctp_error_interrupted(err)) {
                continue;
            }
            std::cerr << "Error polling socket: " << sctp_error_string(err) << std::endl;
            running.store(false);
            break;
        }

        if ((descriptors[0].revents & SCTP_POLL_READ) != 0) {
            wakeup.drain();
        }
        if ((descriptors[0].revents & (SCTP_POLL_ERROR | SCTP_POLL_FATAL)) != 0) {
            std::cerr << "Event-loop wakeup poll reported an error" << std::endl;
            running.store(false);
            break;
        }
        if (!running.load()) {
            break;
        }

        bool fatal = false;
        for (auto&& [descriptor, local] : polled_locals) {
            short revents = descriptor.revents;
            if ((revents & SCTP_POLL_ERROR) != 0) {
                run_icmp_errors(local.socket);
            }
            if ((revents & (SCTP_POLL_READ | SCTP_POLL_ERROR)) != 0) {
                run_receiving(local.socket, local.address.sin_addr);
            }
            fatal = fatal || (revents & SCTP_POLL_FATAL) != 0;
        }
        if (fatal) {
            std::cerr << "Socket poll reported a fatal error" << std::endl;
            running.store(false);
            break;
        }

        run_expire();
        run_sending();
    }
}

void SCTP_Socket::run_expire() {
    std::vector<Expiration_Fallback> expired =
        expirations.drain_expired(std::chrono::steady_clock::now());

    for (const auto& fallback : expired) {
        try {
            handle_expiration(fallback);
        } catch (const std::exception& e) {
            std::cerr << "Error handling timer expiration: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "Error handling timer expiration" << std::endl;
        }
    }
}

namespace {
    // A no-op unless cwnd is above 4 * PMDCS: the decay is never allowed to
    // raise cwnd, as it would after a T3-rtx expiry left cwnd at one PMDCS.
    void decay_idle_cwnd(Peer_Path& path, std::chrono::steady_clock::time_point now) {
        if (path.rto.count() <= 0 || now - path.data_sent_at < path.rto) {
            return;
        }
        auto periods = (now - path.data_sent_at) / path.rto;
        path.data_sent_at += periods * path.rto;
        uint32_t floor = 4 * pmdcs(path);
        if (path.cwnd <= floor) {
            return;
        }
        if (!path.idle_decaying) {
            path.ssthresh = path.cwnd;
            path.idle_decaying = true;
        }
        for (; periods > 0 && path.cwnd > floor; --periods) {
            path.cwnd = std::max(path.cwnd / 2, floor);
        }
    }

    // One packet of new DATA from the head of the outbound queue, bundling
    // messages while they fit the PMDCS and the peer's window. A message is
    // fragmented only if it cannot fit a packet of its own, and a fragment is cut
    // short to fit the window only if it would still fill half the largest
    // window the peer has offered.
    std::vector<data_chunk_value> cut_new_data(Association& assoc, Send_Allowance& allowance) {
        std::vector<data_chunk_value> chunks;
        size_t chunk_limit = amdcs(assoc);
        size_t full_fragment = (chunk_limit - DATA_CHUNK_HEADER_SIZE) & ~size_t{3};
        size_t packet_bytes = 0;
        while (!assoc.outbound.empty()) {
            Outbound_Message& message = assoc.outbound.front();
            size_t remaining = message.bytes.size() - message.offset;
            size_t take = std::min(remaining, full_fragment);
            size_t space = chunk_limit - packet_bytes;
            bool probe = allowance.zero_window_probe && chunks.empty();
            size_t window = probe ? space : std::min<size_t>(space, allowance.rwnd > packet_bytes ? allowance.rwnd - packet_bytes : 0);
            auto wire_size = [](size_t payload) { return DATA_CHUNK_HEADER_SIZE + ((payload + 3) & ~size_t{3}); };

            if (wire_size(take) > window) {
                size_t cut = window > DATA_CHUNK_HEADER_SIZE ? (window - DATA_CHUNK_HEADER_SIZE) & ~size_t{3} : 0;
                bool fragmenting = message.bytes.size() > full_fragment;
                if (!fragmenting || cut == 0 || wire_size(cut) < assoc.peer_max_rwnd / 2) {
                    if (chunks.empty()) {
                        allowance.rwnd_blocked = true;
                    }
                    break;
                }
                take = cut;
            }

            uint8_t flags = (message.offset == 0 ? DATA_FLAG_B : 0)
                | (message.offset + take == message.bytes.size() ? DATA_FLAG_E : 0)
                | (message.unordered ? DATA_FLAG_U : 0);
            auto begin = message.bytes.begin() + static_cast<long>(message.offset);
            chunks.push_back(data_chunk_value{
                .tsn = assoc.next_tsn++,
                .stream_identifier = message.stream,
                .stream_seq_num = message.ssn,
                .payload_protocal = message.ppid,
                .user_data = std::vector<uint8_t>(begin, begin + static_cast<long>(take)),
                .flags = flags,
            });
            packet_bytes += wire_size(take);
            message.offset += take;
            assoc.outbound_bytes -= take;
            if (message.offset == message.bytes.size()) {
                assoc.outbound.pop_front();
            }
            if (probe) {
                break;
            }
        }
        return chunks;
    }
}

void SCTP_Socket::run_sending() {
    start_transmission_opportunity();
    for (size_t sent = 0; sent < MAX_SEND_BATCH; ++sent) {
        std::optional<Send_Queue::Pending> pending = next_packet();
        if (!pending) {
            return;
        }
        // handle_send_packet must not run under the send queue's lock.
        if (!handle_send_packet(pending->deliverable)) {
            sends.defer(std::chrono::steady_clock::now() + SEND_RETRY_DELAY);
            requeue_bundled_sack(*pending);
            return;
        }
        packet_sent(*pending);
    }
}

std::optional<Send_Queue::Pending> SCTP_Socket::next_packet() {
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    Send_Allowances allowances = send_allowances();
    refill_retransmissions(allowances);
    refill_new_data(allowances);
    std::optional<Send_Queue::Pending> pending = sends.peek(std::chrono::steady_clock::now(), allowances);
    arm_zero_window_probes(allowances);
    if (pending && pending->priority != Send_Priority::CONTROL) {
        prepare_data_packet(pending->deliverable, pending->priority == Send_Priority::NEW_DATA);
    }
    return pending;
}

void SCTP_Socket::packet_sent(const Send_Queue::Pending& pending) {
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    sends.commit(pending);
    schedule_expirations_after_send(pending.deliverable, std::chrono::steady_clock::now());
    Association* assoc = find_tcb(pending.deliverable.location);
    if (assoc != nullptr && pending.priority == Send_Priority::NEW_DATA) {
        ++assoc->burst_count;
    }
}

// The queued copy of a packet never carries the SACK prepare_data_packet
// bundled into it, so a failed send would otherwise lose that SACK.
void SCTP_Socket::requeue_bundled_sack(const Send_Queue::Pending& pending) {
    const auto& chunks = pending.deliverable.packet.chunks;
    if (pending.priority == Send_Priority::CONTROL || chunks.empty() || chunks.front().chunk_header.type != SACK) {
        return;
    }
    SCTP_Packet sack;
    sack.header = pending.deliverable.packet.header;
    sack.chunks.push_back(chunks.front());
    enqueue_packet(Deliverable{pending.deliverable.location, pending.deliverable.destination, std::move(sack)});
}

// Max.Burst (6.1 D) is applied by counting the new-DATA packets each association
// sends in one pass of the send loop, rather than by clamping cwnd.
void SCTP_Socket::start_transmission_opportunity() {
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    for (auto& assoc : associations | std::views::values) {
        assoc.burst_count = 0;
    }
}

Send_Allowances SCTP_Socket::send_allowances() {
    Send_Allowances allowances;
    auto now = std::chrono::steady_clock::now();
    for (auto& [key, assoc] : associations) {
        if (!transmits_data(assoc.state)) {
            continue;
        }
        for (Peer_Path& path : assoc.peer_address_list) {
            decay_idle_cwnd(path, now);
        }
        size_t flight_size = bytes_in_flight(assoc);
        allowances.emplace(key, Send_Allowance{
            .flight_size = flight_size,
            .cwnd_open = cwnd_open(assoc, data_path(assoc)),
            .burst_spent = assoc.burst_count >= sctp_parameters::MAX_BURST,
            .rwnd = assoc.peer_rwnd,
            .zero_window_probe = assoc.zero_window_probe_allowed && flight_size == 0,
        });
    }
    return allowances;
}

// Sets the I bit on the last DATA chunk when the packet fills the congestion or
// receiver window, or in SHUTDOWN-PENDING, so the SACK that reopens the window
// or completes the shutdown is not delayed. Also bundles a SACK that is being
// delayed, sending it on its own instead when the packet has no room for it.
void SCTP_Socket::prepare_data_packet(Deliverable& deliverable, bool new_data) {
    auto& chunks = deliverable.packet.chunks;
    auto last_data = std::ranges::find_last_if(chunks, [](const SCTP_Chunk& chunk) {
        return chunk.chunk_header.type == DATA;
    }).begin();
    if (last_data == chunks.end()) {
        return;
    }

    Association* assoc = find_tcb(deliverable.location);
    if (assoc == nullptr) {
        return;
    }
    const Peer_Path* path = find_path(*assoc, deliverable.destination);
    const Peer_Path& sent_on = path != nullptr ? *path : primary(*assoc);
    size_t data_size = 0;
    for (const auto& chunk : chunks) {
        if (chunk.chunk_header.type == DATA) {
            data_size += data_chunk_wire_size(std::get<data_chunk_value>(chunk.chunk_value));
        }
    }
    size_t flight_after = bytes_in_flight(*assoc, &sent_on) + (new_data ? data_size : 0);
    if (flight_after >= sent_on.cwnd || data_size >= assoc->peer_rwnd || assoc->state == SHUTDOWN_PENDING) {
        last_data->chunk_header.flag |= DATA_IMMEDIATE_SACK_FLAG;
    }
    Expiration_Key delayed_sack{deliverable.location, Expiration_Timer_Type::DELAYED_SACK};
    if (!expirations.is_active(delayed_sack) || !receives_data(assoc->state)) {
        return;
    }

    SCTP_Packet sack = make_sack(deliverable.location, *assoc);
    cancel_expiration(delayed_sack);
    size_t sack_size = serialize_sctp_packet(sack).size() - SCTP_COMMON_HEADER_SIZE;
    if (serialize_sctp_packet(deliverable.packet).size() + sack_size <= SCTP_COMMON_HEADER_SIZE + pmdcs(sent_on)) {
        chunks.insert(chunks.begin(), std::move(sack.chunks.front()));
    } else {
        enqueue_packet(Deliverable{deliverable.location, deliverable.destination, std::move(sack)});
    }
}

// Chunks marked for retransmission go out one packet at a time as their
// destination's cwnd allows, each built only once there is room for it. The
// packet T3-rtx or a Fast Retransmit sends first is queued by them directly,
// and is not held here.
void SCTP_Socket::refill_retransmissions(const Send_Allowances& allowances) {
    for (const auto& key : allowances | std::views::keys) {
        if (!sends.has_retransmission_for(key)) {
            schedule_pending_retransmission(key, true);
        }
    }
}

// TSNs are assigned here rather than when the ULP sends, so a packet is cut
// against the window as it stands. At most one is built ahead per association,
// which keeps each association's TSNs on the wire in order.
void SCTP_Socket::refill_new_data(Send_Allowances& allowances) {
    for (auto& [key, allowance] : allowances) {
        if (!allowance.cwnd_open || allowance.burst_spent || sends.has_new_data_for(key)) {
            continue;
        }
        Association* assoc = find_tcb(key);
        std::vector<data_chunk_value> chunks = assoc ? cut_new_data(*assoc, allowance) : std::vector<data_chunk_value>{};
        if (!chunks.empty()) {
            sends.enqueue(Deliverable{key, data_path(*assoc).address,
                build_data(ntohs(local_address.sin_port), ntohs(key.address.sin_port), assoc->peer_ver_tag, std::move(chunks))}, Send_Priority::NEW_DATA);
        }
    }
}

// 6.1 A: the first probe goes one RTO after the window is found closed with
// nothing in flight. T3-rtx then retransmits it with exponential backoff.
void SCTP_Socket::arm_zero_window_probes(const Send_Allowances& allowances) {
    for (const auto& [key, allowance] : allowances) {
        if (!allowance.rwnd_blocked || allowance.flight_size != 0) {
            continue;
        }
        Expiration_Key timer{key, Expiration_Timer_Type::ZERO_WINDOW_PROBE};
        Association* assoc = find_tcb(key);
        if (!expirations.is_active(timer) && assoc != nullptr && !assoc->zero_window_probe_allowed) {
            schedule_expiration(timer, std::chrono::steady_clock::now() + data_path(*assoc).rto);
        }
    }
}

void SCTP_Socket::run_receiving(sctp_socket_t socket, in_addr local) {
    for (size_t received_packets = 0; received_packets < MAX_RECEIVE_BATCH; ++received_packets) {
        uint8_t buffer[MAX_UDP_DATAGRAM];
        sockaddr_in src{};
        socklen_t src_len = sizeof(src);
        int n = recvfrom(socket, reinterpret_cast<char*>(buffer), sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&src), &src_len);
        if (n == SOCKET_ERROR) {
            int err = sctp_last_error();
            if (!sctp_error_would_block(err)) {
                std::cerr << "Error receiving packet: " << sctp_error_string(err) << std::endl;
            }
            return;
        }
        if (n == 0) {
            return;
        }
        try {
            handle_recv_packet(buffer, static_cast<size_t>(n), src, local);
        } catch (const std::exception& e) {
            std::cerr << "Error handling packet: " << e.what() << std::endl;
        }
    }
}

// Wraps enqueue only to wake the loop, which may be in poll() with no deadline.

void SCTP_Socket::enqueue_packet(Deliverable deliverable, Send_Priority priority) {
    if (deliverable.source.s_addr == INADDR_ANY && inbound_datagram != nullptr
            && same_destination(deliverable.destination, inbound_datagram->src)) {
        deliverable.source = inbound_datagram->local;
    }
    sends.enqueue(std::move(deliverable), priority);
    wake_event_loop();
}

// On SCTP_Socket rather than inline at each site: every scheduling path ends here.

void SCTP_Socket::wake_event_loop() {
    wakeup.wake();
}

int SCTP_Socket::next_poll_timeout() {
    auto send_attempt = sends.next_deadline();
    auto expiration = expirations.next_deadline();
    if (!send_attempt && !expiration) {
        return -1;
    }
    auto never = std::chrono::steady_clock::time_point::max();
    auto deadline = std::min(send_attempt.value_or(never), expiration.value_or(never));
    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
    return static_cast<int>(std::clamp<std::chrono::milliseconds::rep>(remaining.count(), 0, INT_MAX));
}

sctp_socket_t SCTP_Socket::sending_socket(const Deliverable& deliverable) {
    if (other_local_addresses.empty()) {
        return udp_socket;
    }
    in_addr source = deliverable.source;
    if (source.s_addr == INADDR_ANY) {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        Association* assoc = find_tcb(deliverable.location);
        const Peer_Path* path = assoc ? find_path(*assoc, deliverable.destination) : nullptr;
        if (path != nullptr) {
            source = path->source;
        }
    }
    for (const Local_Address& other : other_local_addresses) {
        if (other.address.sin_addr.s_addr == source.s_addr) {
            return other.socket;
        }
    }
    return udp_socket;
}

// A packet too big to leave with DF set counts as sent and lost: retrying
// cannot help, and a probe's loss is what the search learns from.
bool SCTP_Socket::handle_send_packet(const Deliverable& deliverable) {
    std::vector<uint8_t> serialized_packet = serialize_sctp_packet(deliverable.packet);
    const char* data = reinterpret_cast<const char*>(serialized_packet.data());
    const sockaddr* to = reinterpret_cast<const sockaddr*>(&deliverable.destination);
    sctp_socket_t socket = sending_socket(deliverable);
    if (deliverable.ip_fragment) {
        sctp_set_dont_fragment(socket, false);
    }
    int sent = sendto(socket, data, serialized_packet.size(), 0, to, sizeof(deliverable.destination));
    int err = sctp_last_error();
    if (deliverable.ip_fragment) {
        sctp_set_dont_fragment(socket, true);
    }

    if (sent == SOCKET_ERROR && sctp_error_too_big(err)) {
        return true;
    }
    if (sent == SOCKET_ERROR || static_cast<size_t>(sent) != serialized_packet.size()) {
        sctp_set_last_error(err);
        std::cerr << "Error sending packet: " << sctp_error_string() << std::endl;
        return false;
    }
    return true;
}

void SCTP_Socket::schedule_expirations_after_send(const Deliverable& deliverable, std::chrono::steady_clock::time_point sent_at) {
    bool sent_data = false;
    for (const auto& chunk : deliverable.packet.chunks) {
        Chunk_Type type = chunk.chunk_header.type;
        switch (type) {
            // A heartbeat arms no timer of its own: its path's is already
            // running. It is timestamped here rather than at build time so the RTT
            // it measures excludes however long the packet sat in the send queue.
            case HEARTBEAT:
                record_heartbeat_sent(deliverable.location, deliverable.destination,
                    std::get<heartbeat_chunk_value>(chunk.chunk_value).info, sent_at);
                break;
            case DATA:
                record_data_sent(deliverable.location, deliverable.destination, std::get<data_chunk_value>(chunk.chunk_value), sent_at);
                sent_data = true;
                break;
            case INIT:
            case COOKIE_ECHO: {
                bool is_init = type == INIT;
                Association* assoc = find_tcb(deliverable.location);
                if (assoc == nullptr || assoc->state != (is_init ? COOKIE_WAIT : COOKIE_ECHOED)) {
                    break;
                }
                std::chrono::milliseconds delay = sctp_parameters::RTO_INITIAL;
                uint16_t retransmits = is_init ? assoc->init_retransmits : assoc->cookie_retransmits;
                for (uint16_t i = 0; i < retransmits && delay < sctp_parameters::RTO_MAX; ++i) {
                    delay = std::min(delay * 2, sctp_parameters::RTO_MAX);
                }
                schedule_expiration(Expiration_Key{deliverable.location, is_init ? Expiration_Timer_Type::T1_INIT : Expiration_Timer_Type::T1_COOKIE},
                    sent_at + delay, deliverable);
                break;
            }
            default:
                break;
        }
    }

    if (sent_data) {
        start_t3_if_stopped(deliverable.location, deliverable.destination);
    }
}

// These wrap Expiration_Queue only to wake the loop: its poll() deadline goes
// stale the moment the heap changes. The wake must be outside the queue's lock.

void SCTP_Socket::schedule_expiration(const Expiration_Key& key, std::chrono::steady_clock::time_point expiration, const Deliverable& retry) {
    expirations.schedule(key, expiration, retry);
    wake_event_loop();
}

void SCTP_Socket::cancel_expiration(const Expiration_Key& key) {
    expirations.cancel(key);
    wake_event_loop();
}

void SCTP_Socket::cancel_expirations(const Association_Key& location) {
    expirations.cancel_all(location);
    wake_event_loop();
}
