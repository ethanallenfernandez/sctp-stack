// The event loop thread: poll() over the UDP socket and the wakeup pair, drain
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
#include <stdexcept>
#include <vector>

void SCTP_Socket::event_loop() {
    while (running.load()) {
        sctp_pollfd descriptors[2]{};
        descriptors[0].fd = udp_socket;
        descriptors[0].events = SCTP_POLL_READ;
        descriptors[1].fd = wakeup.poll_handle();
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
            wakeup.drain();
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
    std::vector<Expiration_Fallback> expired =
        expirations.drain_expired(std::chrono::steady_clock::now());

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

namespace {
    // A no-op unless cwnd is above 4 * PMDCS: the decay is never allowed to
    // raise cwnd, as it would after a T3-rtx expiry left cwnd at one PMDCS.
    void decay_idle_cwnd(Association& assoc, std::chrono::steady_clock::time_point now) {
        if (assoc.rto.count() <= 0 || now - assoc.data_sent_at < assoc.rto) {
            return;
        }
        auto periods = (now - assoc.data_sent_at) / assoc.rto;
        assoc.data_sent_at += periods * assoc.rto;
        uint32_t floor = 4 * assoc.pmdcs;
        if (assoc.cwnd <= floor) {
            return;
        }
        if (!assoc.idle_decaying) {
            assoc.ssthresh = assoc.cwnd;
            assoc.idle_decaying = true;
        }
        for (; periods > 0 && assoc.cwnd > floor; --periods) {
            assoc.cwnd = std::max(assoc.cwnd / 2, floor);
        }
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
    Send_Allowances allowances = send_allowances();
    refill_retransmissions(allowances);
    std::optional<Send_Queue::Pending> pending = sends.peek(std::chrono::steady_clock::now(), allowances);
    arm_zero_window_probes(allowances);
    if (pending && pending->priority != Send_Priority::CONTROL) {
        prepare_data_packet(pending->deliverable, pending->priority == Send_Priority::NEW_DATA);
    }
    return pending;
}

void SCTP_Socket::packet_sent(const Send_Queue::Pending& pending) {
    sends.commit(pending);
    schedule_expirations_after_send(pending.deliverable, std::chrono::steady_clock::now());
    if (pending.priority != Send_Priority::NEW_DATA) {
        return;
    }
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    auto association = associations.find(pending.deliverable.location);
    if (association != associations.end()) {
        ++association->second.burst_count;
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
    enqueue_packet(Deliverable{pending.deliverable.location, std::move(sack)});
}

// Max.Burst (6.1 D) is applied by counting the new-DATA packets each association
// sends in one pass of the send loop, rather than by clamping cwnd.
void SCTP_Socket::start_transmission_opportunity() {
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    for (auto& [key, assoc] : associations) {
        assoc.burst_count = 0;
        (void)key;
    }
}

Send_Allowances SCTP_Socket::send_allowances() {
    Send_Allowances allowances;
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    for (auto& [key, assoc] : associations) {
        if (!transmits_data(assoc.state)) {
            continue;
        }
        decay_idle_cwnd(assoc, now);
        size_t flight_size = bytes_in_flight(assoc);
        allowances.emplace(key, Send_Allowance{
            .flight_size = flight_size,
            .cwnd_open = assoc.single_packet_in_flight ? flight_size == 0 : flight_size < assoc.cwnd,
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
    auto last_data = std::find_if(chunks.rbegin(), chunks.rend(), [](const SCTP_Chunk& chunk) {
        return chunk.chunk_header.type == DATA;
    });
    if (last_data == chunks.rend()) {
        return;
    }

    Expiration_Key delayed_sack{deliverable.location, Expiration_Timer_Type::DELAYED_SACK};
    bool sack_pending = expirations.is_active(delayed_sack);
    SCTP_Packet sack;
    uint32_t pmdcs;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(deliverable.location);
        if (association == associations.end()) {
            return;
        }
        Association& assoc = association->second;
        size_t data_size = 0;
        for (const auto& chunk : chunks) {
            if (chunk.chunk_header.type == DATA) {
                data_size += data_chunk_wire_size(std::get<data_chunk_value>(chunk.chunk_value));
            }
        }
        size_t flight_after = bytes_in_flight(assoc) + (new_data ? data_size : 0);
        if (flight_after >= assoc.cwnd || data_size >= assoc.peer_rwnd || assoc.state == SHUTDOWN_PENDING) {
            last_data->chunk_header.flag |= DATA_IMMEDIATE_SACK_FLAG;
        }
        if (!sack_pending || !receives_data(assoc.state)) {
            return;
        }
        sack = make_sack(deliverable.location, assoc);
        pmdcs = assoc.pmdcs;
    }

    cancel_expiration(delayed_sack);
    size_t sack_size = serialize_sctp_packet(sack).size() - SCTP_COMMON_HEADER_SIZE;
    if (serialize_sctp_packet(deliverable.packet).size() + sack_size <= SCTP_COMMON_HEADER_SIZE + pmdcs) {
        chunks.insert(chunks.begin(), std::move(sack.chunks.front()));
    } else {
        enqueue_packet(Deliverable{deliverable.location, std::move(sack)});
    }
}

// Chunks marked for retransmission go out one packet at a time as cwnd allows,
// each built only once there is room for it. The packet T3-rtx or a Fast
// Retransmit sends first is queued by them directly, and is not held here.
void SCTP_Socket::refill_retransmissions(const Send_Allowances& allowances) {
    for (const auto& [key, allowance] : allowances) {
        if (allowance.cwnd_open && !sends.has_retransmission_for(key)) {
            schedule_pending_retransmission(key);
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
        if (expirations.is_active(timer)) {
            continue;
        }
        std::chrono::microseconds rto;
        {
            std::lock_guard<std::mutex> assoc_lock(associations_mutex);
            auto association = associations.find(key);
            if (association == associations.end() || association->second.zero_window_probe_allowed) {
                continue;
            }
            rto = association->second.rto;
        }
        schedule_expiration(timer, std::chrono::steady_clock::now() + rto, Deliverable{key, SCTP_Packet{}});
    }
}

void SCTP_Socket::run_receiving() {
    for (size_t received_packets = 0; received_packets < MAX_RECEIVE_BATCH; ++received_packets) {
        uint8_t buffer[MAX_UDP_DATAGRAM];
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

// Wraps enqueue only to wake the loop, which may be in poll() with no deadline.

void SCTP_Socket::enqueue_packet(Deliverable deliverable, Send_Priority priority) {
    sends.enqueue(std::move(deliverable), priority);
    wake_event_loop();
}

// On SCTP_Socket rather than inline at each site: every scheduling path ends here.

void SCTP_Socket::wake_event_loop() {
    wakeup.wake();
}

int SCTP_Socket::next_poll_timeout() {
    auto now = std::chrono::steady_clock::now();
    bool have_deadline = false;
    auto deadline = std::chrono::steady_clock::time_point::max();

    if (auto send_attempt = sends.next_deadline()) {
        if (*send_attempt <= now) {
            return 0;
        }
        have_deadline = true;
        deadline = *send_attempt;
    }

    if (auto expiration = expirations.next_deadline()) {
        if (!have_deadline || *expiration < deadline) {
            have_deadline = true;
            deadline = *expiration;
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
        // A heartbeat arms no timer of its own: the periodic one is already
        // running. It is timestamped here rather than at build time so the RTT
        // it measures excludes however long the packet sat in the send queue.
        if (chunk.chunk_header.type == HEARTBEAT) {
            record_heartbeat_sent(deliverable.location, sent_at);
            continue;
        }

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
