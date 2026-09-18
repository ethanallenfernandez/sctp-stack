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

void SCTP_Socket::run_sending() {
    // handle_send_packet must not run under the send queue's lock.
    std::optional<Send_Queue::Pending> pending =
        sends.peek(std::chrono::steady_clock::now());
    if (!pending) {
        return;
    }

    if (!handle_send_packet(pending->deliverable)) {
        sends.defer(std::chrono::steady_clock::now() + SEND_RETRY_DELAY);
        return;
    }

    sends.commit(pending->priority);
    schedule_expirations_after_send(pending->deliverable, std::chrono::steady_clock::now());
    if (pending->priority == Send_Priority::RETRANSMISSION) {
        schedule_pending_retransmission(pending->deliverable.location);
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
