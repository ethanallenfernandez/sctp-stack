// Timer expiry and retransmission scheduling: T1-init and T1-cookie backoff
// (RFC 9260 5.1.6), the T3-rtx timer and its congestion response (6.3.3, 7.2.3),
// the RTO estimator (6.3.1), and building the packets that carry chunks marked
// for retransmission.

#include <sctp/socket.hpp>
#include <sctp/utils.hpp>
#include "builders.hpp"
#include "socket_internal.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <mutex>
#include <vector>

void SCTP_Socket::handle_expiration(const Expiration_Fallback& fallback) {
    if (fallback.key.type == Expiration_Timer_Type::T3_RTX) {
        handle_t3_expiration(fallback.key.location, fallback.key.path.address);
        return;
    }
    if (fallback.key.type == Expiration_Timer_Type::DELAYED_SACK) {
        handle_delayed_sack_expiration(fallback.key.location);
        return;
    }
    if (fallback.key.type == Expiration_Timer_Type::HEARTBEAT) {
        handle_heartbeat_expiration(fallback.key.location, fallback.key.path.address);
        return;
    }
    if (fallback.key.type == Expiration_Timer_Type::T2_SHUTDOWN) {
        handle_t2_expiration(fallback.key.location);
        return;
    }
    if (fallback.key.type == Expiration_Timer_Type::T5_SHUTDOWN_GUARD) {
        handle_t5_expiration(fallback.key.location);
        return;
    }
    if (fallback.key.type == Expiration_Timer_Type::ZERO_WINDOW_PROBE) {
        handle_zero_window_probe_expiration(fallback.key.location);
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
            forget_peer_addresses(fallback.key.location);
            notify_assoc_change(fallback.key.location, Assoc_Change_State::CANT_STR_ASSOC);
            exhausted = true;
        } else {
            ++retransmits;
            should_retry = true;
        }
    }

    if (exhausted) {
        cancel_expirations(fallback.key.location);
        sends.purge(fallback.key.location);
        std::cout << "Association failed after handshake retransmissions" << std::endl;
    } else if (should_retry) {
        enqueue_packet(fallback.retry, Send_Priority::RETRANSMISSION);
    }
}

void SCTP_Socket::record_data_sent(const Association_Key& location, const sockaddr_in& destination, const data_chunk_value& data, std::chrono::steady_clock::time_point sent_at) {
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    auto association = associations.find(location);
    if (association == associations.end() || !transmits_data(association->second.state)) {
        return;
    }

    Association& assoc = association->second;
    Peer_Path* path = find_path(assoc, destination);
    Peer_Path& sent_on = path != nullptr ? *path : primary(assoc);
    sent_on.data_sent_at = sent_at;
    sent_on.idle_decaying = false;
    uint32_t chunk_size = static_cast<uint32_t>(data_chunk_wire_size(data));
    bool exceeds_rwnd = chunk_size > assoc.peer_rwnd;
    assoc.peer_rwnd -= std::min(assoc.peer_rwnd, chunk_size);
    auto outstanding = assoc.outstanding_data.find(data.tsn);
    if (outstanding == assoc.outstanding_data.end()) {
        assoc.zero_window_probing = assoc.zero_window_probe_allowed && exceeds_rwnd;
        assoc.zero_window_probe_allowed = false;
        sent_on.new_data_sent_at = sent_at;
        assoc.outstanding_data.emplace(
            data.tsn,
            Outstanding_Data{data, sent_at, sent_at, false, false, 0, false, false, sent_on.address}
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
    outstanding->second.destination = sent_on.address;
    if (assoc.has_rtt_measurement_tsn && tsn_lte(data.tsn, assoc.rtt_measurement_tsn)) {
        assoc.has_rtt_measurement_tsn = false;
    }
}

void SCTP_Socket::start_t3_if_stopped(const Association_Key& location, const sockaddr_in& destination) {
    if (!expirations.is_active(Expiration_Key{location, Expiration_Timer_Type::T3_RTX, Association_Key{destination}})) {
        restart_t3(location, destination);
    }
}

void SCTP_Socket::restart_t3(const Association_Key& location, const sockaddr_in& destination) {
    Expiration_Key timer{location, Expiration_Timer_Type::T3_RTX, Association_Key{destination}};
    std::chrono::microseconds rto;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(location);
        const Peer_Path* path = association == associations.end() ? nullptr : find_path(association->second, destination);
        if (path == nullptr || !has_unacknowledged_data(association->second, *path)) {
            cancel_expiration(timer);
            return;
        }
        rto = path->rto;
    }
    schedule_expiration(timer, std::chrono::steady_clock::now() + rto, Deliverable{location, {}, SCTP_Packet{}});
}

void SCTP_Socket::restart_t2(const Association_Key& location) {
    std::chrono::microseconds rto;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(location);
        if (association == associations.end()) {
            return;
        }
        rto = data_path(association->second).rto;
    }

    schedule_expiration(
        Expiration_Key{location, Expiration_Timer_Type::T2_SHUTDOWN},
        std::chrono::steady_clock::now() + rto,
        Deliverable{location, {}, SCTP_Packet{}}
    );
}

// Rebuilt rather than replayed: a resent SHUTDOWN carries the Cumulative TSN
// Ack as it stands now.
void SCTP_Socket::handle_t2_expiration(const Association_Key& location) {
    SCTP_Packet packet;
    sockaddr_in destination;
    bool unreachable;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(location);
        if (association == associations.end()
                || (association->second.state != SHUTDOWN_SENT && association->second.state != SHUTDOWN_ACK_SENT)) {
            return;
        }

        Association& assoc = association->second;
        Peer_Path& path = data_path(assoc);
        path.rto = std::min(path.rto * 2, std::chrono::duration_cast<std::chrono::microseconds>(sctp_parameters::RTO_MAX));
        unreachable = ++assoc.error_count > assoc.error_threshold;
        destination = path.address;
        uint16_t src_port = ntohs(local_address.sin_port);
        uint16_t des_port = ntohs(location.address.sin_port);
        packet = assoc.state == SHUTDOWN_SENT
            ? build_shutdown(src_port, des_port, assoc.peer_ver_tag, assoc.last_peer_tsn)
            : build_shutdown_ack(src_port, des_port, assoc.peer_ver_tag);
    }

    if (unreachable) {
        remove_association(location);
        notify_assoc_change(location, Assoc_Change_State::COMM_LOST);
        std::cout << "Association failed: shutdown unanswered" << std::endl;
        return;
    }
    enqueue_packet(Deliverable{location, destination, std::move(packet)});
    restart_t2(location);
}

// Armed once, on entering SHUTDOWN-SENT, and never restarted: T2's count is
// cleared by every packet the peer sends, so this is the only bound it cannot
// push back.
void SCTP_Socket::handle_t5_expiration(const Association_Key& location) {
    uint32_t peer_tag;
    sockaddr_in destination;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(location);
        if (association == associations.end()
                || (association->second.state != SHUTDOWN_SENT && association->second.state != SHUTDOWN_ACK_SENT)) {
            return;
        }
        peer_tag = association->second.peer_ver_tag;
        destination = data_path(association->second).address;
    }

    remove_association(location);
    enqueue_packet(Deliverable{location, destination, build_abort(
        ntohs(local_address.sin_port), ntohs(location.address.sin_port), peer_tag, false, {})});
    notify_assoc_change(location, Assoc_Change_State::COMM_LOST);
    std::cout << "Association aborted: shutdown did not complete in time" << std::endl;
}

// The timed-out chunks are moved to the path they will be retransmitted on,
// so a queued retransmission still bound for the failed path would duplicate them.
void SCTP_Socket::handle_t3_expiration(const Association_Key& location, const sockaddr_in& destination) {
    bool unreachable = false;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(location);
        if (association == associations.end() || !transmits_data(association->second.state)) {
            return;
        }
        Association& assoc = association->second;
        Peer_Path* expired = find_path(assoc, destination);
        if (expired == nullptr || !has_unacknowledged_data(assoc, *expired)) {
            return;
        }

        Peer_Path& path = *expired;
        if (!assoc.zero_window_probing) {
            path.ssthresh = std::max(path.cwnd / 2, 4U * assoc.pmdcs);
            path.cwnd = assoc.pmdcs;
            path.partial_bytes_acked = 0;
            path.single_packet_in_flight = true;
        }
        path.rto = std::min(path.rto * 2, std::chrono::duration_cast<std::chrono::microseconds>(sctp_parameters::RTO_MAX));
        if (!assoc.zero_window_probing || !assoc.sack_since_t3) {
            count_path_error(location, path);
            unreachable = ++assoc.error_count > assoc.error_threshold;
        }
        assoc.sack_since_t3 = false;

        sockaddr_in target = retransmission_path(assoc, path.address).address;
        for (auto& [tsn, outstanding] : assoc.outstanding_data) {
            if (outstanding.gap_acked || outstanding.pending_retransmission || &destination_of(assoc, outstanding) != &path) {
                continue;
            }
            outstanding.pending_retransmission = true;
            outstanding.destination = target;
            assoc.peer_rwnd += static_cast<uint32_t>(data_chunk_wire_size(outstanding.data));
            (void)tsn;
        }
    }

    if (unreachable) {
        remove_association(location);
        notify_assoc_change(location, Assoc_Change_State::COMM_LOST);
        std::cout << "Association failed: peer unreachable" << std::endl;
        return;
    }

    sends.remove_retransmissions_of_type(location, DATA, &destination);
    schedule_pending_retransmission(location);
}

// RFC 9260 8.3. A path's timer runs to its next probe, or, while a probe is
// out, to one RTO after it was sent. A path is idle when no new DATA went to it
// since its last probe was due.
void SCTP_Socket::handle_heartbeat_expiration(const Association_Key& location, const sockaddr_in& destination) {
    Deliverable probe;
    bool unreachable = false;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(location);
        if (association == associations.end() || !transmits_data(association->second.state)) {
            return;
        }
        Association& assoc = association->second;
        Peer_Path* path = find_path(assoc, destination);
        if (path == nullptr) {
            return;
        }

        auto now = std::chrono::steady_clock::now();
        bool probe_now = !path->hb_outstanding;
        if (path->hb_outstanding) {
            path->hb_outstanding = false;
            path->rto = std::min(path->rto * 2, std::chrono::duration_cast<std::chrono::microseconds>(sctp_parameters::RTO_MAX));
            bool was_probing = probes_for_confirmation(assoc, *path);
            bool carries_data = path->confirmed && &data_path(assoc) == path;
            count_path_error(location, *path);
            unreachable = carries_data && ++assoc.error_count > assoc.error_threshold;
            if (was_probing && !path->active) {
                arm_confirmation_probes(location, assoc);
            }
            probe_now = probes_for_confirmation(assoc, *path) || now >= path->hb_next;
        }

        if (!unreachable) {
            if (probe_now && path->hb_enabled) {
                if (path->new_data_sent_at < path->hb_period_start) {
                    probe = build_probe(location, assoc, *path);
                }
                plan_next_probe(assoc, *path, now);
            }
            arm_heartbeat(location, assoc, *path);
        }
    }

    // 8.1: an unreachable peer is not sent an ABORT, it is simply gone.
    if (unreachable) {
        remove_association(location);
        notify_assoc_change(location, Assoc_Change_State::COMM_LOST);
        std::cout << "Association failed: peer unreachable" << std::endl;
        return;
    }
    if (!probe.packet.chunks.empty()) {
        enqueue_packet(std::move(probe));
    }
}

void SCTP_Socket::handle_zero_window_probe_expiration(const Association_Key& location) {
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    auto association = associations.find(location);
    if (association != associations.end() && association->second.outstanding_data.empty()) {
        association->second.zero_window_probe_allowed = true;
    }
}

void SCTP_Socket::start_heartbeats(const Association_Key& key, Association& assoc) {
    auto now = std::chrono::steady_clock::now();
    for (Peer_Path& path : assoc.peer_address_list) {
        plan_next_probe(assoc, path, now);
        if (probes_for_confirmation(assoc, path)) {
            path.hb_next = now;
        }
        arm_heartbeat(key, assoc, path);
    }
}

// HB.interval plus the RTO, jittered by half the RTO either way; every RTO for
// a path being confirmed.
void SCTP_Socket::plan_next_probe(const Association& assoc, Peer_Path& path, std::chrono::steady_clock::time_point now) {
    path.hb_period_start = now;
    if (probes_for_confirmation(assoc, path)) {
        path.hb_next = now + path.rto;
        return;
    }
    uint32_t jitter;
    generate_random(jitter);
    int64_t span = path.rto.count();
    std::chrono::microseconds offset{static_cast<int64_t>(jitter % static_cast<uint64_t>(span + 1)) - span / 2};
    path.hb_next = now + assoc.hb_interval + path.rto + offset;
}

Deliverable SCTP_Socket::build_probe(const Association_Key& key, const Association& assoc, Peer_Path& path) {
    generate_random(path.hb_nonce);
    path.hb_outstanding = true;
    path.hb_sent_at = std::chrono::steady_clock::now();
    return Deliverable{key, path.address, build_heartbeat(
        ntohs(local_address.sin_port),
        ntohs(key.address.sin_port),
        assoc.peer_ver_tag,
        heartbeat_info(path.hb_nonce, path.address)
    )};
}

void SCTP_Socket::arm_heartbeat(const Association_Key& key, const Association& assoc, const Peer_Path& path) {
    Expiration_Key timer{key, Expiration_Timer_Type::HEARTBEAT, Association_Key{path.address}};
    if (path.hb_outstanding) {
        schedule_expiration(timer, path.hb_sent_at + path.rto, Deliverable{key, {}, SCTP_Packet{}});
    } else if (!path.hb_enabled || (!path.confirmed && path.active && !probes_for_confirmation(assoc, path))) {
        cancel_expiration(timer);
    } else {
        schedule_expiration(timer, path.hb_next, Deliverable{key, {}, SCTP_Packet{}});
    }
}

// A path that has just taken a turn at confirmation is probed at once.
void SCTP_Socket::arm_confirmation_probes(const Association_Key& key, Association& assoc) {
    auto now = std::chrono::steady_clock::now();
    for (Peer_Path& path : assoc.peer_address_list) {
        if (probes_for_confirmation(assoc, path) && !path.hb_outstanding
                && !expirations.is_active(Expiration_Key{key, Expiration_Timer_Type::HEARTBEAT, Association_Key{path.address}})) {
            path.hb_period_start = now;
            path.hb_next = now;
            arm_heartbeat(key, assoc, path);
        }
    }
}

// 8.3: an inactive path stops counting.
void SCTP_Socket::count_path_error(const Association_Key& key, Peer_Path& path) {
    if (path.active && ++path.error_count > sctp_parameters::PATH_MAX_RETRANS) {
        path.active = false;
        notify_peer_addr_change(key, path.address, Peer_Addr_State::ADDR_UNREACHABLE);
    }
}

void SCTP_Socket::clear_path_errors(const Association_Key& key, Peer_Path& path) {
    path.error_count = 0;
    if (!path.active) {
        path.active = true;
        notify_peer_addr_change(key, path.address, Peer_Addr_State::ADDR_AVAILABLE);
    }
}

void SCTP_Socket::record_heartbeat_sent(const Association_Key& location, const sockaddr_in& destination, std::chrono::steady_clock::time_point sent_at) {
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    auto association = associations.find(location);
    if (association == associations.end()) {
        return;
    }
    Peer_Path* path = find_path(association->second, destination);
    if (path != nullptr && path->hb_outstanding) {
        path->hb_sent_at = sent_at;
    }
}

void SCTP_Socket::update_rto(Peer_Path& path, std::chrono::microseconds measurement) {
    if (!path.has_srtt) {
        path.srtt = measurement;
        path.rttvar = measurement / 2;
        path.has_srtt = true;
    } else {
        using Floating_Microseconds = std::chrono::duration<double, std::micro>;
        Floating_Microseconds previous_srtt{path.srtt};
        Floating_Microseconds previous_rttvar{path.rttvar};
        Floating_Microseconds new_rtt_measurement{measurement};
        Floating_Microseconds deviation = previous_srtt > new_rtt_measurement ? previous_srtt - new_rtt_measurement : new_rtt_measurement - previous_srtt;


        // RTTVAR is calculated first so both formulas use the previous value of SRTT.
        Floating_Microseconds new_rttvar = (1.0 - sctp_parameters::RTO_BETA) * previous_rttvar + sctp_parameters::RTO_BETA * deviation;
        Floating_Microseconds new_srtt = (1.0 - sctp_parameters::RTO_ALPHA) * previous_srtt + sctp_parameters::RTO_ALPHA * new_rtt_measurement;

        path.rttvar = std::chrono::duration_cast<std::chrono::microseconds>(new_rttvar);
        path.srtt = std::chrono::duration_cast<std::chrono::microseconds>(new_srtt);
    }

    if (path.rttvar.count() == 0) {
        path.rttvar = CLOCK_GRANULARITY;
    }
    path.rto = std::clamp(
        path.srtt + path.rttvar * 4,
        std::chrono::duration_cast<std::chrono::microseconds>(sctp_parameters::RTO_MIN),
        std::chrono::duration_cast<std::chrono::microseconds>(sctp_parameters::RTO_MAX)
    );
}

// One packet of the lowest marked TSNs that share a destination, sent there.
void SCTP_Socket::schedule_pending_retransmission(const Association_Key& key, bool gated) {
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
            if (entry.second.pending_retransmission && !entry.second.gap_acked) {
                ordered.push_back({entry.first, &entry.second});
            }
        }
        if (ordered.empty()) {
            return;
        }
        std::sort(ordered.begin(), ordered.end(), [&](const auto& lhs, const auto& rhs) {
            return static_cast<uint32_t>(lhs.first - assoc.cumulative_tsn_ack)
                < static_cast<uint32_t>(rhs.first - assoc.cumulative_tsn_ack);
        });

        const Peer_Path& to = destination_of(assoc, *ordered.front().second);
        if (gated && !cwnd_open(assoc, to)) {
            return;
        }
        std::vector<data_chunk_value> bundle;
        size_t packet_size = SCTP_COMMON_HEADER_SIZE;
        for (const auto& [tsn, outstanding] : ordered) {
            size_t chunk_size = data_chunk_wire_size(outstanding->data);
            if (&destination_of(assoc, *outstanding) != &to) {
                continue;
            }
            if (!bundle.empty() && packet_size + chunk_size > SCTP_COMMON_HEADER_SIZE + assoc.pmdcs) {
                break;
            }
            bundle.push_back(outstanding->data);
            outstanding->pending_retransmission = false;
            packet_size += chunk_size;
            (void)tsn;
        }
        retransmission = Deliverable{key, to.address, build_data(
            ntohs(local_address.sin_port),
            ntohs(key.address.sin_port),
            assoc.peer_ver_tag,
            std::move(bundle)
        )};
    }
    enqueue_packet(std::move(retransmission), Send_Priority::RETRANSMISSION);
}
