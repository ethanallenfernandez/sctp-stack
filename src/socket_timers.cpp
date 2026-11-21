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
#include <mutex>
#include <ranges>
#include <vector>

void SCTP_Socket::handle_expiration(const Expiration_Fallback& fallback) {
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    const Association_Key& location = fallback.key.location;
    const sockaddr_in& path = fallback.key.path.address;
    switch (fallback.key.type) {
        case Expiration_Timer_Type::T3_RTX: return handle_t3_expiration(location, path);
        case Expiration_Timer_Type::DELAYED_SACK: return send_sack(location);
        case Expiration_Timer_Type::HEARTBEAT: return handle_heartbeat_expiration(location, path);
        case Expiration_Timer_Type::T2_SHUTDOWN: return handle_t2_expiration(location);
        case Expiration_Timer_Type::T5_SHUTDOWN_GUARD: return handle_t5_expiration(location);
        case Expiration_Timer_Type::ZERO_WINDOW_PROBE: return handle_zero_window_probe_expiration(location);
        case Expiration_Timer_Type::PLPMTU_PROBE: return handle_plpmtu_probe_expiration(location, path);
        case Expiration_Timer_Type::PMTU_RAISE: return handle_pmtu_raise_expiration(location, path);
        case Expiration_Timer_Type::T1_INIT:
        case Expiration_Timer_Type::T1_COOKIE: break;
    }

    Association* assoc = find_tcb(location);
    bool is_init = fallback.key.type == Expiration_Timer_Type::T1_INIT;
    if (assoc == nullptr || assoc->state != (is_init ? COOKIE_WAIT : COOKIE_ECHOED)) {
        return;
    }
    uint16_t& retransmits = is_init ? assoc->init_retransmits : assoc->cookie_retransmits;
    if (retransmits >= sctp_parameters::MAX_INIT_RETRANSMITS) {
        return remove_association(location, Assoc_Change_State::CANT_STR_ASSOC);
    }
    ++retransmits;
    enqueue_packet(fallback.retry, Send_Priority::RETRANSMISSION);
}

void SCTP_Socket::record_data_sent(const Association_Key& location, const sockaddr_in& destination, const data_chunk_value& data, std::chrono::steady_clock::time_point sent_at) {
    Association* found = find_tcb(location);
    if (found == nullptr || !transmits_data(found->state)) {
        return;
    }

    Association& assoc = *found;
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
        if (!assoc.rtt_measurement_tsn) {
            assoc.rtt_measurement_tsn = data.tsn;
        }
        return;
    }

    outstanding->second.last_sent = sent_at;
    outstanding->second.retransmitted = true;
    outstanding->second.gap_acked = false;
    outstanding->second.destination = sent_on.address;
    if (assoc.rtt_measurement_tsn && tsn_lte(data.tsn, *assoc.rtt_measurement_tsn)) {
        assoc.rtt_measurement_tsn.reset();
    }
}

void SCTP_Socket::start_t3_if_stopped(const Association_Key& location, const sockaddr_in& destination) {
    if (!expirations.is_active(Expiration_Key{location, Expiration_Timer_Type::T3_RTX, path_key(destination)})) {
        restart_t3(location, destination);
    }
}

void SCTP_Socket::restart_t3(const Association_Key& location, const sockaddr_in& destination) {
    Expiration_Key timer{location, Expiration_Timer_Type::T3_RTX, path_key(destination)};
    Association* assoc = find_tcb(location);
    const Peer_Path* path = assoc ? find_path(*assoc, destination) : nullptr;
    if (path == nullptr || !has_unacknowledged_data(*assoc, *path)) {
        return cancel_expiration(timer);
    }
    schedule_expiration(timer, std::chrono::steady_clock::now() + path->rto);
}

void SCTP_Socket::restart_t2(const Association_Key& location) {
    if (Association* assoc = find_tcb(location)) {
        schedule_expiration(Expiration_Key{location, Expiration_Timer_Type::T2_SHUTDOWN}, std::chrono::steady_clock::now() + data_path(*assoc).rto);
    }
}

// Rebuilt rather than replayed: a resent SHUTDOWN carries the Cumulative TSN
// Ack as it stands now.
void SCTP_Socket::handle_t2_expiration(const Association_Key& location) {
    Association* assoc = find_tcb(location);
    if (assoc == nullptr || (assoc->state != SHUTDOWN_SENT && assoc->state != SHUTDOWN_ACK_SENT)) {
        return;
    }
    Peer_Path& path = data_path(*assoc);
    back_off(path);
    if (++assoc->error_count > sctp_parameters::ASSOCIATION_MAX_RETRANS) {
        return remove_association(location, Assoc_Change_State::COMM_LOST);
    }
    enqueue_packet(Deliverable{location, path.address, assoc->state == SHUTDOWN_SENT
        ? packet_to(location, assoc->peer_ver_tag, SHUTDOWN, shutdown_chunk_value{assoc->last_peer_tsn})
        : packet_to(location, assoc->peer_ver_tag, SHUTDOWN_ACK, empty_chunk_value{})});
    restart_t2(location);
}

// Armed once, on entering SHUTDOWN-SENT, and never restarted: T2's count is
// cleared by every packet the peer sends, so this is the only bound it cannot
// push back.
void SCTP_Socket::handle_t5_expiration(const Association_Key& location) {
    Association* assoc = find_tcb(location);
    if (assoc == nullptr || (assoc->state != SHUTDOWN_SENT && assoc->state != SHUTDOWN_ACK_SENT)) {
        return;
    }
    uint32_t peer_tag = assoc->peer_ver_tag;
    sockaddr_in destination = data_path(*assoc).address;
    remove_association(location, Assoc_Change_State::COMM_LOST);
    enqueue_packet(Deliverable{location, destination, packet_to(location, peer_tag, ABORT, error_chunk_value{})});
}

// The timed-out chunks are moved to the path they will be retransmitted on,
// so a queued retransmission still bound for the failed path would duplicate them.
void SCTP_Socket::handle_t3_expiration(const Association_Key& location, const sockaddr_in& destination) {
    Association* found = find_tcb(location);
    Peer_Path* expired = found && transmits_data(found->state) ? find_path(*found, destination) : nullptr;
    if (expired == nullptr || !has_unacknowledged_data(*found, *expired)) {
        return;
    }

    Association& assoc = *found;
    Peer_Path& path = *expired;
    if (!assoc.zero_window_probing) {
        path.ssthresh = std::max(path.cwnd / 2, 4U * pmdcs(path));
        path.cwnd = pmdcs(path);
        path.partial_bytes_acked = 0;
        path.single_packet_in_flight = true;
    }
    back_off(path);
    if (!assoc.zero_window_probing || !assoc.sack_since_t3) {
        count_path_error(location, path);
        check_for_black_hole(location, path);
        if (++assoc.error_count > sctp_parameters::ASSOCIATION_MAX_RETRANS) {
            return remove_association(location, Assoc_Change_State::COMM_LOST);
        }
    }
    assoc.sack_since_t3 = false;

    sockaddr_in target = retransmission_path(assoc, path.address).address;
    for (auto& outstanding : assoc.outstanding_data | std::views::values) {
        if (outstanding.gap_acked || outstanding.pending_retransmission || &destination_of(assoc, outstanding) != &path) {
            continue;
        }
        outstanding.pending_retransmission = true;
        outstanding.destination = target;
        assoc.peer_rwnd += static_cast<uint32_t>(data_chunk_wire_size(outstanding.data));
    }
    sends.remove_retransmissions_of_type(location, DATA, &destination);
    schedule_pending_retransmission(location);
}

// RFC 9260 8.3. A path's timer runs to its next probe, or, while a probe is
// out, to one RTO after it was sent. A path is idle when no new DATA went to it
// since its last probe was due.
void SCTP_Socket::handle_heartbeat_expiration(const Association_Key& location, const sockaddr_in& destination) {
    Association* assoc = find_tcb(location);
    Peer_Path* path = assoc && transmits_data(assoc->state) ? find_path(*assoc, destination) : nullptr;
    if (path == nullptr) {
        return;
    }

    auto now = std::chrono::steady_clock::now();
    bool probe_now = !path->hb_outstanding;
    if (path->hb_outstanding) {
        path->hb_outstanding = false;
        back_off(*path);
        bool was_probing = probes_for_confirmation(*assoc, *path);
        bool carries_data = path->confirmed && &data_path(*assoc) == path;
        count_path_error(location, *path);
        // 8.1: an unreachable peer is not sent an ABORT, it is simply gone.
        if (carries_data && ++assoc->error_count > sctp_parameters::ASSOCIATION_MAX_RETRANS) {
            return remove_association(location, Assoc_Change_State::COMM_LOST);
        }
        if (was_probing && !path->active) {
            arm_confirmation_probes(location, *assoc);
        }
        probe_now = probes_for_confirmation(*assoc, *path) || now >= path->hb_next;
    }

    if (probe_now && path->hb_enabled) {
        if (path->new_data_sent_at < path->hb_period_start) {
            enqueue_packet(build_probe(location, *assoc, *path));
        }
        plan_next_probe(*assoc, *path, now);
    }
    arm_heartbeat(location, *assoc, *path);
}

void SCTP_Socket::handle_zero_window_probe_expiration(const Association_Key& location) {
    Association* assoc = find_tcb(location);
    if (assoc != nullptr && assoc->outstanding_data.empty()) {
        assoc->zero_window_probe_allowed = true;
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
        start_plpmtud(key, path);
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
    return Deliverable{key, path.address, packet_to(key, assoc.peer_ver_tag, HEARTBEAT, heartbeat_chunk_value{heartbeat_info(path.hb_nonce, path.address)})};
}

void SCTP_Socket::arm_heartbeat(const Association_Key& key, const Association& assoc, const Peer_Path& path) {
    Expiration_Key timer{key, Expiration_Timer_Type::HEARTBEAT, path_key(path.address)};
    if (path.hb_outstanding) {
        schedule_expiration(timer, path.hb_sent_at + path.rto);
    } else if (!path.hb_enabled || (!path.confirmed && path.active && !probes_for_confirmation(assoc, path))) {
        cancel_expiration(timer);
    } else {
        schedule_expiration(timer, path.hb_next);
    }
}

// A path that has just taken a turn at confirmation is probed at once.
void SCTP_Socket::arm_confirmation_probes(const Association_Key& key, Association& assoc) {
    auto now = std::chrono::steady_clock::now();
    for (Peer_Path& path : assoc.peer_address_list) {
        if (probes_for_confirmation(assoc, path) && !path.hb_outstanding
                && !expirations.is_active(Expiration_Key{key, Expiration_Timer_Type::HEARTBEAT, path_key(path.address)})) {
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
        stop_plpmtud(key, path);
        notify_peer_addr_change(key, path.address, Peer_Addr_State::ADDR_UNREACHABLE);
    }
}

void SCTP_Socket::clear_path_errors(const Association_Key& key, Peer_Path& path) {
    path.error_count = 0;
    if (!path.active) {
        path.active = true;
        start_plpmtud(key, path);
        notify_peer_addr_change(key, path.address, Peer_Addr_State::ADDR_AVAILABLE);
    }
}

void SCTP_Socket::record_heartbeat_sent(const Association_Key& location, const sockaddr_in& destination, const std::vector<uint8_t>& info, std::chrono::steady_clock::time_point sent_at) {
    Association* assoc = find_tcb(location);
    Peer_Path* path = assoc ? find_path(*assoc, destination) : nullptr;
    if (path != nullptr && path->hb_outstanding && info.size() == HEARTBEAT_INFO_SIZE && heartbeat_info_nonce(info) == path->hb_nonce) {
        path->hb_sent_at = sent_at;
    }
}

void SCTP_Socket::update_rto(Peer_Path& path, std::chrono::microseconds measurement) {
    if (!path.has_srtt) {
        path.srtt = measurement;
        path.rttvar = measurement / 2;
        path.has_srtt = true;
    } else {
        using std::chrono::duration_cast;
        using sctp_parameters::RTO_ALPHA, sctp_parameters::RTO_BETA;
        // RTTVAR first, so both use the previous SRTT.
        path.rttvar = duration_cast<std::chrono::microseconds>((1.0 - RTO_BETA) * path.rttvar + RTO_BETA * std::chrono::abs(path.srtt - measurement));
        path.srtt = duration_cast<std::chrono::microseconds>((1.0 - RTO_ALPHA) * path.srtt + RTO_ALPHA * measurement);
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
    Association* found = find_tcb(key);
    if (found == nullptr) {
        return;
    }
    Association& assoc = *found;
    std::vector<Outstanding_Data*> ordered;
    for (auto& outstanding : assoc.outstanding_data | std::views::values) {
        if (outstanding.pending_retransmission && !outstanding.gap_acked) {
            ordered.push_back(&outstanding);
        }
    }
    if (ordered.empty()) {
        return;
    }

    const Peer_Path& to = destination_of(assoc, *ordered.front());
    if (gated && !cwnd_open(assoc, to)) {
        return;
    }
    std::vector<data_chunk_value> bundle;
    size_t packet_size = SCTP_COMMON_HEADER_SIZE;
    size_t limit = SCTP_COMMON_HEADER_SIZE + pmdcs(to);
    for (Outstanding_Data* outstanding : ordered) {
        size_t chunk_size = data_chunk_wire_size(outstanding->data);
        if (&destination_of(assoc, *outstanding) != &to) {
            continue;
        }
        if (!bundle.empty() && packet_size + chunk_size > limit) {
            break;
        }
        bundle.push_back(outstanding->data);
        outstanding->pending_retransmission = false;
        packet_size += chunk_size;
        if (packet_size > limit) {
            break;
        }
    }
    enqueue_packet(Deliverable{key, to.address, build_data(ntohs(local_address.sin_port), ntohs(key.address.sin_port), assoc.peer_ver_tag,
        std::move(bundle)), packet_size > limit}, Send_Priority::RETRANSMISSION);
}
