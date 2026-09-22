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
        handle_t3_expiration(fallback.key.location);
        return;
    }
    if (fallback.key.type == Expiration_Timer_Type::DELAYED_SACK) {
        handle_delayed_sack_expiration(fallback.key.location);
        return;
    }
    if (fallback.key.type == Expiration_Timer_Type::HEARTBEAT) {
        handle_heartbeat_expiration(fallback.key.location);
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
        if (expirations.is_active(key)) {
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

        std::vector<data_chunk_value> bundle;
        size_t packet_size = SCTP_COMMON_HEADER_SIZE;
        for (const auto& [tsn, outstanding] : ordered) {
            if (outstanding->gap_acked) {
                continue;
            }
            size_t chunk_size = data_chunk_wire_size(outstanding->data);
            if (!bundle.empty()
                    && packet_size + chunk_size
                        > SCTP_COMMON_HEADER_SIZE + assoc.pmdcs) {
                break;
            }
            bundle.push_back(outstanding->data);
            packet_size += chunk_size;
            (void)tsn;
        }

        retransmission = Deliverable{location, build_data(
            ntohs(local_address.sin_port),
            ntohs(location.address.sin_port),
            assoc.peer_ver_tag,
            std::move(bundle)
        )};
        have_data = !retransmission.packet.chunks.empty();
    }

    if (have_data) {
        enqueue_packet(std::move(retransmission), Send_Priority::RETRANSMISSION);
    }
}

// RFC 9260 8.3: probe only destinations that are idle, on HB.interval plus the
// RTO, jittered. Outstanding DATA is the idle test here: T3-rtx is already
// probing the path, and its expiry counts the same error.
void SCTP_Socket::handle_heartbeat_expiration(const Association_Key& location) {
    Deliverable probe;
    bool send_probe = false;
    bool unreachable = false;
    std::chrono::microseconds rto;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(location);
        if (association == associations.end() || association->second.state != ESTABLISHED) {
            return;
        }

        Association& assoc = association->second;
        if (assoc.hb_outstanding && ++assoc.error_count > assoc.error_threshold) {
            unreachable = true;
        }
        assoc.hb_outstanding = false;
        rto = assoc.rto;

        if (!unreachable && !has_unacknowledged_data(assoc)) {
            generate_random(assoc.hb_nonce);
            assoc.hb_outstanding = true;
            assoc.hb_sent_at = std::chrono::steady_clock::now();
            probe = Deliverable{location, build_heartbeat(
                ntohs(local_address.sin_port),
                ntohs(location.address.sin_port),
                assoc.peer_ver_tag,
                heartbeat_info(assoc.hb_nonce, location.address)
            )};
            send_probe = true;
        }
    }

    // 8.1: an unreachable peer is not sent an ABORT, it is simply gone.
    if (unreachable) {
        remove_association(location);
        notify_assoc_change(location, Assoc_Change_State::COMM_LOST);
        std::cout << "Association failed: peer unreachable" << std::endl;
        return;
    }

    if (send_probe) {
        enqueue_packet(std::move(probe));
    }
    schedule_heartbeat(location, rto);
}

void SCTP_Socket::schedule_heartbeat(const Association_Key& location, std::chrono::microseconds rto) {
    uint32_t jitter;
    generate_random(jitter);
    int64_t span = rto.count();
    std::chrono::microseconds offset{static_cast<int64_t>(jitter % static_cast<uint64_t>(span + 1)) - span / 2};

    schedule_expiration(
        Expiration_Key{location, Expiration_Timer_Type::HEARTBEAT},
        std::chrono::steady_clock::now() + sctp_parameters::HB_INTERVAL + rto + offset,
        Deliverable{location, SCTP_Packet{}}
    );
}

void SCTP_Socket::record_heartbeat_sent(const Association_Key& location, std::chrono::steady_clock::time_point sent_at) {
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    auto association = associations.find(location);
    if (association != associations.end() && association->second.hb_outstanding) {
        association->second.hb_sent_at = sent_at;
    }
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

        std::vector<data_chunk_value> bundle;
        size_t packet_size = SCTP_COMMON_HEADER_SIZE;
        for (const auto& [tsn, outstanding] : ordered) {
            size_t chunk_size = data_chunk_wire_size(outstanding->data);
            if (!bundle.empty()
                    && packet_size + chunk_size
                        > SCTP_COMMON_HEADER_SIZE + assoc.pmdcs) {
                break;
            }
            bundle.push_back(outstanding->data);
            outstanding->pending_retransmission = false;
            packet_size += chunk_size;
            (void)tsn;
        }
        if (bundle.empty()) {
            return;
        }
        retransmission = Deliverable{key, build_data(
            ntohs(local_address.sin_port),
            ntohs(key.address.sin_port),
            assoc.peer_ver_tag,
            std::move(bundle)
        )};
    }
    enqueue_packet(std::move(retransmission), Send_Priority::RETRANSMISSION);
}
