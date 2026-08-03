// Timer expiry and retransmission scheduling: T1-init and T1-cookie backoff
// (RFC 9260 5.1.6), the T3-rtx timer and its congestion response (6.3.3, 7.2.3),
// the RTO estimator (6.3.1), and building the packets that carry chunks marked
// for retransmission.

#include <sctp/socket.hpp>
#include <sctp/utils.hpp>
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

        SCTP_Packet packet;
        packet.header.src_port = ntohs(local_address.sin_port);
        packet.header.des_port = ntohs(location.address.sin_port);
        packet.header.verification_tag = assoc.peer_ver_tag;
        size_t packet_size = SCTP_COMMON_HEADER_SIZE;
        for (const auto& [tsn, outstanding] : ordered) {
            if (outstanding->gap_acked) {
                continue;
            }
            size_t chunk_size = 16 + outstanding->data.user_data.size();
            chunk_size = (chunk_size + 3) & ~size_t{3};
            if (!packet.chunks.empty()
                    && packet_size + chunk_size
                        > SCTP_COMMON_HEADER_SIZE + assoc.pmdcs) {
                break;
            }
            packet.chunks.push_back(SCTP_Chunk{
                .chunk_header = {
                    .type = DATA,
                    .flag = 0,
                    .length = 0,
                },
                .chunk_value = outstanding->data,
            });
            packet_size += chunk_size;
            (void)tsn;
        }

        retransmission = Deliverable{location, std::move(packet)};
        have_data = !retransmission.packet.chunks.empty();
    }

    if (have_data) {
        enqueue_packet(std::move(retransmission), Send_Priority::RETRANSMISSION);
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

        SCTP_Packet packet;
        packet.header.src_port = ntohs(local_address.sin_port);
        packet.header.des_port = ntohs(key.address.sin_port);
        packet.header.verification_tag = assoc.peer_ver_tag;
        size_t packet_size = SCTP_COMMON_HEADER_SIZE;
        for (const auto& [tsn, outstanding] : ordered) {
            size_t chunk_size = (16 + outstanding->data.user_data.size() + 3)
                & ~size_t{3};
            if (!packet.chunks.empty()
                    && packet_size + chunk_size
                        > SCTP_COMMON_HEADER_SIZE + assoc.pmdcs) {
                break;
            }
            packet.chunks.push_back(SCTP_Chunk{
                .chunk_header = {.type = DATA, .flag = 0, .length = 0},
                .chunk_value = outstanding->data,
            });
            outstanding->pending_retransmission = false;
            packet_size += chunk_size;
            (void)tsn;
        }
        if (packet.chunks.empty()) {
            return;
        }
        retransmission = Deliverable{key, std::move(packet)};
    }
    enqueue_packet(std::move(retransmission), Send_Priority::RETRANSMISSION);
}
