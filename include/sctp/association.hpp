#ifndef SCTP_ASSOCIATION_HPP
#define SCTP_ASSOCIATION_HPP

#include <stdint.h>
#include <vector>
#include <utility>
#include <string>
#include <functional>
#include <map>
#include <queue>
#include <chrono>
#include <sctp/platform.hpp>
#include <sctp/sctp.hpp>

enum Association_State {
    COOKIE_WAIT, 
    COOKIE_ECHOED, 
    ESTABLISHED, 
    SHUTDOWN_PENDING, 
    SHUTDOWN_SENT, 
    SHUTDOWN_RECEIVED, 
    SHUTDOWN_ACK_SENT
};

struct Outstanding_Data {
    data_chunk_value data;
    std::chrono::steady_clock::time_point first_sent;
    std::chrono::steady_clock::time_point last_sent;
    bool retransmitted;
    bool gap_acked;
    uint16_t missing_reports;
    bool fast_retransmitted;
    bool pending_retransmission;
};

struct Association {
    uint32_t peer_ver_tag;
    uint32_t this_ver_tag;
    Association_State state;
    std::vector<sockaddr_in> peer_address_list;
    sockaddr_in primary_path;
    uint16_t error_count;
    uint16_t error_threshold;
    uint32_t peer_rwnd;
    uint32_t our_rwnd;
    uint32_t next_tsn;
    uint32_t last_peer_tsn;
    uint16_t init_retransmits;
    uint16_t cookie_retransmits;
    uint32_t cumulative_tsn_ack;
    std::map<uint32_t, Outstanding_Data> outstanding_data;
    bool has_rtt_measurement_tsn;
    uint32_t rtt_measurement_tsn;
    bool has_srtt;
    std::chrono::microseconds srtt;
    std::chrono::microseconds rttvar;
    std::chrono::microseconds rto;
    uint32_t pmdcs;
    uint32_t cwnd;
    uint32_t ssthresh;
    uint32_t partial_bytes_acked;
    bool in_fast_recovery;
    uint32_t fast_recovery_exit_tsn;
    std::map<uint32_t, data_chunk_value> tsn_ooo_buffer;
    std::vector<uint32_t> duplicate_tsns;
    uint8_t delayed_sack_packet_count;
    uint16_t ack_state;
    uint16_t in_streams;
    uint16_t out_streams;
    std::queue<std::vector<uint8_t>> ulp_buffer;
    // Include reassembly buffer
};

struct Association_Key {
    sockaddr_in address;

    bool operator==(const Association_Key& other) const {
        return address.sin_addr.s_addr == other.address.sin_addr.s_addr && address.sin_port == other.address.sin_port;
    }
};

struct Association_Hash {
    size_t operator()(const Association_Key& k) const {
        return std::hash<uint32_t>()(k.address.sin_addr.s_addr) ^ std::hash<uint16_t>()(k.address.sin_port);
    }
};
#endif
