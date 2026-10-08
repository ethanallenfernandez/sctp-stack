#ifndef SCTP_ASSOCIATION_HPP
#define SCTP_ASSOCIATION_HPP

#include <stdint.h>
#include <vector>
#include <utility>
#include <string>
#include <functional>
#include <map>
#include <deque>
#include <chrono>
#include <unordered_map>
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

// A chunk received above the Cumulative TSN Ack. `assembled` once its message
// was completed ahead of the cumulative point and taken out of the chunks: the
// entry stays only for the SACK, and is never dropped to make room.
struct Held_Chunk {
    data_chunk_value data;
    bool assembled{false};
};

// Bytes of one message handed to the ULP; `complete` is false while more of it is to follow.
struct Delivery {
    std::vector<uint8_t> bytes;
    bool complete{true};
    uint16_t stream{0};
};

// Ordered messages that arrived complete ahead of the next SSN, keyed by SSN.
struct Inbound_Stream {
    uint16_t next_ssn{0};
    std::map<uint16_t, std::vector<uint8_t>> early;
};

// Queued by the ULP, cut into DATA chunks only once a packet can carry them.
struct Outbound_Message {
    uint16_t stream;
    uint16_t ssn;
    bool unordered;
    std::vector<uint8_t> bytes;
    size_t offset{0};
};

// The message whose fragments are being consumed in TSN order.
struct Reassembly {
    bool open{false};
    // Part of the message has gone to the ULP ahead of its end: the rest
    // follows as it arrives.
    bool partially_delivered{false};
    bool unordered{false};
    uint16_t stream{0};
    uint16_t ssn{0};
    std::vector<uint8_t> bytes;
};

// A destination transport address of the peer. The UDP port is the
// encapsulation port, which RFC 6951 keeps per destination.
struct Peer_Path {
    sockaddr_in address;
    bool confirmed;
};

struct Association {
    uint32_t peer_ver_tag;
    uint32_t this_ver_tag;
    uint32_t local_tie_tag;
    uint32_t peer_tie_tag;
    Association_State state;
    std::vector<Peer_Path> peer_address_list;
    sockaddr_in primary_path;
    uint16_t error_count;
    uint16_t error_threshold;
    uint32_t hb_nonce;
    bool hb_outstanding;
    std::chrono::steady_clock::time_point hb_sent_at;
    uint32_t peer_rwnd;
    uint32_t peer_max_rwnd;
    bool zero_window_probe_allowed;
    bool zero_window_probing;
    bool sack_since_t3;
    // The a_rwnd we last advertised, and the user data received since, which
    // the peer still counts against it.
    uint32_t our_rwnd;
    uint32_t received_since_sack;
    uint32_t next_tsn;
    uint32_t last_peer_tsn;
    uint16_t init_retransmits;
    uint16_t cookie_retransmits;
    uint8_t stale_cookie_retries;
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
    // Set by a T3-rtx expiry, cleared by the next SACK acknowledging new DATA:
    // until then only one packet may be in flight.
    bool single_packet_in_flight;
    // New-DATA packets sent in the current transmission opportunity.
    uint32_t burst_count;
    // TSN and size of retransmitted chunks recently acked cumulatively, which
    // the peer may yet report as Duplicate TSNs.
    std::deque<std::pair<uint32_t, uint32_t>> acked_retransmissions;
    // Last DATA transmission, moved forward by each idle cwnd decay.
    std::chrono::steady_clock::time_point data_sent_at;
    bool idle_decaying;
    bool in_fast_recovery;
    uint32_t fast_recovery_exit_tsn;
    std::map<uint32_t, Held_Chunk> tsn_ooo_buffer;
    std::vector<uint32_t> duplicate_tsns;
    uint8_t delayed_sack_packet_count;
    uint16_t ack_state;
    uint16_t in_streams;
    uint16_t out_streams;
    std::vector<uint16_t> next_ssn; // Indexed into by stream number
    std::deque<Outbound_Message> outbound;
    Reassembly reassembly;
    std::unordered_map<uint16_t, Inbound_Stream> inbound_streams;
    // Messages completed while another is part way through partial delivery,
    // which has the ULP's attention until its end arrives.
    std::vector<Delivery> held_deliveries;
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
