#ifndef SCTP_ASSOCIATION_HPP
#define SCTP_ASSOCIATION_HPP

#include <stdint.h>
#include <vector>
#include <utility>
#include <string>
#include <functional>
#include <map>
#include <optional>
#include <deque>
#include <chrono>
#include <unordered_map>
#include <sctp/platform/compat.hpp>
#include <sctp/protocol/sctp.hpp>
#include <sctp/protocol/tsn.hpp>

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
    // Where it was last sent, or, while pending retransmission, where it goes next.
    sockaddr_in destination{};
};

struct Acked_Retransmission {
    uint32_t tsn;
    uint32_t size;
    sockaddr_in destination;
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
    uint32_t ppid{0};
};

// Ordered messages that arrived complete ahead of the next SSN, keyed by SSN.
struct Inbound_Stream {
    uint16_t next_ssn{0};
    std::map<uint16_t, Delivery> early;
};

// Queued by the ULP, cut into DATA chunks only once a packet can carry them.
struct Outbound_Message {
    uint16_t stream;
    uint16_t ssn;
    bool unordered;
    std::vector<uint8_t> bytes;
    size_t offset{0};
    uint32_t ppid{0};
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
    uint32_t ppid{0};
    std::vector<uint8_t> bytes;
};

enum class Plpmtud_State {
    DISABLED,
    BASE,
    SEARCHING,
    SEARCH_COMPLETE,
    ERROR,
};

// RFC 8899 5.1.3 for one destination. search_high is the smallest size known
// not to get through, above MAX_PLPMTU until one is found. confirming marks a
// probe at the PLPMTU itself, sent in SEARCH_COMPLETE on suspicion of a black hole.
struct Plpmtud {
    Plpmtud_State state{Plpmtud_State::DISABLED};
    uint32_t plpmtu{plpmtud_parameters::BASE_PLPMTU};
    uint32_t probed_size{plpmtud_parameters::BASE_PLPMTU};
    uint32_t search_high{plpmtud_parameters::MAX_PLPMTU + 1};
    uint8_t probe_count{0};
    bool probe_outstanding{false};
    bool confirming{false};
    uint64_t probe_nonce{0};
};

// A destination of the peer, at the UDP encapsulation port this address last
// sent from. The SCTP port is the association's.
struct Peer_Path {
    sockaddr_in udp_address;
    bool confirmed;
    // Our address its packets last arrived at, and so the one we send to it
    // from. INADDR_ANY until then: the first address bound.
    in_addr source{};
    bool active{true};
    uint16_t error_count{0};
    bool hb_enabled{true};
    bool hb_outstanding{false};
    uint64_t hb_nonce{0};
    std::chrono::steady_clock::time_point hb_sent_at{};
    std::chrono::steady_clock::time_point hb_next{};
    std::chrono::steady_clock::time_point hb_period_start{};
    // Last first transmission of DATA, which makes the path not idle (8.3).
    std::chrono::steady_clock::time_point new_data_sent_at{};
    bool has_srtt{false};
    std::chrono::microseconds srtt{0};
    std::chrono::microseconds rttvar{0};
    std::chrono::microseconds rto{sctp_parameters::RTO_INITIAL};
    uint32_t cwnd{0};
    uint32_t ssthresh{0};
    uint32_t partial_bytes_acked{0};
    // Set by a T3-rtx expiry, cleared by the next SACK acknowledging DATA sent
    // here: until then only one packet may be in flight.
    bool single_packet_in_flight{false};
    // Last DATA transmission, moved forward by each idle cwnd decay.
    std::chrono::steady_clock::time_point data_sent_at{};
    bool idle_decaying{false};
    Plpmtud plpmtud{};
};

// Who the peer is and the tags that prove it, for the association's life.
struct TCB_Peer {
    // Host order. The peer's UDP encapsulation ports are per path.
    uint16_t sctp_port{};
    uint32_t this_ver_tag{};
    uint32_t peer_ver_tag{};
    uint32_t local_tie_tag{};
    uint32_t peer_tie_tag{};
};

// Only while the association forms.
struct Handshake {
    uint16_t init_retransmits{};
    uint16_t cookie_retransmits{};
    uint8_t stale_cookie_retries{};
};

struct Paths {
    std::vector<Peer_Path> list;
    sockaddr_in primary{};
    // Association-wide; each path also counts its own.
    uint16_t error_count{};
    std::chrono::milliseconds hb_interval{sctp_parameters::HB_INTERVAL};
};

struct TCB_Send_Side {
    // ULP messages not yet cut into DATA chunks.
    uint16_t out_streams{};
    std::vector<uint16_t> next_ssn; // Indexed into by stream number
    std::deque<Outbound_Message> outbound;
    size_t outbound_bytes{};

    uint32_t next_tsn{};
    // The peer's acknowledgement of our DATA.
    uint32_t cumulative_tsn_ack{};
    std::map<uint32_t, Outstanding_Data, Tsn_Less> outstanding;
    // TSN and size of retransmitted chunks recently acked cumulatively, which
    // the peer may yet report as Duplicate TSNs.
    std::deque<Acked_Retransmission> acked_retransmissions;
    std::optional<uint32_t> rtt_measurement_tsn{};

    uint32_t peer_rwnd{};
    uint32_t peer_max_rwnd{};
    bool zero_window_probe_allowed{};
    bool zero_window_probing{};
    bool sack_since_t3{};

    // cwnd itself is kept per path.
    bool in_fast_recovery{};
    uint32_t fast_recovery_exit_tsn{};
    // New-DATA packets sent in the current transmission opportunity.
    uint32_t burst_count{};
};

struct TCB_Receive_Side {
    uint16_t in_streams{};
    // Our Cumulative TSN Ack point.
    uint32_t last_peer_tsn{};
    std::map<uint32_t, Held_Chunk, Tsn_Less> ooo;
    std::vector<uint32_t> duplicate_tsns;
    uint8_t delayed_sack_packet_count{};
    // The a_rwnd we last advertised, and the user data received since, which
    // the peer still counts against it.
    uint32_t our_rwnd{RWND};
    uint32_t received_since_sack{};
    Reassembly reassembly;
    std::unordered_map<uint16_t, Inbound_Stream> streams;
    // Messages completed while another is part way through partial delivery,
    // which has the ULP's attention until its end arrives.
    std::vector<Delivery> held_deliveries;
};

struct Association_TCB {
    Association_State state{COOKIE_WAIT};
    TCB_Peer peer{};
    Handshake handshake{};
    Paths paths{};
    TCB_Send_Side send{};
    TCB_Receive_Side receive{};
};

// Names one association while it lives and while its received data waits to
// be read. Never reused; 0 names none.
enum class Association_Key : uint32_t {};

// A peer transport address: IPv4 address and SCTP port, network order. With
// the port 0, one destination within an association.
struct Peer_Key {
    sockaddr_in sctp_address;

    bool operator==(const Peer_Key& other) const {
        return sctp_address.sin_addr.s_addr == other.sctp_address.sin_addr.s_addr && sctp_address.sin_port == other.sctp_address.sin_port;
    }
};

struct Peer_Key_Hash {
    size_t operator()(const Peer_Key& k) const {
        return std::hash<uint64_t>()(uint64_t{k.sctp_address.sin_addr.s_addr} << 16 | k.sctp_address.sin_port);
    }
};
#endif
