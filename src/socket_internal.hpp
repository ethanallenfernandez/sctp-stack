#ifndef SCTP_SOCKET_INTERNAL_HPP
#define SCTP_SOCKET_INTERNAL_HPP

// Constants and helpers shared between the socket_*.cpp translation units.

#include <sctp/association.hpp>
#include <sctp/expiration_queue.hpp>
#include <sctp/sctp.hpp>
#include <sctp/platform.hpp>
#include "builders.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <unordered_map>
#include <vector>

// Which timer to arm after a chunk of a given type reaches the wire, and the
// un-backed-off timeout to arm it with.
struct Expiration_Policy {
    Expiration_Timer_Type timer_type;
    std::chrono::milliseconds initial_timeout;
};

inline const std::unordered_map<Chunk_Type, std::vector<Expiration_Policy>> EXPIRE_HANDLERS{
    {INIT, {{Expiration_Timer_Type::T1_INIT, std::chrono::seconds(1)}}},
    {COOKIE_ECHO, {{Expiration_Timer_Type::T1_COOKIE, std::chrono::seconds(1)}}},
    {DATA, {{Expiration_Timer_Type::T3_RTX, std::chrono::milliseconds(0)}}},
};

constexpr std::chrono::microseconds CLOCK_GRANULARITY{1000};
constexpr std::chrono::milliseconds T5_SHUTDOWN_GUARD = 5 * sctp_parameters::RTO_MAX;
constexpr std::chrono::milliseconds SEND_RETRY_DELAY{10};
constexpr std::chrono::milliseconds CLOSE_POLL_INTERVAL{10};
// Time given to the last SHUTDOWN COMPLETE or ABORT to reach the wire.
constexpr std::chrono::milliseconds CLOSE_DRAIN_TIMEOUT{100};
constexpr uint32_t DEFAULT_PMDCS = 1200;
constexpr uint32_t SLOW_START_INCREASE_PMDCS = 1;
constexpr size_t ACKED_RETRANSMISSION_MEMORY = 64;
constexpr size_t MAX_RECEIVE_BATCH = 64;
constexpr size_t MAX_UDP_DATAGRAM = 65535;
constexpr size_t MAX_SEND_BATCH = 64;
constexpr uint8_t DATA_IMMEDIATE_SACK_FLAG = 0x08;
// Must exceed any cookie lifespan, so a cookie still inside it always has its
// signing key retained.
constexpr std::chrono::minutes COOKIE_SECRET_ROTATION{60};
// Ceiling on VALID_COOKIE_LIFE plus a peer's Cookie Preservative (5.2.6).
constexpr std::chrono::seconds MAX_COOKIE_LIFE{120};
static_assert(MAX_COOKIE_LIFE < COOKIE_SECRET_ROTATION);
// New INITs sent in answer to Stale Cookie errors before giving up.
constexpr uint8_t MAX_STALE_COOKIE_RETRIES = 2;
// What we advertise as OS and MIS in INIT and INIT ACK.
constexpr uint16_t LOCAL_OUT_STREAMS = 10;
constexpr uint16_t LOCAL_MAX_IN_STREAMS = 65535;

inline uint32_t initial_cwnd(uint32_t pmdcs) {
    return std::min(4U * pmdcs, std::max(2U * pmdcs, 4404U));
}

// The peer's SCTP port is the association's, so within one association a
// destination is its IP address alone. The UDP port beside it is only where
// encapsulated packets for it go.
inline bool same_destination(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_addr.s_addr == b.sin_addr.s_addr;
}

inline Association_Key path_key(const sockaddr_in& address) {
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_addr = address.sin_addr;
    return Association_Key{destination};
}

inline Association_Key peer_key(const sockaddr_in& address, uint16_t sctp_port) {
    Association_Key key = path_key(address);
    key.address.sin_port = htons(sctp_port);
    return key;
}

inline Peer_Path* find_path(Association& assoc, const sockaddr_in& address) {
    auto path = std::find_if(assoc.peer_address_list.begin(), assoc.peer_address_list.end(), [&](const Peer_Path& candidate) {
        return same_destination(candidate.address, address);
    });
    return path == assoc.peer_address_list.end() ? nullptr : &*path;
}

inline const Peer_Path* find_path(const Association& assoc, const sockaddr_in& address) {
    return find_path(const_cast<Association&>(assoc), address);
}

inline Peer_Path& primary(Association& assoc) {
    Peer_Path* path = find_path(assoc, assoc.primary_path);
    return path != nullptr ? *path : assoc.peer_address_list.front();
}

inline const Peer_Path& primary(const Association& assoc) {
    return primary(const_cast<Association&>(assoc));
}

inline Peer_Path make_path(const sockaddr_in& address, bool confirmed, uint32_t pmdcs) {
    Peer_Path path{address, confirmed};
    path.cwnd = initial_cwnd(pmdcs);
    path.ssthresh = RWND;
    return path;
}

// New DATA goes to the primary while it is active, and otherwise to one
// alternate, the first active CONFIRMED path (8.2).
inline Peer_Path& data_path(Association& assoc) {
    Peer_Path& preferred = primary(assoc);
    if (preferred.active) {
        return preferred;
    }
    auto alternate = std::find_if(assoc.peer_address_list.begin(), assoc.peer_address_list.end(), [](const Peer_Path& path) {
        return path.confirmed && path.active;
    });
    return alternate == assoc.peer_address_list.end() ? preferred : *alternate;
}

inline const Peer_Path& data_path(const Association& assoc) {
    return data_path(const_cast<Association&>(assoc));
}

// 6.4: timed-out DATA goes to an active CONFIRMED path other than the one it
// was last sent to, the next such in list order, if there is one.
inline Peer_Path& retransmission_path(Association& assoc, const sockaddr_in& last) {
    Peer_Path& preferred = data_path(assoc);
    if (!same_destination(preferred.address, last)) {
        return preferred;
    }
    auto& paths = assoc.peer_address_list;
    size_t from = static_cast<size_t>(&preferred - paths.data());
    for (size_t step = 1; step < paths.size(); ++step) {
        Peer_Path& candidate = paths[(from + step) % paths.size()];
        if (candidate.confirmed && candidate.active) {
            return candidate;
        }
    }
    return preferred;
}

inline Peer_Path& destination_of(Association& assoc, const Outstanding_Data& outstanding) {
    Peer_Path* path = find_path(assoc, outstanding.destination);
    return path != nullptr ? *path : primary(assoc);
}

inline const Peer_Path& destination_of(const Association& assoc, const Outstanding_Data& outstanding) {
    return destination_of(const_cast<Association&>(assoc), outstanding);
}

// Paths awaiting confirmation are probed every RTO, HB.Max.Burst of them at a
// time in list order; the rest wait for one of those to confirm or fail.
inline bool probes_for_confirmation(const Association& assoc, const Peer_Path& path) {
    uint32_t ahead = 0;
    for (const Peer_Path& candidate : assoc.peer_address_list) {
        bool probing = !candidate.confirmed && candidate.active && candidate.hb_enabled;
        if (&candidate == &path) {
            return probing && ahead < sctp_parameters::HB_MAX_BURST;
        }
        ahead += probing;
    }
    return false;
}

// A reply goes back where its packet came from, unless that address is UNCONFIRMED.
inline sockaddr_in reply_destination(const Association& assoc, const sockaddr_in& src) {
    const Peer_Path* path = find_path(assoc, src);
    return path != nullptr && path->confirmed ? src : data_path(assoc).address;
}

// The INIT's source, which the INIT ACK carrying the cookie was sent to.
inline sockaddr_in cookie_source(const State_Cookie& cookie) {
    sockaddr_in source{};
    source.sin_family = AF_INET;
    source.sin_addr.s_addr = htonl(cookie.peer_ipv4);
    source.sin_port = htons(cookie.peer_udp_port);
    return source;
}

inline Association_Key cookie_key(const State_Cookie& cookie) {
    return peer_key(cookie_source(cookie), cookie.sctp_src_port);
}

inline bool has_unacknowledged_data(const Association& assoc) {
    return std::any_of(
        assoc.outstanding_data.begin(),
        assoc.outstanding_data.end(),
        [](const auto& entry) {
            return !entry.second.gap_acked;
        }
    );
}

inline bool has_unacknowledged_data(const Association& assoc, const Peer_Path& path) {
    return std::any_of(assoc.outstanding_data.begin(), assoc.outstanding_data.end(), [&](const auto& entry) {
        return !entry.second.gap_acked && &destination_of(assoc, entry.second) == &path;
    });
}

inline size_t bytes_in_flight(const Association& assoc, const Peer_Path* path = nullptr) {
    size_t total = 0;
    for (const auto& [tsn, outstanding] : assoc.outstanding_data) {
        if (!outstanding.gap_acked && !outstanding.pending_retransmission
                && (path == nullptr || &destination_of(assoc, outstanding) == path)) {
            total += data_chunk_wire_size(outstanding.data);
        }
    }
    return total;
}

inline bool cwnd_open(const Association& assoc, const Peer_Path& path) {
    size_t flight = bytes_in_flight(assoc, &path);
    return path.single_packet_in_flight ? flight == 0 : flight < path.cwnd;
}

// RFC 9260 6: DATA is sent and SACKs processed in these states...
inline bool transmits_data(Association_State state) {
    return state == ESTABLISHED || state == SHUTDOWN_PENDING || state == SHUTDOWN_RECEIVED;
}

// ...and DATA is received in these.
inline bool receives_data(Association_State state) {
    return state == ESTABLISHED || state == SHUTDOWN_PENDING || state == SHUTDOWN_SENT;
}

inline std::vector<uint8_t> be32_bytes(uint32_t v) {
    return {static_cast<uint8_t>(v >> 24), static_cast<uint8_t>(v >> 16), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v)};
}

inline uint32_t read_be32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1]) << 16 | static_cast<uint32_t>(p[2]) << 8 | p[3];
}

// The Heartbeat Info is ours to define: the nonce, then the destination's
// address and UDP port as they sit in sockaddr_in. The send time is not in
// here - the path records it after sendto, which is both more accurate and not
// something the peer can forge.
constexpr size_t HEARTBEAT_INFO_SIZE = 14;

inline std::vector<uint8_t> heartbeat_info(uint64_t nonce, const sockaddr_in& destination) {
    std::vector<uint8_t> info = be32_bytes(static_cast<uint32_t>(nonce >> 32));
    std::vector<uint8_t> low = be32_bytes(static_cast<uint32_t>(nonce));
    info.insert(info.end(), low.begin(), low.end());
    const uint8_t* address = reinterpret_cast<const uint8_t*>(&destination.sin_addr.s_addr);
    info.insert(info.end(), address, address + sizeof(destination.sin_addr.s_addr));
    const uint8_t* port = reinterpret_cast<const uint8_t*>(&destination.sin_port);
    info.insert(info.end(), port, port + sizeof(destination.sin_port));
    return info;
}

inline uint64_t heartbeat_info_nonce(const std::vector<uint8_t>& info) {
    return static_cast<uint64_t>(read_be32(info.data())) << 32 | read_be32(info.data() + 4);
}

inline sockaddr_in heartbeat_info_destination(const std::vector<uint8_t>& info) {
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    std::copy_n(info.data() + 8, sizeof(destination.sin_addr.s_addr), reinterpret_cast<uint8_t*>(&destination.sin_addr.s_addr));
    std::copy_n(info.data() + 12, sizeof(destination.sin_port), reinterpret_cast<uint8_t*>(&destination.sin_port));
    return destination;
}

// RFC 9260 3.3.10.1: Stream Identifier, then 16 reserved bits.
inline error_cause invalid_stream_cause(uint16_t stream_id) {
    return error_cause{CAUSE_INVALID_STREAM_ID, {static_cast<uint8_t>(stream_id >> 8), static_cast<uint8_t>(stream_id), 0, 0}};
}

// RFC 9260 3.3.10.3: Measure of Staleness, in microseconds.
inline error_cause stale_cookie_cause(uint32_t staleness_us) {
    return error_cause{CAUSE_STALE_COOKIE, be32_bytes(staleness_us)};
}

template <typename T>
inline auto generate_random(T& input) -> decltype(input) {
    random_bytes(reinterpret_cast<uint8_t*>(&input), sizeof(input));
    return input;
}

// Initiate Tags and Tie-Tags are drawn from 1..2^32-1 (RFC 9260 5.3.1); 0 is
// reserved for INIT and, in a cookie, means "no Tie-Tag".
inline uint32_t generate_nonzero_tag() {
    uint32_t tag;
    do {
        generate_random(tag);
    } while (tag == 0);
    return tag;
}
#endif
