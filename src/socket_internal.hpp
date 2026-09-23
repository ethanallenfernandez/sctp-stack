#ifndef SCTP_SOCKET_INTERNAL_HPP
#define SCTP_SOCKET_INTERNAL_HPP

// Constants and helpers shared between the socket_*.cpp translation units.

#include <sctp/association.hpp>
#include <sctp/expiration_queue.hpp>
#include <sctp/sctp.hpp>
#include <sctp/platform.hpp>

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
constexpr size_t MAX_RECEIVE_BATCH = 64;
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
constexpr uint16_t LOCAL_OUT_STREAMS = 1;
constexpr uint16_t LOCAL_MAX_IN_STREAMS = 1;

inline bool has_unacknowledged_data(const Association& assoc) {
    return std::any_of(
        assoc.outstanding_data.begin(),
        assoc.outstanding_data.end(),
        [](const auto& entry) {
            return !entry.second.gap_acked;
        }
    );
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

// The Heartbeat Info is ours to define: a nonce the ACK is matched against, and
// the destination it went to, which tells paths apart once there is more than
// one. The send time is not in here - the TCB records it after sendto, which is
// both more accurate and not something the peer can forge.
constexpr size_t HEARTBEAT_INFO_SIZE = 10;

inline std::vector<uint8_t> heartbeat_info(uint32_t nonce, const sockaddr_in& destination) {
    std::vector<uint8_t> info = be32_bytes(nonce);
    const uint8_t* address = reinterpret_cast<const uint8_t*>(&destination.sin_addr.s_addr);
    info.insert(info.end(), address, address + sizeof(destination.sin_addr.s_addr));
    const uint8_t* port = reinterpret_cast<const uint8_t*>(&destination.sin_port);
    info.insert(info.end(), port, port + sizeof(destination.sin_port));
    return info;
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
