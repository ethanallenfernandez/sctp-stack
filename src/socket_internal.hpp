#ifndef SCTP_SOCKET_INTERNAL_HPP
#define SCTP_SOCKET_INTERNAL_HPP

// Constants and helpers shared between the socket_*.cpp translation units.
// Internal to the library: not installed, not referenced by any public header.
//
// These lived in an anonymous namespace in socket.cpp. Splitting that file
// across four translation units means they can no longer be anonymous, so they
// are inline / constexpr here instead.

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

// RFC 9260 6.3.1: the RTO estimator's clock granularity floor.
constexpr std::chrono::microseconds CLOCK_GRANULARITY{1000};
// How long to back off after a local send failure before retrying the wire.
constexpr std::chrono::milliseconds SEND_RETRY_DELAY{10};
constexpr uint32_t DEFAULT_PMDCS = 1200;
// Datagrams drained per readable poll() before yielding back to the loop.
constexpr size_t MAX_RECEIVE_BATCH = 64;
// DATA chunk I-bit: peer is asking for an immediate SACK (RFC 9260 6.2).
constexpr uint8_t DATA_IMMEDIATE_SACK_FLAG = 0x08;

inline bool has_unacknowledged_data(const Association& assoc) {
    return std::any_of(
        assoc.outstanding_data.begin(),
        assoc.outstanding_data.end(),
        [](const auto& entry) {
            return !entry.second.gap_acked;
        }
    );
}

template <typename T>
inline auto generate_random(T& input) -> decltype(input) {
    random_bytes(reinterpret_cast<uint8_t*>(&input), sizeof(input));
    return input;
}
#endif
