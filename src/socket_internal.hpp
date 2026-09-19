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
constexpr std::chrono::milliseconds SEND_RETRY_DELAY{10};
constexpr uint32_t DEFAULT_PMDCS = 1200;
constexpr size_t MAX_RECEIVE_BATCH = 64;
constexpr uint8_t DATA_IMMEDIATE_SACK_FLAG = 0x08;
// Must exceed VALID_COOKIE_LIFE, so a cookie still inside its lifespan always
// has its signing key retained.
constexpr std::chrono::minutes COOKIE_SECRET_ROTATION{60};

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
