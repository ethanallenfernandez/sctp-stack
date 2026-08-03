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

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <random>
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

// Seeded from the full entropy of random_device rather than a single 32-bit
// draw. NOTE: mt19937 is not cryptographically secure - its state is
// recoverable from enough observed output, so a determined attacker can predict
// future tags. Move this to the OS CSPRNG when implementing the state cookie.
inline std::mt19937& tag_rng() {
    static thread_local std::mt19937 gen = [] {
        std::random_device rd;
        std::seed_seq seq{rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()};
        return std::mt19937(seq);
    }();
    return gen;
}

inline uint32_t random_u32() {
    return std::uniform_int_distribution<uint32_t>(0, UINT32_MAX)(tag_rng());
}

inline uint32_t random_verification_tag() {
    return std::uniform_int_distribution<uint32_t>(1, UINT32_MAX)(tag_rng());
}

#endif
