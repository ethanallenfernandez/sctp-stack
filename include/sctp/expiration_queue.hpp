#ifndef SCTP_EXPIRATION_QUEUE_HPP
#define SCTP_EXPIRATION_QUEUE_HPP

// The retransmission timer heap: T1-init, T1-cookie, T3-rtx and the delayed
// SACK timer (RFC 9260 6.3.2, 5.1, 6.2).
//
// Cancellation is by generation counter rather than by removal from the heap:
// std::priority_queue cannot erase from the middle, so schedule() stamps each
// entry with a generation and records the live one in `active`. An entry whose
// generation no longer matches is stale and is discarded when it surfaces.
//
// None of these operations wake the event loop. SCTP_Socket wraps them to add
// that, because the wake must happen after the lock is released.

#include <sctp/association.hpp>
#include <sctp/deliverable.hpp>

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <queue>
#include <unordered_map>
#include <vector>

enum class Expiration_Timer_Type {
    T1_INIT,
    T1_COOKIE,
    T3_RTX,
    DELAYED_SACK,
};

struct Expiration_Key {
    Association_Key location;
    Expiration_Timer_Type type;

    bool operator==(const Expiration_Key& other) const {
        return location == other.location && type == other.type;
    }
};

struct Expiration_Key_Hash {
    size_t operator()(const Expiration_Key& key) const {
        size_t location_hash = Association_Hash{}(key.location);
        size_t type_hash = std::hash<uint8_t>{}(static_cast<uint8_t>(key.type));
        return location_hash ^ (type_hash + 0x9e3779b9U + (location_hash << 6) + (location_hash >> 2));
    }
};

struct Expiration_Fallback {
    Expiration_Key key;
    std::chrono::steady_clock::time_point expiration;
    uint64_t generation;
    Deliverable retry;
};

struct Compare_Expiration {
    bool operator()(const Expiration_Fallback& lhs, const Expiration_Fallback& rhs) const {
        return lhs.expiration > rhs.expiration;
    }
};

class Expiration_Queue {
    public:
        void schedule( // Also replaces any timer already running for this key.
            const Expiration_Key& key,
            std::chrono::steady_clock::time_point expiration,
            const Deliverable& retry
        );
        void cancel(const Expiration_Key& key);
        void cancel_all(const Association_Key& location);
        void clear();
        bool is_active(const Expiration_Key& key);
        bool has_any_for(const Association_Key& location);
        uint64_t generation_of(const Expiration_Key& key);
        std::vector<Expiration_Fallback> drain_expired(std::chrono::steady_clock::time_point now);
        std::optional<std::chrono::steady_clock::time_point> next_deadline();

    private:
        std::priority_queue<
            Expiration_Fallback,
            std::vector<Expiration_Fallback>,
            Compare_Expiration
        > queue;
        std::unordered_map<Expiration_Key, uint64_t, Expiration_Key_Hash> active;
        uint64_t next_generation{1};
        std::mutex mutex;
};

#endif
