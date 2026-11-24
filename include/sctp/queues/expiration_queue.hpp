#ifndef SCTP_EXPIRATION_QUEUE_HPP
#define SCTP_EXPIRATION_QUEUE_HPP

#include <sctp/protocol/association.hpp>
#include <sctp/queues/deliverable.hpp>

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
    HEARTBEAT,
    T2_SHUTDOWN,
    T5_SHUTDOWN_GUARD,
    ZERO_WINDOW_PROBE,
    PLPMTU_PROBE,
    PMTU_RAISE,
};

// `path` names the destination for timers kept per destination, and is left
// zero for those kept per association.
struct Expiration_Key {
    Association_Key location{};
    Expiration_Timer_Type type;
    Peer_Key path{};

    bool operator==(const Expiration_Key& other) const {
        return location == other.location && type == other.type && path == other.path;
    }
};

struct Expiration_Key_Hash {
    size_t operator()(const Expiration_Key& key) const {
        size_t hash = std::hash<Association_Key>{}(key.location);
        for (size_t part : {std::hash<uint8_t>{}(static_cast<uint8_t>(key.type)), Peer_Key_Hash{}(key.path)}) {
            hash ^= part + 0x9e3779b9U + (hash << 6) + (hash >> 2);
        }
        return hash;
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

// Every protocol timer, one per key; scheduling a key replaces any timer already
// running for it. std::priority_queue cannot erase from the middle, so each
// entry is stamped with a generation and `active` holds the live one per key;
// stale entries are discarded when they surface. Nothing here wakes the event
// loop: SCTP_Socket wraps these to do that after releasing the lock.
class Expiration_Queue {
    friend struct SCTP_Socket_Test_Access;

    public:
        void schedule(
            const Expiration_Key& key,
            std::chrono::steady_clock::time_point expiration,
            const Deliverable& retry
        );
        void cancel(const Expiration_Key& key);
        void cancel_all(const Association_Key& location);
        void cancel_all(const Association_Key& location, Expiration_Timer_Type type);
        void clear();
        bool is_active(const Expiration_Key& key);
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
