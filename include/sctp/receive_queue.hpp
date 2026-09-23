#ifndef SCTP_RECEIVE_QUEUE_HPP
#define SCTP_RECEIVE_QUEUE_HPP

// Messages delivered to the ULP but not yet read, per association. Held apart
// from the TCB so they outlive it: a graceful close removes the association
// before the application has necessarily read everything it was sent.
//
// pop_any() serves associations round-robin through `ready`, which holds
// exactly the keys with messages waiting.

#include <sctp/association.hpp>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <queue>
#include <unordered_map>
#include <utility>
#include <vector>

class Receive_Queue {
    public:
        void push(const Association_Key& key, std::vector<uint8_t> message);
        std::optional<std::pair<Association_Key, std::vector<uint8_t>>> pop_any();
        std::optional<std::vector<uint8_t>> pop_from(const Association_Key& key);
        void clear();

        // Inspection, and the per-association occupancy a_rwnd will be built from.
        size_t messages(const Association_Key& key);
        size_t buffered_bytes(const Association_Key& key);

    private:
        struct Pending {
            std::queue<std::vector<uint8_t>> messages;
            size_t bytes{0};
        };

        // Caller must hold `mutex`. Erases the entry once it is empty.
        std::vector<uint8_t> pop_locked(std::unordered_map<Association_Key, Pending, Association_Hash>::iterator it);

        std::unordered_map<Association_Key, Pending, Association_Hash> pending;
        std::deque<Association_Key> ready;
        std::mutex mutex;
};

#endif
