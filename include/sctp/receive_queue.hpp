#ifndef SCTP_RECEIVE_QUEUE_HPP
#define SCTP_RECEIVE_QUEUE_HPP

// Messages delivered to the ULP but not yet read, per association. Held apart
// from the TCB so they outlive it: a graceful close removes the association
// before the application has necessarily read everything it was sent.
//
// A message may be pushed in pieces before it has fully arrived; each piece
// continues the message at the back until one completes it. A read takes at
// most one message, and what does not fit the caller's buffer stays queued.
//
// read_any() serves associations round-robin through `ready`, which holds
// exactly the keys with bytes waiting. An association stays at the front while
// its message is part-read, so consecutive reads return one message whole.

#include <sctp/association.hpp>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

// Bytes of one message handed to the ULP; `complete` is false while more of it is to follow.
struct Delivery {
    std::vector<uint8_t> bytes;
    bool complete{true};
};

class Receive_Queue {
    public:
        struct Read {
            Association_Key key;
            size_t bytes;
            // More of this message remains, queued or yet to arrive.
            bool partial;
        };

        void push(const Association_Key& key, std::vector<uint8_t> bytes, bool complete = true);
        std::optional<Read> read_any(uint8_t* out, size_t capacity);
        std::optional<Read> read_from(const Association_Key& key, uint8_t* out, size_t capacity);
        void clear();

        // Inspection, and the per-association occupancy a_rwnd will be built from.
        size_t messages(const Association_Key& key);
        size_t buffered_bytes(const Association_Key& key);

    private:
        struct Message {
            std::vector<uint8_t> bytes;
            size_t offset;
            bool complete;
        };

        struct Pending {
            std::deque<Message> messages;
            size_t bytes{0};
        };

        // Caller must hold `mutex`. Erases the entry once it is empty.
        Read read_locked(std::unordered_map<Association_Key, Pending, Association_Hash>::iterator it, uint8_t* out, size_t capacity);

        std::unordered_map<Association_Key, Pending, Association_Hash> pending;
        std::deque<Association_Key> ready;
        std::mutex mutex;
};

#endif
