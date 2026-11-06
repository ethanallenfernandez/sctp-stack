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

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

class Receive_Queue {
    public:
        struct Read {
            Association_Key key;
            size_t bytes;
            // More of this message remains, queued or yet to arrive.
            bool partial;
            uint16_t stream;
        };

        void push(const Association_Key& key, std::vector<uint8_t> bytes, bool complete = true, uint16_t stream = 0);
        // Each waits up to timeout for a message, or until close().
        std::optional<Read> read_any(uint8_t* out, size_t capacity, std::chrono::milliseconds timeout = {});
        std::optional<Read> read_from(const Association_Key& key, uint8_t* out, size_t capacity, std::chrono::milliseconds timeout = {});
        // Drops a message whose end will never arrive, read or not.
        void abandon_open(const Association_Key& key);
        // The association under key has ended: what it left stays readable, but
        // no longer counts against the window of the next one under that key.
        void detach(const Association_Key& key);
        void close();
        void clear();

        // Inspection, and the per-association occupancy a_rwnd is built from.
        size_t messages(const Association_Key& key);
        size_t buffered_bytes(const Association_Key& key);

    private:
        struct Message {
            std::vector<uint8_t> bytes;
            size_t offset;
            bool complete;
            uint16_t stream;
        };

        struct Pending {
            std::deque<Message> messages;
            size_t bytes{0};
            // Of bytes, those at the front left by an ended association.
            size_t detached{0};
        };

        // Caller must hold `mutex`. Erases the entry once it is empty.
        Read read_locked(std::unordered_map<Association_Key, Pending, Association_Hash>::iterator it, uint8_t* out, size_t capacity);

        std::unordered_map<Association_Key, Pending, Association_Hash> pending;
        std::deque<Association_Key> ready;
        bool closed{false};
        std::mutex mutex;
        std::condition_variable available;
};

#endif
