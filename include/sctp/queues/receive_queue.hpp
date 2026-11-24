#ifndef SCTP_RECEIVE_QUEUE_HPP
#define SCTP_RECEIVE_QUEUE_HPP

#include <sctp/protocol/association.hpp>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

// Messages delivered to the ULP but not yet read, per association. Held apart
// from the TCB so they outlive it: a graceful close removes the association
// before the application has necessarily read everything it was sent.
//
// A message may be pushed in pieces before it has fully arrived; each piece
// continues the message at the back until one completes it. A read takes at
// most one message, and is partial while more of it remains queued or yet to
// arrive. abandon_open drops a message whose end will never arrive, and
// buffered_bytes is the occupancy a_rwnd is built from.
class Receive_Queue {
    friend struct SCTP_Socket_Test_Access;

    public:
        struct Read {
            Association_Key key{};
            size_t bytes;
            bool partial;
            uint16_t stream;
            uint32_t ppid;
        };

        void push(const Association_Key& key, std::vector<uint8_t> bytes, bool complete = true, uint16_t stream = 0, uint32_t ppid = 0);
        std::optional<Read> read_any(uint8_t* out, size_t capacity);
        std::optional<Read> read_from(const Association_Key& key, uint8_t* out, size_t capacity);
        void abandon_open(const Association_Key& key);
        void clear();

        size_t buffered_bytes(const Association_Key& key);

    private:
        struct Message {
            std::vector<uint8_t> bytes;
            size_t offset;
            bool complete;
            uint16_t stream;
            uint32_t ppid;
        };

        struct Pending {
            std::deque<Message> messages;
            size_t bytes{0};
        };

        Read read_locked(std::unordered_map<Association_Key, Pending>::iterator it, uint8_t* out, size_t capacity);

        std::unordered_map<Association_Key, Pending> pending;
        std::mutex mutex;
};

#endif
