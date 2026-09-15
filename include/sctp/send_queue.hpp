#ifndef SCTP_SEND_QUEUE_HPP
#define SCTP_SEND_QUEUE_HPP

// Outbound packet scheduling: protocol control traffic first, then
// retransmissions, then new DATA.
//
// Sending is deliberately split into peek() / commit() rather than a single
// pop(). The actual sendto() must not run while the queue lock is held, so the
// event loop peeks the front packet, releases the lock, writes to the wire, and
// only then commits the pop. On a failed write it calls defer() instead and the
// packet stays queued. This is safe because only the event-loop thread pops.

#include <sctp/association.hpp>
#include <sctp/deliverable.hpp>
#include <sctp/sctp.hpp>

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <queue>
#include <vector>

enum class Send_Priority {
    CONTROL,
    RETRANSMISSION,
    NEW_DATA,
};

class Send_Queue {
    public:
        struct Pending {
            Send_Priority priority;
            Deliverable deliverable;
        };

        void enqueue(Deliverable deliverable, Send_Priority priority);

        // Front packet of the highest-priority non-empty queue. Returns nullopt
        // if everything is empty or a failed send is still backing off. Does
        // not pop -- the caller must follow with commit() or defer().
        std::optional<Pending> peek(std::chrono::steady_clock::time_point now);
        void commit(Send_Priority priority);
        void defer(std::chrono::steady_clock::time_point retry_at);

        // Drops every queued packet for an association, used when it goes away.
        void purge(const Association_Key& location);

        // Drops DATA chunks the peer has acknowledged from packets still
        // waiting to be retransmitted, and drops packets left with no chunks.
        void remove_acked_retransmissions(const Association_Key& location, const sack_chunk_value& sack);
        void remove_retransmissions_of_type(const Association_Key& location, Chunk_Type type);

        void clear();

        // When the event loop should next attempt a send: nullopt if nothing is
        // queued, otherwise the backoff deadline (which may be in the past,
        // meaning send now).
        std::optional<std::chrono::steady_clock::time_point> next_deadline();

        // Inspection, for tests and diagnostics.
        size_t size();
        bool has_packets_for(const Association_Key& location);
        std::vector<uint32_t> front_data_tsns(Send_Priority priority);
        size_t front_chunk_count(Send_Priority priority);

    private:
        // Caller must hold `mutex`.
        std::queue<Deliverable>& queue_for(Send_Priority priority);

        std::queue<Deliverable> control;
        std::queue<Deliverable> retransmission;
        std::queue<Deliverable> new_data;
        std::chrono::steady_clock::time_point next_send_attempt{};
        std::mutex mutex;
};

#endif
