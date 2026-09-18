#ifndef SCTP_SEND_QUEUE_HPP
#define SCTP_SEND_QUEUE_HPP

// Outbound scheduling: control traffic, then retransmissions, then new DATA.
//
// peek()/commit() instead of pop() so sendto() runs outside the queue lock. A
// failed write calls defer() and the packet stays queued. Safe because only the
// event-loop thread pops.

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

        // Highest-priority front packet, or nullopt if empty or backing off.
        // Does not pop: follow with commit() or defer().
        std::optional<Pending> peek(std::chrono::steady_clock::time_point now);
        void commit(Send_Priority priority);
        void defer(std::chrono::steady_clock::time_point retry_at);

        void purge(const Association_Key& location);

        // Drops acked DATA from pending retransmissions, and empty packets.
        void remove_acked_retransmissions(const Association_Key& location, const sack_chunk_value& sack);
        void remove_retransmissions_of_type(const Association_Key& location, Chunk_Type type);

        void clear();

        // Next send attempt, or nullopt if nothing is queued. May be in the
        // past, meaning send now.
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
