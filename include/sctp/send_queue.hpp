#ifndef SCTP_SEND_QUEUE_HPP
#define SCTP_SEND_QUEUE_HPP

// Outbound scheduling: control traffic, then retransmissions, then new DATA.
//
// peek()/commit() instead of pop() so sendto() runs outside the queue lock. A
// failed write calls defer() and the packet stays queued. Safe because only the
// event-loop thread pops.
//
// New DATA is admitted per association against a Send_Allowance snapshot the
// caller builds from the TCBs, so one association with a closed window does not
// hold back another. Within an association, a refused packet also holds back
// every later one, keeping TSNs on the wire in the order they were assigned.

#include <sctp/association.hpp>
#include <sctp/deliverable.hpp>
#include <sctp/sctp.hpp>

#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

enum class Send_Priority {
    CONTROL,
    RETRANSMISSION,
    NEW_DATA,
};

struct Send_Allowance {
    size_t flight_size;
    bool cwnd_open;
    bool burst_spent;
    uint32_t rwnd;
    bool zero_window_probe;
    // Set by peek() when this association's next packet was refused by rwnd
    // alone.
    bool rwnd_blocked{false};
};

using Send_Allowances = std::unordered_map<Association_Key, Send_Allowance, Association_Hash>;

class Send_Queue {
    public:
        struct Pending {
            Send_Priority priority;
            Deliverable deliverable;
            uint64_t id;
        };

        void enqueue(Deliverable deliverable, Send_Priority priority);

        // Highest-priority sendable packet, or nullopt if there is none or the
        // queue is backing off. New DATA for an association missing from
        // `allowances` is not sendable. Does not pop: follow with commit() or
        // defer().
        std::optional<Pending> peek(std::chrono::steady_clock::time_point now, Send_Allowances& allowances);
        // As above with every window open, for draining the queue in tests.
        std::optional<Pending> peek(std::chrono::steady_clock::time_point now);
        void commit(const Pending& pending);
        void defer(std::chrono::steady_clock::time_point retry_at);

        void purge(const Association_Key& location);
        bool has_retransmission_for(const Association_Key& location);

        // Drops acked DATA from pending retransmissions, and empty packets.
        void remove_acked_retransmissions(const Association_Key& location, const sack_chunk_value& sack);
        void remove_retransmissions_of_type(const Association_Key& location, Chunk_Type type);

        void clear();

        // Next send attempt, or nullopt if nothing is sendable. May be in the
        // past, meaning send now. New DATA refused by the last peek() does not
        // count until something is enqueued: what reopens a window (a SACK, a
        // timer) wakes the event loop by itself.
        std::optional<std::chrono::steady_clock::time_point> next_deadline();

        // Inspection, for tests and diagnostics.
        size_t size();
        bool has_packets_for(const Association_Key& location);
        std::vector<uint32_t> front_data_tsns(Send_Priority priority);
        size_t front_chunk_count(Send_Priority priority);

    private:
        struct Queued {
            uint64_t id;
            Deliverable deliverable;
        };

        // Caller must hold `mutex`.
        std::deque<Queued>& queue_for(Send_Priority priority);
        std::optional<Pending> peek_locked(std::chrono::steady_clock::time_point now, Send_Allowances* allowances);

        std::deque<Queued> control;
        std::deque<Queued> retransmission;
        std::deque<Queued> new_data;
        uint64_t next_id{0};
        bool new_data_blocked{false};
        std::chrono::steady_clock::time_point next_send_attempt{};
        std::mutex mutex;
};

#endif
