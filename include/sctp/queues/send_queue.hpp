#ifndef SCTP_SEND_QUEUE_HPP
#define SCTP_SEND_QUEUE_HPP

#include <sctp/protocol/association.hpp>
#include <sctp/queues/deliverable.hpp>
#include <sctp/protocol/sctp.hpp>

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

// rwnd_blocked is set by peek() when the association's next packet was refused
// by rwnd alone.
struct Send_Allowance {
    size_t flight_size;
    bool cwnd_open;
    bool burst_spent;
    uint32_t rwnd;
    bool zero_window_probe;
    bool rwnd_blocked{false};
};

// Control packets pile up only while the socket refuses writes. Past this many,
// new ones are dropped, as if lost on the wire.
constexpr size_t MAX_QUEUED_CONTROL = 256;

using Send_Allowances = std::unordered_map<Association_Key, Send_Allowance>;

// Outbound scheduling: control traffic, then retransmissions, then new DATA.
//
// peek() and commit() replace pop() so sendto() runs outside the queue lock; a
// failed write calls defer() and the packet stays queued. This is safe because
// only the event loop thread pops.
//
// New DATA is admitted per association against a Send_Allowance snapshot the
// caller builds from the TCBs, so one association with a closed window does not
// hold back another; an association missing from the snapshot sends none.
// Within an association, a refused packet also holds back every later one,
// keeping TSNs on the wire in the order they were assigned. next_deadline()
// ignores new DATA refused by the last peek() until something is enqueued,
// since whatever reopens a window wakes the event loop by itself.
class Send_Queue {
    friend struct SCTP_Socket_Test_Access;

    public:
        struct Pending {
            Send_Priority priority;
            Deliverable deliverable;
            uint64_t id;
        };

        void enqueue(Deliverable deliverable, Send_Priority priority);

        std::optional<Pending> peek(std::chrono::steady_clock::time_point now, Send_Allowances& allowances);
        std::optional<Pending> peek(std::chrono::steady_clock::time_point now);
        void commit(const Pending& pending);
        void defer(std::chrono::steady_clock::time_point retry_at);

        void purge(const Association_Key& location);
        bool has_retransmission_for(const Association_Key& location);
        bool has_new_data_for(const Association_Key& location);

        void remove_acked_retransmissions(const Association_Key& location, const sack_chunk_value& sack);
        void remove_retransmissions_of_type(const Association_Key& location, Chunk_Type type, const sockaddr_in* destination = nullptr);

        void clear();

        std::optional<std::chrono::steady_clock::time_point> next_deadline();

        size_t size();

    private:
        struct Queued {
            uint64_t id;
            Deliverable deliverable;
        };

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
