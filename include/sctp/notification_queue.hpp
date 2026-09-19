#ifndef NOTIFICATION_QUEUE_HPP
#define NOTIFICATION_QUEUE_HPP

#include <sctp/association.hpp>
#include <sctp/sctp.hpp>

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <queue>
#include <variant>
#include <vector>

enum class Notification_Type {
    SCTP_ASSOC_CHANGE,
    SCTP_REMOTE_ERROR,
    SCTP_SEND_FAILED,
    SCTP_PEER_ADDR_CHANGE,
    SCTP_SHUTDOWN_EVENT,
    COUNT
};

enum class Assoc_Change_State {
    COMM_UP,
    COMM_LOST,
    RESTART,
    SHUTDOWN_COMP,
    CANT_STR_ASSOC
};

struct Assoc_Change {
    Assoc_Change_State state;
};

// Every cause of one ERROR chunk, raw, including codes we do not act on.
struct Remote_Error {
    std::vector<error_cause> causes;
};

struct Notification {
    Notification_Type type;
    Association_Key src;
    uint64_t sequence_number;   // assigned by enqueue
    std::variant<Assoc_Change, Remote_Error> payload;
};

constexpr size_t MAX_QUEUED_NOTIFICATIONS = 1024;

class Notification_Queue {
    public:
        Notification_Queue();

        void enqueue(Notification notification);
        std::optional<Notification> dequeue();
        std::optional<Notification> wait_dequeue(std::chrono::milliseconds timeout);
        void set_subscribed(Notification_Type type, bool on);
        bool is_subscribed(Notification_Type type);
        void close();
        void clear();
        size_t size();
        uint64_t dropped();

    private:
        std::optional<Notification> pop_front();
        std::queue<Notification> queue;
        std::array<bool, static_cast<size_t>(Notification_Type::COUNT)> subscribed{};
        uint64_t next_sequence_number{1};
        uint64_t dropped_count{0};
        bool closed{false};
        std::mutex mutex;
        std::condition_variable available;
};

#endif
