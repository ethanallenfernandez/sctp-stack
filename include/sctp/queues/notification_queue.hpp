#ifndef NOTIFICATION_QUEUE_HPP
#define NOTIFICATION_QUEUE_HPP

#include <sctp/protocol/association.hpp>
#include <sctp/protocol/sctp.hpp>

#include <cstdint>
#include <mutex>
#include <optional>
#include <queue>
#include <variant>
#include <vector>

enum class Notification_Type {
    SCTP_ASSOC_CHANGE,
    SCTP_REMOTE_ERROR,
    SCTP_PEER_ADDR_CHANGE,
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

enum class Peer_Addr_State {
    ADDR_AVAILABLE,
    ADDR_UNREACHABLE,
    ADDR_CONFIRMED
};

struct Peer_Addr_Change {
    sockaddr_in address;
    Peer_Addr_State state;
};

// Every cause of one ERROR chunk, raw, including codes we do not act on.
struct Remote_Error {
    std::vector<error_cause> causes;
};

struct Notification {
    Notification_Type type;
    Association_Key src{};
    std::variant<Assoc_Change, Remote_Error, Peer_Addr_Change> payload;
};

class Notification_Queue {
    public:
        void enqueue(Notification notification);
        std::optional<Notification> dequeue();

    private:
        std::queue<Notification> queue;
        std::mutex mutex;
};

#endif
