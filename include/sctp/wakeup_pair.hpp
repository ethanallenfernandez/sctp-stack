#ifndef SCTP_WAKEUP_PAIR_HPP
#define SCTP_WAKEUP_PAIR_HPP

// A connected loopback UDP socket pair used to interrupt the event loop's
// poll() from another thread. Writing a byte to the writer makes the reader
// readable, which is portable across POSIX poll() and Windows WSAPoll().

#include <sctp/platform.hpp>

class Wakeup_Pair {
    public:
        Wakeup_Pair() = default;
        ~Wakeup_Pair();

        Wakeup_Pair(const Wakeup_Pair&) = delete;
        Wakeup_Pair& operator=(const Wakeup_Pair&) = delete;

        void close();
        void wake();
        void drain();
        sctp_socket_t poll_handle() const { return reader; }
        bool open();
        bool is_open() const { return reader != INVALID_SOCKET; }

    private:
        sctp_socket_t reader{INVALID_SOCKET};
        sctp_socket_t writer{INVALID_SOCKET};
};

#endif
