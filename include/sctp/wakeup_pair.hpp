#ifndef SCTP_WAKEUP_PAIR_HPP
#define SCTP_WAKEUP_PAIR_HPP

// A connected loopback UDP socket pair used to interrupt the event loop's
// poll() from another thread. Writing a byte to the writer makes the reader
// readable, which is portable across POSIX poll() and Windows WSAPoll() where
// a pipe or eventfd is not.

#include <sctp/platform.hpp>

class Wakeup_Pair {
    public:
        Wakeup_Pair() = default;
        ~Wakeup_Pair();

        Wakeup_Pair(const Wakeup_Pair&) = delete;
        Wakeup_Pair& operator=(const Wakeup_Pair&) = delete;

        // Creates the pair, binding the reader to an ephemeral loopback port and
        // connecting the writer to it. Both ends are set non-blocking. On
        // failure everything is closed again and the platform error code that
        // caused the failure is left set.
        bool open();
        void close();

        // Safe to call from any thread, and a no-op when the pair is not open.
        void wake();

        // Consumes every queued wakeup byte. Called by the event loop once poll()
        // reports the reader readable.
        void drain();

        sctp_socket_t poll_handle() const { return reader; }
        bool is_open() const { return reader != INVALID_SOCKET; }

    private:
        sctp_socket_t reader{INVALID_SOCKET};
        sctp_socket_t writer{INVALID_SOCKET};
};

#endif
