#ifndef SCTP_PLATFORM_HPP
#define SCTP_PLATFORM_HPP

// Socket API compatibility layer. Include this instead of <winsock2.h> or the
// POSIX socket headers; everything below is defined on both platforms.

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>   // must precede windows.h
  #include <ws2tcpip.h>   // also provides socklen_t
  #pragma comment(lib, "Ws2_32.lib")
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <poll.h>
  #include <cerrno>
  #include <cstring>
#endif

#include <cstddef>
#include <string>
#include <string_view>

#ifdef _WIN32
using sctp_socket_t = SOCKET;
using sctp_pollfd = WSAPOLLFD;
constexpr short SCTP_POLL_READ = POLLRDNORM;
#else
using sctp_socket_t = int;
using sctp_pollfd = pollfd;
constexpr sctp_socket_t INVALID_SOCKET = -1;
constexpr int SOCKET_ERROR = -1;
constexpr short SCTP_POLL_READ = POLLIN;
#endif

constexpr short SCTP_POLL_ERROR = POLLERR;
constexpr short SCTP_POLL_FATAL = POLLHUP | POLLNVAL;

// Winsock needs per-process init; POSIX does not. Winsock refcounts these
// internally, so paired calls from multiple sockets are safe.
inline bool sctp_platform_startup() {
#ifdef _WIN32
    WSADATA wsa_data;
    return WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0;
#else
    return true;
#endif
}

inline void sctp_platform_cleanup() {
#ifdef _WIN32
    WSACleanup();
#endif
}

inline int sctp_close_socket(sctp_socket_t s) {
#ifdef _WIN32
    return closesocket(s);
#else
    return ::close(s);
#endif
}

inline int sctp_last_error() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

inline void sctp_set_last_error(int err) {
#ifdef _WIN32
    WSASetLastError(err);
#else
    errno = err;
#endif
}

inline std::string sctp_error_string(int err) {
#ifdef _WIN32
    return std::to_string(err);
#else
    return std::string(std::strerror(err)) + " (" + std::to_string(err) + ")";
#endif
}

inline std::string sctp_error_string() {
    return sctp_error_string(sctp_last_error());
}

inline bool sctp_error_would_block(int err) {
#ifdef _WIN32
    return err == WSAEWOULDBLOCK;
#else
    return err == EAGAIN || err == EWOULDBLOCK;
#endif
}

inline bool sctp_error_interrupted(int err) {
#ifdef _WIN32
    return err == WSAEINTR;
#else
    return err == EINTR;
#endif
}

inline int sctp_poll(
        sctp_pollfd* descriptors, size_t count, int timeout_ms) {
#ifdef _WIN32
    return WSAPoll(
        descriptors, static_cast<ULONG>(count), timeout_ms);
#else
    return ::poll(
        descriptors, static_cast<nfds_t>(count), timeout_ms);
#endif
}

// Puts the socket in non-blocking mode so recvfrom() returns immediately when
// no datagram is queued.
inline bool sctp_set_nonblocking(sctp_socket_t s) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(s, FIONBIO, &mode) != SOCKET_ERROR;
#else
    int flags = ::fcntl(s, F_GETFL, 0);
    if (flags == -1) {
        return false;
    }
    return ::fcntl(s, F_SETFL, flags | O_NONBLOCK) != -1;
#endif
}

// inet_addr() cannot distinguish 255.255.255.255 from failure and is deprecated
// on both platforms; inet_pton() is available on Windows since Vista.
inline bool sctp_parse_ipv4(std::string_view ip_address, in_addr& out) {
    std::string ip{ip_address};
    return ::inet_pton(AF_INET, ip.c_str(), &out) == 1;
}

#endif
