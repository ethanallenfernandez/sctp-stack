// Loopback UDP wakeup pair backing Wakeup_Pair. Failure paths save and restore
// the platform error code around close(), which clobbers it.

#include <sctp/wakeup_pair.hpp>
#include <sctp/platform.hpp>
#include <iostream>

Wakeup_Pair::~Wakeup_Pair() {
    close();
}

bool Wakeup_Pair::open() {
    close();

    reader = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (reader == INVALID_SOCKET) {
        return false;
    }
    writer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (writer == INVALID_SOCKET) {
        int err = sctp_last_error();
        close();
        sctp_set_last_error(err);
        return false;
    }

    sockaddr_in wakeup_address{};
    wakeup_address.sin_family = AF_INET;
    wakeup_address.sin_port = 0;
    if (!sctp_parse_ipv4("127.0.0.1", wakeup_address.sin_addr)
            || bind(
                reader,
                reinterpret_cast<const sockaddr*>(&wakeup_address),
                sizeof(wakeup_address)) == SOCKET_ERROR) {
        int err = sctp_last_error();
        close();
        sctp_set_last_error(err);
        return false;
    }

    socklen_t address_length = sizeof(wakeup_address);
    if (getsockname(
            reader,
            reinterpret_cast<sockaddr*>(&wakeup_address),
            &address_length) == SOCKET_ERROR
            || connect(
                writer,
                reinterpret_cast<const sockaddr*>(&wakeup_address),
                sizeof(wakeup_address)) == SOCKET_ERROR
            || !sctp_set_nonblocking(reader)
            || !sctp_set_nonblocking(writer)) {
        int err = sctp_last_error();
        close();
        sctp_set_last_error(err);
        return false;
    }
    return true;
}

void Wakeup_Pair::close() {
    if (reader != INVALID_SOCKET) {
        sctp_close_socket(reader);
        reader = INVALID_SOCKET;
    }
    if (writer != INVALID_SOCKET) {
        sctp_close_socket(writer);
        writer = INVALID_SOCKET;
    }
}

void Wakeup_Pair::wake() {
    if (writer == INVALID_SOCKET) {
        return;
    }

    const char byte = 1;
    int sent = send(writer, &byte, 1, 0);
    if (sent == SOCKET_ERROR && !sctp_error_would_block(sctp_last_error())) {
        std::cout << "Error waking event loop: " << sctp_error_string() << std::endl;
    }
}

void Wakeup_Pair::drain() {
    char buffer[64];
    while (recv(reader, buffer, sizeof(buffer), 0) > 0) {}
    int err = sctp_last_error();
    if (!sctp_error_would_block(err)) {
        std::cout << "Error draining event-loop wakeup: " << sctp_error_string(err) << std::endl;
    }
}
