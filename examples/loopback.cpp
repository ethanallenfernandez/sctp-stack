#include <sctp/socket.hpp>

#include <chrono>
#include <iostream>
#include <thread>

namespace {

// The library never blocks, so waits poll. An association is up once the ULP
// is told COMMUNICATION UP for it.
bool await_up(SCTP_Socket& stack, const Association_Key& key, int timeout_ms) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        auto notification = stack.sctp_recv_notification();
        const auto* change = notification ? std::get_if<Assoc_Change>(&notification->payload) : nullptr;
        if (change && change->state == Assoc_Change_State::COMM_UP && notification->src == key) {
            return true;
        }
        if (!notification) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    return false;
}

size_t receive(SCTP_Socket& stack, const Association_Key& from, std::vector<uint8_t>& buffer, int timeout_ms) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    size_t n = 0;
    while ((n = stack.sctp_recv_data_from(from, buffer)) == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return n;
}

} // namespace

int main() {
    SCTP_Socket socket1{};
    socket1.sctp_bind("127.0.0.1", 9899);
    socket1.sctp_run();

    SCTP_Socket socket2{};
    socket2.sctp_bind("127.0.0.1", 5000);
    socket2.sctp_run();

    Association_Key assoc_key;
    if (socket1.sctp_associate("127.0.0.1", 5000, assoc_key) != Sctp_Status::OK
            || !await_up(socket1, assoc_key, 5000)) {
        std::cout << "Failed to establish association within timeout." << std::endl;
        return -1;
    }
    std::cout << "Association established successfully." << std::endl;

    std::string message = "Hello from socket1!";
    std::vector<uint8_t> data(message.begin(), message.end());

    std::cout << "Socket1 Sending: " << message << std::endl;
    socket1.sctp_send_data(assoc_key, data);

    std::vector<uint8_t> recv_buffer(2048);
    size_t received = receive(socket2, socket1.get_this_association_key(), recv_buffer, 5000);
    if (received == 0) {
        std::cout << "Nothing received within timeout." << std::endl;
        return -1;
    }
    std::string received_message(recv_buffer.begin(), recv_buffer.begin() + received);
    std::cout << "Socket2 Received: " << received_message << std::endl;

}