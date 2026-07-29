#include <sctp/socket.hpp>
#include <iostream>

int main() {
    SCTP_Socket socket1{};
    socket1.sctp_bind("127.0.0.1", 9899);
    socket1.sctp_run();

    SCTP_Socket socket2{};
    socket2.sctp_bind("127.0.0.1", 5000);
    socket2.sctp_run();

    Association_Key assoc_key = socket1.sctp_associate("127.0.0.1", 5000);
    
    int await_result = socket1.await_established_association(assoc_key, 5000);
    if (await_result != 0) {
        std::cout << "Failed to establish association within timeout." << std::endl;
        return -1;
    } else {
        std::cout << "Association established successfully." << std::endl;
    }

    std::string message = "Hello from socket1!";
    std::vector<uint8_t> data(message.begin(), message.end());

    std::cout << "Socket1 Sending: " << message << std::endl;
    socket1.sctp_send_data(assoc_key, data);

    std::vector<uint8_t> recv_buffer(2048);
    
    while (true) {
        size_t received = socket2.sctp_recv_data_from(socket1.get_this_association_key(), recv_buffer);
        if (received > 0) {
            std::string received_message(recv_buffer.begin(), recv_buffer.begin() + received);
            std::cout << "Socket2 Received: " << received_message << std::endl;
            break;
        }
    }

}