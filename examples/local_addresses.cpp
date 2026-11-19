// Multiple local addresses: one stack bound to 127.0.0.1 and 127.0.0.2.
//
//   multihomed  127.0.0.1 + 127.0.0.2 : 9900
//   peer        127.0.0.3 : 5000          associates to multihomed
//   third       127.0.0.4 : 5001          multihomed associates to it
//
// Every wait is long so the demo survives being paused in a debugger.

#include <sctp/socket.hpp>

#include <cstdio>
#include <string>
#include <vector>

// Read by examples/local_addresses.gdb to tell the three stacks apart.
SCTP_Socket* demo_multihomed = nullptr;
SCTP_Socket* demo_peer = nullptr;
SCTP_Socket* demo_third = nullptr;

namespace {

constexpr int WAIT_MS = 60000;

void step(const char* text) {
    std::printf("\n=== %s\n", text);
}

sockaddr_in address(const char* ip, int port) {
    sockaddr_in out{};
    out.sin_family = AF_INET;
    out.sin_port = htons(port);
    sctp_parse_ipv4(ip, out.sin_addr);
    return out;
}

bool await_confirmed(SCTP_Socket& stack, const sockaddr_in& at) {
    while (auto notification = stack.sctp_recv_notification(WAIT_MS)) {
        const auto* change = std::get_if<Peer_Addr_Change>(&notification->payload);
        if (change && change->state == Peer_Addr_State::ADDR_CONFIRMED && change->address.sin_addr.s_addr == at.sin_addr.s_addr) {
            return true;
        }
    }
    return false;
}

std::string receive(SCTP_Socket& stack, Association_Key* from = nullptr) {
    std::vector<uint8_t> buffer(256);
    size_t n = stack.sctp_recv_data(buffer, from, nullptr, nullptr, WAIT_MS);
    return std::string(buffer.begin(), buffer.begin() + n);
}

std::vector<uint8_t> bytes(const std::string& text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

} // namespace

int main() {
    SCTP_Socket multihomed;
    SCTP_Socket peer;
    SCTP_Socket third;
    demo_multihomed = &multihomed;
    demo_peer = &peer;
    demo_third = &third;

    step("1. multihomed binds two addresses at one port; the others bind one");
    if (!multihomed.sctp_bindx({"127.0.0.1", "127.0.0.2"}, 9900)
            || !peer.sctp_bind("127.0.0.3", 5000)
            || !third.sctp_bind("127.0.0.4", 5001)
            || !multihomed.sctp_run() || !peer.sctp_run() || !third.sctp_run()) {
        std::printf("could not start the stacks\n");
        return 1;
    }
    peer.sctp_subscribe(Notification_Type::SCTP_PEER_ADDR_CHANGE, true);

    step("2. peer associates to 127.0.0.1; multihomed's INIT ACK lists both of its addresses");
    Association_Key to_multihomed;
    if (peer.sctp_associate("127.0.0.1", 9900, to_multihomed) != Sctp_Status::OK
            || peer.await_established_association(to_multihomed, WAIT_MS) != Sctp_Status::OK) {
        std::printf("association failed\n");
        return 1;
    }
    std::printf("established\n");

    step("3. peer heartbeats 127.0.0.2, learned from the INIT ACK; the HEARTBEAT ACK leaves from 127.0.0.2");
    sockaddr_in second = address("127.0.0.2", 9900);
    std::printf(await_confirmed(peer, second) ? "127.0.0.2 confirmed\n" : "127.0.0.2 never confirmed\n");

    step("4. peer sends to 127.0.0.2; multihomed now sends to peer from 127.0.0.2");
    peer.sctp_set_primary(to_multihomed, second);
    peer.sctp_send_data(to_multihomed, bytes("hello from peer"));
    Association_Key to_peer;
    std::printf("multihomed received: %s\n", receive(multihomed, &to_peer).c_str());
    multihomed.sctp_send_data(to_peer, bytes("hello back"));
    std::printf("peer received: %s\n", receive(peer).c_str());

    step("5. multihomed associates to third; its INIT lists both of its addresses");
    Association_Key to_third;
    if (multihomed.sctp_associate("127.0.0.4", 5001, to_third) != Sctp_Status::OK
            || multihomed.await_established_association(to_third, WAIT_MS) != Sctp_Status::OK) {
        std::printf("association failed\n");
        return 1;
    }
    std::printf("established\n");

    step("done");
    multihomed.sctp_close();
    peer.sctp_close();
    third.sctp_close();
    return 0;
}
