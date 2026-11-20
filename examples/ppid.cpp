// Payload Protocol Identifier: passed down with a message, sent on every DATA
// chunk of it, and handed up with it at the other end.
//
//   sender    127.0.0.1 : 5020   associates to receiver
//   receiver  127.0.0.1 : 9920
//
// Every wait is long so the demo survives being paused in a debugger.

#include <sctp/socket.hpp>

#include <cstdio>
#include <string>
#include <vector>

// Read by examples/ppid.gdb to tell the two stacks apart.
SCTP_Socket* demo_sender = nullptr;
SCTP_Socket* demo_receiver = nullptr;

namespace {

constexpr int WAIT_MS = 60000;
// Values from IANA's SCTP Payload Protocol Identifiers registry.
constexpr uint32_t PPID_WEBRTC_STRING = 51;
constexpr uint32_t PPID_WEBRTC_BINARY = 53;

void step(const char* text) {
    std::printf("\n=== %s\n", text);
}

std::vector<uint8_t> bytes(const std::string& text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

// Reads one whole message and prints what came with it.
void receive(SCTP_Socket& stack, const Association_Key& from) {
    std::vector<uint8_t> buffer(64 * 1024);
    size_t total = 0;
    bool partial = false;
    uint16_t stream = 0;
    uint32_t ppid = 0;
    do {
        size_t n = stack.sctp_recv_data_from(from, buffer, &partial, &stream, WAIT_MS, &ppid);
        if (n == 0) {
            std::printf("nothing received\n");
            return;
        }
        total += n;
    } while (partial);
    std::printf("received %zu bytes  stream %u  ppid %u\n", total, stream, ppid);
}

} // namespace

int main() {
    SCTP_Socket sender;
    SCTP_Socket receiver;
    demo_sender = &sender;
    demo_receiver = &receiver;

    step("1. sender associates to receiver");
    if (!receiver.sctp_bind("127.0.0.1", 9920) || !sender.sctp_bind("127.0.0.1", 5020)
            || !receiver.sctp_run() || !sender.sctp_run()) {
        std::printf("could not start the stacks\n");
        return 1;
    }
    Association_Key to_receiver;
    if (sender.sctp_associate("127.0.0.1", 9920, to_receiver) != Sctp_Status::OK
            || sender.await_established_association(to_receiver, WAIT_MS) != Sctp_Status::OK) {
        std::printf("association failed\n");
        return 1;
    }
    Association_Key to_sender = receiver.get_this_association_key();
    to_sender.address.sin_port = htons(5020);
    std::printf("established\n");

    step("2. a short text message, PPID 51");
    sender.sctp_send_data(to_receiver, bytes("hello"), 0, false, 0, PPID_WEBRTC_STRING);
    receive(receiver, to_sender);

    step("3. a 4000-byte message, PPID 53: four DATA chunks, each carrying it");
    sender.sctp_send_data(to_receiver, std::vector<uint8_t>(4000, 0xAB), 1, false, 0, PPID_WEBRTC_BINARY);
    receive(receiver, to_sender);

    step("4. an unordered message, PPID 51");
    sender.sctp_send_data(to_receiver, bytes("out of band"), 2, true, 0, PPID_WEBRTC_STRING);
    receive(receiver, to_sender);

    step("5. a message sent without a PPID");
    sender.sctp_send_data(to_receiver, bytes("plain"));
    receive(receiver, to_sender);

    step("done");
    sender.sctp_close();
    receiver.sctp_close();
    return 0;
}
