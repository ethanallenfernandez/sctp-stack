// Payload Protocol Identifier (RFC 9260 3.3.1): passed down by the ULP, sent on
// every fragment, and handed up to the peer's ULP with the message.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "serialize.hpp"
#include "socket_internal.hpp"

#include <cstdio>
#include <string>
#include <vector>

namespace {

constexpr uint32_t OUR_TAG = 0x0A0B0C0D;
constexpr uint32_t PEER_TAG = 0x11223344;
constexpr uint16_t PEER_PORT = 40001;
constexpr uint16_t LOCAL_PORT = 9896;
constexpr uint32_t INITIAL_TSN = 1000;
constexpr uint32_t PEER_TSN = 5000;
constexpr size_t FRAGMENT_SIZE = (BASE_PMDCS - DATA_CHUNK_HEADER_SIZE) & ~size_t{3};

sockaddr_in peer_address() {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(PEER_PORT);
    sctp_parse_ipv4("127.0.0.1", address.sin_addr);
    return address;
}

} // namespace

struct SCTP_Socket_Test_Access {
    static Association_Key establish(SCTP_Socket& stack) {
        stack.local_address.sin_family = AF_INET;
        stack.local_address.sin_port = htons(LOCAL_PORT);
        sctp_parse_ipv4("127.0.0.1", stack.local_address.sin_addr);

        Association_Key key = peer_key(peer_address(), PEER_PORT);
        Association assoc = stack.init_new_association(peer_address());
        assoc.this_ver_tag = OUR_TAG;
        assoc.peer_ver_tag = PEER_TAG;
        assoc.state = ESTABLISHED;
        assoc.next_tsn = INITIAL_TSN;
        assoc.cumulative_tsn_ack = INITIAL_TSN - 1;
        assoc.last_peer_tsn = PEER_TSN - 1;
        assoc.peer_rwnd = 65535;
        assoc.peer_max_rwnd = 65535;
        stack.associations.insert_or_assign(key, assoc);
        return key;
    }

    static std::vector<data_chunk_value> drain(SCTP_Socket& stack) {
        std::vector<data_chunk_value> sent;
        for (;;) {
            stack.start_transmission_opportunity();
            auto pending = stack.next_packet();
            if (!pending) {
                return sent;
            }
            stack.packet_sent(*pending);
            for (const SCTP_Chunk& chunk : pending->deliverable.packet.chunks) {
                if (chunk.chunk_header.type == DATA) {
                    sent.push_back(std::get<data_chunk_value>(chunk.chunk_value));
                }
            }
        }
    }

    static void deliver(SCTP_Socket& stack, uint32_t tsn, uint16_t stream, uint16_t ssn, uint32_t ppid, const std::string& text, uint8_t flags) {
        data_chunk_value data{PEER_TSN + tsn, stream, ssn, ppid, std::vector<uint8_t>(text.begin(), text.end())};
        data.flags = flags;
        std::vector<uint8_t> wire = serialize_sctp_packet(build_data(PEER_PORT, LOCAL_PORT, OUR_TAG, {data}));
        stack.handle_recv_packet(wire.data(), wire.size(), peer_address());
    }
};

namespace {

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

using Access = SCTP_Socket_Test_Access;

void test_send() {
    std::printf("Sending:\n");
    SCTP_Socket stack;
    Association_Key key = Access::establish(stack);

    stack.sctp_send_data(key, std::vector<uint8_t>(2 * FRAGMENT_SIZE + 1, 'm'), 0, false, 0xDEADBEEF);
    stack.sctp_send_data(key, {'d'});
    auto sent = Access::drain(stack);
    check(sent.size() == 4 && sent[0].payload_protocal == 0xDEADBEEF && sent[1].payload_protocal == 0xDEADBEEF
          && sent[2].payload_protocal == 0xDEADBEEF, "every fragment of a message carries its PPID");
    check(sent.size() == 4 && sent[3].payload_protocal == 0, "a message sent without one carries 0");
}

void test_receive() {
    std::printf("Receiving:\n");
    SCTP_Socket stack;
    Association_Key key = Access::establish(stack);
    std::vector<uint8_t> buffer(64);
    Association_Key from{};
    uint16_t stream = 0;
    uint32_t ppid = 0;

    Access::deliver(stack, 2, 3, 1, 9, "second", DATA_FLAG_B | DATA_FLAG_E);
    Access::deliver(stack, 0, 3, 0, 7, "fir", DATA_FLAG_B);
    Access::deliver(stack, 1, 3, 0, 7, "st", DATA_FLAG_E);
    Access::deliver(stack, 3, 1, 0, 11, "unordered", DATA_FLAG_U | DATA_FLAG_B | DATA_FLAG_E);

    size_t n = stack.sctp_recv_data_from(key, buffer, nullptr, &stream, &ppid);
    check(n == 5 && std::string(buffer.begin(), buffer.begin() + 5) == "first" && ppid == 7 && stream == 3,
          "a reassembled message goes up with its PPID");
    n = stack.sctp_recv_data_from(key, buffer, nullptr, nullptr, &ppid);
    check(n == 6 && ppid == 9, "so does one completed early and held for ordering");
    n = stack.sctp_recv_data(buffer, &from, nullptr, nullptr, &ppid);
    check(n == 9 && ppid == 11 && from == key, "and an unordered one");
}

} // namespace

int main() {
    test_send();
    test_receive();
    if (failures != 0) {
        std::printf("\n%d PPID test(s) FAILED\n", failures);
        return 1;
    }
    std::printf("\nAll PPID tests passed\n");
    return 0;
}
