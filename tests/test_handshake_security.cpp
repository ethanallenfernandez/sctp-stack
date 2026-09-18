// The two properties the state cookie exists to provide.
//
// Neither is visible to the rest of the suite: a stack that allocated on every
// INIT, or that skipped the tag check, passes everything else. Both bugs have
// been real here - the second was introduced by the COOKIE ECHO exemption in
// validate_verification_tag and caught only by this test.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "serialize.hpp"

#include <chrono>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct SCTP_Socket_Test_Access {
    static size_t association_count(SCTP_Socket& stack) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        return stack.associations.size();
    }
};

namespace {

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

// A plain UDP socket that owns its address, so packets it sends genuinely match
// the association's key. Sending from an unbound socket would be dropped for
// the wrong reason and hide whatever the test was checking.
struct RawPeer {
    sctp_socket_t fd = INVALID_SOCKET;
    sockaddr_in self{};
    sockaddr_in target{};

    bool open(uint16_t own_port, uint16_t stack_port) {
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd == INVALID_SOCKET) return false;
        self.sin_family = AF_INET;
        self.sin_port = htons(own_port);
        sctp_parse_ipv4("127.0.0.1", self.sin_addr);
        if (bind(fd, reinterpret_cast<sockaddr*>(&self), sizeof(self)) != 0) return false;
        timeval timeout{2, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        target.sin_family = AF_INET;
        target.sin_port = htons(stack_port);
        sctp_parse_ipv4("127.0.0.1", target.sin_addr);
        return true;
    }

    void close_it() {
        if (fd != INVALID_SOCKET) sctp_close_socket(fd);
        fd = INVALID_SOCKET;
    }

    void send(const SCTP_Packet& packet) {
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        sendto(fd, reinterpret_cast<const char*>(wire.data()), wire.size(), 0,
               reinterpret_cast<sockaddr*>(&target), sizeof(target));
    }

    bool recv(SCTP_Packet& out) {
        uint8_t buffer[2048];
        int n = recvfrom(fd, reinterpret_cast<char*>(buffer), sizeof(buffer), 0, nullptr, nullptr);
        if (n <= 0) return false;
        out = deserialize_sctp_packet(buffer, static_cast<size_t>(n));
        return true;
    }
};

SCTP_Packet header_only(uint16_t src_port, uint16_t des_port, uint32_t tag) {
    SCTP_Packet packet;
    packet.header.src_port = src_port;
    packet.header.des_port = des_port;
    packet.header.verification_tag = tag;
    packet.header.checksum = 0;
    return packet;
}

void settle() {
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
}

/*--------------------- unauthenticated state allocation --------------------*/

// A spoofed-source flood must not pin memory: the responder has no proof the
// peer can receive at the address it claims until the cookie comes back.
void test_init_flood_allocates_nothing() {
    std::printf("INIT flood allocates no state (RFC 9260 5.1.3):\n");

    constexpr uint16_t STACK_PORT = 39501;
    constexpr int FLOOD = 500;

    SCTP_Socket stack;
    if (!stack.sctp_bind("127.0.0.1", STACK_PORT) || !stack.sctp_run()) {
        check(false, "stack started"); return;
    }

    RawPeer peer;
    if (!peer.open(39502, STACK_PORT)) { check(false, "peer socket setup"); return; }

    for (int i = 0; i < FLOOD; i++) {
        SCTP_Packet init = header_only(static_cast<uint16_t>(20000 + i), STACK_PORT, 0);
        init.chunks.push_back(SCTP_Chunk{
            .chunk_header = {.type = INIT, .flag = 0, .length = 0},
            .chunk_value = init_chunk_value{
                .initiate_tag = 0x1000u + static_cast<uint32_t>(i),
                .a_rwnd = RWND,
                .out_streams = 1,
                .in_streams = 1,
                .initial_tsn = 0x3000u + static_cast<uint32_t>(i),
                .optional_parameters = {}}});
        peer.send(init);
    }
    settle();

    check(SCTP_Socket_Test_Access::association_count(stack) == 0,
          "500 INITs left the association map empty");

    // The responder must still be usable: holding no state is only correct if a
    // genuine peer can still complete a handshake through the same path.
    SCTP_Socket client;
    if (!client.sctp_bind("127.0.0.1", 39503) || !client.sctp_run()) {
        check(false, "client started"); peer.close_it(); return;
    }
    Association_Key key = client.sctp_associate("127.0.0.1", STACK_PORT);
    check(client.await_established_association(key, 3000) == 0,
          "a real handshake still completes after the flood");
    check(SCTP_Socket_Test_Access::association_count(stack) == 1,
          "and allocates exactly one association");

    peer.close_it();
}

/*------------------------ verification tag bypass --------------------------*/

// COOKIE ECHO is exempt from the tag rules, but validate_verification_tag runs
// once per packet. Applying the exemption to a live association would let
// anything bundled behind a junk COOKIE ECHO through unchecked.
void test_cookie_echo_does_not_bypass_tag_check() {
    std::printf("COOKIE ECHO does not bypass the tag check (RFC 9260 8.5.1):\n");

    constexpr uint16_t STACK_PORT = 39601;
    constexpr uint16_t PEER_PORT = 39602;
    constexpr uint32_t PEER_TAG = 0x11112222;
    constexpr uint32_t PEER_TSN = 0x30000000;
    constexpr uint32_t WRONG_TAG = 0xBADBAD00;

    SCTP_Socket stack;
    if (!stack.sctp_bind("127.0.0.1", STACK_PORT) || !stack.sctp_run()) {
        check(false, "stack started"); return;
    }

    RawPeer peer;
    if (!peer.open(PEER_PORT, STACK_PORT)) { check(false, "peer socket setup"); return; }

    SCTP_Packet init = header_only(PEER_PORT, STACK_PORT, 0);
    init.chunks.push_back(SCTP_Chunk{
        .chunk_header = {.type = INIT, .flag = 0, .length = 0},
        .chunk_value = init_chunk_value{PEER_TAG, RWND, 1, 1, PEER_TSN, {}}});
    peer.send(init);

    SCTP_Packet init_ack;
    if (!peer.recv(init_ack) || init_ack.chunks.empty()
            || init_ack.chunks[0].chunk_header.type != INIT_ACK) {
        check(false, "received INIT_ACK"); peer.close_it(); return;
    }
    const auto& init_ack_value = std::get<init_chunk_value>(init_ack.chunks[0].chunk_value);
    uint32_t stack_tag = init_ack_value.initiate_tag;

    std::vector<uint8_t> cookie;
    if (!find_parameter(init_ack_value.optional_parameters, PARAM_STATE_COOKIE, cookie)) {
        check(false, "INIT_ACK carries a State Cookie"); peer.close_it(); return;
    }

    SCTP_Packet echo = header_only(PEER_PORT, STACK_PORT, stack_tag);
    echo.chunks.push_back(SCTP_Chunk{
        .chunk_header = {.type = COOKIE_ECHO, .flag = 0, .length = 0},
        .chunk_value = cookie_echo_chunk_value{cookie}});
    peer.send(echo);

    SCTP_Packet cookie_ack;
    if (!peer.recv(cookie_ack) || cookie_ack.chunks.empty()
            || cookie_ack.chunks[0].chunk_header.type != COOKIE_ACK) {
        check(false, "received COOKIE_ACK"); peer.close_it(); return;
    }
    check(true, "association established");

    std::string message = "INJECTED";
    std::vector<uint8_t> payload(message.begin(), message.end());
    std::vector<uint8_t> received(2048);

    // Control: the tag check works on a bare DATA chunk.
    SCTP_Packet plain = header_only(PEER_PORT, STACK_PORT, WRONG_TAG);
    plain.chunks.push_back(SCTP_Chunk{
        .chunk_header = {.type = DATA, .flag = 0, .length = 0},
        .chunk_value = data_chunk_value{PEER_TSN, 0, 0, 0, payload}});
    peer.send(plain);
    settle();
    check(stack.sctp_recv_data(received, nullptr) == 0, "bare DATA with a wrong tag is rejected");

    // The regression: same wrong tag, prefixed with a cookie that will not
    // verify. The TSN is the one the stack is waiting for, so nothing except
    // the tag check can reject it.
    SCTP_Packet bundled = header_only(PEER_PORT, STACK_PORT, WRONG_TAG);
    bundled.chunks.push_back(SCTP_Chunk{
        .chunk_header = {.type = COOKIE_ECHO, .flag = 0, .length = 0},
        .chunk_value = cookie_echo_chunk_value{std::vector<uint8_t>(STATE_COOKIE_SIZE, 0xFF)}});
    bundled.chunks.push_back(SCTP_Chunk{
        .chunk_header = {.type = DATA, .flag = 0, .length = 0},
        .chunk_value = data_chunk_value{PEER_TSN, 0, 0, 0, payload}});
    peer.send(bundled);
    settle();
    check(stack.sctp_recv_data(received, nullptr) == 0,
          "DATA bundled behind a junk COOKIE ECHO is rejected");

    // And the association is undisturbed by the attempt.
    check(SCTP_Socket_Test_Access::association_count(stack) == 1, "the association survived the attempt");

    peer.close_it();
}

} // namespace

int main() {
    test_init_flood_allocates_nothing();
    test_cookie_echo_does_not_bypass_tag_check();

    if (failures == 0) {
        std::printf("\nALL TESTS PASSED (0 failures)\n");
    } else {
        std::printf("\n%d FAILURE(S)\n", failures);
    }
    return failures == 0 ? 0 : 1;
}
