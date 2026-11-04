// UDP encapsulation ports (RFC 6951 5.1, 5.4): an association is found by the
// peer's address and SCTP port, and each destination is sent to whatever UDP
// port it last sent from, once its packet has passed the tag check. Here the
// peer's SCTP port is never its UDP port, so a lookup on the wrong one fails.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "serialize.hpp"
#include "socket_internal.hpp"

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr uint32_t PEER_TAG = 0x11223344;
constexpr uint32_t PEER_TSN = 1000;
constexpr uint16_t PEER_SCTP_PORT = 5000;
constexpr uint16_t PEER_UDP_PORT = 40000;
constexpr uint16_t OUR_PORT = 9899;

sockaddr_in address(const char* ip, uint16_t udp_port = PEER_UDP_PORT) {
    sockaddr_in out{};
    out.sin_family = AF_INET;
    out.sin_port = htons(udp_port);
    sctp_parse_ipv4(ip, out.sin_addr);
    return out;
}

const sockaddr_in A = address("127.0.0.1");
const sockaddr_in B = address("127.0.0.2");

sockaddr_in rebound(const sockaddr_in& at, uint16_t udp_port) {
    sockaddr_in out = at;
    out.sin_port = htons(udp_port);
    return out;
}

Association_Key key_of(const sockaddr_in& at, uint16_t sctp_port = PEER_SCTP_PORT) {
    return peer_key(at, sctp_port);
}

} // namespace

struct SCTP_Socket_Test_Access {
    struct Sent {
        SCTP_Packet packet;
        sockaddr_in destination;
    };

    static void receive(SCTP_Socket& stack, const sockaddr_in& udp_src, uint32_t tag, std::vector<SCTP_Chunk> chunks,
                        uint16_t sctp_port = PEER_SCTP_PORT) {
        SCTP_Packet packet;
        packet.header = {sctp_port, OUR_PORT, tag, 0};
        packet.chunks = std::move(chunks);
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        stack.handle_recv_packet(wire.data(), wire.size(), udp_src);
    }

    static std::vector<Sent> drain(SCTP_Socket& stack) {
        std::vector<Sent> out;
        auto now = std::chrono::steady_clock::now();
        while (auto pending = stack.sends.peek(now)) {
            std::vector<uint8_t> bytes = serialize_sctp_packet(pending->deliverable.packet);
            out.push_back({deserialize_sctp_packet(bytes.data(), bytes.size()), pending->deliverable.destination});
            stack.sends.commit(*pending);
        }
        return out;
    }

    static Association* tcb(SCTP_Socket& stack, const Association_Key& key) {
        auto it = stack.associations.find(key);
        return it == stack.associations.end() ? nullptr : &it->second;
    }

    static size_t association_count(SCTP_Socket& stack) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        return stack.associations.size();
    }

    static void set_local_port(SCTP_Socket& stack) {
        stack.local_address.sin_family = AF_INET;
        stack.local_address.sin_port = htons(OUR_PORT);
    }
};

namespace {

using Access = SCTP_Socket_Test_Access;

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

const Access::Sent* first_with(const std::vector<Access::Sent>& sent, Chunk_Type type) {
    for (const auto& s : sent) {
        if (!s.packet.chunks.empty() && s.packet.chunks[0].chunk_header.type == type) return &s;
    }
    return nullptr;
}

bool sent_to(const Access::Sent* sent, const sockaddr_in& at) {
    return sent && sent->destination.sin_addr.s_addr == at.sin_addr.s_addr && sent->destination.sin_port == at.sin_port;
}

uint16_t udp_port_of(SCTP_Socket& stack, const sockaddr_in& at) {
    Association* assoc = Access::tcb(stack, key_of(A));
    const Peer_Path* path = assoc ? find_path(*assoc, at) : nullptr;
    return path ? ntohs(path->address.sin_port) : 0;
}

SCTP_Chunk init_chunk(std::vector<uint8_t> params = {}) {
    return {{INIT, 0, 0}, init_chunk_value{PEER_TAG, RWND, 10, 10, PEER_TSN, std::move(params)}};
}

SCTP_Chunk heartbeat_chunk() {
    return {{HEARTBEAT, 0, 0}, heartbeat_chunk_value{{1, 2, 3, 4}}};
}

std::vector<uint8_t> ipv4_parameter(const sockaddr_in& at) {
    std::vector<uint8_t> out;
    append_parameter(out, PARAM_IPV4_ADDRESS, reinterpret_cast<const uint8_t*>(&at.sin_addr.s_addr), 4);
    return out;
}

// INIT, INIT ACK and COOKIE ECHO from A. Returns our tag, or 0.
uint32_t establish(SCTP_Socket& stack, std::vector<uint8_t> params = {}) {
    Access::receive(stack, A, 0, {init_chunk(std::move(params))});
    auto sent = Access::drain(stack);
    const Access::Sent* init_ack = first_with(sent, INIT_ACK);
    if (!init_ack) return 0;
    const auto& value = std::get<init_chunk_value>(init_ack->packet.chunks[0].chunk_value);
    std::vector<uint8_t> cookie;
    find_parameter(value.optional_parameters, PARAM_STATE_COOKIE, cookie);
    Access::receive(stack, A, value.initiate_tag, {{{COOKIE_ECHO, 0, 0}, cookie_echo_chunk_value{cookie}}});
    Access::drain(stack);
    Association* assoc = Access::tcb(stack, key_of(A));
    return assoc && assoc->state == ESTABLISHED ? value.initiate_tag : 0;
}

/*-------------------------------- lookup -----------------------------------*/

void test_keyed_on_sctp_port() {
    std::printf("The association is keyed on the peer's SCTP port:\n");
    SCTP_Socket stack;
    Access::set_local_port(stack);

    Access::receive(stack, A, 0, {init_chunk()});
    auto sent = Access::drain(stack);
    const Access::Sent* init_ack = first_with(sent, INIT_ACK);
    check(sent_to(init_ack, A), "INIT ACK goes to the INIT's UDP port");
    check(init_ack && init_ack->packet.header.des_port == PEER_SCTP_PORT && init_ack->packet.header.src_port == OUR_PORT,
          "and is addressed to its SCTP port");
    if (!init_ack) return;

    const auto& value = std::get<init_chunk_value>(init_ack->packet.chunks[0].chunk_value);
    std::vector<uint8_t> cookie;
    find_parameter(value.optional_parameters, PARAM_STATE_COOKIE, cookie);
    Access::receive(stack, A, value.initiate_tag, {{{COOKIE_ECHO, 0, 0}, cookie_echo_chunk_value{cookie}}});
    sent = Access::drain(stack);
    check(Access::tcb(stack, key_of(A)) != nullptr, "TCB keyed on address and SCTP port");
    check(Access::tcb(stack, Association_Key{A}) == nullptr, "not on the UDP port");
    check(sent_to(first_with(sent, COOKIE_ACK), A), "COOKIE ACK goes to the UDP port");
    check(udp_port_of(stack, A) == PEER_UDP_PORT, "the path holds the UDP port");
}

void test_other_sctp_port_is_out_of_the_blue() {
    std::printf("Another SCTP port at the same address is another endpoint:\n");
    SCTP_Socket stack;
    Access::set_local_port(stack);
    uint32_t our_tag = establish(stack);
    check(our_tag != 0, "established");

    Access::receive(stack, A, our_tag, {heartbeat_chunk()}, PEER_SCTP_PORT + 1);
    auto sent = Access::drain(stack);
    const Access::Sent* abort = first_with(sent, ABORT);
    check(abort && (abort->packet.chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT)
              && abort->packet.header.des_port == PEER_SCTP_PORT + 1,
          "answered as out of the blue, with a reflected ABORT");
    check(!first_with(sent, HEARTBEAT_ACK), "and not as the association's HEARTBEAT");
    Association* assoc = Access::tcb(stack, key_of(A));
    check(assoc && assoc->state == ESTABLISHED && Access::association_count(stack) == 1, "the association is untouched");
}

/*------------------------------ port changes -------------------------------*/

void test_port_follows_the_peer() {
    std::printf("A destination's UDP port follows its packets:\n");
    SCTP_Socket stack;
    Access::set_local_port(stack);
    uint32_t our_tag = establish(stack);
    check(our_tag != 0, "established");

    // As after a NAT rebinding.
    sockaddr_in moved = rebound(A, PEER_UDP_PORT + 1);
    Access::receive(stack, moved, our_tag, {heartbeat_chunk()});
    auto sent = Access::drain(stack);
    check(Access::association_count(stack) == 1, "the packet from the new UDP port finds the association");
    check(sent_to(first_with(sent, HEARTBEAT_ACK), moved), "the reply goes to the new port");
    check(udp_port_of(stack, A) == PEER_UDP_PORT + 1, "and so does everything after it");

    Access::receive(stack, rebound(A, PEER_UDP_PORT + 2), our_tag ^ 1, {heartbeat_chunk()});
    sent = Access::drain(stack);
    check(sent.empty(), "a packet with the wrong tag is dropped");
    check(udp_port_of(stack, A) == PEER_UDP_PORT + 1, "and does not move the port");

    sockaddr_in init_from = rebound(A, PEER_UDP_PORT + 3);
    Access::receive(stack, init_from, 0, {init_chunk()});
    sent = Access::drain(stack);
    check(sent_to(first_with(sent, INIT_ACK), init_from), "an INIT is answered where it came from");
    check(udp_port_of(stack, A) == PEER_UDP_PORT + 1, "but does not move the port either");
}

void test_port_per_destination() {
    std::printf("Each destination keeps its own UDP port:\n");
    SCTP_Socket stack;
    Access::set_local_port(stack);
    uint32_t our_tag = establish(stack, ipv4_parameter(B));
    check(our_tag != 0, "established, with B listed");
    check(udp_port_of(stack, B) == PEER_UDP_PORT, "B starts at the INIT's UDP port");

    sockaddr_in b_moved = rebound(B, PEER_UDP_PORT + 10);
    Access::receive(stack, b_moved, our_tag, {heartbeat_chunk()});
    auto sent = Access::drain(stack);
    check(Access::association_count(stack) == 1, "B's packet finds the association by B and the SCTP port");
    check(first_with(sent, HEARTBEAT_ACK) != nullptr, "and is answered");
    check(udp_port_of(stack, B) == PEER_UDP_PORT + 10, "B moves to the port it sent from");
    check(udp_port_of(stack, A) == PEER_UDP_PORT, "A stays where it was");
}

/*------------------------------- over UDP ----------------------------------*/

struct Raw_Peer {
    sctp_socket_t fd = INVALID_SOCKET;
    sockaddr_in self{};

    bool open(uint16_t port) {
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd == INVALID_SOCKET) return false;
        self = address("127.0.0.1", port);
        if (bind(fd, reinterpret_cast<sockaddr*>(&self), sizeof(self)) != 0) return false;
        timeval timeout{2, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        return true;
    }

    ~Raw_Peer() {
        if (fd != INVALID_SOCKET) sctp_close_socket(fd);
    }

    void send(const SCTP_Packet& packet, uint16_t to_port) {
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        sockaddr_in to = address("127.0.0.1", to_port);
        sendto(fd, reinterpret_cast<const char*>(wire.data()), wire.size(), 0, reinterpret_cast<sockaddr*>(&to), sizeof(to));
    }

    bool recv(SCTP_Packet& out) {
        uint8_t buffer[2048];
        int n = recvfrom(fd, reinterpret_cast<char*>(buffer), sizeof(buffer), 0, nullptr, nullptr);
        if (n <= 0) return false;
        out = deserialize_sctp_packet(buffer, static_cast<size_t>(n));
        return true;
    }
};

void test_associate_with_udp_port() {
    std::printf("sctp_associate takes the UDP port apart from the SCTP port:\n");
    constexpr uint16_t STACK_PORT = 39801;
    constexpr uint16_t FIRST_UDP = 39802;
    constexpr uint16_t SECOND_UDP = 39803;

    Raw_Peer first, second;
    if (!first.open(FIRST_UDP) || !second.open(SECOND_UDP)) { check(false, "peer sockets"); return; }
    SCTP_Socket stack;
    stack.sctp_set_linger(0);
    if (!stack.sctp_bind("127.0.0.1", STACK_PORT) || !stack.sctp_run()) { check(false, "stack started"); return; }

    Association_Key key = stack.sctp_associate("127.0.0.1", PEER_SCTP_PORT, FIRST_UDP);
    check(ntohs(key.address.sin_port) == PEER_SCTP_PORT, "the key names the SCTP port");

    SCTP_Packet init;
    bool got_init = first.recv(init) && !init.chunks.empty() && init.chunks[0].chunk_header.type == INIT;
    check(got_init, "INIT arrives at the UDP port given");
    check(got_init && init.header.des_port == PEER_SCTP_PORT && init.header.src_port == STACK_PORT,
          "addressed to the SCTP port");
    if (!got_init) return;

    // The INIT ACK comes back from another UDP port, as through a NAT.
    uint32_t our_tag = std::get<init_chunk_value>(init.chunks[0].chunk_value).initiate_tag;
    std::vector<uint8_t> cookie(32, 0xAB);
    second.send(build_init_ack(PEER_SCTP_PORT, STACK_PORT, our_tag, PEER_TAG, PEER_TSN, cookie), STACK_PORT);

    SCTP_Packet echo;
    bool got_echo = second.recv(echo) && !echo.chunks.empty() && echo.chunks[0].chunk_header.type == COOKIE_ECHO;
    check(got_echo, "COOKIE ECHO goes to the port the INIT ACK came from");
    check(got_echo && echo.header.des_port == PEER_SCTP_PORT && echo.header.verification_tag == PEER_TAG,
          "under the SCTP port and the peer's tag");

    second.send(build_cookie_ack(PEER_SCTP_PORT, STACK_PORT, our_tag), STACK_PORT);
    check(stack.await_established_association(key, 2000) == 0, "established");
    stack.sctp_close(0);
}

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    test_keyed_on_sctp_port();
    test_other_sctp_port_is_out_of_the_blue();
    test_port_follows_the_peer();
    test_port_per_destination();
    test_associate_with_udp_port();

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
