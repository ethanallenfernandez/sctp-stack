// Duplicate and unexpected handshake chunks (RFC 9260 5.2): INIT collision,
// peer restart, and late cookies, driven from a raw UDP peer so every tag is
// chosen by the test rather than by the stack under test.

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

    static bool snapshot(SCTP_Socket& stack, uint16_t peer_port, Association& out) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(peer_port);
        sctp_parse_ipv4("127.0.0.1", address.sin_addr);

        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        auto it = stack.associations.find(Association_Key{address});
        if (it == stack.associations.end()) return false;
        out = it->second;
        return true;
    }
};

namespace {

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

struct RawPeer {
    sctp_socket_t fd = INVALID_SOCKET;
    sockaddr_in self{};
    sockaddr_in target{};
    uint16_t port = 0;
    uint16_t stack_port = 0;

    bool open(uint16_t own_port, uint16_t stack) {
        port = own_port;
        stack_port = stack;
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd == INVALID_SOCKET) return false;
        self.sin_family = AF_INET;
        self.sin_port = htons(own_port);
        sctp_parse_ipv4("127.0.0.1", self.sin_addr);
        if (bind(fd, reinterpret_cast<sockaddr*>(&self), sizeof(self)) != 0) return false;
        target.sin_family = AF_INET;
        target.sin_port = htons(stack);
        sctp_parse_ipv4("127.0.0.1", target.sin_addr);
        return true;
    }

    ~RawPeer() {
        if (fd != INVALID_SOCKET) sctp_close_socket(fd);
    }

    void send(const SCTP_Packet& packet) {
        std::vector<uint8_t> wire = serialize_sctp_packet(packet);
        sendto(fd, reinterpret_cast<const char*>(wire.data()), wire.size(), 0,
               reinterpret_cast<sockaddr*>(&target), sizeof(target));
    }

    // Skips anything else the stack sends meanwhile (INIT retransmissions, SACKs).
    bool recv_type(Chunk_Type type, SCTP_Packet& out, int timeout_ms = 2000) {
        timeval timeout{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        uint8_t buffer[2048];
        for (;;) {
            int n = recvfrom(fd, reinterpret_cast<char*>(buffer), sizeof(buffer), 0, nullptr, nullptr);
            if (n <= 0) return false;
            out = deserialize_sctp_packet(buffer, static_cast<size_t>(n));
            if (!out.chunks.empty() && out.chunks[0].chunk_header.type == type) return true;
        }
    }

    SCTP_Packet packet(uint32_t tag) const {
        SCTP_Packet p;
        p.header = {port, stack_port, tag, 0};
        return p;
    }

    void send_init(uint32_t tag, uint32_t tsn) {
        SCTP_Packet p = packet(0);
        p.chunks.push_back(SCTP_Chunk{{INIT, 0, 0}, init_chunk_value{tag, RWND, 1, 1, tsn, {}}});
        send(p);
    }

    void send_init_ack(uint32_t vtag, uint32_t tag, uint32_t tsn) {
        std::vector<uint8_t> cookie(16, 0xAB), params;
        append_parameter(params, PARAM_STATE_COOKIE, cookie.data(), cookie.size());
        SCTP_Packet p = packet(vtag);
        p.chunks.push_back(SCTP_Chunk{{INIT_ACK, 0, 0}, init_chunk_value{tag, RWND, 1, 1, tsn, params}});
        send(p);
    }

    void send_echo(uint32_t vtag, const std::vector<uint8_t>& cookie, const std::string& bundled = "", uint32_t tsn = 0) {
        SCTP_Packet p = packet(vtag);
        p.chunks.push_back(SCTP_Chunk{{COOKIE_ECHO, 0, 0}, cookie_echo_chunk_value{cookie}});
        if (!bundled.empty()) {
            p.chunks.push_back(SCTP_Chunk{{DATA, 0, 0},
                data_chunk_value{tsn, 0, 0, 0, std::vector<uint8_t>(bundled.begin(), bundled.end())}});
        }
        send(p);
    }

    void send_data(uint32_t vtag, uint32_t tsn, const std::string& payload) {
        SCTP_Packet p = packet(vtag);
        p.chunks.push_back(SCTP_Chunk{{DATA, 0, 0},
            data_chunk_value{tsn, 0, 0, 0, std::vector<uint8_t>(payload.begin(), payload.end())}});
        send(p);
    }
};

struct Init_Ack {
    uint32_t vtag = 0;
    init_chunk_value value;
    std::vector<uint8_t> cookie;
    State_Cookie parsed{};
};

bool recv_init_ack(RawPeer& peer, Init_Ack& out) {
    SCTP_Packet p;
    if (!peer.recv_type(INIT_ACK, p)) return false;
    out.vtag = p.header.verification_tag;
    out.value = std::get<init_chunk_value>(p.chunks[0].chunk_value);
    return find_parameter(out.value.optional_parameters, PARAM_STATE_COOKIE, out.cookie)
        && deserialize_state_cookie(out.cookie, out.parsed);
}

bool recv_cookie_ack(RawPeer& peer, uint32_t& vtag, int timeout_ms = 2000) {
    SCTP_Packet p;
    if (!peer.recv_type(COOKIE_ACK, p, timeout_ms)) return false;
    vtag = p.header.verification_tag;
    return true;
}

std::string recv_string(SCTP_Socket& stack) {
    std::vector<uint8_t> buffer(2048);
    size_t n = stack.sctp_recv_data(buffer, nullptr);
    return std::string(buffer.begin(), buffer.begin() + static_cast<long>(n));
}

void settle() {
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
}

bool start(SCTP_Socket& stack, uint16_t port) {
    return stack.sctp_bind("127.0.0.1", port) && stack.sctp_run();
}

/*------------------------------ 5.2.1 ------------------------------------*/

void test_init_in_cookie_wait() {
    std::printf("INIT in COOKIE-WAIT reuses our INIT's parameters (5.2.1):\n");
    constexpr uint16_t STACK_PORT = 39701, PEER_PORT = 39702;
    constexpr uint32_t PEER_TAG = 0x0A0A0A0A, PEER_TSN = 0x100;

    SCTP_Socket stack;
    RawPeer peer;
    if (!start(stack, STACK_PORT) || !peer.open(PEER_PORT, STACK_PORT)) { check(false, "setup"); return; }

    Association_Key key = stack.sctp_associate("127.0.0.1", PEER_PORT);
    SCTP_Packet init;
    if (!peer.recv_type(INIT, init)) { check(false, "stack sent INIT"); return; }
    const auto& our_init = std::get<init_chunk_value>(init.chunks[0].chunk_value);

    peer.send_init(PEER_TAG, PEER_TSN);
    Init_Ack ack;
    if (!recv_init_ack(peer, ack)) { check(false, "received INIT ACK with a cookie"); return; }
    check(ack.vtag == PEER_TAG, "INIT ACK carries the colliding INIT's tag");
    check(ack.value.initiate_tag == our_init.initiate_tag, "Initiate Tag is the one from our INIT");
    check(ack.value.initial_tsn == our_init.initial_tsn, "Initial TSN is the one from our INIT");
    check(ack.parsed.local_tie_tag == 0 && ack.parsed.peer_tie_tag == 0, "Tie-Tags are 0 in COOKIE-WAIT");

    Association tcb;
    check(SCTP_Socket_Test_Access::snapshot(stack, PEER_PORT, tcb) && tcb.state == COOKIE_WAIT,
          "state is unchanged by the INIT");

    // Our TCB has no peer tag yet, so this is Table 12 row "M 0": action B.
    peer.send_echo(our_init.initiate_tag, ack.cookie);
    uint32_t vtag = 0;
    check(recv_cookie_ack(peer, vtag) && vtag == PEER_TAG, "COOKIE ACK sent under the peer's tag (B)");
    check(stack.await_established_association(key, 1000) == 0, "association is ESTABLISHED");
    check(SCTP_Socket_Test_Access::snapshot(stack, PEER_PORT, tcb) && tcb.peer_ver_tag == PEER_TAG,
          "peer tag adopted from the cookie");

    // T1-init must be stopped: no INIT retransmission after the RTO.
    SCTP_Packet stray;
    check(!peer.recv_type(INIT, stray, 1500), "T1-init stopped");
}

void test_init_in_cookie_echoed() {
    std::printf("INIT in COOKIE-ECHOED populates random Tie-Tags (5.2.1):\n");
    constexpr uint16_t STACK_PORT = 39711, PEER_PORT = 39712;
    constexpr uint32_t PEER_TAG_1 = 0x1B1B1B1B, PEER_TAG_2 = 0x2B2B2B2B, PEER_TSN = 0x200;

    SCTP_Socket stack;
    RawPeer peer;
    if (!start(stack, STACK_PORT) || !peer.open(PEER_PORT, STACK_PORT)) { check(false, "setup"); return; }

    Association_Key key = stack.sctp_associate("127.0.0.1", PEER_PORT);
    SCTP_Packet init;
    if (!peer.recv_type(INIT, init)) { check(false, "stack sent INIT"); return; }
    const auto& our_init = std::get<init_chunk_value>(init.chunks[0].chunk_value);

    peer.send_init_ack(our_init.initiate_tag, PEER_TAG_1, PEER_TSN);
    SCTP_Packet echo;
    if (!peer.recv_type(COOKIE_ECHO, echo)) { check(false, "stack sent COOKIE ECHO"); return; }

    peer.send_init(PEER_TAG_2, PEER_TSN);
    Init_Ack ack;
    if (!recv_init_ack(peer, ack)) { check(false, "received INIT ACK with a cookie"); return; }
    check(ack.value.initiate_tag == our_init.initiate_tag, "Initiate Tag is the one from our INIT");
    check(ack.value.initial_tsn == our_init.initial_tsn, "Initial TSN is the one from our INIT");

    Association tcb;
    SCTP_Socket_Test_Access::snapshot(stack, PEER_PORT, tcb);
    check(tcb.state == COOKIE_ECHOED, "state is unchanged by the INIT");
    check(ack.parsed.local_tie_tag != 0 && ack.parsed.peer_tie_tag != 0, "Tie-Tags are populated");
    check(ack.parsed.local_tie_tag == tcb.local_tie_tag && ack.parsed.peer_tie_tag == tcb.peer_tie_tag,
          "and stored in the TCB");
    check(ack.parsed.local_tie_tag != tcb.this_ver_tag && ack.parsed.peer_tie_tag != tcb.peer_ver_tag,
          "and are not the live verification tags");

    // Local tag matches, peer tag is new: action B.
    peer.send_echo(our_init.initiate_tag, ack.cookie);
    uint32_t vtag = 0;
    check(recv_cookie_ack(peer, vtag) && vtag == PEER_TAG_2, "COOKIE ACK sent under the new peer tag (B)");
    check(stack.await_established_association(key, 1000) == 0, "association is ESTABLISHED");
    check(SCTP_Socket_Test_Access::snapshot(stack, PEER_PORT, tcb) && tcb.peer_ver_tag == PEER_TAG_2,
          "peer tag updated from the cookie");
}

/*------------------------------ 5.2.4 A ----------------------------------*/

void test_peer_restart() {
    std::printf("A restarted peer replaces the association (5.2.4 action A):\n");
    constexpr uint16_t STACK_PORT = 39721, PEER_PORT = 39722;
    constexpr uint32_t OLD_TAG = 0x3C3C3C3C, OLD_TSN = 0x300;
    constexpr uint32_t NEW_TAG = 0x4C4C4C4C, NEW_TSN = 0x9000;

    SCTP_Socket stack;
    RawPeer peer;
    if (!start(stack, STACK_PORT) || !peer.open(PEER_PORT, STACK_PORT)) { check(false, "setup"); return; }

    peer.send_init(OLD_TAG, OLD_TSN);
    Init_Ack first;
    if (!recv_init_ack(peer, first)) { check(false, "first handshake INIT ACK"); return; }
    uint32_t old_stack_tag = first.value.initiate_tag;
    uint32_t vtag = 0;
    peer.send_echo(old_stack_tag, first.cookie);
    if (!recv_cookie_ack(peer, vtag)) { check(false, "first handshake COOKIE ACK"); return; }
    peer.send_data(old_stack_tag, OLD_TSN, "BEFORE");
    settle();
    check(recv_string(stack) == "BEFORE", "original association carries DATA");

    // The peer "crashes" and opens again with fresh tags.
    peer.send_init(NEW_TAG, NEW_TSN);
    Init_Ack second;
    if (!recv_init_ack(peer, second)) { check(false, "restart INIT ACK"); return; }
    uint32_t new_stack_tag = second.value.initiate_tag;
    check(second.vtag == NEW_TAG, "INIT ACK carries the new INIT's tag");
    check(new_stack_tag != old_stack_tag, "INIT ACK offers a new tag");
    check(second.parsed.local_tie_tag != 0 && second.parsed.peer_tie_tag != 0, "Tie-Tags populated");
    check(second.parsed.local_tie_tag != old_stack_tag && second.parsed.peer_tie_tag != OLD_TAG,
          "Tie-Tags are not the live verification tags");

    Association tcb;
    SCTP_Socket_Test_Access::snapshot(stack, PEER_PORT, tcb);
    check(tcb.state == ESTABLISHED && tcb.this_ver_tag == old_stack_tag && tcb.peer_ver_tag == OLD_TAG,
          "INIT alone leaves the association untouched");

    peer.send_echo(new_stack_tag, second.cookie, "AFTER", NEW_TSN);
    check(recv_cookie_ack(peer, vtag) && vtag == NEW_TAG, "COOKIE ACK sent under the new peer tag");
    SCTP_Socket_Test_Access::snapshot(stack, PEER_PORT, tcb);
    check(tcb.state == ESTABLISHED && tcb.this_ver_tag == new_stack_tag && tcb.peer_ver_tag == NEW_TAG,
          "association now holds the new tags");
    check(SCTP_Socket_Test_Access::association_count(stack) == 1, "and there is still exactly one");
    settle();
    check(recv_string(stack) == "AFTER", "DATA bundled with the restart cookie is delivered");

    peer.send_data(old_stack_tag, NEW_TSN + 1, "STALE-TAG");
    settle();
    check(recv_string(stack).empty(), "DATA under the old tag is rejected");
}

/*--------------------------- 5.2.4 C, unlisted ---------------------------*/

void test_old_cookies_are_discarded() {
    std::printf("Old cookies are discarded (5.2.4 action C and unlisted rows):\n");
    constexpr uint16_t STACK_PORT = 39731, PEER_PORT = 39732;
    constexpr uint32_t PEER_TAG = 0x5D5D5D5D, OTHER_TAG = 0x6D6D6D6D, PEER_TSN = 0x500;

    SCTP_Socket stack;
    RawPeer peer;
    if (!start(stack, STACK_PORT) || !peer.open(PEER_PORT, STACK_PORT)) { check(false, "setup"); return; }

    // Three cookies minted with no TCB, so all carry zero Tie-Tags.
    Init_Ack other, late, used;
    peer.send_init(OTHER_TAG, PEER_TSN);
    peer.send_init(PEER_TAG, PEER_TSN);
    peer.send_init(PEER_TAG, PEER_TSN);
    if (!recv_init_ack(peer, other) || !recv_init_ack(peer, late) || !recv_init_ack(peer, used)) {
        check(false, "received three INIT ACKs"); return;
    }

    uint32_t vtag = 0;
    peer.send_echo(used.value.initiate_tag, used.cookie);
    if (!recv_cookie_ack(peer, vtag)) { check(false, "handshake COOKIE ACK"); return; }

    // X M 0 0: our tag differs, peer's matches.
    peer.send_echo(late.value.initiate_tag, late.cookie);
    check(!recv_cookie_ack(peer, vtag, 500), "late cookie gets no COOKIE ACK (C)");

    // X X 0 0: would be a restart if zero Tie-Tags counted as a match.
    peer.send_echo(other.value.initiate_tag, other.cookie);
    check(!recv_cookie_ack(peer, vtag, 500), "zero Tie-Tags never match (no forced restart)");

    Association tcb;
    SCTP_Socket_Test_Access::snapshot(stack, PEER_PORT, tcb);
    check(tcb.this_ver_tag == used.value.initiate_tag && tcb.peer_ver_tag == PEER_TAG,
          "association is undisturbed");
}

/*------------------------- simultaneous open ------------------------------*/

void test_simultaneous_open() {
    std::printf("Two stacks opening at once converge on one association (5.2.1):\n");
    constexpr uint16_t PORT_A = 39741, PORT_B = 39742;

    SCTP_Socket a, b;
    if (!start(a, PORT_A) || !start(b, PORT_B)) { check(false, "setup"); return; }

    Association_Key to_b = a.sctp_associate("127.0.0.1", PORT_B);
    Association_Key to_a = b.sctp_associate("127.0.0.1", PORT_A);
    check(a.await_established_association(to_b, 3000) == 0, "A reached ESTABLISHED");
    check(b.await_established_association(to_a, 3000) == 0, "B reached ESTABLISHED");

    Association at_a, at_b;
    SCTP_Socket_Test_Access::snapshot(a, PORT_B, at_a);
    SCTP_Socket_Test_Access::snapshot(b, PORT_A, at_b);
    check(at_a.this_ver_tag == at_b.peer_ver_tag && at_b.this_ver_tag == at_a.peer_ver_tag,
          "both ends agree on the tags");

    std::string message = "HELLO";
    a.sctp_send_data(to_b, std::vector<uint8_t>(message.begin(), message.end()));
    settle();
    check(recv_string(b) == message, "DATA flows over the converged association");
}

} // namespace

int main() {
    test_init_in_cookie_wait();
    test_init_in_cookie_echoed();
    test_peer_restart();
    test_old_cookies_are_discarded();
    test_simultaneous_open();

    if (failures == 0) {
        std::printf("\nALL TESTS PASSED (0 failures)\n");
    } else {
        std::printf("\n%d FAILURE(S)\n", failures);
    }
    return failures == 0 ? 0 : 1;
}
