// Out-of-order delivery and TSN serial-number arithmetic.
//
// Drives a real SCTP_Socket over a plain UDP socket: performs the four-way
// handshake by hand, then feeds DATA chunks in a deliberately scrambled order
// and checks what the application layer actually receives.
//
// This path has never been exercised before, so these are new baselines rather
// than regression guards.

#include <sctp/socket.hpp>
#include <sctp/utils.hpp>
#include "serialize.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <chrono>

static int failures = 0;

static void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

/*--------------------------- tsn_lt truth table ----------------------------*/

static void test_tsn_lt() {
    std::printf("TSN serial number arithmetic (RFC 1982 / RFC 9260 3.1):\n");

    struct { uint32_t a, b; bool want; const char* why; } cases[] = {
        {5, 10, true,  "5 < 10, no wrap"},
        {10, 5, false, "10 < 5 is false"},
        {5, 5,  false, "equal is not less-than"},
        {0xFFFFFFFF, 0, true,  "0 follows 0xFFFFFFFF across the wrap"},
        {0, 0xFFFFFFFF, false, "0xFFFFFFFF does not follow 0"},
        {0xFFFFFFF0, 5, true,  "wrap: 5 is 21 ahead of 0xFFFFFFF0"},
        {5, 0xFFFFFFF0, false, "reverse of the above"},
        {0, 0x7FFFFFFF, true,  "exactly half the space ahead"},
        {0, 0x80000000, false, "past half the space is ambiguous, must be false"},
    };
    for (auto& c : cases) {
        check(tsn_lt(c.a, c.b) == c.want, c.why);
    }
}

/*------------------------------ UDP peer -----------------------------------*/

namespace {

constexpr uint16_t SERVER_PORT = 19901;
constexpr uint16_t CLIENT_PORT = 19902;
constexpr uint32_t CLIENT_TAG  = 0xC1C1C1C1;

struct RawPeer {
    sctp_socket_t fd = INVALID_SOCKET;
    sockaddr_in   server{};
    sockaddr_in   self{};

    bool open() {
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd == INVALID_SOCKET) return false;

        self.sin_family = AF_INET;
        self.sin_port   = htons(CLIENT_PORT);
        sctp_parse_ipv4("127.0.0.1", self.sin_addr);
        if (bind(fd, (sockaddr*)&self, sizeof(self)) == SOCKET_ERROR) return false;

        timeval tv{}; tv.tv_sec = 2;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

        server.sin_family = AF_INET;
        server.sin_port   = htons(SERVER_PORT);
        sctp_parse_ipv4("127.0.0.1", server.sin_addr);
        return true;
    }

    void send(const SCTP_Packet& p) {
        std::vector<uint8_t> w = serialize_sctp_packet(p);
        sendto(fd, (const char*)w.data(), w.size(), 0,
               (const sockaddr*)&server, sizeof(server));
    }

    // Returns false on timeout.
    bool recv(SCTP_Packet& out) {
        uint8_t buf[2048];
        sockaddr_in from{};
        socklen_t   flen = sizeof(from);
        int n = recvfrom(fd, (char*)buf, sizeof(buf), 0, (sockaddr*)&from, &flen);
        if (n <= 0) return false;
        try { out = deserialize_sctp_packet(buf, (size_t)n); }
        catch (const std::exception&) { return false; }
        return true;
    }

    void close_it() {
        if (fd != INVALID_SOCKET) { sctp_close_socket(fd); fd = INVALID_SOCKET; }
    }
};

SCTP_Packet make_header(uint32_t ver_tag) {
    SCTP_Packet p;
    p.header.src_port = CLIENT_PORT;
    p.header.des_port = SERVER_PORT;
    p.header.verification_tag = ver_tag;
    p.header.checksum = 0;
    return p;
}

SCTP_Packet make_data(uint32_t ver_tag, uint32_t tsn, const std::string& payload) {
    SCTP_Packet p = make_header(ver_tag);
    p.chunks.push_back(SCTP_Chunk{
        .chunk_header = { .type = DATA, .flag = 0, .length = 0 },
        .chunk_value = data_chunk_value{
            .tsn = tsn, .stream_identifier = 0, .stream_seq_num = 0,
            .payload_protocal = 0,
            .user_data = std::vector<uint8_t>(payload.begin(), payload.end())
        }
    });
    return p;
}

// Pulls one message, retrying while the event loop catches up.
bool recv_from_stack(SCTP_Socket& s, const Association_Key& key, std::string& out) {
    std::vector<uint8_t> buf(512);
    for (int i = 0; i < 100; i++) {
        size_t n = s.sctp_recv_data_from(key, buf);
        if (n > 0) { out.assign(buf.begin(), buf.begin() + n); return true; }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

} // namespace

/*--------------------------- reordering test -------------------------------*/

static void test_out_of_order_delivery(uint32_t base_tsn, const char* label) {
    std::printf("Out-of-order DATA delivery (%s, initial TSN 0x%08X):\n",
                label, base_tsn);

    SCTP_Socket server{};
    if (!server.sctp_bind("127.0.0.1", SERVER_PORT)) {
        check(false, "server bind"); return;
    }
    server.sctp_run();

    RawPeer peer;
    if (!peer.open()) { check(false, "peer socket setup"); return; }

    // --- handshake -----------------------------------------------------
    SCTP_Packet init = make_header(0);
    init.chunks.push_back(SCTP_Chunk{
        .chunk_header = { .type = INIT, .flag = 0, .length = 0 },
        .chunk_value = init_chunk_value{
            .initiate_tag = CLIENT_TAG, .a_rwnd = RWND,
            .out_streams = 1, .in_streams = 1,
            .initial_tsn = base_tsn, .optional_parameters = {}
        }
    });
    peer.send(init);

    SCTP_Packet init_ack;
    if (!peer.recv(init_ack) || init_ack.chunks.empty() ||
        init_ack.chunks[0].chunk_header.type != INIT_ACK) {
        check(false, "received INIT_ACK"); peer.close_it(); return;
    }
    uint32_t server_tag = std::get<init_chunk_value>(init_ack.chunks[0].chunk_value).initiate_tag;
    check(init_ack.header.verification_tag == CLIENT_TAG, "INIT_ACK echoes our tag");

    SCTP_Packet cookie_echo = make_header(server_tag);
    cookie_echo.chunks.push_back(SCTP_Chunk{
        .chunk_header = { .type = COOKIE_ECHO, .flag = 0, .length = 0 },
        .chunk_value = cookie_echo_chunk_value{ .cookie_data = {} }
    });
    peer.send(cookie_echo);

    SCTP_Packet cookie_ack;
    if (!peer.recv(cookie_ack) || cookie_ack.chunks.empty() ||
        cookie_ack.chunks[0].chunk_header.type != COOKIE_ACK) {
        check(false, "received COOKIE_ACK"); peer.close_it(); return;
    }
    check(true, "association established");

    // --- scrambled DATA ------------------------------------------------
    // Server expects base_tsn first. Send +1 and +2 early so they must be
    // buffered, then base_tsn to fill the gap, then +3 and +4 in order.
    // Before the fix, +3 and +4 stranded in the out-of-order buffer forever.
    peer.send(make_data(server_tag, base_tsn + 1, "two"));
    peer.send(make_data(server_tag, base_tsn + 2, "three"));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    peer.send(make_data(server_tag, base_tsn + 0, "one"));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    peer.send(make_data(server_tag, base_tsn + 3, "four"));
    peer.send(make_data(server_tag, base_tsn + 4, "five"));

    Association_Key key{peer.self};
    const char* expect[] = {"one", "two", "three", "four", "five"};
    std::string got_all;
    bool all_ok = true;
    for (int i = 0; i < 5; i++) {
        std::string got;
        if (!recv_from_stack(server, key, got)) {
            std::printf("      (timed out waiting for message %d, expected \"%s\")\n",
                        i + 1, expect[i]);
            all_ok = false;
            break;
        }
        got_all += got + " ";
        if (got != expect[i]) all_ok = false;
    }
    std::printf("      delivered: %s\n", got_all.empty() ? "(nothing)" : got_all.c_str());
    check(all_ok, "all 5 chunks delivered once, in TSN order");

    peer.close_it();
}

int main() {
    test_tsn_lt();
    std::printf("\n");
    test_out_of_order_delivery(1000, "no wrap");
    std::printf("\n");
    // Straddles the 32-bit boundary: TSNs run 0xFFFFFFFE, FFFFFFFF, 0, 1, 2.
    test_out_of_order_delivery(0xFFFFFFFE, "across the TSN wrap");

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
