// Kernel interop, stage 0: send an INIT to the Linux kernel's SCTP stack and
// validate the INIT_ACK it sends back.
//
// Why this test matters more than its size suggests: every other test in this
// suite is written against our own encoder, so a bug both sides of a loopback
// agree on is invisible to them. That is precisely how the CRC-32C polynomial
// error survived. Here the *kernel* computes the checksum and lays out the
// bytes, and we validate them with our own code — so this is the only test that
// can catch that class of bug.
//
// It deliberately stops after INIT_ACK. Completing the handshake needs us to
// echo the State Cookie (not implemented yet), and per RFC 9260 5.1.3 the
// responder holds no state until COOKIE_ECHO returns, so abandoning the
// handshake here leaks nothing on the kernel side.
//
// Requires root setup first; skips cleanly (exit 0) when absent:
//     sudo modprobe sctp
//     sudo sysctl -w net.sctp.udp_port=9899
//     sudo sysctl -w net.sctp.encap_port=9900

#include <sctp/platform.hpp>
#include <sctp/sctp.hpp>
#include "serialize.hpp"
#include "checksum.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
int main() {
    std::printf("Kernel interop: SKIPPED (Linux-only; kernel SCTP not available on Windows)\n");
    return 0;
}
#else

#include <cerrno>

namespace {

// Kernel listens for UDP-encapsulated SCTP here; must equal net.sctp.udp_port.
constexpr uint16_t KERNEL_UDP_PORT = 9899;
// Our UDP socket. Cannot be KERNEL_UDP_PORT: the kernel owns that one once
// net.sctp.udp_port is set. Should equal net.sctp.encap_port.
constexpr uint16_t OUR_UDP_PORT = 9900;
// SCTP port the kernel listener binds. sctp_associate() currently ties the SCTP
// destination port to the UDP destination port, so keep them equal.
constexpr uint16_t KERNEL_SCTP_PORT = 9899;

constexpr uint16_t PARAM_STATE_COOKIE = 7;   // RFC 9260 3.3.3

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

void hexdump(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; i += 16) {
        std::printf("      %04zx  ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < n) std::printf("%02x ", p[i + j]); else std::printf("   ");
        }
        std::printf("\n");
    }
}

uint16_t rd16be(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] << 8 | p[1]);
}

/*------------------------- availability detection --------------------------*/

bool read_sysctl_long(const char* path, long& out) {
    FILE* f = std::fopen(path, "r");
    if (!f) return false;
    bool ok = (std::fscanf(f, "%ld", &out) == 1);
    std::fclose(f);
    return ok;
}

// Returns false with a human-readable reason when the environment is not set up.
bool interop_available(std::string& why) {
    long udp_port = 0;
    if (!read_sysctl_long("/proc/sys/net/sctp/udp_port", udp_port)) {
        why = "kernel SCTP module not loaded (no /proc/sys/net/sctp/udp_port)";
        return false;
    }
    if (udp_port == 0) {
        why = "net.sctp.udp_port is 0 (UDP encapsulation disabled)";
        return false;
    }
    if (udp_port != KERNEL_UDP_PORT) {
        char buf[128];
        std::snprintf(buf, sizeof buf,
                      "net.sctp.udp_port is %ld, this test expects %u",
                      udp_port, KERNEL_UDP_PORT);
        why = buf;
        return false;
    }
    return true;
}

void print_skip(const std::string& why) {
    std::printf("Kernel interop (stage 0): SKIPPED\n");
    std::printf("  reason: %s\n", why.c_str());
    std::printf("  enable with:\n");
    std::printf("      sudo modprobe sctp\n");
    std::printf("      sudo sysctl -w net.sctp.udp_port=%u\n", KERNEL_UDP_PORT);
    std::printf("      sudo sysctl -w net.sctp.encap_port=%u\n", OUR_UDP_PORT);
}

/*------------------------------ TLV walking --------------------------------*/

// Walks the variable-length parameter list of an INIT/INIT_ACK chunk
// (RFC 9260 3.2.1: 2-byte type, 2-byte length inclusive of the header, value,
// padded to a 4-byte boundary).
bool find_parameter(const std::vector<uint8_t>& params, uint16_t want,
                    std::vector<uint8_t>& value_out, std::string& err) {
    size_t off = 0;
    while (off + 4 <= params.size()) {
        uint16_t type = rd16be(&params[off]);
        uint16_t len  = rd16be(&params[off + 2]);
        if (len < 4) { err = "parameter length below 4"; return false; }
        if (off + len > params.size()) { err = "parameter length overruns chunk"; return false; }
        if (type == want) {
            value_out.assign(params.begin() + off + 4, params.begin() + off + len);
            return true;
        }
        off += (static_cast<size_t>(len) + 3) & ~size_t{3};
    }
    err = "parameter not present";
    return false;
}

/*--------------------------- kernel SCTP listener --------------------------*/

// A listening one-to-one SCTP socket is all stage 0 needs: the kernel answers
// INIT with INIT_ACK from the listen socket, and accept() only returns once the
// handshake completes — which we never do.
struct KernelListener {
    sctp_socket_t fd = INVALID_SOCKET;

    bool start(std::string& err) {
        fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
        if (fd == INVALID_SOCKET) {
            err = std::string("socket(IPPROTO_SCTP): ") + std::strerror(errno);
            return false;
        }
        int one = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(KERNEL_SCTP_PORT);
        sctp_parse_ipv4("127.0.0.1", a.sin_addr);
        if (::bind(fd, (sockaddr*)&a, sizeof a) != 0) {
            err = std::string("bind SCTP :") + std::to_string(KERNEL_SCTP_PORT)
                + ": " + std::strerror(errno);
            return false;
        }
        if (::listen(fd, 1) != 0) {
            err = std::string("listen: ") + std::strerror(errno);
            return false;
        }
        return true;
    }

    void stop() {
        if (fd != INVALID_SOCKET) { sctp_close_socket(fd); fd = INVALID_SOCKET; }
    }
};

} // namespace

/*----------------------------------- test ----------------------------------*/

int main() {
    std::string why;
    if (!interop_available(why)) {
        print_skip(why);
        return 0;                     // not a failure: keeps `make test` green
    }

    std::printf("Kernel interop (stage 0): INIT -> kernel, validate INIT_ACK\n");

    KernelListener kernel;
    std::string err;
    if (!kernel.start(err)) {
        // Setup looked right but the listener would not come up. Report rather
        // than skip, so a real regression is not silently swallowed.
        std::printf("  [FAIL] start kernel SCTP listener: %s\n", err.c_str());
        return 1;
    }
    std::printf("  kernel SCTP listening on 127.0.0.1:%u\n", KERNEL_SCTP_PORT);

    // Our plain UDP socket: this is the encapsulation the kernel expects.
    sctp_socket_t udp = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp == INVALID_SOCKET) {
        std::printf("  [FAIL] create UDP socket: %s\n", std::strerror(errno));
        kernel.stop();
        return 1;
    }
    sockaddr_in self{};
    self.sin_family = AF_INET;
    self.sin_port = htons(OUR_UDP_PORT);
    sctp_parse_ipv4("127.0.0.1", self.sin_addr);
    if (::bind(udp, (sockaddr*)&self, sizeof self) != 0) {
        std::printf("  [FAIL] bind UDP :%u: %s\n", OUR_UDP_PORT, std::strerror(errno));
        std::printf("         (if EADDRINUSE, net.sctp.udp_port may be set to %u)\n",
                    OUR_UDP_PORT);
        sctp_close_socket(udp);
        kernel.stop();
        return 1;
    }
    timeval tv{}; tv.tv_sec = 2;
    ::setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(KERNEL_UDP_PORT);
    sctp_parse_ipv4("127.0.0.1", dst.sin_addr);

    // --- build and send INIT ------------------------------------------------
    // Fixed rather than random so a packet capture is reproducible. Any
    // non-zero value is valid (RFC 9260 3.1).
    const uint32_t our_tag = 0xABCD1234u;
    const uint32_t our_tsn = 0x11112222u;

    SCTP_Packet init;
    init.header.src_port = OUR_UDP_PORT;
    init.header.des_port = KERNEL_SCTP_PORT;
    init.header.verification_tag = 0;      // RFC 9260 8.5: zero for INIT
    init.header.checksum = 0;
    init.chunks.push_back(SCTP_Chunk{
        .chunk_header = { .type = INIT, .flag = 0, .length = 0 },
        .chunk_value = init_chunk_value{
            .initiate_tag = our_tag,
            .a_rwnd = RWND,
            .out_streams = 1,
            .in_streams = 1,
            .initial_tsn = our_tsn,
            .optional_parameters = {}
        }
    });
    std::vector<uint8_t> wire = serialize_sctp_packet(init);

    // --- send, with retries in case the first datagram races the listener ----
    std::vector<uint8_t> reply;
    for (int attempt = 0; attempt < 3 && reply.empty(); attempt++) {
        ::sendto(udp, (const char*)wire.data(), wire.size(), 0,
                 (const sockaddr*)&dst, sizeof dst);

        uint8_t buf[2048];
        sockaddr_in from{};
        socklen_t flen = sizeof from;
        int n = ::recvfrom(udp, (char*)buf, sizeof buf, 0, (sockaddr*)&from, &flen);
        if (n > 0) reply.assign(buf, buf + n);
    }

    if (reply.empty()) {
        std::printf("  [FAIL] no reply from kernel after 3 INITs\n");
        std::printf("         a silent drop usually means a bad CRC-32C, since the\n");
        std::printf("         kernel discards those without responding. also check\n");
        std::printf("         net.sctp.encap_port == %u\n", OUR_UDP_PORT);
        failures++;
        sctp_close_socket(udp);
        kernel.stop();
        std::printf("\nTESTS FAILED (%d failure%s)\n", failures, failures == 1 ? "" : "s");
        return 1;
    }

    std::printf("  got %zu bytes back from the kernel\n", reply.size());

    // --- validate ----------------------------------------------------------
    // The kernel computed this checksum. Validating it with our own CRC-32C is
    // the independent cross-check the loopback tests structurally cannot do.
    bool big_enough = reply.size() >= SCTP_COMMON_HEADER_SIZE;
    check(big_enough, "reply is at least a common header");
    if (!big_enough) { hexdump(reply.data(), reply.size()); goto done; }

    {
        uint32_t got_sum = sctp_read_wire_checksum(reply.data());
        std::vector<uint8_t> zeroed = reply;
        sctp_clear_wire_checksum(zeroed.data());
        uint32_t calc = calculate_sctp_checksum(zeroed.data(), zeroed.size());
        bool sum_ok = (got_sum == calc);
        std::printf("  [%s] kernel's CRC-32C validates under our implementation"
                    " (0x%08X)\n", sum_ok ? "PASS" : "FAIL", got_sum);
        if (!sum_ok) {
            std::printf("         ours: 0x%08X  theirs: 0x%08X\n", calc, got_sum);
            failures++;
            hexdump(reply.data(), reply.size());
        }

        SCTP_Packet ack;
        bool parsed = true;
        try {
            ack = deserialize_sctp_packet(reply.data(), reply.size());
        } catch (const std::exception& e) {
            parsed = false;
            std::printf("  [FAIL] parse kernel reply: %s\n", e.what());
            failures++;
            hexdump(reply.data(), reply.size());
        }
        if (!parsed) goto done;

        check(!ack.chunks.empty(), "reply contains at least one chunk");
        if (ack.chunks.empty()) { hexdump(reply.data(), reply.size()); goto done; }

        Chunk_Type t = ack.chunks[0].chunk_header.type;
        if (t == ABORT) {
            std::printf("  [FAIL] kernel replied ABORT — it parsed our INIT but"
                        " rejected it\n");
            failures++;
            hexdump(reply.data(), reply.size());
            goto done;
        }
        check(t == INIT_ACK, "first chunk is INIT_ACK");
        if (t != INIT_ACK) { hexdump(reply.data(), reply.size()); goto done; }

        // Byte order: the kernel echoes our Initiate Tag as the Verification
        // Tag. A byte-swap bug anywhere in the header shows up right here.
        check(ack.header.verification_tag == our_tag,
              "INIT_ACK verification tag echoes our initiate tag");
        check(ack.header.src_port == KERNEL_SCTP_PORT, "src_port is the kernel's SCTP port");
        check(ack.header.des_port == OUR_UDP_PORT, "des_port is our SCTP port");

        const auto& iv = std::get<init_chunk_value>(ack.chunks[0].chunk_value);
        check(iv.initiate_tag != 0, "kernel's initiate tag is non-zero");
        check(iv.out_streams > 0 && iv.in_streams > 0, "stream counts are non-zero");
        check(!iv.optional_parameters.empty(), "INIT_ACK carries optional parameters");

        // The State Cookie is mandatory in INIT_ACK. Locating it also proves out
        // the TLV walk that stage 2 needs in order to echo it.
        std::vector<uint8_t> cookie;
        std::string perr;
        bool have_cookie = find_parameter(iv.optional_parameters,
                                          PARAM_STATE_COOKIE, cookie, perr);
        if (have_cookie) {
            std::printf("  [PASS] State Cookie parameter present (%zu bytes)\n",
                        cookie.size());
        } else {
            std::printf("  [FAIL] State Cookie parameter: %s\n", perr.c_str());
            failures++;
        }
    }

done:
    sctp_close_socket(udp);
    kernel.stop();

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}

#endif // _WIN32
