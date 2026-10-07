// Kernel interop: this stack against the Linux kernel's SCTP over UDP
// encapsulation, in both roles, through handshake, DATA, streams,
// fragmentation, heartbeats and every way an association ends.
//
// The only test whose peer we did not write, so the only one that can catch a
// bug our encoder and our other tests agree on.
//
// Runs in a private user + network namespace, so it needs no root and its
// net.sctp sysctls and port 9899 never touch the host or the other tests. The
// sctp module is autoloaded by creating a socket. Without user namespaces it
// falls back to a host already set up with:
//     sudo modprobe sctp
//     sudo sysctl -w net.sctp.udp_port=9899
//     sudo sysctl -w net.sctp.encap_port=9900
// and skips (exit 0) otherwise. SCTP_INTEROP_NETNS=current uses the namespace
// it was started in, so a capture can run alongside it:
//     unshare -rn sh -c 'ip link set lo up; echo 9899 > /proc/sys/net/sctp/udp_port;
//         echo 9900 > /proc/sys/net/sctp/encap_port; tcpdump -i lo -w x.pcap & ...'
//
// The stack derives SCTP ports from UDP ports, so the kernel's SCTP port must
// equal net.sctp.udp_port, ours equals our UDP port, and a kernel client must
// bind before connecting.

#include <sctp/platform.hpp>
#include <sctp/socket.hpp>

#include <cstdio>
#include <string>
#include <vector>

#ifdef _WIN32
int main() {
    std::printf("Kernel interop: SKIPPED (Linux-only; kernel SCTP not available on Windows)\n");
    return 0;
}
#else

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/sctp.h>
#include <sched.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <mutex>
#include <thread>

using Clock = std::chrono::steady_clock;

struct SCTP_Socket_Test_Access {
    static size_t association_count(SCTP_Socket& stack) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        return stack.associations.size();
    }
};

namespace {

using Access = SCTP_Socket_Test_Access;

constexpr uint16_t KERNEL_PORT = 9899;
constexpr uint16_t OUR_PORT = 9900;
constexpr int TIMEOUT_MS = 5000;

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

void section(const char* name) {
    std::printf("\n%s\n", name);
}

/*------------------------------ environment --------------------------------*/

bool write_file(const char* path, const std::string& text) {
    std::ofstream f(path);
    f << text;
    return f.good();
}

bool read_long(const char* path, long& out) {
    std::ifstream f(path);
    return static_cast<bool>(f >> out);
}

bool sctp_available() {
    int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (fd < 0) return false;
    ::close(fd);
    return true;
}

// Must run before any thread exists: unshare(CLONE_NEWUSER) refuses a
// multithreaded process.
bool enter_private_netns(std::string& why) {
    uid_t uid = ::getuid();
    gid_t gid = ::getgid();
    if (::unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) {
        why = std::string("unshare: ") + std::strerror(errno);
        return false;
    }
    write_file("/proc/self/setgroups", "deny");
    if (!write_file("/proc/self/uid_map", "0 " + std::to_string(uid) + " 1")
        || !write_file("/proc/self/gid_map", "0 " + std::to_string(gid) + " 1")) {
        why = "could not write uid/gid map";
        return false;
    }

    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ifreq ifr{};
    std::strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    bool up = fd >= 0 && ::ioctl(fd, SIOCGIFFLAGS, &ifr) == 0
        && (ifr.ifr_flags |= IFF_UP, ::ioctl(fd, SIOCSIFFLAGS, &ifr) == 0);
    if (fd >= 0) ::close(fd);
    if (!up) {
        why = std::string("bring up lo: ") + std::strerror(errno);
        return false;
    }

    if (!write_file("/proc/sys/net/sctp/udp_port", std::to_string(KERNEL_PORT))
        || !write_file("/proc/sys/net/sctp/encap_port", std::to_string(OUR_PORT))) {
        why = "could not set net.sctp.udp_port / encap_port in the namespace";
        return false;
    }
    return true;
}

bool host_configured(std::string& why) {
    long udp_port = 0;
    if (!read_long("/proc/sys/net/sctp/udp_port", udp_port) || udp_port != KERNEL_PORT) {
        why = "net.sctp.udp_port is not " + std::to_string(KERNEL_PORT);
        return false;
    }
    return true;
}

// Extensions the stack does not implement would put chunks on the wire it
// cannot parse.
bool extensions_off(std::string& why) {
    for (const char* name : {"auth_enable", "addip_enable", "intl_enable", "reconf_enable"}) {
        long v = 0;
        std::string path = std::string("/proc/sys/net/sctp/") + name;
        if (read_long(path.c_str(), v) && v != 0) {
            why = std::string("net.sctp.") + name + " is on";
            return false;
        }
    }
    return true;
}

std::map<std::string, long> sctp_snmp() {
    std::map<std::string, long> out;
    std::ifstream f("/proc/net/sctp/snmp");
    std::string name;
    long value;
    while (f >> name >> value) out[name] = value;
    return out;
}

/*------------------------------ kernel side --------------------------------*/

void set_timeouts(int fd, int ms) {
    timeval tv{ms / 1000, (ms % 1000) * 1000};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

sockaddr_in loopback(uint16_t port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}

int kernel_socket() {
    int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (fd < 0) return fd;
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    int buf = 1 << 20;
    ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof buf);
    sctp_initmsg init{};
    init.sinit_num_ostreams = 10;
    init.sinit_max_instreams = 10;
    ::setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, &init, sizeof init);
    ::setsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, &one, sizeof one);
    ::setsockopt(fd, IPPROTO_SCTP, SCTP_RECVRCVINFO, &one, sizeof one);
    set_timeouts(fd, TIMEOUT_MS);
    return fd;
}

bool kernel_send(int fd, const std::vector<uint8_t>& data, uint16_t sid = 0, bool unordered = false) {
    iovec iov{const_cast<uint8_t*>(data.data()), data.size()};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(sctp_sndinfo))]{};
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof control;
    cmsghdr* c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = IPPROTO_SCTP;
    c->cmsg_type = SCTP_SNDINFO;
    c->cmsg_len = CMSG_LEN(sizeof(sctp_sndinfo));
    sctp_sndinfo info{};
    info.snd_sid = sid;
    info.snd_flags = unordered ? SCTP_UNORDERED : 0;
    std::memcpy(CMSG_DATA(c), &info, sizeof info);
    return ::sendmsg(fd, &msg, 0) == static_cast<ssize_t>(data.size());
}

struct Kernel_Message {
    std::vector<uint8_t> bytes;
    sctp_rcvinfo info{};
    bool have_info{false};
};

// 1 on a whole message, 0 on EOF, -1 with errno set otherwise.
int kernel_recv(int fd, Kernel_Message& out) {
    out = Kernel_Message{};
    std::vector<uint8_t> chunk(1 << 16);
    for (;;) {
        iovec iov{chunk.data(), chunk.size()};
        alignas(cmsghdr) char control[CMSG_SPACE(sizeof(sctp_rcvinfo))]{};
        msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control;
        msg.msg_controllen = sizeof control;
        ssize_t n = ::recvmsg(fd, &msg, 0);
        if (n <= 0) return n == 0 ? 0 : -1;
        if (msg.msg_flags & MSG_NOTIFICATION) continue;
        for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
            if (c->cmsg_level == IPPROTO_SCTP && c->cmsg_type == SCTP_RCVINFO && !out.have_info) {
                std::memcpy(&out.info, CMSG_DATA(c), sizeof out.info);
                out.have_info = true;
            }
        }
        out.bytes.insert(out.bytes.end(), chunk.begin(), chunk.begin() + n);
        if (msg.msg_flags & MSG_EOR) return 1;
    }
}

bool kernel_status(int fd, sctp_status& status) {
    status = sctp_status{};
    socklen_t len = sizeof status;
    return ::getsockopt(fd, IPPROTO_SCTP, SCTP_STATUS, &status, &len) == 0;
}

bool set_maxseg(int fd, uint32_t bytes) {
    sctp_assoc_value v{};
    v.assoc_value = bytes;
    return ::setsockopt(fd, IPPROTO_SCTP, SCTP_MAXSEG, &v, sizeof v) == 0;
}

void abortive_close(int fd) {
    linger l{1, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof l);
    ::close(fd);
}

/*-------------------------------- our side ---------------------------------*/

std::vector<uint8_t> pattern(size_t n, uint8_t seed) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; i++) v[i] = static_cast<uint8_t>(seed + i * 7 + (i >> 8));
    return v;
}

std::vector<uint8_t> text(const char* s) {
    return std::vector<uint8_t>(s, s + std::strlen(s));
}

// Reassembles one message across partial reads.
bool our_recv(SCTP_Socket& stack, const Association_Key& key, std::vector<uint8_t>& out,
              uint16_t* stream = nullptr, int timeout_ms = TIMEOUT_MS) {
    out.clear();
    std::vector<uint8_t> buffer(1 << 18);
    auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    while (Clock::now() < deadline) {
        bool partial = false;
        uint16_t sid = 0;
        size_t n = stack.sctp_recv_data_from(key, buffer, &partial, &sid);
        if (n == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        if (out.empty() && stream) *stream = sid;
        out.insert(out.end(), buffer.begin(), buffer.begin() + n);
        if (!partial) return true;
    }
    return false;
}

std::optional<Assoc_Change_State> next_assoc_change(SCTP_Socket& stack, Association_Key* src = nullptr,
                                                   int timeout_ms = TIMEOUT_MS) {
    auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    while (Clock::now() < deadline) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
        auto n = stack.sctp_recv_notification(static_cast<int>(std::max<int64_t>(remaining.count(), 1)));
        if (!n) continue;
        if (n->type == Notification_Type::SCTP_REMOTE_ERROR) {
            const auto& causes = std::get<Remote_Error>(n->payload).causes;
            for (const auto& c : causes) std::printf("      remote ERROR cause %u\n", c.code);
            continue;
        }
        if (n->type != Notification_Type::SCTP_ASSOC_CHANGE) continue;
        if (src) *src = n->src;
        return std::get<Assoc_Change>(n->payload).state;
    }
    return std::nullopt;
}

const char* state_name(std::optional<Assoc_Change_State> s) {
    if (!s) return "none";
    switch (*s) {
        case Assoc_Change_State::COMM_UP: return "COMM_UP";
        case Assoc_Change_State::COMM_LOST: return "COMM_LOST";
        case Assoc_Change_State::RESTART: return "RESTART";
        case Assoc_Change_State::SHUTDOWN_COMP: return "SHUTDOWN_COMP";
        case Assoc_Change_State::CANT_STR_ASSOC: return "CANT_STR_ASSOC";
    }
    return "?";
}

void expect_change(SCTP_Socket& stack, Assoc_Change_State want, const std::string& what) {
    auto got = next_assoc_change(stack);
    check(got == want, what + " (got " + state_name(got) + ")");
}

bool await_empty(SCTP_Socket& stack, int timeout_ms = TIMEOUT_MS) {
    auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    while (Access::association_count(stack) != 0 && Clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return Access::association_count(stack) == 0;
}

/*--------------------------------- phases ----------------------------------*/

// We initiate; returns the kernel's accepted socket, or -1.
int associate_to_kernel(SCTP_Socket& stack, int listener, Association_Key& key) {
    key = stack.sctp_associate("127.0.0.1", KERNEL_PORT);
    bool up = stack.await_established_association(key, TIMEOUT_MS) == 0;
    int fd = up ? ::accept(listener, nullptr, nullptr) : -1;
    if (fd >= 0) set_timeouts(fd, TIMEOUT_MS);
    auto change = next_assoc_change(stack);
    if (!up || fd < 0 || change != Assoc_Change_State::COMM_UP) {
        std::printf("  [FAIL] associate: established=%d accept=%d notification=%s\n",
                    up, fd, state_name(change));
        failures++;
        if (fd >= 0) ::close(fd);
        return -1;
    }
    return fd;
}

void phase_handshake(SCTP_Socket& stack, int fd) {
    section("Handshake, we initiate");
    sctp_status st;
    bool have = kernel_status(fd, st);
    check(have && st.sstat_state == SCTP_ESTABLISHED, "kernel reports ESTABLISHED");
    check(st.sstat_instrms == 10 && st.sstat_outstrms == 10,
          "streams negotiated to 10/10 (kernel sees in=" + std::to_string(st.sstat_instrms)
          + " out=" + std::to_string(st.sstat_outstrms) + ")");
    check(st.sstat_primary.spinfo_state == SCTP_ACTIVE, "kernel's path to us is ACTIVE");
    (void)stack;
}

void phase_small_data(SCTP_Socket& stack, const Association_Key& key, int fd) {
    section("Small DATA");
    auto out = text("hello kernel");
    stack.sctp_send_data(key, out);
    Kernel_Message m;
    check(kernel_recv(fd, m) == 1 && m.bytes == out, "kernel receives our message intact");
    check(m.have_info && m.info.rcv_sid == 0 && m.info.rcv_ssn == 0 && !(m.info.rcv_flags & SCTP_UNORDERED),
          "kernel sees stream 0, SSN 0, ordered");

    auto in = text("hello stack");
    check(kernel_send(fd, in), "kernel sends");
    std::vector<uint8_t> got;
    uint16_t sid = 99;
    check(our_recv(stack, key, got, &sid) && got == in, "we receive the kernel's message intact");
    check(sid == 0, "on stream 0");
}

void phase_streams(SCTP_Socket& stack, const Association_Key& key, int fd) {
    section("Streams and unordered delivery");
    std::map<uint16_t, uint16_t> kernel_next_ssn{{0, 1}};
    bool ok = true;
    for (uint16_t round = 0; round < 3; round++) {
        for (uint16_t sid = 0; sid < 10; sid++) {
            auto msg = pattern(40 + sid, static_cast<uint8_t>(round * 10 + sid));
            stack.sctp_send_data(key, msg, sid);
            Kernel_Message m;
            uint16_t expect_ssn = kernel_next_ssn[sid]++;
            if (kernel_recv(fd, m) != 1 || m.bytes != msg || m.info.rcv_sid != sid || m.info.rcv_ssn != expect_ssn) {
                std::printf("      sid %u round %u: kernel saw sid=%u ssn=%u (want ssn %u) len=%zu\n",
                            sid, round, m.info.rcv_sid, m.info.rcv_ssn, expect_ssn, m.bytes.size());
                ok = false;
            }
        }
    }
    check(ok, "30 messages over streams 0-9: kernel sees each stream's SSNs count up from 0");

    auto un = text("unordered");
    stack.sctp_send_data(key, un, 3, true);
    Kernel_Message m;
    check(kernel_recv(fd, m) == 1 && m.bytes == un && m.info.rcv_sid == 3 && (m.info.rcv_flags & SCTP_UNORDERED),
          "kernel sees our unordered message as unordered on stream 3");

    ok = true;
    for (uint16_t sid = 0; sid < 10; sid++) {
        auto msg = pattern(30 + sid, static_cast<uint8_t>(100 + sid));
        bool unordered = sid % 3 == 0;
        if (!kernel_send(fd, msg, sid, unordered)) { ok = false; continue; }
        std::vector<uint8_t> got;
        uint16_t got_sid = 99;
        if (!our_recv(stack, key, got, &got_sid) || got != msg || got_sid != sid) {
            std::printf("      kernel->us sid %u: got sid %u len %zu\n", sid, got_sid, got.size());
            ok = false;
        }
    }
    check(ok, "kernel's messages on streams 0-9, some unordered, arrive on the right stream");
}

void phase_fragmentation(SCTP_Socket& stack, const Association_Key& key, int fd) {
    section("Fragmentation and flow control");

    auto big = pattern(200 * 1024, 1);
    stack.sctp_send_data(key, big);
    Kernel_Message m;
    check(kernel_recv(fd, m) == 1 && m.bytes == big, "kernel reassembles our 200 kB message");

    // Kernel sends from a thread: a stall must show up as a timeout, not a hang.
    auto kernel_to_us = [&](const std::vector<uint8_t>& msg, int read_delay_ms, const std::string& what) {
        auto before = sctp_snmp();
        auto started = Clock::now();
        std::atomic<bool> sent{false};
        std::thread sender([&] { sent = kernel_send(fd, msg); });
        std::this_thread::sleep_for(std::chrono::milliseconds(read_delay_ms));
        std::vector<uint8_t> got;
        bool received = our_recv(stack, key, got, nullptr, 15000);
        sender.join();
        auto after = sctp_snmp();
        std::printf("      %lld ms; kernel T3 expiries %ld, retransmitted chunks %ld\n",
                    static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count()),
                    after["SctpT3RtxExpireds"] - before["SctpT3RtxExpireds"],
                    after["SctpRetransChunks"] - before["SctpRetransChunks"]);
        check(sent && received && got == msg,
              what + (received ? "" : " (timed out, got " + std::to_string(got.size()) + " bytes)"));
    };

    check(set_maxseg(fd, 1000), "kernel SCTP_MAXSEG set to 1000");
    kernel_to_us(pattern(200 * 1024, 2), 0, "we reassemble the kernel's 200 kB message in 1000-byte fragments");
    kernel_to_us(pattern(300 * 1024, 3), 1500,
                 "300 kB with our reader stalled 1.5 s: window closes, kernel probes, transfer completes");

    sctp_status st;
    kernel_status(fd, st);
    std::printf("      kernel's view of our rwnd afterwards: %u\n", st.sstat_rwnd);

    check(set_maxseg(fd, 0), "kernel SCTP_MAXSEG back to the path MTU");
    kernel_status(fd, st);
    std::printf("      kernel fragment point now: %u bytes (our RWND is %d)\n", st.sstat_fragmentation_point, RWND);
    kernel_to_us(pattern(200 * 1024, 4), 0, "we receive 200 kB in chunks near our whole window");
}

void phase_heartbeat(SCTP_Socket& stack, const Association_Key& key, int fd) {
    section("Heartbeats from the kernel");
    sctp_rtoinfo rto{};
    rto.srto_initial = 200;
    rto.srto_min = 100;
    rto.srto_max = 400;
    check(::setsockopt(fd, IPPROTO_SCTP, SCTP_RTOINFO, &rto, sizeof rto) == 0, "kernel RTO bounded to 100-400 ms");
    sctp_paddrparams p{};
    p.spp_flags = SPP_HB_ENABLE;
    p.spp_hbinterval = 100;
    p.spp_pathmaxrxt = 1;
    check(::setsockopt(fd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &p, sizeof p) == 0,
          "kernel heartbeat interval 100 ms, Path.Max.Retrans 1");

    long before = sctp_snmp()["SctpInCtrlChunks"];
    std::this_thread::sleep_for(std::chrono::milliseconds(3000));
    long acks = sctp_snmp()["SctpInCtrlChunks"] - before;

    sctp_status st;
    check(kernel_status(fd, st) && st.sstat_state == SCTP_ESTABLISHED
          && st.sstat_primary.spinfo_state == SCTP_ACTIVE,
          "after 3 s idle the kernel still has us ESTABLISHED and ACTIVE");
    check(acks >= 3, "kernel received " + std::to_string(acks) + " control chunks while idle (our HEARTBEAT ACKs)");
    check(Access::association_count(stack) == 1 && !stack.sctp_recv_notification(0), "no change on our side");

    auto in = text("after heartbeats");
    kernel_send(fd, in);
    std::vector<uint8_t> got;
    check(our_recv(stack, key, got) && got == in, "association still carries DATA");
}

void phase_teardowns(SCTP_Socket& stack, int listener) {
    Association_Key key;
    int fd;

    section("We shut down");
    if ((fd = associate_to_kernel(stack, listener, key)) >= 0) {
        stack.sctp_send_data(key, text("last words"));
        stack.sctp_shutdown(key);
        Kernel_Message m;
        check(kernel_recv(fd, m) == 1 && m.bytes == text("last words"), "kernel gets the DATA queued before SHUTDOWN");
        check(kernel_recv(fd, m) == 0, "then reads EOF");
        expect_change(stack, Assoc_Change_State::SHUTDOWN_COMP, "SHUTDOWN_COMP");
        check(await_empty(stack), "TCB removed");
        ::close(fd);
    }

    section("Kernel shuts down");
    if ((fd = associate_to_kernel(stack, listener, key)) >= 0) {
        kernel_send(fd, text("bye"));
        ::close(fd);
        std::vector<uint8_t> got;
        check(our_recv(stack, key, got) && got == text("bye"), "we get the DATA sent before close()");
        expect_change(stack, Assoc_Change_State::SHUTDOWN_COMP, "SHUTDOWN_COMP");
        check(await_empty(stack), "TCB removed");
    }

    section("We abort");
    if ((fd = associate_to_kernel(stack, listener, key)) >= 0) {
        stack.sctp_abort(key, text("test abort"));
        Kernel_Message m;
        int r = kernel_recv(fd, m);
        int err = errno;
        check(r == -1 && err == ECONNRESET,
              std::string("kernel recv fails with ECONNRESET (") + (r == -1 ? std::strerror(err) : "returned " + std::to_string(r)) + ")");
        ::close(fd);
    }

    section("Kernel aborts");
    if ((fd = associate_to_kernel(stack, listener, key)) >= 0) {
        abortive_close(fd);
        expect_change(stack, Assoc_Change_State::COMM_LOST, "COMM_LOST");
        check(await_empty(stack), "TCB removed");
    }
}

void phase_kernel_initiates(SCTP_Socket& stack) {
    section("Kernel initiates");
    int fd = kernel_socket();
    sockaddr_in self = loopback(KERNEL_PORT);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&self), sizeof self) != 0) {
        std::printf("  [FAIL] bind kernel client to %u: %s\n", KERNEL_PORT, std::strerror(errno));
        failures++;
        ::close(fd);
        return;
    }
    sockaddr_in peer = loopback(OUR_PORT);
    int r = ::connect(fd, reinterpret_cast<sockaddr*>(&peer), sizeof peer);
    check(r == 0, std::string("kernel connect() completes (") + (r == 0 ? "ok" : std::strerror(errno)) + ")");
    Association_Key key;
    expect_change(stack, Assoc_Change_State::COMM_UP, "COMM_UP");
    key = Association_Key{loopback(KERNEL_PORT)};
    if (r != 0) { ::close(fd); return; }

    sctp_status st;
    kernel_status(fd, st);
    check(st.sstat_instrms == 10 && st.sstat_outstrms == 10,
          "streams negotiated to 10/10 (kernel sees in=" + std::to_string(st.sstat_instrms)
          + " out=" + std::to_string(st.sstat_outstrms) + ")");

    auto in = pattern(50 * 1024, 5);
    check(kernel_send(fd, in, 4), "kernel sends 50 kB on stream 4");
    std::vector<uint8_t> got;
    uint16_t sid = 99;
    check(our_recv(stack, key, got, &sid) && got == in && sid == 4, "we receive it on stream 4");

    auto out = pattern(50 * 1024, 6);
    stack.sctp_send_data(key, out, 7);
    Kernel_Message m;
    check(kernel_recv(fd, m) == 1 && m.bytes == out && m.info.rcv_sid == 7, "kernel receives ours on stream 7");

    ::close(fd);
    expect_change(stack, Assoc_Change_State::SHUTDOWN_COMP, "kernel close(): SHUTDOWN_COMP");
    check(await_empty(stack), "TCB removed");
}

} // namespace

/*----------------------------------- test ----------------------------------*/

int main() {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    if (!sctp_available()) {
        std::printf("Kernel interop: SKIPPED\n  reason: kernel SCTP unavailable (%s)\n", std::strerror(errno));
        return 0;
    }
    std::string why;
    const char* netns = std::getenv("SCTP_INTEROP_NETNS");
    bool isolated = !(netns && std::string(netns) == "current") && enter_private_netns(why);
    if (!isolated && !host_configured(why)) {
        std::printf("Kernel interop: SKIPPED\n  reason: %s\n", why.c_str());
        std::printf("  needs unprivileged user namespaces, or a host set up with:\n");
        std::printf("      sudo modprobe sctp\n");
        std::printf("      sudo sysctl -w net.sctp.udp_port=%u\n", KERNEL_PORT);
        std::printf("      sudo sysctl -w net.sctp.encap_port=%u\n", OUR_PORT);
        return 0;
    }
    if (!extensions_off(why)) {
        std::printf("Kernel interop: SKIPPED\n  reason: %s\n", why.c_str());
        return 0;
    }
    std::printf("Kernel interop (%s)\n", isolated ? "private network namespace" : "host network namespace");
    auto snmp_before = sctp_snmp();

    int listener = kernel_socket();
    sockaddr_in kaddr = loopback(KERNEL_PORT);
    if (listener < 0 || ::bind(listener, reinterpret_cast<sockaddr*>(&kaddr), sizeof kaddr) != 0
        || ::listen(listener, 4) != 0) {
        std::printf("  [FAIL] kernel listener on %u: %s\n", KERNEL_PORT, std::strerror(errno));
        return 1;
    }

    SCTP_Socket stack;
    stack.sctp_subscribe(Notification_Type::SCTP_REMOTE_ERROR, true);
    if (!stack.sctp_bind("127.0.0.1", OUR_PORT) || !stack.sctp_run()) {
        std::printf("  [FAIL] start our stack on %u\n", OUR_PORT);
        return 1;
    }

    Association_Key key;
    int fd = associate_to_kernel(stack, listener, key);
    if (fd >= 0) {
        phase_handshake(stack, fd);
        phase_small_data(stack, key, fd);
        phase_streams(stack, key, fd);
        phase_fragmentation(stack, key, fd);
        phase_heartbeat(stack, key, fd);
        ::close(fd);
        expect_change(stack, Assoc_Change_State::SHUTDOWN_COMP, "kernel close() after the data phases: SHUTDOWN_COMP");
        await_empty(stack);
    }
    phase_teardowns(stack, listener);
    ::close(listener);
    phase_kernel_initiates(stack);

    stack.sctp_close(1000);

    section("Kernel counters");
    auto snmp_after = sctp_snmp();
    for (const char* name : {"SctpChecksumErrors", "SctpOutOfBlues", "SctpAborteds", "SctpShutdowns",
                             "SctpInCtrlChunks", "SctpInOrderChunks", "SctpInUnorderChunks", "SctpOutCtrlChunks",
                             "SctpRetransChunks", "SctpT3RtxExpireds", "SctpFastRetransmits"}) {
        std::printf("      %-22s %ld\n", name, snmp_after[name] - snmp_before[name]);
    }
    if (isolated) {
        check(snmp_after["SctpChecksumErrors"] == snmp_before["SctpChecksumErrors"], "kernel saw no checksum errors");
        check(snmp_after["SctpOutOfBlues"] == snmp_before["SctpOutOfBlues"], "kernel saw no out-of-the-blue packets");
    }

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}

#endif // _WIN32
