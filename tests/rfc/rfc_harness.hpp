#ifndef SCTP_RFC_HARNESS_HPP
#define SCTP_RFC_HARNESS_HPP

// In-process harness for the RFC conformance tests (tests/rfc*.cpp). Packets
// from the peer are built here and handed to handle_recv_packet; what the
// stack sends is taken off its send queue through next_packet/packet_sent,
// which is run_sending without the sendto, so timers are armed as on the wire.
// Timers are fired by draining the expiration heap, not by waiting.
//
// Every check names the requirement it covers, an ID from
// tests/rfc_requirements.md: <RFC>-<section>-<n>, the n-th sentence of that
// section using requirements language.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "builders.hpp"
#include "checksum.hpp"
#include "serialize.hpp"
#include "socket_internal.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace rfc {

using Clock = std::chrono::steady_clock;

constexpr uint16_t LOCAL_PORT = 9899;
constexpr uint16_t PEER_PORT = 40000;
constexpr uint32_t PEER_TAG = 0x11223344;
constexpr uint32_t PEER_TSN = 5000;
constexpr uint32_t OUR_TAG = 0x0A0B0C0D;
constexpr uint32_t OUR_TSN = 1000;
constexpr const char* PEER_IP = "127.0.0.1";

inline int failures = 0;
inline int checks = 0;

// One check of one requirement.
inline void req(const char* id, bool ok, const std::string& what) {
    ++checks;
    std::printf("  [%s] %-16s %s\n", ok ? "PASS" : "FAIL", id, what.c_str());
    if (!ok) {
        ++failures;
    }
}

inline void section(const char* title) {
    std::printf("%s\n", title);
}

inline int summary(const char* name) {
    std::printf("\n%s: %d of %d checks passed\n", name, checks - failures, checks);
    return failures == 0 ? 0 : 1;
}

inline sockaddr_in addr(const char* ip = PEER_IP, uint16_t port = PEER_PORT) {
    sockaddr_in out{};
    out.sin_family = AF_INET;
    out.sin_port = htons(port);
    sctp_parse_ipv4(ip, out.sin_addr);
    return out;
}

inline Association_Key key(const char* ip = PEER_IP, uint16_t port = PEER_PORT) {
    return Association_Key{addr(ip, port)};
}

inline in_addr ipv4(const char* ip) {
    in_addr out{};
    sctp_parse_ipv4(ip, out);
    return out;
}

// A packet from the peer to us under tag.
inline SCTP_Packet packet(uint32_t tag, std::vector<SCTP_Chunk> chunks = {}) {
    SCTP_Packet out;
    out.header = {PEER_PORT, LOCAL_PORT, tag, 0};
    out.chunks = std::move(chunks);
    return out;
}

inline SCTP_Chunk chunk(Chunk_Type type, Chunk_Value_Type value, uint8_t flags = 0) {
    return SCTP_Chunk{{type, flags, 0}, std::move(value)};
}

inline data_chunk_value data(uint32_t tsn, std::vector<uint8_t> bytes = {'d'}, uint8_t flags = DATA_FLAG_B | DATA_FLAG_E,
                             uint16_t stream = 0, uint16_t ssn = 0, uint32_t ppid = 0) {
    data_chunk_value out{tsn, stream, ssn, ppid, std::move(bytes)};
    out.flags = flags;
    return out;
}

inline SCTP_Chunk data_chunk(const data_chunk_value& value, uint8_t extra_flags = 0) {
    return chunk(DATA, value, static_cast<uint8_t>(value.flags | extra_flags));
}

inline SCTP_Chunk sack_chunk(uint32_t cumulative, uint32_t a_rwnd = RWND, std::vector<sack_gap_ack_block> gaps = {},
                             std::vector<uint32_t> duplicates = {}) {
    return chunk(SACK, sack_chunk_value{cumulative, a_rwnd, std::move(gaps), std::move(duplicates)});
}

inline init_chunk_value init_value(uint32_t tag = PEER_TAG, uint32_t tsn = PEER_TSN, uint32_t a_rwnd = RWND,
                                   uint16_t os = 10, uint16_t mis = 10, std::vector<uint8_t> params = {}) {
    return init_chunk_value{tag, a_rwnd, os, mis, tsn, std::move(params)};
}

inline std::vector<uint8_t> parameter(uint16_t type, std::vector<uint8_t> value) {
    std::vector<uint8_t> out;
    append_parameter(out, type, value.data(), value.size());
    return out;
}

inline std::vector<uint8_t> ipv4_parameter(const char* ip) {
    in_addr address = ipv4(ip);
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&address.s_addr);
    return parameter(PARAM_IPV4_ADDRESS, {bytes, bytes + 4});
}

inline std::vector<uint8_t> concat(std::initializer_list<std::vector<uint8_t>> parts) {
    std::vector<uint8_t> out;
    for (const auto& part : parts) {
        out.insert(out.end(), part.begin(), part.end());
    }
    return out;
}

inline const SCTP_Chunk* find_chunk(const SCTP_Packet& p, Chunk_Type type) {
    for (const auto& c : p.chunks) {
        if (c.chunk_header.type == type) {
            return &c;
        }
    }
    return nullptr;
}

template <typename T>
inline const T* find_value(const SCTP_Packet& p, Chunk_Type type) {
    const SCTP_Chunk* c = find_chunk(p, type);
    return c ? std::get_if<T>(&c->chunk_value) : nullptr;
}

inline bool has_cause(const SCTP_Packet& p, Chunk_Type type, uint16_t code) {
    const auto* v = find_value<error_chunk_value>(p, type);
    return v && std::any_of(v->causes.begin(), v->causes.end(), [&](const error_cause& c) { return c.code == code; });
}

inline bool only(const SCTP_Packet& p, Chunk_Type type) {
    return p.chunks.size() == 1 && p.chunks[0].chunk_header.type == type;
}

struct Sent {
    std::vector<Deliverable> out;

    size_t size() const { return out.size(); }
    bool empty() const { return out.empty(); }
    const SCTP_Packet& operator[](size_t i) const { return out[i].packet; }

    // The first packet carrying type, if any. Not on a temporary: the pointer
    // would outlive it.
    const Deliverable* with(Chunk_Type type) const&& = delete;
    const Deliverable* with(Chunk_Type type) const& {
        for (const auto& d : out) {
            if (find_chunk(d.packet, type)) {
                return &d;
            }
        }
        return nullptr;
    }
    bool any(Chunk_Type type) const { return static_cast<const Sent&>(*this).with(type) != nullptr; }
    std::vector<const Deliverable*> all(Chunk_Type type) const&& = delete;
    std::vector<const Deliverable*> all(Chunk_Type type) const& {
        std::vector<const Deliverable*> found;
        for (const auto& d : out) {
            if (find_chunk(d.packet, type)) {
                found.push_back(&d);
            }
        }
        return found;
    }
    size_t count(Chunk_Type type) const {
        size_t n = 0;
        for (const auto& d : out) {
            for (const auto& c : d.packet.chunks) {
                n += c.chunk_header.type == type;
            }
        }
        return n;
    }
    std::vector<data_chunk_value> data() const {
        std::vector<data_chunk_value> chunks;
        for (const auto& d : out) {
            for (const auto& c : d.packet.chunks) {
                if (c.chunk_header.type == DATA) {
                    chunks.push_back(std::get<data_chunk_value>(c.chunk_value));
                }
            }
        }
        return chunks;
    }
};

} // namespace rfc

struct SCTP_Socket_Test_Access {
    static void setup(SCTP_Socket& s) {
        s.local_address = rfc::addr("127.0.0.1", rfc::LOCAL_PORT);
    }

    static Association* tcb(SCTP_Socket& s, const Association_Key& k = rfc::key()) {
        auto it = s.associations.find(k);
        return it == s.associations.end() ? nullptr : &it->second;
    }

    static size_t association_count(SCTP_Socket& s) {
        return s.associations.size();
    }

    // A TCB as the handshake would leave it, without running the handshake.
    // Extra addresses are CONFIRMED and active.
    static Association& establish(SCTP_Socket& s, Association_State state = ESTABLISHED,
                                  std::vector<const char*> others = {}, uint32_t peer_rwnd = RWND) {
        setup(s);
        Association_Key k = rfc::key();
        Association assoc = s.init_new_association(k.address);
        assoc.state = state;
        assoc.this_ver_tag = rfc::OUR_TAG;
        assoc.peer_ver_tag = rfc::PEER_TAG;
        assoc.next_tsn = rfc::OUR_TSN;
        assoc.cumulative_tsn_ack = rfc::OUR_TSN - 1;
        assoc.last_peer_tsn = rfc::PEER_TSN - 1;
        assoc.peer_rwnd = peer_rwnd;
        assoc.peer_max_rwnd = peer_rwnd;
        assoc.out_streams = 10;
        assoc.in_streams = 10;
        assoc.next_ssn.assign(10, 0);
        auto& tcb = s.associations.insert_or_assign(k, assoc).first->second;
        std::vector<sockaddr_in> addresses;
        for (const char* ip : others) {
            addresses.push_back(rfc::addr(ip));
        }
        s.add_peer_addresses(k, tcb, addresses);
        for (Peer_Path& path : tcb.peer_address_list) {
            path.confirmed = true;
            path.data_sent_at = rfc::Clock::now();
        }
        return tcb;
    }

    static void receive_wire(SCTP_Socket& s, std::vector<uint8_t> wire, const sockaddr_in& src = rfc::addr(),
                             in_addr local = rfc::ipv4("127.0.0.1")) {
        s.handle_recv_packet(wire.data(), wire.size(), src, local);
    }

    static void receive(SCTP_Socket& s, const SCTP_Packet& p, const sockaddr_in& src = rfc::addr(),
                        in_addr local = rfc::ipv4("127.0.0.1")) {
        receive_wire(s, serialize_sctp_packet(p), src, local);
    }

    // Everything the stack would put on the wire now, in order, windows applied.
    static rfc::Sent sent(SCTP_Socket& s) {
        rfc::Sent result;
        for (int pass = 0; pass < 64; ++pass) {
            s.start_transmission_opportunity();
            bool any = false;
            while (auto pending = s.next_packet()) {
                s.packet_sent(*pending);
                result.out.push_back(pending->deliverable);
                any = true;
            }
            if (!any) {
                break;
            }
        }
        return result;
    }

    // One transmission opportunity only.
    static rfc::Sent sent_once(SCTP_Socket& s) {
        rfc::Sent result;
        s.start_transmission_opportunity();
        while (auto pending = s.next_packet()) {
            s.packet_sent(*pending);
            result.out.push_back(pending->deliverable);
        }
        return result;
    }

    static Expiration_Key timer(const Association_Key& k, Expiration_Timer_Type type, const char* ip = nullptr) {
        return Expiration_Key{k, type, ip ? path_key(rfc::addr(ip)) : Association_Key{}};
    }

    static bool armed(SCTP_Socket& s, Expiration_Timer_Type type, const char* ip = nullptr, const Association_Key& k = rfc::key()) {
        return s.expirations.is_active(timer(k, type, ip));
    }

    // The running timer's generation, 0 if none: a restart changes it.
    static uint64_t generation(SCTP_Socket& s, Expiration_Timer_Type type, const char* ip = nullptr, const Association_Key& k = rfc::key()) {
        auto live = s.expirations.active.find(timer(k, type, ip));
        return live == s.expirations.active.end() ? 0 : live->second;
    }

    // Time until the timer would fire, or nullopt if it is not running.
    static std::optional<std::chrono::milliseconds> remaining(SCTP_Socket& s, Expiration_Timer_Type type, const char* ip = nullptr,
                                                              const Association_Key& k = rfc::key()) {
        Expiration_Key wanted = timer(k, type, ip);
        auto live = s.expirations.active.find(wanted);
        if (live == s.expirations.active.end()) {
            return std::nullopt;
        }
        std::optional<std::chrono::milliseconds> result;
        std::vector<Expiration_Fallback> kept;
        while (!s.expirations.queue.empty()) {
            kept.push_back(s.expirations.queue.top());
            s.expirations.queue.pop();
        }
        for (const auto& entry : kept) {
            if (entry.key == wanted && entry.generation == live->second) {
                result = std::chrono::duration_cast<std::chrono::milliseconds>(entry.expiration - rfc::Clock::now());
            }
            s.expirations.queue.push(entry);
        }
        return result;
    }

    // Fires the running timer of this type (on this path), as if its time had
    // come, leaving every other timer as it was. False if none was running.
    static bool fire(SCTP_Socket& s, Expiration_Timer_Type type, const char* ip = nullptr, const Association_Key& k = rfc::key()) {
        Expiration_Key wanted = timer(k, type, ip);
        auto live = s.expirations.active.find(wanted);
        if (live == s.expirations.active.end()) {
            return false;
        }
        std::optional<Expiration_Fallback> target;
        std::vector<Expiration_Fallback> kept;
        while (!s.expirations.queue.empty()) {
            Expiration_Fallback entry = s.expirations.queue.top();
            s.expirations.queue.pop();
            if (entry.key == wanted && entry.generation == live->second) {
                target = entry;
            } else {
                kept.push_back(entry);
            }
        }
        for (auto& entry : kept) {
            s.expirations.queue.push(entry);
        }
        if (!target) {
            return false;
        }
        s.expirations.active.erase(wanted);
        s.handle_expiration(*target);
        return true;
    }

    static std::vector<Notification> notifications(SCTP_Socket& s) {
        std::vector<Notification> out;
        while (auto n = s.notifications.dequeue()) {
            out.push_back(*n);
        }
        return out;
    }

    static bool notified(const std::vector<Notification>& ns, Assoc_Change_State state) {
        return std::any_of(ns.begin(), ns.end(), [&](const Notification& n) {
            const auto* c = std::get_if<Assoc_Change>(&n.payload);
            return c && c->state == state;
        });
    }

    static bool notified(const std::vector<Notification>& ns, Peer_Addr_State state) {
        return std::any_of(ns.begin(), ns.end(), [&](const Notification& n) {
            const auto* c = std::get_if<Peer_Addr_Change>(&n.payload);
            return c && c->state == state;
        });
    }

    // sctp_associate without an event loop running.
    static Association_Key associate(SCTP_Socket& s, const char* ip = rfc::PEER_IP) {
        setup(s);
        Association_Key k{};
        s.running.store(true);
        s.sctp_associate(ip, rfc::PEER_PORT, k);
        s.running.store(false);
        return k;
    }

    // We initiate: INIT out, INIT ACK in, COOKIE ECHO out, COOKIE ACK in.
    // Returns what was sent at each step.
    struct Initiated {
        Association_Key key;
        rfc::Sent init;
        rfc::Sent echo;
        rfc::Sent after_ack;
    };
    static Initiated initiate(SCTP_Socket& s, std::vector<uint8_t> init_ack_params = {}, bool finish = true) {
        Initiated r;
        r.key = associate(s);
        r.init = sent(s);
        const auto* init = r.init.empty() ? nullptr : rfc::find_value<init_chunk_value>(r.init[0], INIT);
        if (!init) {
            return r;
        }
        std::vector<uint8_t> params = init_ack_params.empty()
            ? rfc::parameter(PARAM_STATE_COOKIE, std::vector<uint8_t>(32, 0xC0)) : init_ack_params;
        receive(s, rfc::packet(init->initiate_tag, {rfc::chunk(INIT_ACK, rfc::init_value(rfc::PEER_TAG, rfc::PEER_TSN, RWND, 10, 10, params))}));
        r.echo = sent(s);
        if (finish) {
            receive(s, rfc::packet(init->initiate_tag, {rfc::chunk(COOKIE_ACK, empty_chunk_value{})}));
            r.after_ack = sent(s);
        }
        return r;
    }

    // The peer initiates: INIT in, INIT ACK out, COOKIE ECHO in (with any
    // bundled chunks), COOKIE ACK out.
    struct Responded {
        rfc::Sent init_ack;
        std::vector<uint8_t> cookie;
        uint32_t our_tag{0};
        rfc::Sent cookie_ack;
    };
    static Responded respond(SCTP_Socket& s, init_chunk_value init = rfc::init_value(), std::vector<SCTP_Chunk> bundled = {},
                             const sockaddr_in& src = rfc::addr()) {
        setup(s);
        Responded r;
        receive(s, rfc::packet(0, {rfc::chunk(INIT, init)}), src);
        r.init_ack = sent(s);
        const auto* ack = r.init_ack.empty() ? nullptr : rfc::find_value<init_chunk_value>(r.init_ack[0], INIT_ACK);
        if (!ack) {
            return r;
        }
        r.our_tag = ack->initiate_tag;
        find_parameter(ack->optional_parameters, PARAM_STATE_COOKIE, r.cookie);
        std::vector<SCTP_Chunk> chunks{rfc::chunk(COOKIE_ECHO, cookie_echo_chunk_value{r.cookie})};
        chunks.insert(chunks.end(), bundled.begin(), bundled.end());
        receive(s, rfc::packet(r.our_tag, chunks), src);
        r.cookie_ack = sent(s);
        return r;
    }

    // Our next new DATA: queued by the ULP, cut when windows allow.
    static Sctp_Status send(SCTP_Socket& s, std::vector<uint8_t> bytes, uint16_t stream = 0, bool unordered = false, uint32_t ppid = 0) {
        return s.sctp_send_data(rfc::key(), bytes, stream, unordered, ppid);
    }

    static size_t read(SCTP_Socket& s, std::vector<uint8_t>& buffer, bool* partial = nullptr, uint16_t* stream = nullptr) {
        return s.sctp_recv_data_from(rfc::key(), buffer, partial, stream);
    }

    static Cookie_Auth& cookies(SCTP_Socket& s) {
        return s.cookie_authorizer;
    }

    static uint32_t receive_window(SCTP_Socket& s) {
        Association* a = tcb(s);
        return a ? s.receive_window(rfc::key(), *a) : 0;
    }

    static void handle_icmp_ptb(SCTP_Socket& s, const sockaddr_in& to, const std::vector<uint8_t>& quoted, uint32_t mtu) {
        s.handle_icmp_ptb(to, quoted.data(), quoted.size(), mtu);
    }

    static Sctp_Status associate_status(SCTP_Socket& s, const char* ip = rfc::PEER_IP) {
        Association_Key k{};
        s.running.store(true);
        Sctp_Status status = s.sctp_associate(ip, rfc::PEER_PORT, k);
        s.running.store(false);
        return status;
    }

    static bool bound_ports_match(SCTP_Socket& s) {
        for (const auto& other : s.other_local_addresses) {
            if (other.address.sin_port != s.local_address.sin_port) {
                return false;
            }
        }
        return !s.other_local_addresses.empty() && s.local_address.sin_port != 0;
    }

    static Peer_Path* path(SCTP_Socket& s, const char* ip, const Association_Key& k = rfc::key()) {
        Association* a = tcb(s, k);
        return a ? find_path(*a, rfc::addr(ip)) : nullptr;
    }

    static bool data_path_is(SCTP_Socket& s, const char* ip) {
        Association* a = tcb(s);
        return a && same_destination(data_path(*a).address, rfc::addr(ip));
    }

    static void start_heartbeats_for(SCTP_Socket& s, const Association_Key& k = rfc::key()) {
        s.start_heartbeats(k, *tcb(s, k));
    }

    static void schedule_retransmission(SCTP_Socket& s) {
        s.schedule_pending_retransmission(rfc::key());
    }

    // Real sockets, for what only the kernel can produce: ICMP errors and UDP headers.
    static bool bind_real(SCTP_Socket& s, uint16_t port = rfc::LOCAL_PORT) {
        return s.sctp_bind("127.0.0.1", port);
    }

    static void flush(SCTP_Socket& s) {
        s.run_sending();
    }

    static void raw_send(SCTP_Socket& s, const SCTP_Packet& p, const sockaddr_in& to) {
        std::vector<uint8_t> w = serialize_sctp_packet(p);
        sendto(s.udp_socket, reinterpret_cast<const char*>(w.data()), w.size(), 0, reinterpret_cast<const sockaddr*>(&to), sizeof(to));
    }

    // Waits up to timeout for an ICMP error on the socket, then hands it to the stack.
    static void icmp(SCTP_Socket& s, std::chrono::milliseconds timeout = std::chrono::milliseconds(200)) {
        auto deadline = rfc::Clock::now() + timeout;
        while (rfc::Clock::now() < deadline) {
            sctp_pollfd fd{};
            fd.fd = s.udp_socket;
            fd.events = 0;
            if (sctp_poll(&fd, 1, 10) > 0 && (fd.revents & SCTP_POLL_ERROR)) {
                break;
            }
        }
        s.run_icmp_errors(s.udp_socket);
    }

    static void close_associations(SCTP_Socket& s) {
        s.close_associations();
    }

    static void decay(SCTP_Socket& s) {
        s.send_allowances();
    }

    static std::vector<in_addr> advertised(SCTP_Socket& s) {
        return s.advertised_addresses();
    }

    static void add_local(SCTP_Socket& s, const char* ip) {
        s.other_local_addresses.push_back({rfc::addr(ip, rfc::LOCAL_PORT), INVALID_SOCKET});
    }
};

namespace rfc {
using Access = SCTP_Socket_Test_Access;
} // namespace rfc

#endif
