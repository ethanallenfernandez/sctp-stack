#ifndef SCTP_SOCKET_INTERNAL_HPP
#define SCTP_SOCKET_INTERNAL_HPP

// Constants and helpers shared between the src/socket translation units.

#include <sctp/protocol/association.hpp>
#include <sctp/queues/expiration_queue.hpp>
#include <sctp/protocol/sctp.hpp>
#include <sctp/platform/compat.hpp>
#include "protocol/builders.hpp"
#include "protocol/serialize.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ranges>
#include <unordered_map>
#include <vector>

constexpr std::chrono::microseconds CLOCK_GRANULARITY{1000};
constexpr std::chrono::milliseconds T5_SHUTDOWN_GUARD = 5 * sctp_parameters::RTO_MAX;
constexpr std::chrono::milliseconds SEND_RETRY_DELAY{10};
constexpr std::chrono::milliseconds CLOSE_POLL_INTERVAL{10};
// Time given to the last SHUTDOWN COMPLETE or ABORT to reach the wire.
constexpr std::chrono::milliseconds CLOSE_DRAIN_TIMEOUT{100};
constexpr uint32_t SLOW_START_INCREASE_PMDCS = 1;
constexpr size_t ACKED_RETRANSMISSION_MEMORY = 64;
constexpr size_t MAX_RECEIVE_BATCH = 64;
constexpr size_t MAX_UDP_DATAGRAM = 65535;
constexpr size_t MAX_SEND_BATCH = 64;
// Unsent bytes an association queues before refusing more. A message is taken
// whatever its size when nothing is queued.
constexpr size_t SEND_BUFFER = 256 * 1024;
constexpr uint8_t DATA_IMMEDIATE_SACK_FLAG = 0x08;
// New INITs sent in answer to Stale Cookie errors before giving up.
constexpr uint8_t MAX_STALE_COOKIE_RETRIES = 2;

inline constexpr uint32_t pmdcs_of(uint32_t plpmtu) {
    return plpmtu - static_cast<uint32_t>(UDP_HEADER_SIZE + SCTP_COMMON_HEADER_SIZE);
}

constexpr uint32_t BASE_PMDCS = pmdcs_of(plpmtud_parameters::BASE_PLPMTU);

inline uint32_t pmdcs(const Peer_Path& path) {
    return pmdcs_of(path.plpmtud.plpmtu);
}

inline uint32_t initial_cwnd(uint32_t pmdcs) {
    return std::min(4U * pmdcs, std::max(2U * pmdcs, 4404U));
}

// The peer's SCTP port is the association's, so within one association a
// destination is its IP address alone. The UDP port beside it is only where
// encapsulated packets for it go.
inline bool same_destination(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_addr.s_addr == b.sin_addr.s_addr;
}

inline Peer_Key path_key(const sockaddr_in& address) {
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_addr = address.sin_addr;
    return Peer_Key{destination};
}

inline Peer_Key peer_key(const sockaddr_in& address, uint16_t sctp_port) {
    Peer_Key key = path_key(address);
    key.sctp_address.sin_port = htons(sctp_port);
    return key;
}

// The datagram this thread is handling. A reply to it leaves from the address
// it arrived at, which is the one its sender knows, TCB or not.
struct Inbound_Datagram {
    sockaddr_in src;
    in_addr local;
};
inline thread_local const Inbound_Datagram* inbound_datagram = nullptr;

inline Peer_Path* find_path(Association_TCB& assoc, const sockaddr_in& address) {
    auto path = std::ranges::find_if(assoc.paths.list, [&](const Peer_Path& candidate) {
        return same_destination(candidate.udp_address, address);
    });
    return path == assoc.paths.list.end() ? nullptr : &*path;
}

inline const Peer_Path* find_path(const Association_TCB& assoc, const sockaddr_in& address) {
    return find_path(const_cast<Association_TCB&>(assoc), address);
}

inline Peer_Path& primary(Association_TCB& assoc) {
    Peer_Path* path = find_path(assoc, assoc.paths.primary);
    return path != nullptr ? *path : assoc.paths.list.front();
}

inline const Peer_Path& primary(const Association_TCB& assoc) {
    return primary(const_cast<Association_TCB&>(assoc));
}

inline void back_off(Peer_Path& path) {
    path.rto = std::min<std::chrono::microseconds>(path.rto * 2, sctp_parameters::RTO_MAX);
}

inline Peer_Path make_path(const sockaddr_in& address, bool confirmed) {
    Peer_Path path{address, confirmed};
    path.cwnd = initial_cwnd(pmdcs(path));
    path.ssthresh = RWND;
    return path;
}

// The smallest PMDCS over the destinations DATA can go to, so a chunk
// retransmitted to an alternate still fits.
inline uint32_t amdcs(const Association_TCB& assoc) {
    uint32_t smallest = 0;
    for (const Peer_Path& path : assoc.paths.list) {
        if (path.confirmed && path.active && (smallest == 0 || pmdcs(path) < smallest)) {
            smallest = pmdcs(path);
        }
    }
    return smallest == 0 ? BASE_PMDCS : smallest;
}

// New DATA goes to the primary while it is active, and otherwise to one
// alternate, the first active CONFIRMED path.
inline Peer_Path& data_path(Association_TCB& assoc) {
    Peer_Path& preferred = primary(assoc);
    if (preferred.active) {
        return preferred;
    }
    auto alternate = std::ranges::find_if(assoc.paths.list, [](const Peer_Path& path) {
        return path.confirmed && path.active;
    });
    return alternate == assoc.paths.list.end() ? preferred : *alternate;
}

inline const Peer_Path& data_path(const Association_TCB& assoc) {
    return data_path(const_cast<Association_TCB&>(assoc));
}

// Timed-out DATA goes to an active CONFIRMED path other than the one it
// was last sent to, the next such in list order, if there is one.
inline Peer_Path& retransmission_path(Association_TCB& assoc, const sockaddr_in& last) {
    Peer_Path& preferred = data_path(assoc);
    if (!same_destination(preferred.udp_address, last)) {
        return preferred;
    }
    auto& paths = assoc.paths.list;
    size_t from = static_cast<size_t>(&preferred - paths.data());
    for (size_t step = 1; step < paths.size(); ++step) {
        Peer_Path& candidate = paths[(from + step) % paths.size()];
        if (candidate.confirmed && candidate.active) {
            return candidate;
        }
    }
    return preferred;
}

inline Peer_Path& destination_of(Association_TCB& assoc, const Outstanding_Data& outstanding) {
    Peer_Path* path = find_path(assoc, outstanding.destination);
    return path != nullptr ? *path : primary(assoc);
}

inline const Peer_Path& destination_of(const Association_TCB& assoc, const Outstanding_Data& outstanding) {
    return destination_of(const_cast<Association_TCB&>(assoc), outstanding);
}

// Paths awaiting confirmation are probed every RTO, HB.Max.Burst of them at a
// time in list order; the rest wait for one of those to confirm or fail.
inline bool probes_for_confirmation(const Association_TCB& assoc, const Peer_Path& path) {
    uint32_t ahead = 0;
    for (const Peer_Path& candidate : assoc.paths.list) {
        bool probing = !candidate.confirmed && candidate.active && candidate.hb_enabled;
        if (&candidate == &path) {
            return probing && ahead < sctp_parameters::HB_MAX_BURST;
        }
        ahead += probing;
    }
    return false;
}

// A reply goes back where its packet came from, unless that address is UNCONFIRMED.
inline sockaddr_in reply_destination(const Association_TCB& assoc, const sockaddr_in& src) {
    const Peer_Path* path = find_path(assoc, src);
    return path != nullptr && path->confirmed ? src : data_path(assoc).udp_address;
}

// The INIT's source, which the INIT ACK carrying the cookie was sent to.
inline sockaddr_in cookie_source(const State_Cookie& cookie) {
    sockaddr_in source{};
    source.sin_family = AF_INET;
    source.sin_addr.s_addr = htonl(cookie.peer_ipv4);
    source.sin_port = htons(cookie.peer_udp_port);
    return source;
}

inline Peer_Key cookie_key(const State_Cookie& cookie) {
    return peer_key(cookie_source(cookie), cookie.sctp_src_port);
}

inline bool has_unacknowledged_data(const Association_TCB& assoc, const Peer_Path& path) {
    return std::ranges::any_of(assoc.send.outstanding | std::views::values, [&](const Outstanding_Data& outstanding) {
        return !outstanding.gap_acked && &destination_of(assoc, outstanding) == &path;
    });
}

inline size_t bytes_in_flight(const Association_TCB& assoc, const Peer_Path* path = nullptr) {
    size_t total = 0;
    for (const auto& [tsn, outstanding] : assoc.send.outstanding) {
        if (!outstanding.gap_acked && !outstanding.pending_retransmission
                && (path == nullptr || &destination_of(assoc, outstanding) == path)) {
            total += data_chunk_wire_size(outstanding.data);
        }
    }
    return total;
}

inline bool cwnd_open(const Association_TCB& assoc, const Peer_Path& path) {
    size_t flight = bytes_in_flight(assoc, &path);
    return path.single_packet_in_flight ? flight == 0 : flight < path.cwnd;
}

inline bool is_forming(Association_State state) {
    return state == COOKIE_WAIT || state == COOKIE_ECHOED;
}

inline bool transmits_data(Association_State state) {
    return state == ESTABLISHED || state == SHUTDOWN_PENDING || state == SHUTDOWN_RECEIVED;
}

inline bool receives_data(Association_State state) {
    return state == ESTABLISHED || state == SHUTDOWN_PENDING || state == SHUTDOWN_SENT;
}

// The Heartbeat Info is ours to define: the nonce, then the destination's
// address and UDP port as they sit in sockaddr_in. The send time is not in
// here: the path records it after sendto, which is both more accurate and not
// something the peer can forge.
constexpr size_t HEARTBEAT_INFO_SIZE = 14;

inline std::vector<uint8_t> heartbeat_info(uint64_t nonce, const sockaddr_in& destination) {
    std::vector<uint8_t> info = be32_bytes(static_cast<uint32_t>(nonce >> 32));
    info.append_range(be32_bytes(static_cast<uint32_t>(nonce)));
    const uint8_t* address = reinterpret_cast<const uint8_t*>(&destination.sin_addr.s_addr);
    info.insert(info.end(), address, address + sizeof(destination.sin_addr.s_addr));
    const uint8_t* port = reinterpret_cast<const uint8_t*>(&destination.sin_port);
    info.insert(info.end(), port, port + sizeof(destination.sin_port));
    return info;
}

inline uint64_t heartbeat_info_nonce(const std::vector<uint8_t>& info) {
    return static_cast<uint64_t>(read_be32(info.data())) << 32 | read_be32(info.data() + 4);
}

inline sockaddr_in heartbeat_info_destination(const std::vector<uint8_t>& info) {
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    std::copy_n(info.data() + 8, sizeof(destination.sin_addr.s_addr), reinterpret_cast<uint8_t*>(&destination.sin_addr.s_addr));
    std::copy_n(info.data() + 12, sizeof(destination.sin_port), reinterpret_cast<uint8_t*>(&destination.sin_port));
    return destination;
}

inline error_cause invalid_stream_cause(uint16_t stream_id) {
    return error_cause{CAUSE_INVALID_STREAM_ID, {static_cast<uint8_t>(stream_id >> 8), static_cast<uint8_t>(stream_id), 0, 0}};
}

inline error_cause stale_cookie_cause(uint32_t staleness_us) {
    return error_cause{CAUSE_STALE_COOKIE, be32_bytes(staleness_us)};
}

template <typename T>
inline auto generate_random(T& input) -> decltype(input) {
    random_bytes(reinterpret_cast<uint8_t*>(&input), sizeof(input));
    return input;
}

// 0 also means "no Tie-Tag" in a cookie, so Tie-Tags are drawn nonzero too.
inline uint32_t generate_nonzero_tag() {
    uint32_t tag;
    do {
        generate_random(tag);
    } while (tag == 0);
    return tag;
}
#endif
