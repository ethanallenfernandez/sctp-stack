// Datagram PLPMTUD (RFC 8899, 6.2 for SCTP and SCTP/UDP), kept per destination
// as RFC 9260 7.3 requires, and the ICMP Packet Too Big messages that feed it
// (RFC 9260 10, RFC 8899 4.6).

#include <sctp/socket.hpp>
#include <sctp/protocol/tsn.hpp>
#include "protocol/builders.hpp"
#include "socket/internal.hpp"

#include <chrono>
#include <mutex>

using namespace plpmtud_parameters;

namespace {
    // MAX_PLPMTU first, then halving the interval between what got through and
    // what did not. 0 once there is nothing left to try.
    uint32_t next_probe_size(const Plpmtud& plpmtud) {
        if (plpmtud.plpmtu >= MAX_PLPMTU) {
            return 0;
        }
        if (plpmtud.search_high > MAX_PLPMTU) {
            return MAX_PLPMTU;
        }
        uint32_t middle = ((plpmtud.plpmtu + plpmtud.search_high) / 2) & ~3U;
        return middle > plpmtud.plpmtu ? middle : 0;
    }

    Expiration_Key probe_timer(const Association_Key& key, const Peer_Path& path) {
        return Expiration_Key{key, Expiration_Timer_Type::PLPMTU_PROBE, path_key(path.udp_address)};
    }

    Expiration_Key raise_timer(const Association_Key& key, const Peer_Path& path) {
        return Expiration_Key{key, Expiration_Timer_Type::PMTU_RAISE, path_key(path.udp_address)};
    }
}

// BASE_PLPMTU is already in use, so the first probe can wait an RTO rather
// than race whatever else the association does first.
void SCTP_Socket::start_plpmtud(const Association_Key& key, Peer_Path& path) {
    if (!path.confirmed || !path.active) {
        return;
    }
    cancel_expiration(raise_timer(key, path));
    path.plpmtud = Plpmtud{};
    path.plpmtud.state = Plpmtud_State::BASE;
    schedule_plpmtu_probe(key, path, path.rto);
}

void SCTP_Socket::stop_plpmtud(const Association_Key& key, Peer_Path& path) {
    path.plpmtud = Plpmtud{};
    cancel_expiration(probe_timer(key, path));
    cancel_expiration(raise_timer(key, path));
}

// The timer sends the probe, so a probe is only ever built in one place.
void SCTP_Socket::schedule_plpmtu_probe(const Association_Key& key, Peer_Path& path, std::chrono::microseconds delay) {
    path.plpmtud.probe_outstanding = false;
    path.plpmtud.probe_count = 0;
    schedule_expiration(probe_timer(key, path), std::chrono::steady_clock::now() + delay);
}

void SCTP_Socket::complete_plpmtu_search(const Association_Key& key, Peer_Path& path) {
    path.plpmtud.state = Plpmtud_State::SEARCH_COMPLETE;
    path.plpmtud.confirming = false;
    path.plpmtud.probe_outstanding = false;
    cancel_expiration(probe_timer(key, path));
    schedule_expiration(raise_timer(key, path), std::chrono::steady_clock::now() + PMTU_RAISE_TIMER);
}

void SCTP_Socket::continue_plpmtu_search(const Association_Key& key, Peer_Path& path) {
    uint32_t next = next_probe_size(path.plpmtud);
    if (next == 0) {
        return complete_plpmtu_search(key, path);
    }
    path.plpmtud.probed_size = next;
    schedule_plpmtu_probe(key, path);
}

// 4.3: losing DATA on a path whose PLPMTU was raised past BASE_PLPMTU may mean
// the path no longer carries packets that large.
void SCTP_Socket::check_for_black_hole(const Association_Key& key, Peer_Path& path) {
    Plpmtud& plpmtud = path.plpmtud;
    if (plpmtud.state != Plpmtud_State::SEARCH_COMPLETE || plpmtud.confirming || plpmtud.plpmtu <= BASE_PLPMTU) {
        return;
    }
    plpmtud.confirming = true;
    plpmtud.probed_size = plpmtud.plpmtu;
    schedule_plpmtu_probe(key, path);
}

Deliverable SCTP_Socket::make_plpmtu_probe(const Association_Key& key, const Association_TCB& assoc, Peer_Path& path) {
    generate_random(path.plpmtud.probe_nonce);
    path.plpmtud.probe_outstanding = true;
    return Deliverable{key, path.udp_address, build_plpmtu_probe(ntohs(local_address.sin_port), assoc.peer.sctp_port,
        assoc.peer.peer_ver_tag, heartbeat_info(path.plpmtud.probe_nonce, path.udp_address), path.plpmtud.probed_size)};
}

void SCTP_Socket::handle_plpmtu_probe_ack(const Association_Key& key, Association_TCB& assoc, Peer_Path& path) {
    Plpmtud& plpmtud = path.plpmtud;
    plpmtud.probe_outstanding = false;
    plpmtud.probe_count = 0;
    plpmtud.plpmtu = plpmtud.probed_size;
    clear_path_errors(key, path);
    if (&data_path(assoc) == &path) {
        assoc.paths.error_count = 0;
    }

    if (plpmtud.confirming) {
        plpmtud.confirming = false;
        cancel_expiration(probe_timer(key, path));
        return;
    }
    plpmtud.state = Plpmtud_State::SEARCHING;
    continue_plpmtu_search(key, path);
}

void SCTP_Socket::handle_plpmtu_probe_expiration(const Association_Key& location, const sockaddr_in& destination) {
    Association_TCB* assoc = find_tcb(location);
    Peer_Path* path = assoc && transmits_data(assoc->state) ? find_path(*assoc, destination) : nullptr;
    if (path == nullptr) {
        return;
    }

    Plpmtud& plpmtud = path->plpmtud;
    if (plpmtud.probe_outstanding) {
        plpmtud.probe_outstanding = false;
        if (++plpmtud.probe_count >= MAX_PROBES) {
            plpmtud.probe_count = 0;
            if (plpmtud.state == Plpmtud_State::BASE) {
                plpmtud.state = Plpmtud_State::ERROR;
                return schedule_expiration(raise_timer(location, *path), std::chrono::steady_clock::now() + PMTU_RAISE_TIMER);
            }
            if (plpmtud.confirming) {
                return start_plpmtud(location, *path);
            }
            plpmtud.search_high = plpmtud.probed_size;
            uint32_t next = next_probe_size(plpmtud);
            if (next == 0) {
                return complete_plpmtu_search(location, *path);
            }
            plpmtud.probed_size = next;
        }
    } else if (plpmtud.state != Plpmtud_State::BASE && plpmtud.state != Plpmtud_State::SEARCHING && !plpmtud.confirming) {
        return;
    }

    enqueue_packet(make_plpmtu_probe(location, *assoc, *path));
    schedule_expiration(probe_timer(location, *path), std::chrono::steady_clock::now() + PROBE_TIMER);
}

void SCTP_Socket::handle_pmtu_raise_expiration(const Association_Key& location, const sockaddr_in& destination) {
    Association_TCB* assoc = find_tcb(location);
    Peer_Path* path = assoc && transmits_data(assoc->state) ? find_path(*assoc, destination) : nullptr;
    if (path == nullptr) {
        return;
    }

    Plpmtud& plpmtud = path->plpmtud;
    if (plpmtud.state == Plpmtud_State::ERROR) {
        start_plpmtud(location, *path);
        return;
    }
    if (plpmtud.state != Plpmtud_State::SEARCH_COMPLETE || plpmtud.confirming) {
        return;
    }
    plpmtud.state = Plpmtud_State::SEARCHING;
    plpmtud.search_high = MAX_PLPMTU + 1;
    continue_plpmtu_search(location, *path);
}

// quoted starts at the SCTP common header of the packet the PTB answers. A
// Verification Tag of 0 would be an INIT's, and no association runs DPLPMTUD
// before it is established.
void SCTP_Socket::handle_icmp_ptb(const sockaddr_in& destination, const uint8_t* quoted, size_t length, uint32_t ptb_size) {
    if (length < 8 || ptb_size <= IPV4_HEADER_SIZE) {
        return;
    }
    uint16_t peer_sctp_port = static_cast<uint16_t>(quoted[2] << 8 | quoted[3]);
    uint32_t tag = read_be32(quoted + 4);

    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    Association_Key key = association_at(peer_key(destination, peer_sctp_port));
    Association_TCB* assoc = find_tcb(key);
    Peer_Path* path = assoc && tag != 0 && tag == assoc->peer.peer_ver_tag ? find_path(*assoc, destination) : nullptr;
    if (path == nullptr || path->plpmtud.state == Plpmtud_State::DISABLED) {
        return;
    }

    Plpmtud& plpmtud = path->plpmtud;
    uint32_t pl_ptb_size = ptb_size - static_cast<uint32_t>(IPV4_HEADER_SIZE);
    uint32_t aligned = pl_ptb_size & ~3U;
    if (pl_ptb_size < MIN_PLPMTU || pl_ptb_size >= plpmtud.probed_size) {
        return;
    }
    if (pl_ptb_size < BASE_PLPMTU) {
        cancel_expiration(probe_timer(key, *path));
        plpmtud = Plpmtud{};
        plpmtud.state = Plpmtud_State::ERROR;
        schedule_expiration(raise_timer(key, *path), std::chrono::steady_clock::now() + PMTU_RAISE_TIMER);
        return;
    }
    if (pl_ptb_size < plpmtud.plpmtu) {
        cancel_expiration(raise_timer(key, *path));
        plpmtud.plpmtu = BASE_PLPMTU;
        plpmtud.state = Plpmtud_State::SEARCHING;
        plpmtud.confirming = false;
        plpmtud.search_high = aligned + 4;
        plpmtud.probed_size = aligned;
        schedule_plpmtu_probe(key, *path);
        return;
    }
    if (plpmtud.state != Plpmtud_State::SEARCHING) {
        return;
    }
    plpmtud.search_high = aligned + 4;
    if (aligned <= plpmtud.plpmtu) {
        complete_plpmtu_search(key, *path);
        return;
    }
    plpmtud.probed_size = aligned;
    schedule_plpmtu_probe(key, *path);
}

void SCTP_Socket::run_icmp_errors(sctp_socket_t socket) {
#ifdef __linux__
    for (size_t received = 0; received < MAX_RECEIVE_BATCH; ++received) {
        uint8_t quoted[64];
        sockaddr_in destination{};
        alignas(cmsghdr) char control[256];
        iovec vector{quoted, sizeof(quoted)};
        msghdr message{};
        message.msg_name = &destination;
        message.msg_namelen = sizeof(destination);
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        message.msg_control = control;
        message.msg_controllen = sizeof(control);
        ssize_t length = recvmsg(socket, &message, MSG_ERRQUEUE | MSG_DONTWAIT);
        if (length < 0) {
            return;
        }
        for (cmsghdr* header = CMSG_FIRSTHDR(&message); header != nullptr; header = CMSG_NXTHDR(&message, header)) {
            if (header->cmsg_level != IPPROTO_IP || header->cmsg_type != IP_RECVERR) {
                continue;
            }
            const auto* error = reinterpret_cast<const sock_extended_err*>(CMSG_DATA(header));
            if (error->ee_origin == SO_EE_ORIGIN_ICMP && error->ee_type == ICMP_DEST_UNREACH && error->ee_code == ICMP_FRAG_NEEDED) {
                handle_icmp_ptb(destination, quoted, static_cast<size_t>(length), error->ee_info);
            }
        }
    }
#endif
}
