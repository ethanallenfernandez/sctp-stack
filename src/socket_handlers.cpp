// Inbound chunk handling: packet validation and dispatch, the four-way
// handshake (RFC 9260 5.1), SACK processing and fast retransmit (6.2, 7.2.4),
// SACK generation with gap ack blocks (3.3.4), and DATA reception with the
// out-of-order buffer and reassembly.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include <sctp/utils.hpp>
#include "checksum.hpp"
#include "serialize.hpp"
#include "builders.hpp"
#include "socket_internal.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iterator>
#include <mutex>
#include <stdexcept>
#include <vector>

namespace {
    // User data held back from the ULP: for reordering, reassembly, or ordered
    // delivery.
    size_t held_bytes(const Association& assoc) {
        size_t total = assoc.reassembly.bytes.size();
        for (const auto& [tsn, held] : assoc.tsn_ooo_buffer) {
            total += held.data.user_data.size();
            (void)tsn;
        }
        for (const auto& [id, stream] : assoc.inbound_streams) {
            for (const auto& [ssn, bytes] : stream.early) {
                total += bytes.size();
                (void)ssn;
            }
            (void)id;
        }
        for (const auto& delivery : assoc.held_deliveries) {
            total += delivery.bytes.size();
        }
        return total;
    }

    // What the peer believes is left of our window: what we last advertised,
    // less what it has sent us since.
    uint32_t peer_view_of_window(const Association& assoc) {
        return assoc.our_rwnd > assoc.received_since_sack ? assoc.our_rwnd - assoc.received_since_sack : 0;
    }

    // Whether anything held is complete and waiting only on the TSN at the
    // Cumulative TSN Ack point. Nothing could be dropped to make room for it.
    bool blocked_on_cumulative_tsn(const Association& assoc) {
        bool assembled = std::any_of(assoc.tsn_ooo_buffer.begin(), assoc.tsn_ooo_buffer.end(), [](const auto& entry) {
            return entry.second.assembled;
        });
        return assembled || std::any_of(assoc.inbound_streams.begin(), assoc.inbound_streams.end(), [](const auto& entry) {
            return !entry.second.early.empty();
        });
    }

    // With the receive buffer full, a new chunk above everything received is
    // dropped. One below it instead takes the place of the highest TSN held for
    // reordering, which is dropped even if a Gap Ack Block already reported it.
    // Each report is counted once: an entry is consumed when it is matched.
    uint32_t duplicate_bytes(Association& assoc, const sack_chunk_value& sack, std::vector<uint32_t>& per_path) {
        uint32_t total = 0;
        for (uint32_t tsn : sack.duplicate_tsns) {
            auto outstanding = assoc.outstanding_data.find(tsn);
            uint32_t size = 0;
            sockaddr_in destination{};
            if (outstanding != assoc.outstanding_data.end()) {
                size = static_cast<uint32_t>(data_chunk_wire_size(outstanding->second.data));
                destination = outstanding->second.destination;
            } else {
                auto& acked = assoc.acked_retransmissions;
                auto match = std::find_if(acked.begin(), acked.end(), [tsn](const Acked_Retransmission& entry) {
                    return entry.tsn == tsn;
                });
                if (match == acked.end()) {
                    continue;
                }
                size = match->size;
                destination = match->destination;
                acked.erase(match);
            }
            Peer_Path* path = find_path(assoc, destination);
            per_path[static_cast<size_t>((path != nullptr ? path : &primary(assoc)) - assoc.peer_address_list.data())] += size;
            total += size;
        }
        return total;
    }

    bool make_room(Association& assoc, uint32_t tsn, size_t& used) {
        auto highest = std::find_if(assoc.tsn_ooo_buffer.rbegin(), assoc.tsn_ooo_buffer.rend(), [](const auto& entry) {
            return !entry.second.assembled;
        });
        if (highest == assoc.tsn_ooo_buffer.rend() || tsn_gt(tsn, highest->first)) {
            return false;
        }
        used -= highest->second.data.user_data.size();
        assoc.tsn_ooo_buffer.erase(std::next(highest).base());
        return true;
    }

    bool partial_delivery_open(const Association& assoc) {
        return assoc.reassembly.open && assoc.reassembly.partially_delivered;
    }

    void hand_up(Association& assoc, Delivery delivery, std::vector<Delivery>& delivered) {
        (partial_delivery_open(assoc) ? assoc.held_deliveries : delivered).push_back(std::move(delivery));
    }

    void advance_stream(Association& assoc, uint16_t stream_id, std::vector<Delivery>& delivered) {
        Inbound_Stream& stream = assoc.inbound_streams[stream_id];
        ++stream.next_ssn;
        for (auto next = stream.early.find(stream.next_ssn); next != stream.early.end(); next = stream.early.find(++stream.next_ssn)) {
            hand_up(assoc, Delivery{std::move(next->second), true, stream_id}, delivered);
            stream.early.erase(next);
        }
    }

    // False if the SSN was already delivered or is already waiting: the peer
    // reused it.
    bool order_message(Association& assoc, uint16_t stream_id, uint16_t ssn, bool unordered, std::vector<uint8_t> bytes, std::vector<Delivery>& delivered) {
        if (unordered) {
            hand_up(assoc, Delivery{std::move(bytes), true, stream_id}, delivered);
            return true;
        }
        Inbound_Stream& stream = assoc.inbound_streams[stream_id];
        if (ssn != stream.next_ssn) {
            return ssn_gt(ssn, stream.next_ssn) && stream.early.emplace(ssn, std::move(bytes)).second;
        }
        hand_up(assoc, Delivery{std::move(bytes), true, stream_id}, delivered);
        advance_stream(assoc, stream_id, delivered);
        return true;
    }

    // Takes the next chunk in TSN order. False if it can neither begin a message
    // nor continue the open one. Without keep_bytes only the framing is checked:
    // the stream is invalid, or the message was already assembled ahead of the
    // Cumulative TSN Ack.
    bool reassemble(Association& assoc, const data_chunk_value& data, bool keep_bytes, std::vector<Delivery>& delivered) {
        Reassembly& message = assoc.reassembly;
        bool begins = (data.flags & DATA_FLAG_B) != 0;
        bool ends = (data.flags & DATA_FLAG_E) != 0;
        bool unordered = (data.flags & DATA_FLAG_U) != 0;
        if (begins == message.open) {
            return false;
        }
        if (begins) {
            message = Reassembly{true, false, unordered, data.stream_identifier, data.stream_seq_num, {}};
        } else if (data.stream_identifier != message.stream || unordered != message.unordered
                || (!unordered && data.stream_seq_num != message.ssn)) {
            return false;
        }
        message.open = !ends;
        if (!keep_bytes) {
            return true;
        }
        message.bytes.insert(message.bytes.end(), data.user_data.begin(), data.user_data.end());
        if (message.partially_delivered) {
            delivered.push_back(Delivery{std::move(message.bytes), ends, message.stream});
            message.bytes.clear();
            if (ends) {
                std::move(assoc.held_deliveries.begin(), assoc.held_deliveries.end(), std::back_inserter(delivered));
                assoc.held_deliveries.clear();
            }
            return true;
        }
        if (!ends) {
            return true;
        }
        std::vector<uint8_t> bytes = std::move(message.bytes);
        message.bytes.clear();
        return order_message(assoc, message.stream, message.ssn, message.unordered, std::move(bytes), delivered);
    }

    // A message lying wholly above the Cumulative TSN Ack is taken out as soon
    // as its last fragment arrives, so a gap holds back only its own stream.
    bool assemble_early(Association& assoc, uint32_t tsn, std::vector<Delivery>& delivered) {
        auto usable = [&](uint32_t at) -> const data_chunk_value* {
            auto it = assoc.tsn_ooo_buffer.find(at);
            if (it == assoc.tsn_ooo_buffer.end() || it->second.assembled || it->second.data.user_data.empty()) {
                return nullptr;
            }
            return &it->second.data;
        };
        const data_chunk_value* arrived = usable(tsn);
        if (arrived == nullptr) {
            return true;
        }
        uint16_t stream = arrived->stream_identifier;
        uint16_t ssn = arrived->stream_seq_num;
        bool unordered = (arrived->flags & DATA_FLAG_U) != 0;
        // A fragment of the same message that does not open or close another.
        auto continues = [&](const data_chunk_value* chunk, uint8_t foreign_edge) {
            return chunk != nullptr && (chunk->flags & foreign_edge) == 0 && chunk->stream_identifier == stream
                && ((chunk->flags & DATA_FLAG_U) != 0) == unordered && (unordered || chunk->stream_seq_num == ssn);
        };

        uint32_t first = tsn;
        while ((usable(first)->flags & DATA_FLAG_B) == 0) {
            if (!continues(usable(first - 1), DATA_FLAG_E)) {
                return true;
            }
            --first;
        }
        uint32_t last = tsn;
        while ((usable(last)->flags & DATA_FLAG_E) == 0) {
            if (!continues(usable(last + 1), DATA_FLAG_B)) {
                return true;
            }
            ++last;
        }

        std::vector<uint8_t> bytes;
        for (uint32_t at = first;; ++at) {
            Held_Chunk& held = assoc.tsn_ooo_buffer.at(at);
            bytes.insert(bytes.end(), held.data.user_data.begin(), held.data.user_data.end());
            held.data.user_data = {};
            held.assembled = true;
            if (at == last) {
                break;
            }
        }
        return order_message(assoc, stream, ssn, unordered, std::move(bytes), delivered);
    }

    // Leading reports win: keeps as many as fit in room, each costing per_report on top of its size.
    void trim_reports(std::vector<std::vector<uint8_t>>& reports, size_t room, size_t per_report) {
        auto fits = reports.begin();
        for (size_t used = 0; fits != reports.end(); ++fits) {
            used += per_report + fits->size();
            if (used > room) {
                break;
            }
        }
        reports.erase(fits, reports.end());
    }

    error_cause missing_parameter_cause(uint16_t type) {
        return error_cause{CAUSE_MISSING_MANDATORY_PARAM, {0, 0, 0, 1, static_cast<uint8_t>(type >> 8), static_cast<uint8_t>(type)}};
    }

    error_cause unresolvable_address_cause(const std::vector<uint8_t>& host_name) {
        std::vector<uint8_t> info;
        append_parameter(info, PARAM_HOST_NAME_ADDRESS, host_name.data(), host_name.size());
        return error_cause{CAUSE_UNRESOLVABLE_ADDRESS, std::move(info)};
    }

    Parameter_Scan scan_init(const init_chunk_value& init) {
        return scan_parameters(init.optional_parameters, {
            PARAM_IPV4_ADDRESS,
            PARAM_IPV6_ADDRESS,
            PARAM_COOKIE_PRESERVATIVE,
            PARAM_HOST_NAME_ADDRESS,
            PARAM_SUPPORTED_ADDRESS_TYPES,
        });
    }

    Parameter_Scan scan_init_ack(const init_chunk_value& init_ack) {
        return scan_parameters(init_ack.optional_parameters, {
            PARAM_STATE_COOKIE,
            PARAM_IPV4_ADDRESS,
            PARAM_IPV6_ADDRESS,
            PARAM_UNRECOGNIZED,
            PARAM_HOST_NAME_ADDRESS,
        });
    }

    // The source address first, then each IPv4 Address parameter once, all with
    // the source's UDP port until each sends from its own.
    std::vector<sockaddr_in> transport_addresses(const sockaddr_in& src, const std::vector<uint8_t>& recognized) {
        std::vector<sockaddr_in> out{src};
        for (uint32_t address : find_ipv4_addresses(recognized)) {
            sockaddr_in listed = src;
            listed.sin_addr.s_addr = htonl(address);
            if (std::none_of(out.begin(), out.end(), [&](const sockaddr_in& seen) { return same_destination(seen, listed); })) {
                out.push_back(listed);
            }
        }
        return out;
    }

    // What an INIT or INIT ACK leading the packet would make the peer's addresses.
    std::vector<sockaddr_in> init_addresses(const SCTP_Packet& packet, const sockaddr_in& src) {
        if (packet.chunks.empty()) {
            return {};
        }
        const SCTP_Chunk& first = packet.chunks[0];
        switch (first.chunk_header.type) {
            case INIT:
                return transport_addresses(src, scan_init(std::get<init_chunk_value>(first.chunk_value)).recognized);
            case INIT_ACK:
                return transport_addresses(src, scan_init_ack(std::get<init_chunk_value>(first.chunk_value)).recognized);
            default:
                return {};
        }
    }

    // A copy of each IPv4 Address parameter that was new. The source address,
    // unless also listed, has no parameter to copy.
    std::vector<error_cause> new_address_causes(const std::vector<sockaddr_in>& added, const std::vector<uint8_t>& recognized) {
        std::vector<uint32_t> listed = find_ipv4_addresses(recognized);
        std::vector<uint8_t> info;
        for (const sockaddr_in& address : added) {
            if (std::find(listed.begin(), listed.end(), ntohl(address.sin_addr.s_addr)) != listed.end()) {
                append_parameter(info, PARAM_IPV4_ADDRESS, reinterpret_cast<const uint8_t*>(&address.sin_addr.s_addr), 4);
            }
        }
        if (info.empty()) {
            return {};
        }
        return {error_cause{CAUSE_RESTART_WITH_NEW_ADDRESSES, std::move(info)}};
    }

    std::vector<sockaddr_in> cookie_addresses(const State_Cookie& cookie) {
        std::vector<sockaddr_in> out{cookie_source(cookie)};
        for (uint32_t address : cookie.peer_addresses) {
            sockaddr_in listed = out.front();
            listed.sin_addr.s_addr = htonl(address);
            out.push_back(listed);
        }
        return out;
    }

    error_cause unrecognized_chunk_cause(const SCTP_Chunk& chunk) {
        const auto& body = std::get<unknown_chunk_value>(chunk.chunk_value).body;
        uint16_t length = static_cast<uint16_t>(SCTP_CHUNK_HEADER_SIZE + body.size());
        std::vector<uint8_t> info{
            static_cast<uint8_t>(chunk.chunk_header.type),
            chunk.chunk_header.flag,
            static_cast<uint8_t>(length >> 8),
            static_cast<uint8_t>(length),
        };
        info.insert(info.end(), body.begin(), body.end());
        return error_cause{CAUSE_UNRECOGNIZED_CHUNK, std::move(info)};
    }

    // flight_before is the flightsize before this SACK was applied. It is what
    // says whether the window being grown was actually in use.
    void grow_cwnd(const Association& assoc, Peer_Path& path, uint32_t bytes_acked, uint32_t duplicate_bytes, size_t flight_before) {
        bool cwnd_full = flight_before >= path.cwnd;
        if (path.cwnd <= path.ssthresh) {
            if (cwnd_full && !assoc.in_fast_recovery) {
                path.cwnd += std::min(bytes_acked, SLOW_START_INCREASE_PMDCS * assoc.pmdcs);
            }
            return;
        }

        path.partial_bytes_acked += bytes_acked + duplicate_bytes;
        if (path.partial_bytes_acked >= path.cwnd && cwnd_full) {
            path.partial_bytes_acked -= path.cwnd;
            path.cwnd += assoc.pmdcs;
        } else if (path.partial_bytes_acked > path.cwnd) {
            path.partial_bytes_acked = path.cwnd;
        }
    }

    // What one SACK did to the DATA sent to one destination.
    struct Path_Ack {
        size_t flight_before{0};
        uint32_t bytes_acked{0};
        uint32_t duplicate_bytes{0};
        bool newly_acknowledged{false};
        bool have_earliest{false};
        uint32_t earliest_tsn{0};
        bool reneged{false};
        bool fast_retransmitted{false};
    };

    enum class T3_Action { STOP, RESTART, START };

    size_t index_of(const Association& assoc, const Peer_Path& path) {
        return static_cast<size_t>(&path - assoc.peer_address_list.data());
    }

    bool contains_chunk(const SCTP_Packet& packet, Chunk_Type type) {
        return std::any_of(packet.chunks.begin(), packet.chunks.end(), [type](const SCTP_Chunk& chunk) {
            return chunk.chunk_header.type == type;
        });
    }

    bool carries_stale_cookie(const SCTP_Chunk& chunk) {
        const auto& error = std::get<error_chunk_value>(chunk.chunk_value);
        return std::any_of(error.causes.begin(), error.causes.end(), [](const error_cause& cause) {
            return cause.code == CAUSE_STALE_COOKIE;
        });
    }
}

void SCTP_Socket::handle_recv_packet(const uint8_t* data, size_t n, const sockaddr_in& src) {
    if (n < SCTP_COMMON_HEADER_SIZE) {
        return;
    }

    uint32_t received_checksum = sctp_read_wire_checksum(data);

    std::vector<uint8_t> data_copy(data, data + n);
    sctp_clear_wire_checksum(data_copy.data());

    uint32_t calculated_checksum = calculate_sctp_checksum(data_copy.data(), data_copy.size());

    if (calculated_checksum != received_checksum) {
        return;
    }

    SCTP_Packet in_pkt;
    try {
        in_pkt = deserialize_sctp_packet(data, n);
    } catch (const std::exception&) {
        return;
    }

    Association_Key key;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        key = association_key_for(peer_key(src, in_pkt.header.src_port));
        if (associations.count(key) == 0) {
            for (const sockaddr_in& address : init_addresses(in_pkt, src)) {
                Association_Key listed = association_key_for(peer_key(address, in_pkt.header.src_port));
                if (associations.count(listed) != 0) {
                    key = listed;
                    break;
                }
            }
        }
    }

    switch (validate_verification_tag(in_pkt, key)) {
        case Packet_Validation::ACCEPT:
            break;
        case Packet_Validation::ABORT_OOTB:
            send_abort(in_pkt.header, key, src, in_pkt.header.verification_tag, true, {});
            return;
        case Packet_Validation::ABORT_INIT:
            send_abort(in_pkt.header, key, src, std::get<init_chunk_value>(in_pkt.chunks[0].chunk_value).initiate_tag, false, {});
            return;
        case Packet_Validation::SHUTDOWN_COMPLETE_OOTB:
            enqueue_packet(Deliverable{key, src, build_shutdown_complete(
                in_pkt.header.des_port, in_pkt.header.src_port, in_pkt.header.verification_tag, true)});
            return;
        case Packet_Validation::DISCARD:
            return;
    }

    std::vector<error_cause> unrecognized;
    for (auto it = in_pkt.chunks.begin(); it != in_pkt.chunks.end();) {
        if (!std::holds_alternative<unknown_chunk_value>(it->chunk_value)) {
            ++it;
            continue;
        }
        uint8_t type = it->chunk_header.type;
        if (type & 0x40) {
            unrecognized.push_back(unrecognized_chunk_cause(*it));
        }
        it = (type & 0x80) ? in_pkt.chunks.erase(it) : in_pkt.chunks.erase(it, in_pkt.chunks.end());
    }

    // A COOKIE ECHO skipped the tag check, so it gates the rest of the packet.
    // An accepted cookie proves the header tag: verify() matched it against the
    // cookie's local tag, which every accepting path leaves in the TCB.
    bool carried_cookie_echo = !in_pkt.chunks.empty() && in_pkt.chunks[0].chunk_header.type == COOKIE_ECHO;
    if (carried_cookie_echo) {
        if (!handle_cookie_echo(in_pkt.header, in_pkt.chunks[0], key, src)) {
            return;
        }
    }

    // An INIT carries no proof that it came from the peer.
    if (in_pkt.chunks.empty() || in_pkt.chunks[0].chunk_header.type != INIT) {
        record_encapsulation_port(key, src);
    }

    // 9.2: any packet from the peer in SHUTDOWN-SENT gives it more time.
    bool shutdown_sent = false;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(key);
        if (it != associations.end() && it->second.state == SHUTDOWN_SENT) {
            it->second.error_count = 0;
            shutdown_sent = true;
        }
    }
    if (shutdown_sent) {
        restart_t2(key);
    }

    for (size_t i = carried_cookie_echo ? 1 : 0; i < in_pkt.chunks.size(); i++) {
        switch(in_pkt.chunks[i].chunk_header.type) {
            case INIT:
                SCTP_Socket::handle_init(in_pkt.header, in_pkt.chunks[i], key, src);
                break;
            case INIT_ACK:
                SCTP_Socket::handle_init_ack(in_pkt.header, in_pkt.chunks[i], key, src);
                break;
            case COOKIE_ACK:
                SCTP_Socket::handle_cookie_ack(in_pkt.header, in_pkt.chunks[i], key, src);
                break;
            case DATA:
                // Special, needs to be handled once per packet, not once per chunk. Handler called after the loop.
                break;
            case SACK:
                SCTP_Socket::handle_sack(in_pkt.header, in_pkt.chunks[i], key, src);
                break;
            case OP_ERROR:
                SCTP_Socket::handle_error(in_pkt.header, in_pkt.chunks[i], key, src);
                break;
            case ABORT:
                SCTP_Socket::handle_abort(in_pkt.header, in_pkt.chunks[i], key, src);
                return; // ABORT so stop processing packets
            case HEARTBEAT:
                SCTP_Socket::handle_heartbeat(in_pkt.header, in_pkt.chunks[i], key, src);
                break;
            case HEARTBEAT_ACK:
                SCTP_Socket::handle_heartbeat_ack(in_pkt.header, in_pkt.chunks[i], key, src);
                break;
            case SHUTDOWN:
                SCTP_Socket::handle_shutdown(in_pkt.header, in_pkt.chunks[i], key, src);
                break;
            case SHUTDOWN_ACK:
                SCTP_Socket::handle_shutdown_ack(in_pkt.header, in_pkt.chunks[i], key, src);
                break;
            case SHUTDOWN_COMPLETE:
                SCTP_Socket::handle_shutdown_complete(in_pkt.header, in_pkt.chunks[i], key, src);
                break;
            default:
                break;
        }
    }

    // DATA bundled with a COOKIE ECHO must skip the delayed-SACK timer.
    handle_data_packet(in_pkt, key, src, carried_cookie_echo);

    if (!unrecognized.empty()) {
        report_unrecognized_chunks(in_pkt.header, key, src, std::move(unrecognized));
    }
}

Packet_Validation SCTP_Socket::validate_verification_tag(const SCTP_Packet& pkt, const Association_Key& key) {
    if (pkt.chunks.empty()) {
        return Packet_Validation::DISCARD;
    }

    const SCTP_Chunk_Header& first = pkt.chunks[0].chunk_header;

    // Our SCTP port is our UDP port; no endpoint here listens on any other.
    if (pkt.header.des_port != ntohs(local_address.sin_port)) {
        if (first.type != INIT) {
            return ootb_response(pkt);
        }
        return pkt.header.verification_tag == 0 && pkt.chunks.size() == 1
                && std::get<init_chunk_value>(pkt.chunks[0].chunk_value).initiate_tag != 0
            ? Packet_Validation::ABORT_INIT
            : Packet_Validation::DISCARD;
    }

    if (first.type == INIT) {
        return pkt.header.verification_tag == 0 && pkt.chunks.size() == 1
            ? Packet_Validation::ACCEPT
            : Packet_Validation::DISCARD;
    }

    // 8.5.1 D: a restarting or colliding peer echoes under a tag the live TCB
    // does not hold, so the cookie is checked instead. handle_recv_packet drops
    // everything bundled behind it unless the cookie is accepted.
    if (first.type == COOKIE_ECHO) {
        return Packet_Validation::ACCEPT;
    }

    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    auto it = associations.find(key);
    if (it == associations.end()) {
        return ootb_response(pkt);
    }

    // 8.5.1 B and C: the T bit says which tag the sender could reach for. Set, it
    // had no TCB and echoed ours back, so the match is against the tag we handed
    // the peer; clear, it held a TCB and addressed us under our own.
    if (first.type == ABORT || first.type == SHUTDOWN_COMPLETE) {
        uint32_t expected = (first.flag & CHUNK_FLAG_T_BIT)
            ? it->second.peer_ver_tag
            : it->second.this_ver_tag;
        return expected != 0 && pkt.header.verification_tag == expected
            ? Packet_Validation::ACCEPT
            : Packet_Validation::DISCARD;
    }

    // 8.5.1 E: the SHUTDOWN ACK belongs to an association this TCB replaced.
    if ((it->second.state == COOKIE_WAIT || it->second.state == COOKIE_ECHOED) && contains_chunk(pkt, SHUTDOWN_ACK)) {
        return ootb_response(pkt);
    }

    return pkt.header.verification_tag == it->second.this_ver_tag
        ? Packet_Validation::ACCEPT
        : Packet_Validation::DISCARD;
}

// 8.4: an unattributable packet is answered with an ABORT, except where a reply
// would bounce forever or the sender is already tearing the association down.
// The rules are ordered: an ABORT anywhere in the packet outranks the rest.
Packet_Validation SCTP_Socket::ootb_response(const SCTP_Packet& pkt) {
    if (contains_chunk(pkt, ABORT)) {
        return Packet_Validation::DISCARD;
    }
    if (contains_chunk(pkt, SHUTDOWN_ACK)) {
        return Packet_Validation::SHUTDOWN_COMPLETE_OOTB;
    }
    bool stale_cookie = std::any_of(pkt.chunks.begin(), pkt.chunks.end(), [](const SCTP_Chunk& chunk) {
        return chunk.chunk_header.type == OP_ERROR && carries_stale_cookie(chunk);
    });
    if (stale_cookie || contains_chunk(pkt, SHUTDOWN_COMPLETE) || contains_chunk(pkt, COOKIE_ACK)) {
        return Packet_Validation::DISCARD;
    }
    return Packet_Validation::ABORT_OOTB;
}

// After dispatch: a bundled COOKIE ECHO may have created the TCB. COOKIE_WAIT
// has no peer tag to address the report with.
void SCTP_Socket::report_unrecognized_chunks(const SCTP_Common_Header& header, const Association_Key& key, const sockaddr_in& src, std::vector<error_cause> causes) {
    uint32_t peer_tag;
    size_t budget;
    sockaddr_in destination;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(key);
        if (it == associations.end() || it->second.state == COOKIE_WAIT) {
            return;
        }
        peer_tag = it->second.peer_ver_tag;
        budget = it->second.pmdcs;
        destination = reply_destination(it->second, src);
    }

    size_t size = SCTP_CHUNK_HEADER_SIZE;
    auto fits = causes.begin();
    for (; fits != causes.end(); ++fits) {
        size += (SCTP_CHUNK_HEADER_SIZE + fits->info.size() + 3) & ~size_t{3};
        if (size > budget) {
            break;
        }
    }
    causes.erase(fits, causes.end());
    if (!causes.empty()) {
        send_error(header, key, destination, peer_tag, std::move(causes));
    }
}

void SCTP_Socket::handle_init(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src) {
    const auto& init = std::get<init_chunk_value>(chunk.chunk_value);
    // The association closed here is the one this INIT asks for. A TCB already
    // held for this peer survives: an INIT carries no proof of origin.
    if (init.initiate_tag == 0) {
        send_abort(header, key, src, header.verification_tag, true, {error_cause{CAUSE_INVALID_MANDATORY_PARAM, {}}});
        return;
    }
    // The Initiate Tag is the peer's own, learned from the chunk rather than
    // reflected off the header, so the T bit stays clear.
    if (init.out_streams == 0 || init.in_streams == 0) {
        send_abort(header, key, src, init.initiate_tag, false, {error_cause{CAUSE_INVALID_MANDATORY_PARAM, {}}});
        return;
    }
    Parameter_Scan params = scan_init(init);
    std::vector<uint8_t> host_name;
    if (find_parameter(params.recognized, PARAM_HOST_NAME_ADDRESS, host_name)) {
        send_abort(header, key, src, init.initiate_tag, false, {unresolvable_address_cause(host_name)});
        return;
    }
    std::vector<sockaddr_in> addresses = transport_addresses(src, params.recognized);
    std::vector<uint8_t> preservative;
    uint32_t lifespan_increment_ms = find_parameter(params.recognized, PARAM_COOKIE_PRESERVATIVE, preservative)
        && preservative.size() == 4 ? read_be32(preservative.data()) : 0;

    uint32_t local_tag = generate_nonzero_tag();
    uint32_t local_tsn;
    generate_random(local_tsn);
    uint32_t local_tie_tag = 0;
    uint32_t peer_tie_tag = 0;
    sockaddr_in destination = src;
    std::vector<sockaddr_in> added;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto existing = associations.find(key);
        if (existing != associations.end()) {
            Association& assoc = existing->second;

            switch (assoc.state) {
                case SHUTDOWN_ACK_SENT:
                    enqueue_packet(Deliverable{key, reply_destination(assoc, src), build_shutdown_ack(header.des_port, header.src_port, assoc.peer_ver_tag)});
                    return;
                case COOKIE_WAIT:
                    // The primary path is the address the ULP gave, and the INIT
                    // reported it: that is how it found this TCB.
                    local_tag = assoc.this_ver_tag;
                    local_tsn = assoc.next_tsn;
                    destination = primary(assoc).address;
                    break;
                default:
                    std::copy_if(addresses.begin(), addresses.end(), std::back_inserter(added), [&](const sockaddr_in& address) {
                        return find_path(assoc, address) == nullptr;
                    });
                    if (!added.empty()) {
                        break;
                    }
                    if (assoc.state == COOKIE_ECHOED) {
                        local_tag = assoc.this_ver_tag;
                        local_tsn = assoc.next_tsn;
                    }
                    if (assoc.local_tie_tag == 0) {
                        assoc.local_tie_tag = generate_nonzero_tag();
                        assoc.peer_tie_tag = generate_nonzero_tag();
                    }
                    local_tie_tag = assoc.local_tie_tag;
                    peer_tie_tag = assoc.peer_tie_tag;
            }
        }
    }
    if (!added.empty()) {
        send_abort(header, key, src, init.initiate_tag, false, new_address_causes(added, params.recognized));
        return;
    }

    std::vector<uint32_t> other_addresses;
    for (auto address = addresses.begin() + 1; address != addresses.end(); ++address) {
        other_addresses.push_back(ntohl(address->sin_addr.s_addr));
    }
    std::vector<uint8_t> cookie = cookie_authorizer.generate(
        header,
        init,
        src,
        local_tag,
        local_tsn,
        local_tie_tag,
        peer_tie_tag,
        lifespan_increment_ms,
        other_addresses
    );

    size_t init_ack_size = SCTP_CHUNK_HEADER_SIZE + 16 + SCTP_CHUNK_HEADER_SIZE + ((cookie.size() + 3) & ~size_t{3});
    trim_reports(params.reported, DEFAULT_PMDCS - std::min<size_t>(DEFAULT_PMDCS, init_ack_size), SCTP_CHUNK_HEADER_SIZE);

    enqueue_packet(Deliverable{key, destination, build_init_ack(
        header.des_port,
        header.src_port,
        init.initiate_tag,
        local_tag,
        local_tsn,
        cookie,
        params.reported
    )});
}

void SCTP_Socket::handle_init_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src) {
    const auto& init_ack = std::get<init_chunk_value>(chunk.chunk_value);

    std::unique_lock<std::mutex> assoc_lock(associations_mutex);
    auto it = associations.find(key);
    if (it == associations.end() || it->second.state != COOKIE_WAIT) {
        return;
    }

    // 3.3.3: the TCB goes whether or not the optional ABORT does. That ABORT
    // follows the purge in remove_association, and reflects our own tag.
    if (init_ack.initiate_tag == 0) {
        assoc_lock.unlock();
        remove_association(key);
        send_abort(header, key, src, header.verification_tag, true, {error_cause{CAUSE_INVALID_MANDATORY_PARAM, {}}});
        notify_assoc_change(key, Assoc_Change_State::CANT_STR_ASSOC);
        return;
    }

    Parameter_Scan params = scan_init_ack(init_ack);
    std::vector<uint8_t> cookie;
    if (!find_parameter(params.recognized, PARAM_STATE_COOKIE, cookie)) {
        assoc_lock.unlock();
        remove_association(key);
        send_abort(header, key, src, init_ack.initiate_tag, false, {missing_parameter_cause(PARAM_STATE_COOKIE)});
        notify_assoc_change(key, Assoc_Change_State::CANT_STR_ASSOC);
        return;
    }
    if (init_ack.out_streams == 0 || init_ack.in_streams == 0) {
        assoc_lock.unlock();
        remove_association(key);
        send_abort(header, key, src, init_ack.initiate_tag, false, {error_cause{CAUSE_INVALID_MANDATORY_PARAM, {}}});
        notify_assoc_change(key, Assoc_Change_State::CANT_STR_ASSOC);
        return;
    }
    std::vector<uint8_t> host_name;
    if (find_parameter(params.recognized, PARAM_HOST_NAME_ADDRESS, host_name)) {
        assoc_lock.unlock();
        remove_association(key);
        send_abort(header, key, src, init_ack.initiate_tag, false, {unresolvable_address_cause(host_name)});
        notify_assoc_change(key, Assoc_Change_State::CANT_STR_ASSOC);
        return;
    }

    Association& assoc = it->second;
    add_peer_addresses(key, assoc, transport_addresses(src, params.recognized));
    sockaddr_in destination = reply_destination(assoc, src);
    assoc.last_peer_tsn = init_ack.initial_tsn - 1;
    assoc.peer_ver_tag = init_ack.initiate_tag;
    assoc.peer_rwnd = init_ack.a_rwnd;
    assoc.peer_max_rwnd = init_ack.a_rwnd;
    assoc.out_streams = std::min(LOCAL_OUT_STREAMS, init_ack.in_streams);
    assoc.in_streams = std::min(LOCAL_MAX_IN_STREAMS, init_ack.out_streams);
    assoc.next_ssn.assign(assoc.out_streams, 0);
    assoc.state = COOKIE_ECHOED;
    uint32_t peer_tag = assoc.peer_ver_tag;
    // COOKIE ECHO, then the ERROR chunk and cause headers.
    size_t room = assoc.pmdcs - std::min<size_t>(assoc.pmdcs,
        3 * SCTP_CHUNK_HEADER_SIZE + ((cookie.size() + 3) & ~size_t{3}));
    assoc_lock.unlock();
    cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::T1_INIT});
    sends.remove_retransmissions_of_type(key, INIT);

    trim_reports(params.reported, room, 0);
    std::vector<error_cause> errors;
    if (!params.reported.empty()) {
        std::vector<uint8_t> info;
        for (const auto& parameter : params.reported) {
            info.insert(info.end(), parameter.begin(), parameter.end());
        }
        errors.push_back(error_cause{CAUSE_UNRECOGNIZED_PARAMS, std::move(info)});
    }
    enqueue_packet(Deliverable{key, destination, build_cookie_echo(
        header.des_port, header.src_port, peer_tag, std::move(cookie), std::move(errors))});
}

void SCTP_Socket::send_cookie_ack(const SCTP_Common_Header& header, const Association_Key& key, const sockaddr_in& destination, uint32_t peer_tag) {
    enqueue_packet(Deliverable{key, destination, build_cookie_ack(header.des_port, header.src_port, peer_tag)});
}

void SCTP_Socket::send_stale_cookie_error(
        const SCTP_Common_Header& header,
        const Association_Key& key,
        const sockaddr_in& destination,
        const State_Cookie& cookie,
        uint32_t staleness_us) {
    send_error(header, key, destination, cookie.peer_ver_tag, {stale_cookie_cause(staleness_us)});
}

void SCTP_Socket::send_error(
        const SCTP_Common_Header& header,
        const Association_Key& key,
        const sockaddr_in& destination,
        uint32_t peer_tag,
        std::vector<error_cause> causes) {
    enqueue_packet(Deliverable{key, destination, build_error(
        header.des_port, header.src_port, peer_tag, std::move(causes))});
}

void SCTP_Socket::send_abort(
    const SCTP_Common_Header& header,
    const Association_Key& key,
    const sockaddr_in& destination,
    uint32_t tag,
    bool reflected,
    std::vector<error_cause> causes
) {
    enqueue_packet(Deliverable{
        key,
        destination,
        build_abort(header.des_port, header.src_port, tag, reflected, std::move(causes))
    });
}

bool SCTP_Socket::handle_cookie_echo(
    const SCTP_Common_Header& header,
    const SCTP_Chunk& chunk,
    Association_Key& key,
    const sockaddr_in& src
) {
    const auto& echo = std::get<cookie_echo_chunk_value>(chunk.chunk_value);

    State_Cookie cookie{};
    uint32_t staleness_us = 0;
    Cookie_Result result = cookie_authorizer.verify(echo.cookie_data, header, src, cookie, staleness_us);
    if (result != Cookie_Result::VALID && result != Cookie_Result::STALE) {
        return false;
    }

    // Send and expiration queue locks are leaves, so it is safe to touch them
    // here. Holding the lock through a restart's purge keeps an API-thread send
    // on the new association from being purged with the old one's packets.
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    key = association_key_for(cookie_key(cookie));
    auto it = associations.find(key);
    if (it == associations.end()) {
        if (result == Cookie_Result::STALE) {
            send_stale_cookie_error(header, key, src, cookie, staleness_us);
            return false;
        }
        auto created = associations.insert_or_assign(key, init_new_association(cookie));
        add_peer_addresses(key, created.first->second, cookie_addresses(cookie));
        notify_assoc_change(key, Assoc_Change_State::COMM_UP);
        start_heartbeats(key, created.first->second);
        send_cookie_ack(header, key, reply_destination(created.first->second, src), cookie.peer_ver_tag);
        return true;
    }

    // RFC 9260 5.2.4, Table 12. A zero Tie-Tag means "none" and never matches.
    Association& tcb = it->second;
    bool local_match = cookie.local_ver_tag == tcb.this_ver_tag;
    bool peer_match = cookie.peer_ver_tag == tcb.peer_ver_tag;
    bool tie_tags_match = cookie.local_tie_tag != 0
        && cookie.local_tie_tag == tcb.local_tie_tag
        && cookie.peer_tie_tag == tcb.peer_tie_tag;

    sockaddr_in destination = reply_destination(tcb, src);
    // Step 3: a stale cookie whose tags both match is a retransmission (case E).
    if (result == Cookie_Result::STALE && !(local_match && peer_match)) {
        send_stale_cookie_error(header, key, destination, cookie, staleness_us);
        return false;
    }

    if (local_match && peer_match) {
        // D
        if (tcb.state == COOKIE_ECHOED) {
            tcb.state = ESTABLISHED;
            notify_assoc_change(key, Assoc_Change_State::COMM_UP);
            start_heartbeats(key, tcb);
        }
    } else if (!local_match && !peer_match && tie_tags_match) {
        // A: peer restart
        // The SHUTDOWN ACK is for the old association, so it goes under the old
        // tag: the restarted peer reflects it back, which is what we accept.
        if (tcb.state == SHUTDOWN_ACK_SENT) {
            enqueue_packet(Deliverable{key, destination, build_shutdown_ack(header.des_port, header.src_port, tcb.peer_ver_tag)});
            send_error(header, key, destination, cookie.peer_ver_tag, {error_cause{CAUSE_COOKIE_WHILE_SHUTTING_DOWN, {}}});
            return false;
        }
        cancel_expirations(key);
        sends.purge(key);
        forget_peer_addresses(key);
        abandon_partial_delivery(key, tcb);
        receives.detach(key);
        tcb = init_new_association(cookie);
        add_peer_addresses(key, tcb, cookie_addresses(cookie));
        destination = reply_destination(tcb, src);
        notify_assoc_change(key, Assoc_Change_State::RESTART);
        start_heartbeats(key, tcb);
    } else if (local_match) {
        // B: collision, peer's tag is new or not yet known
        add_peer_addresses(key, tcb, cookie_addresses(cookie));
        tcb.peer_ver_tag = cookie.peer_ver_tag;
        tcb.last_peer_tsn = cookie.peer_initial_tsn - 1;
        tcb.peer_rwnd = cookie.peer_a_rwnd;
        tcb.peer_max_rwnd = cookie.peer_a_rwnd;
        tcb.tsn_ooo_buffer.clear();
        abandon_partial_delivery(key, tcb);
        tcb.reassembly = {};
        tcb.inbound_streams.clear();
        tcb.held_deliveries.clear();
        tcb.duplicate_tsns.clear();
        // A shutdown in progress is kept rather than silently cancelled.
        if (tcb.state == COOKIE_WAIT || tcb.state == COOKIE_ECHOED) {
            tcb.state = ESTABLISHED;
            notify_assoc_change(key, Assoc_Change_State::COMM_UP);
            start_heartbeats(key, tcb);
        } else if (transmits_data(tcb.state)) {
            arm_confirmation_probes(key, tcb);
        }
    } else {
        // C, and anything not in the table
        return false;
    }

    cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::T1_INIT});
    cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::T1_COOKIE});
    sends.remove_retransmissions_of_type(key, INIT);
    sends.remove_retransmissions_of_type(key, COOKIE_ECHO);
    send_cookie_ack(header, key, destination, cookie.peer_ver_tag);
    return true;
}

void SCTP_Socket::handle_error(const SCTP_Common_Header&, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in&) {
    const auto& error = std::get<error_chunk_value>(chunk.chunk_value);
    if (error.causes.empty()) {
        return;
    }

    SCTP_Packet retry_init;
    sockaddr_in destination;
    bool handshake_failed = false;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(key);
        if (it == associations.end()) {
            return;
        }
        Association& assoc = it->second;

        for (const auto& cause : error.causes) {
            switch (cause.code) {
                case CAUSE_STALE_COOKIE: {
                    bool handled = !retry_init.chunks.empty() || handshake_failed;
                    if (handled || assoc.state != COOKIE_ECHOED || cause.info.size() != 4) {
                        break;
                    }
                    if (assoc.stale_cookie_retries >= MAX_STALE_COOKIE_RETRIES) {
                        handshake_failed = true;
                        break;
                    }
                    
                    uint32_t staleness_ms = read_be32(cause.info.data()) / 1000 + 1;
                    ++assoc.stale_cookie_retries;
                    assoc.state = COOKIE_WAIT;
                    assoc.peer_ver_tag = 0;
                    assoc.init_retransmits = 0;
                    assoc.cookie_retransmits = 0;
                    destination = primary(assoc).address;
                    retry_init = build_init(
                        ntohs(local_address.sin_port),
                        ntohs(key.address.sin_port),
                        assoc.this_ver_tag,
                        assoc.next_tsn,
                        staleness_ms + std::min(staleness_ms, 1000U));
                    break;
                }
                case CAUSE_COOKIE_WHILE_SHUTTING_DOWN: // TODO
                    break;
                case CAUSE_UNRECOGNIZED_CHUNK: // TODO
                    break;
                default:
                    break;
            }
        }

        // Every cause is passed up raw, unknown codes included, unless the
        // ERROR was consumed by handshake recovery.
        if (retry_init.chunks.empty() && !handshake_failed) {
            notifications.enqueue(Notification{Notification_Type::SCTP_REMOTE_ERROR, key, 0, Remote_Error{error.causes}});
            return;
        }
    }

    cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::T1_COOKIE});
    sends.remove_retransmissions_of_type(key, COOKIE_ECHO);
    if (!handshake_failed) {
        enqueue_packet(Deliverable{key, destination, std::move(retry_init)});
        return;
    }

    remove_association(key);
    notify_assoc_change(key, Assoc_Change_State::CANT_STR_ASSOC);
}

void SCTP_Socket::handle_abort(const SCTP_Common_Header&, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in&) {
    const auto& abort = std::get<error_chunk_value>(chunk.chunk_value);

    bool forming;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(key);
        if (it == associations.end()) {
            return;
        }
        forming = it->second.state == COOKIE_WAIT || it->second.state == COOKIE_ECHOED;
    }

    if (!abort.causes.empty()) {
        notifications.enqueue(Notification{Notification_Type::SCTP_REMOTE_ERROR, key, 0, Remote_Error{abort.causes}});
    }
    remove_association(key);
    notify_assoc_change(key, forming ? Assoc_Change_State::CANT_STR_ASSOC : Assoc_Change_State::COMM_LOST);
}

// 9.1: tear the association down locally, then tell the peer. The ABORT is
// enqueued after remove_association, whose purge would otherwise drop it along
// with the DATA that must not accompany it.
void SCTP_Socket::abort_association(
    const Association_Key& key,
    const SCTP_Common_Header& header,
    const sockaddr_in& src,
    std::vector<error_cause> causes
) {
    uint32_t peer_tag;
    bool forming;
    sockaddr_in destination;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(key);
        if (it == associations.end()) {
            return;
        }
        peer_tag = it->second.peer_ver_tag;
        forming = it->second.state == COOKIE_WAIT || it->second.state == COOKIE_ECHOED;
        destination = reply_destination(it->second, src);
    }

    remove_association(key);
    if (peer_tag != 0) {
        send_abort(header, key, destination, peer_tag, false, std::move(causes));
    }
    notify_assoc_change(key, forming ? Assoc_Change_State::CANT_STR_ASSOC : Assoc_Change_State::COMM_LOST);
}

// Cumulative against next_tsn rather than outstanding_data being empty: DATA
// still in the send queue has a TSN but no outstanding entry yet, and messages
// still in the outbound queue have no TSN at all.
void SCTP_Socket::do_next_shutdown_step(const Association_Key& key) {
    SCTP_Packet packet;
    sockaddr_in destination;
    bool guard = false;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(key);
        if (it == associations.end()) {
            return;
        }
        Association& assoc = it->second;
        if (assoc.cumulative_tsn_ack != assoc.next_tsn - 1 || !assoc.outbound.empty()) {
            return;
        }

        destination = data_path(assoc).address;
        uint16_t src_port = ntohs(local_address.sin_port);
        uint16_t des_port = ntohs(key.address.sin_port);
        switch (assoc.state) {
            case SHUTDOWN_PENDING:
                packet = build_shutdown(src_port, des_port, assoc.peer_ver_tag, assoc.last_peer_tsn);
                assoc.state = SHUTDOWN_SENT;
                guard = true;
                break;
            case SHUTDOWN_RECEIVED:
                packet = build_shutdown_ack(src_port, des_port, assoc.peer_ver_tag);
                assoc.state = SHUTDOWN_ACK_SENT;
                break;
            default:
                return;
        }
    }

    expirations.cancel_all(key, Expiration_Timer_Type::HEARTBEAT);
    cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::DELAYED_SACK});
    expirations.cancel_all(key, Expiration_Timer_Type::T3_RTX);
    enqueue_packet(Deliverable{key, destination, std::move(packet)});
    restart_t2(key);
    if (guard) {
        schedule_expiration(
            Expiration_Key{key, Expiration_Timer_Type::T5_SHUTDOWN_GUARD},
            std::chrono::steady_clock::now() + T5_SHUTDOWN_GUARD,
            Deliverable{key, {}, SCTP_Packet{}}
        );
    }
}

void SCTP_Socket::handle_cookie_ack(const SCTP_Common_Header&, const SCTP_Chunk&, const Association_Key& key, const sockaddr_in&) {
    std::unique_lock<std::mutex> assoc_lock(associations_mutex);
    auto it = associations.find(key);
    if (it == associations.end() || it->second.state != COOKIE_ECHOED) {
        return;
    }

    Association& assoc = it->second;
    assoc.state = ESTABLISHED;
    notify_assoc_change(key, Assoc_Change_State::COMM_UP);
    start_heartbeats(key, assoc);
    assoc_lock.unlock();
    cancel_expiration(
        Expiration_Key{key, Expiration_Timer_Type::T1_COOKIE});
    sends.remove_retransmissions_of_type(key, COOKIE_ECHO);
}

void SCTP_Socket::handle_heartbeat(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src) {
    const auto& info = std::get<heartbeat_chunk_value>(chunk.chunk_value).info;
    uint32_t peer_tag;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(key);
        // The Info is echoed verbatim and the peer chooses its length, so an
        // oversized one would build a reply we cannot put on the wire.
        if (it == associations.end() || it->second.state == SHUTDOWN_SENT || it->second.state == SHUTDOWN_ACK_SENT
                || 2 * SCTP_CHUNK_HEADER_SIZE + info.size() > it->second.pmdcs) {
            return;
        }
        peer_tag = it->second.peer_ver_tag;
    }

    enqueue_packet(Deliverable{key, src, build_heartbeat_ack(header.des_port, header.src_port, peer_tag, info)});
}

// 5.4: the ACK is credited to the path its Info names, which may not be the
// one it arrived from.
void SCTP_Socket::handle_heartbeat_ack(const SCTP_Common_Header&, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in&) {
    const auto& info = std::get<heartbeat_chunk_value>(chunk.chunk_value).info;
    if (info.size() != HEARTBEAT_INFO_SIZE) {
        return;
    }

    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    auto it = associations.find(key);
    if (it == associations.end()) {
        return;
    }

    // The nonce tells this ACK from one answering a heartbeat two intervals
    // back, which would otherwise clear the error count of a failing path.
    Association& assoc = it->second;
    Peer_Path* path = find_path(assoc, heartbeat_info_destination(info));
    if (path == nullptr || !path->hb_outstanding || heartbeat_info_nonce(info) != path->hb_nonce) {
        return;
    }

    auto now = std::chrono::steady_clock::now();
    path->hb_outstanding = false;
    update_rto(*path, std::chrono::duration_cast<std::chrono::microseconds>(now - path->hb_sent_at));
    clear_path_errors(key, *path);
    // 8.1: only the path carrying DATA answers for the association, or an
    // idle alternate would keep alive one whose data path has failed.
    if (&data_path(assoc) == path) {
        assoc.error_count = 0;
    }
    if (!path->confirmed) {
        path->confirmed = true;
        notify_peer_addr_change(key, path->address, Peer_Addr_State::ADDR_CONFIRMED);
        plan_next_probe(assoc, *path, now);
    }
    if (transmits_data(assoc.state)) {
        arm_heartbeat(key, assoc, *path);
        arm_confirmation_probes(key, assoc);
    }
}

// The Cumulative TSN Ack is applied as a SACK with no Gap Ack Blocks, except
// that the missing blocks are not a renege (3.3.8): gap-acked chunks stay so.
void SCTP_Socket::handle_shutdown(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src) {
    uint32_t cumulative_tsn_ack = std::get<shutdown_chunk_value>(chunk.chunk_value).cumulative_tsn_ack;
    bool reply_ack = false;
    bool violation = false;
    bool first_shutdown = false;
    bool advanced = false;
    std::vector<sockaddr_in> t3_restarts;
    uint32_t peer_tag;
    sockaddr_in destination;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(key);
        if (it == associations.end()) {
            return;
        }
        Association& assoc = it->second;
        peer_tag = assoc.peer_ver_tag;
        destination = reply_destination(assoc, src);

        switch (assoc.state) {
            case COOKIE_WAIT:
            case COOKIE_ECHOED:
                return;
            case SHUTDOWN_SENT:
                assoc.state = SHUTDOWN_ACK_SENT;
                [[fallthrough]];
            case SHUTDOWN_ACK_SENT:
                reply_ack = true;
                break;
            default:
                if (!tsn_lt(cumulative_tsn_ack, assoc.next_tsn)) {
                    violation = true;
                    break;
                }
                advanced = tsn_gt(cumulative_tsn_ack, assoc.cumulative_tsn_ack);
                if (advanced) {
                    bool acked_new = false;
                    std::vector<bool> acked_on(assoc.peer_address_list.size(), false);
                    for (auto entry = assoc.outstanding_data.begin(); entry != assoc.outstanding_data.end();) {
                        if (!tsn_lte(entry->first, cumulative_tsn_ack)) {
                            ++entry;
                            continue;
                        }
                        if (!entry->second.gap_acked) {
                            Peer_Path& path = destination_of(assoc, entry->second);
                            acked_on[index_of(assoc, path)] = true;
                            clear_path_errors(key, path);
                            acked_new = true;
                        }
                        entry = assoc.outstanding_data.erase(entry);
                    }
                    for (size_t i = 0; i < acked_on.size(); ++i) {
                        if (acked_on[i]) {
                            t3_restarts.push_back(assoc.peer_address_list[i].address);
                        }
                    }
                    assoc.cumulative_tsn_ack = cumulative_tsn_ack;
                    if (assoc.has_rtt_measurement_tsn && tsn_lte(assoc.rtt_measurement_tsn, cumulative_tsn_ack)) {
                        assoc.has_rtt_measurement_tsn = false;
                    }
                    if (assoc.in_fast_recovery && tsn_gte(cumulative_tsn_ack, assoc.fast_recovery_exit_tsn)) {
                        assoc.in_fast_recovery = false;
                    }
                    if (acked_new) {
                        assoc.error_count = 0;
                    }
                }
                first_shutdown = assoc.state != SHUTDOWN_RECEIVED;
                assoc.state = SHUTDOWN_RECEIVED;
        }
    }

    if (violation) {
        abort_association(key, header, src, {error_cause{CAUSE_PROTOCOL_VIOLATION, {}}});
        return;
    }
    if (reply_ack) {
        enqueue_packet(Deliverable{key, destination, build_shutdown_ack(header.des_port, header.src_port, peer_tag)});
        restart_t2(key);
        return;
    }

    if (first_shutdown) {
        notifications.enqueue(Notification{Notification_Type::SCTP_SHUTDOWN_EVENT, key, 0, Shutdown_Event{}});
    }
    if (advanced) {
        sends.remove_acked_retransmissions(key, sack_chunk_value{cumulative_tsn_ack, 0, 0, 0, {}, {}});
        for (const sockaddr_in& path : t3_restarts) {
            restart_t3(key, path);
        }
    }
    do_next_shutdown_step(key);
}

void SCTP_Socket::handle_shutdown_ack(const SCTP_Common_Header& header, const SCTP_Chunk&, const Association_Key& key, const sockaddr_in& src) {
    uint32_t peer_tag;
    sockaddr_in destination;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(key);
        if (it == associations.end() || (it->second.state != SHUTDOWN_SENT && it->second.state != SHUTDOWN_ACK_SENT)) {
            return;
        }
        peer_tag = it->second.peer_ver_tag;
        destination = reply_destination(it->second, src);
    }

    remove_association(key);
    enqueue_packet(Deliverable{key, destination, build_shutdown_complete(header.des_port, header.src_port, peer_tag, false)});
    notify_assoc_change(key, Assoc_Change_State::SHUTDOWN_COMP);
}

void SCTP_Socket::handle_shutdown_complete(const SCTP_Common_Header&, const SCTP_Chunk&, const Association_Key& key, const sockaddr_in&) {
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(key);
        if (it == associations.end() || it->second.state != SHUTDOWN_ACK_SENT) {
            return;
        }
    }

    remove_association(key);
    notify_assoc_change(key, Assoc_Change_State::SHUTDOWN_COMP);
}

void SCTP_Socket::handle_sack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src) {
    const auto& sack = std::get<sack_chunk_value>(chunk.chunk_value);

    bool acks_unsent;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(key);
        if (association == associations.end() || !transmits_data(association->second.state)) {
            return;
        }
        uint32_t next_tsn = association->second.next_tsn;
        acks_unsent = !tsn_lt(sack.cumulative_tsn_ack, next_tsn)
            || std::any_of(sack.gap_ack_blocks.begin(), sack.gap_ack_blocks.end(), [&](const sack_gap_ack_block& block) {
                return !tsn_lt(sack.cumulative_tsn_ack + block.end, next_tsn);
            });
    }
    if (acks_unsent) {
        abort_association(key, header, src, {error_cause{CAUSE_PROTOCOL_VIOLATION, {}}});
        return;
    }

    bool schedule_fast_retransmission = false;
    bool entered_fast_recovery = false;
    std::vector<std::pair<sockaddr_in, T3_Action>> t3_actions;

    { // Scope for association lock
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(key);
        if (association == associations.end() || !transmits_data(association->second.state)) {
            return;
        }

        Association& assoc = association->second;
        if (tsn_lt(sack.cumulative_tsn_ack, assoc.cumulative_tsn_ack)) {
            return;
        }
        uint32_t previous_cumulative_tsn_ack = assoc.cumulative_tsn_ack;
        bool cumulative_ack_advanced =
            tsn_gt(sack.cumulative_tsn_ack, previous_cumulative_tsn_ack);

        std::vector<Peer_Path>& paths = assoc.peer_address_list;
        std::vector<Path_Ack> acks(paths.size());
        auto ack_of = [&](const Outstanding_Data& outstanding) -> Path_Ack& {
            return acks[index_of(assoc, destination_of(assoc, outstanding))];
        };
        for (size_t i = 0; i < paths.size(); ++i) {
            acks[i].flight_before = bytes_in_flight(assoc, &paths[i]);
        }
        for (const auto& [tsn, outstanding] : assoc.outstanding_data) {
            if (outstanding.gap_acked) {
                continue;
            }
            Path_Ack& ack = ack_of(outstanding);
            if (!ack.have_earliest || tsn - assoc.cumulative_tsn_ack < ack.earliest_tsn - assoc.cumulative_tsn_ack) {
                ack.have_earliest = true;
                ack.earliest_tsn = tsn;
            }
        }

        bool newly_acknowledged = false;
        std::vector<uint32_t> reneged_tsns;
        bool have_htna = false;
        uint32_t htna = 0;
        bool have_highest_reported = false;
        uint32_t highest_reported = sack.cumulative_tsn_ack;
        auto now = std::chrono::steady_clock::now();

        for (const auto& [tsn, outstanding] : assoc.outstanding_data) {
            bool acknowledged = sack_acknowledges(sack, tsn);
            if (acknowledged && !outstanding.gap_acked) {
                if (!have_htna || tsn_gt(tsn, htna)) {
                    htna = tsn;
                    have_htna = true;
                }
            }
            if (acknowledged
                    && (!have_highest_reported
                        || tsn_gt(tsn, highest_reported))) {
                highest_reported = tsn;
                have_highest_reported = true;
            }
        }

        for (auto it = assoc.outstanding_data.begin(); it != assoc.outstanding_data.end();) {
            uint32_t tsn = it->first;
            Outstanding_Data& outstanding = it->second;
            bool acknowledged = sack_acknowledges(sack, tsn);
            bool cumulatively_acknowledged = tsn_lte(tsn, sack.cumulative_tsn_ack);

            if (acknowledged && !outstanding.gap_acked) {
                Path_Ack& ack = ack_of(outstanding);
                newly_acknowledged = true;
                ack.newly_acknowledged = true;
                ack.bytes_acked += static_cast<uint32_t>(data_chunk_wire_size(outstanding.data));
                if (assoc.has_rtt_measurement_tsn && tsn == assoc.rtt_measurement_tsn && !outstanding.retransmitted) {
                    update_rto(destination_of(assoc, outstanding), std::chrono::duration_cast<std::chrono::microseconds>(now - outstanding.first_sent));
                    assoc.has_rtt_measurement_tsn = false;
                }
            }

            if (cumulatively_acknowledged) {
                if (outstanding.retransmitted) {
                    assoc.acked_retransmissions.push_back(Acked_Retransmission{
                        tsn, static_cast<uint32_t>(data_chunk_wire_size(outstanding.data)), outstanding.destination});
                    if (assoc.acked_retransmissions.size() > ACKED_RETRANSMISSION_MEMORY) {
                        assoc.acked_retransmissions.pop_front();
                    }
                }
                it = assoc.outstanding_data.erase(it);
                continue;
            }

            if (acknowledged) {
                outstanding.gap_acked = true;
                outstanding.pending_retransmission = false;
            } else if (outstanding.gap_acked) {
                outstanding.gap_acked = false;
                ack_of(outstanding).reneged = true;
                reneged_tsns.push_back(tsn);
                if (!outstanding.fast_retransmitted) {
                    ++outstanding.missing_reports;
                }
            }
            ++it;
        }

        assoc.cumulative_tsn_ack = sack.cumulative_tsn_ack;
        std::vector<uint32_t> duplicates(paths.size(), 0);
        duplicate_bytes(assoc, sack, duplicates);
        if (newly_acknowledged) {
            assoc.error_count = 0;
        }
        for (size_t i = 0; i < paths.size(); ++i) {
            Path_Ack& ack = acks[i];
            if (ack.newly_acknowledged) {
                clear_path_errors(key, paths[i]);
                paths[i].single_packet_in_flight = false;
            }
            if (ack.newly_acknowledged || duplicates[i] > 0) {
                grow_cwnd(assoc, paths[i], ack.bytes_acked, duplicates[i], ack.flight_before);
            }
            bool sent_here = std::any_of(assoc.outstanding_data.begin(), assoc.outstanding_data.end(), [&](const auto& entry) {
                return &destination_of(assoc, entry.second) == &paths[i];
            });
            if (!sent_here) {
                paths[i].partial_bytes_acked = 0;
            }
        }

        for (auto& [tsn, outstanding] : assoc.outstanding_data) {
            if (outstanding.gap_acked || outstanding.fast_retransmitted) {
                continue;
            }

            bool was_reneged = std::find(
                reneged_tsns.begin(), reneged_tsns.end(), tsn)
                != reneged_tsns.end();
            bool reported_missing = false;
            if (assoc.in_fast_recovery && cumulative_ack_advanced) {
                reported_missing = have_highest_reported
                    && tsn_lt(tsn, highest_reported);
            } else {
                reported_missing = have_htna && tsn_lt(tsn, htna);
            }

            // Reneging was already counted once while applying the Gap Ack
            // state transition above.
            if (reported_missing && !was_reneged) {
                ++outstanding.missing_reports;
            }
            if (outstanding.missing_reports >= 3) {
                outstanding.fast_retransmitted = true;
                outstanding.pending_retransmission = true;
                ack_of(outstanding).fast_retransmitted = true;
                schedule_fast_retransmission = true;
            }
        }

        if (schedule_fast_retransmission && !assoc.in_fast_recovery) {
            for (size_t i = 0; i < paths.size(); ++i) {
                if (acks[i].fast_retransmitted) {
                    paths[i].ssthresh = std::max(paths[i].cwnd / 2, 4U * assoc.pmdcs);
                    paths[i].cwnd = paths[i].ssthresh;
                    paths[i].partial_bytes_acked = 0;
                }
            }

            if (!assoc.outstanding_data.empty()) {
                assoc.in_fast_recovery = true;
                assoc.fast_recovery_exit_tsn = assoc.outstanding_data.rbegin()->first;
                entered_fast_recovery = true;
            }
        }

        if (assoc.in_fast_recovery
                && tsn_gte(sack.cumulative_tsn_ack,
                           assoc.fast_recovery_exit_tsn)) {
            assoc.in_fast_recovery = false;
        }

        if (!assoc.has_rtt_measurement_tsn) {
            bool found = false;
            uint32_t candidate_tsn = 0;
            uint32_t candidate_distance = 0;
            for (const auto& [tsn, outstanding] : assoc.outstanding_data) {
                if (outstanding.gap_acked || outstanding.retransmitted) {
                    continue;
                }
                bool ambiguous = std::any_of(
                    assoc.outstanding_data.begin(),
                    assoc.outstanding_data.end(),
                    [&](const auto& other) {
                        return other.second.retransmitted && tsn_lte(other.first, tsn) && other.second.last_sent >= outstanding.first_sent;
                    });
                if (ambiguous) {
                    continue;
                }
                uint32_t distance = tsn - assoc.cumulative_tsn_ack;
                if (!found || distance < candidate_distance) {
                    found = true;
                    candidate_tsn = tsn;
                    candidate_distance = distance;
                }
            }
            if (found) {
                assoc.has_rtt_measurement_tsn = true;
                assoc.rtt_measurement_tsn = candidate_tsn;
            }
        }

        size_t flight_size = bytes_in_flight(assoc);
        assoc.peer_rwnd = flight_size >= sack.a_rwnd ? 0 : sack.a_rwnd - static_cast<uint32_t>(flight_size);
        assoc.peer_max_rwnd = std::max(assoc.peer_max_rwnd, sack.a_rwnd);
        assoc.sack_since_t3 = true;
        if (sack.a_rwnd > 0) {
            assoc.zero_window_probing = false;
        }

        // 6.3.2 R2-R4, and 7.2.4 step 4.
        for (size_t i = 0; i < paths.size(); ++i) {
            const Path_Ack& ack = acks[i];
            auto earliest = assoc.outstanding_data.find(ack.earliest_tsn);
            bool retransmits_earliest = schedule_fast_retransmission && ack.have_earliest
                && earliest != assoc.outstanding_data.end() && earliest->second.pending_retransmission;
            if (!has_unacknowledged_data(assoc, paths[i])) {
                if (expirations.is_active(Expiration_Key{key, Expiration_Timer_Type::T3_RTX, path_key(paths[i].address)})) {
                    t3_actions.emplace_back(paths[i].address, T3_Action::STOP);
                }
            } else if ((ack.have_earliest && sack_acknowledges(sack, ack.earliest_tsn)) || retransmits_earliest) {
                t3_actions.emplace_back(paths[i].address, T3_Action::RESTART);
            } else if (ack.reneged) {
                t3_actions.emplace_back(paths[i].address, T3_Action::START);
            }
        }
    }

    sends.remove_acked_retransmissions(key, sack);
    if (entered_fast_recovery) {
        schedule_pending_retransmission(key);
    }
    for (const auto& [destination, action] : t3_actions) {
        switch (action) {
            case T3_Action::STOP:
                cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::T3_RTX, path_key(destination)});
                break;
            case T3_Action::RESTART:
                restart_t3(key, destination);
                break;
            case T3_Action::START:
                start_t3_if_stopped(key, destination);
                break;
        }
    }
    do_next_shutdown_step(key);
}

void SCTP_Socket::send_sack(const Association_Key& key) {
    SCTP_Packet sack_packet;
    sockaddr_in destination;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(key);
        if (association == associations.end()
                || !receives_data(association->second.state)) {
            return;
        }
        sack_packet = make_sack(key, association->second);
        destination = data_path(association->second).address;
    }
    cancel_expiration(
        Expiration_Key{key, Expiration_Timer_Type::DELAYED_SACK});
    enqueue_packet(Deliverable{key, destination, std::move(sack_packet)});
}

// Caller must hold associations_mutex.
SCTP_Packet SCTP_Socket::make_sack(const Association_Key& key, Association& assoc) {
    std::vector<sack_gap_ack_block> gaps;
    for (const auto& [tsn, data] : assoc.tsn_ooo_buffer) {
        uint16_t offset = static_cast<uint16_t>(tsn - assoc.last_peer_tsn);
        (void)data;
        if (gaps.empty() || static_cast<uint32_t>(gaps.back().end) + 1 != offset) {
            gaps.push_back({offset, offset});
        } else {
            gaps.back().end = offset;
        }
    }

    // Receiver SWS avoidance: an opening too small to be worth a packet is held
    // back until it grows. A shrinking window is always advertised as it is.
    uint32_t window = receive_window(key, assoc);
    uint32_t believed = peer_view_of_window(assoc);
    if (window > believed && window - believed < std::min<uint32_t>(RWND / 2, assoc.pmdcs)) {
        window = believed;
    }
    assoc.our_rwnd = window;
    assoc.received_since_sack = 0;

    SCTP_Packet sack_packet = build_sack(
        ntohs(local_address.sin_port),
        ntohs(key.address.sin_port),
        assoc.peer_ver_tag,
        assoc.last_peer_tsn,
        window,
        std::move(gaps),
        std::move(assoc.duplicate_tsns)
    );
    assoc.duplicate_tsns.clear();
    assoc.delayed_sack_packet_count = 0;
    return sack_packet;
}

void SCTP_Socket::handle_delayed_sack_expiration(
        const Association_Key& location) {
    send_sack(location);
}

void SCTP_Socket::handle_data_packet(
    const SCTP_Packet& packet,
    const Association_Key& key,
    const sockaddr_in& src,
    bool acknowledge_immediately
) {

    // 3.3.1: a DATA chunk carrying no user data is fatal to the association.
    for (const auto& chunk : packet.chunks) {
        if (chunk.chunk_header.type != DATA) {
            continue;
        }
        const auto& data = std::get<data_chunk_value>(chunk.chunk_value);
        if (data.user_data.empty()) {
            abort_association(key, packet.header, src, {error_cause{CAUSE_NO_USER_DATA, be32_bytes(data.tsn)}});
            return;
        }
    }

    bool have_data = false;
    bool reply_shutdown = false;
    SCTP_Packet shutdown_reply;
    bool send_immediately = acknowledge_immediately;
    bool start_delayed_timer = false;
    std::vector<error_cause> invalid_streams;
    std::vector<Delivery> delivered;
    bool violation = false;
    uint32_t peer_tag = 0;
    sockaddr_in destination;
    sockaddr_in reply_to;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(key);
        if (it == associations.end() || !receives_data(it->second.state)) {
            return;
        }

        Association& assoc = it->second;
        peer_tag = assoc.peer_ver_tag;
        destination = data_path(assoc).address;
        reply_to = reply_destination(assoc, src);
        bool hole_existed = !assoc.tsn_ooo_buffer.empty();
        bool saw_duplicate = false;
        bool dropped = false;
        size_t used = receives.buffered_bytes(key) + held_bytes(assoc);

        for (const auto& chunk : packet.chunks) {
            if (chunk.chunk_header.type != DATA) {
                continue;
            }
            have_data = true;
            send_immediately = send_immediately
                || (chunk.chunk_header.flag & DATA_IMMEDIATE_SACK_FLAG) != 0;
            const auto& data = std::get<data_chunk_value>(chunk.chunk_value);
            assoc.received_since_sack += static_cast<uint32_t>(data.user_data.size());
            uint32_t tsn = data.tsn;
            // RFC 9260 6.5: an invalid stream is still acked, but reported and never delivered.
            bool valid_stream = data.stream_identifier < assoc.in_streams;
            if (tsn_lte(tsn, assoc.last_peer_tsn) || assoc.tsn_ooo_buffer.count(tsn) != 0) {
                assoc.duplicate_tsns.push_back(tsn);
                saw_duplicate = true;
                continue;
            }
            // Past what a Gap Ack Block can report, and past any window we can offer.
            if (tsn - assoc.last_peer_tsn > UINT16_MAX || (used >= RWND && !make_room(assoc, tsn, used)
                    && !(tsn == assoc.last_peer_tsn + 1 && blocked_on_cumulative_tsn(assoc)))) {
                dropped = true;
                continue;
            }
            if (valid_stream) {
                used += data.user_data.size();
            } else {
                invalid_streams.push_back(invalid_stream_cause(data.stream_identifier));
            }
            if (tsn == assoc.last_peer_tsn + 1) {
                assoc.last_peer_tsn = tsn;
                if (!reassemble(assoc, data, valid_stream, delivered) || !read_ooo_buffer(assoc, delivered)) {
                    violation = true;
                    break;
                }
            } else {
                auto inserted = assoc.tsn_ooo_buffer.emplace(tsn, Held_Chunk{data});
                if (!valid_stream) {
                    inserted.first->second.data.user_data.clear();
                } else if (!assemble_early(assoc, tsn, delivered)) {
                    violation = true;
                    break;
                }
            }
        }

        if (!have_data) {
            return;
        }
        // Once the window cannot take another full-size chunk, the rest of the
        // message could only arrive after the ULP reads, so it gets what there is.
        // Only the message next in its stream can go up early: the ULP sees it
        // through to its end before anything else.
        Reassembly& message = assoc.reassembly;
        if (message.open && !message.bytes.empty() && used + assoc.pmdcs > RWND
                && (message.unordered || message.ssn == assoc.inbound_streams[message.stream].next_ssn)) {
            delivered.push_back(Delivery{std::move(message.bytes), false, message.stream});
            message.bytes.clear();
            message.partially_delivered = true;
            if (!message.unordered) {
                advance_stream(assoc, message.stream, delivered);
            }
        }
        // 9.2: in SHUTDOWN-SENT every DATA packet is answered with a SHUTDOWN,
        // and with a SACK as well whenever the SHUTDOWN alone would not say it all.
        if (assoc.state == SHUTDOWN_SENT) {
            reply_shutdown = true;
            shutdown_reply = build_shutdown(ntohs(local_address.sin_port), ntohs(key.address.sin_port), peer_tag, assoc.last_peer_tsn);
            if (!assoc.tsn_ooo_buffer.empty() || !assoc.duplicate_tsns.empty() || dropped) {
                shutdown_reply.chunks.push_back(std::move(make_sack(key, assoc).chunks[0]));
            }
        }
        send_immediately = send_immediately || saw_duplicate || dropped
            || hole_existed || !assoc.tsn_ooo_buffer.empty();
        if (!reply_shutdown && !send_immediately) {
            ++assoc.delayed_sack_packet_count;
            send_immediately = assoc.delayed_sack_packet_count >= 2;
            start_delayed_timer = !send_immediately;
        }
    }

    if (violation) {
        abort_association(key, packet.header, src, {error_cause{CAUSE_PROTOCOL_VIOLATION, {}}});
        return;
    }
    for (auto& delivery : delivered) {
        receives.push(key, std::move(delivery.bytes), delivery.complete, delivery.stream);
    }
    if (!invalid_streams.empty()) {
        send_error(packet.header, key, reply_to, peer_tag, std::move(invalid_streams));
    }
    if (reply_shutdown) {
        cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::DELAYED_SACK});
        enqueue_packet(Deliverable{key, destination, std::move(shutdown_reply)});
        restart_t2(key);
    } else if (send_immediately) {
        send_sack(key);
    } else if (start_delayed_timer) {
        schedule_expiration(
            Expiration_Key{key, Expiration_Timer_Type::DELAYED_SACK},
            std::chrono::steady_clock::now() + sctp_parameters::SACK_DELAY,
            Deliverable{key, {}, SCTP_Packet{}});
    }
}

// Receive buffer space not yet taken by messages waiting for the ULP or by DATA
// held for reordering or reassembly, in bytes of user data.
uint32_t SCTP_Socket::receive_window(const Association_Key& key, const Association& assoc) {
    size_t used = receives.buffered_bytes(key) + held_bytes(assoc);
    return used >= RWND ? 0 : static_cast<uint32_t>(RWND - used);
}

void SCTP_Socket::maybe_send_window_update(const Association_Key& key) {
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(key);
        if (association == associations.end() || !receives_data(association->second.state)) {
            return;
        }
        uint32_t window = receive_window(key, association->second);
        if (window < peer_view_of_window(association->second) + RWND / 4) {
            return;
        }
    }
    send_sack(key);
}

bool SCTP_Socket::read_ooo_buffer(Association& assoc, std::vector<Delivery>& delivered) {
    uint32_t tsn = assoc.last_peer_tsn + 1;
    for (auto it = assoc.tsn_ooo_buffer.find(tsn); it != assoc.tsn_ooo_buffer.end(); it = assoc.tsn_ooo_buffer.find(++tsn)) {
        const Held_Chunk& held = it->second;
        if (!reassemble(assoc, held.data, !held.assembled && !held.data.user_data.empty(), delivered)) {
            return false;
        }
        assoc.tsn_ooo_buffer.erase(it);
    }
    assoc.last_peer_tsn = tsn - 1;
    return true;
}
