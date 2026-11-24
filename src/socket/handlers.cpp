// Inbound chunk handling: packet validation and dispatch, the four-way
// handshake, SACK processing and fast retransmit, SACK generation, and DATA
// reception with the out-of-order buffer, reassembly and ordered delivery.

#include <sctp/socket.hpp>
#include <sctp/platform/compat.hpp>
#include <sctp/protocol/tsn.hpp>
#include "protocol/checksum.hpp"
#include "protocol/serialize.hpp"
#include "protocol/builders.hpp"
#include "socket/internal.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <mutex>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <utility>
#include <vector>

namespace {
    // User data held back from the ULP: for reordering, reassembly, or ordered
    // delivery.
    size_t held_bytes(const TCB_Receive_Side& receive) {
        size_t total = receive.reassembly.bytes.size();
        for (const auto& held : receive.ooo | std::views::values) {
            total += held.data.user_data.size();
        }
        for (const auto& stream : receive.streams | std::views::values) {
            for (const auto& early : stream.early | std::views::values) {
                total += early.bytes.size();
            }
        }
        for (const auto& delivery : receive.held_deliveries) {
            total += delivery.bytes.size();
        }
        return total;
    }

    // What the peer believes is left of our window: what we last advertised,
    // less what it has sent us since.
    uint32_t peer_view_of_window(const TCB_Receive_Side& receive) {
        return receive.our_rwnd > receive.received_since_sack ? receive.our_rwnd - receive.received_since_sack : 0;
    }

    // Whether anything held is complete and waiting only on the TSN at the
    // Cumulative TSN Ack point. Nothing could be dropped to make room for it.
    bool blocked_on_cumulative_tsn(const TCB_Receive_Side& receive) {
        return std::ranges::any_of(receive.ooo | std::views::values, &Held_Chunk::assembled)
            || std::ranges::any_of(receive.streams | std::views::values, [](const Inbound_Stream& stream) {
                return !stream.early.empty();
            });
    }

    // Bytes the SACK reports as duplicates, per destination. An acked
    // retransmission is consumed when matched, so each is counted once.
    uint32_t duplicate_bytes(Association_TCB& assoc, const sack_chunk_value& sack, std::vector<uint32_t>& per_path) {
        uint32_t total = 0;
        for (uint32_t tsn : sack.duplicate_tsns) {
            auto outstanding = assoc.send.outstanding.find(tsn);
            uint32_t size = 0;
            sockaddr_in destination{};
            if (outstanding != assoc.send.outstanding.end()) {
                size = static_cast<uint32_t>(data_chunk_wire_size(outstanding->second.data));
                destination = outstanding->second.destination;
            } else {
                auto& acked = assoc.send.acked_retransmissions;
                auto match = std::ranges::find(acked, tsn, &Acked_Retransmission::tsn);
                if (match == acked.end()) {
                    continue;
                }
                size = match->size;
                destination = match->destination;
                acked.erase(match);
            }
            Peer_Path* path = find_path(assoc, destination);
            per_path[static_cast<size_t>((path != nullptr ? path : &primary(assoc)) - assoc.paths.list.data())] += size;
            total += size;
        }
        return total;
    }

    // With the receive buffer full, a new chunk above everything received is
    // dropped. One below it instead takes the place of the highest TSN held for
    // reordering, which is dropped even if a Gap Ack Block already reported it.
    bool make_room(TCB_Receive_Side& receive, uint32_t tsn, size_t& used) {
        auto highest = std::ranges::find_last_if(receive.ooo, [](const auto& entry) {
            return !entry.second.assembled;
        }).begin();
        if (highest == receive.ooo.end() || tsn_gt(tsn, highest->first)) {
            return false;
        }
        used -= highest->second.data.user_data.size();
        receive.ooo.erase(highest);
        return true;
    }

    bool partial_delivery_open(const TCB_Receive_Side& receive) {
        return receive.reassembly.open && receive.reassembly.partially_delivered;
    }

    void hand_up(TCB_Receive_Side& receive, Delivery delivery, std::vector<Delivery>& delivered) {
        (partial_delivery_open(receive) ? receive.held_deliveries : delivered).push_back(std::move(delivery));
    }

    void advance_stream(TCB_Receive_Side& receive, uint16_t stream_id, std::vector<Delivery>& delivered) {
        Inbound_Stream& stream = receive.streams[stream_id];
        ++stream.next_ssn;
        for (auto next = stream.early.find(stream.next_ssn); next != stream.early.end(); next = stream.early.find(++stream.next_ssn)) {
            hand_up(receive, std::move(next->second), delivered);
            stream.early.erase(next);
        }
    }

    // False if the SSN was already delivered or is already waiting: the peer
    // reused it.
    bool order_message(TCB_Receive_Side& receive, uint16_t stream_id, uint16_t ssn, bool unordered, std::vector<uint8_t> bytes, uint32_t ppid, std::vector<Delivery>& delivered) {
        Delivery message{std::move(bytes), true, stream_id, ppid};
        if (unordered) {
            hand_up(receive, std::move(message), delivered);
            return true;
        }
        Inbound_Stream& stream = receive.streams[stream_id];
        if (ssn != stream.next_ssn) {
            return ssn_gt(ssn, stream.next_ssn) && stream.early.emplace(ssn, std::move(message)).second;
        }
        hand_up(receive, std::move(message), delivered);
        advance_stream(receive, stream_id, delivered);
        return true;
    }

    // Takes the next chunk in TSN order. False if it can neither begin a message
    // nor continue the open one. Without keep_bytes only the framing is checked:
    // the stream is invalid, or the message was already assembled ahead of the
    // Cumulative TSN Ack.
    bool reassemble(TCB_Receive_Side& receive, const data_chunk_value& data, bool keep_bytes, std::vector<Delivery>& delivered) {
        Reassembly& message = receive.reassembly;
        bool begins = (data.flags & DATA_FLAG_B) != 0;
        bool ends = (data.flags & DATA_FLAG_E) != 0;
        bool unordered = (data.flags & DATA_FLAG_U) != 0;
        if (begins == message.open) {
            return false;
        }
        if (begins) {
            message = Reassembly{true, false, unordered, data.stream_identifier, data.stream_seq_num, data.payload_protocal, {}};
        } else if (data.stream_identifier != message.stream || unordered != message.unordered
                || (!unordered && data.stream_seq_num != message.ssn)) {
            return false;
        }
        message.open = !ends;
        if (!keep_bytes) {
            return true;
        }
        message.bytes.append_range(data.user_data);
        if (message.partially_delivered) {
            delivered.push_back(Delivery{std::move(message.bytes), ends, message.stream, message.ppid});
            message.bytes.clear();
            if (ends) {
                delivered.append_range(receive.held_deliveries | std::views::as_rvalue);
                receive.held_deliveries.clear();
            }
            return true;
        }
        if (!ends) {
            return true;
        }
        std::vector<uint8_t> bytes = std::move(message.bytes);
        message.bytes.clear();
        return order_message(receive, message.stream, message.ssn, message.unordered, std::move(bytes), message.ppid, delivered);
    }

    // Consumes the held chunks the Cumulative TSN Ack has just reached.
    bool read_ooo_buffer(TCB_Receive_Side& receive, std::vector<Delivery>& delivered) {
        uint32_t tsn = receive.last_peer_tsn + 1;
        for (auto it = receive.ooo.find(tsn); it != receive.ooo.end(); it = receive.ooo.find(++tsn)) {
            const Held_Chunk& held = it->second;
            if (!reassemble(receive, held.data, !held.assembled && !held.data.user_data.empty(), delivered)) {
                return false;
            }
            receive.ooo.erase(it);
        }
        receive.last_peer_tsn = tsn - 1;
        return true;
    }

    // A message lying wholly above the Cumulative TSN Ack is taken out as soon
    // as its last fragment arrives, so a gap holds back only its own stream. A
    // neighbouring fragment belongs to it when it shares its stream and
    // ordering and does not open or close another message.
    bool assemble_early(TCB_Receive_Side& receive, uint32_t tsn, std::vector<Delivery>& delivered) {
        auto usable = [&](uint32_t at) -> const data_chunk_value* {
            auto it = receive.ooo.find(at);
            if (it == receive.ooo.end() || it->second.assembled || it->second.data.user_data.empty()) {
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

        uint32_t ppid = usable(first)->payload_protocal;
        std::vector<uint8_t> bytes;
        for (uint32_t at = first;; ++at) {
            Held_Chunk& held = receive.ooo.at(at);
            bytes.append_range(held.data.user_data);
            held.data.user_data = {};
            held.assembled = true;
            if (at == last) {
                break;
            }
        }
        return order_message(receive, stream, ssn, unordered, std::move(bytes), ppid, delivered);
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
            if (std::ranges::none_of(out, [&](const sockaddr_in& seen) { return same_destination(seen, listed); })) {
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
            if (std::ranges::contains(listed, ntohl(address.sin_addr.s_addr))) {
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
            std::to_underlying(chunk.chunk_header.type),
            chunk.chunk_header.flag,
            static_cast<uint8_t>(length >> 8),
            static_cast<uint8_t>(length),
        };
        info.append_range(body);
        return error_cause{CAUSE_UNRECOGNIZED_CHUNK, std::move(info)};
    }

    // flight_before is the flightsize before this SACK was applied. It is what
    // says whether the window being grown was actually in use.
    void grow_cwnd(const TCB_Send_Side& send, Peer_Path& path, uint32_t bytes_acked, uint32_t duplicate_bytes, size_t flight_before) {
        bool cwnd_full = flight_before >= path.cwnd;
        if (path.cwnd <= path.ssthresh) {
            if (cwnd_full && !send.in_fast_recovery) {
                path.cwnd += std::min(bytes_acked, SLOW_START_INCREASE_PMDCS * pmdcs(path));
            }
            return;
        }

        path.partial_bytes_acked += bytes_acked + duplicate_bytes;
        if (path.partial_bytes_acked >= path.cwnd && cwnd_full) {
            path.partial_bytes_acked -= path.cwnd;
            path.cwnd += pmdcs(path);
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
        std::optional<uint32_t> earliest;
        bool reneged{false};
        bool fast_retransmitted{false};
    };

    size_t index_of(const Association_TCB& assoc, const Peer_Path& path) {
        return static_cast<size_t>(&path - assoc.paths.list.data());
    }

    bool contains_chunk(const SCTP_Packet& packet, Chunk_Type type) {
        return std::ranges::any_of(packet.chunks, [type](const SCTP_Chunk& chunk) {
            return chunk.chunk_header.type == type;
        });
    }

    bool carries_stale_cookie(const SCTP_Chunk& chunk) {
        return std::ranges::contains(std::get<error_chunk_value>(chunk.chunk_value).causes, CAUSE_STALE_COOKIE, &error_cause::code);
    }
}

// Unknown chunks are resolved by their type's upper bits before dispatch. A
// leading COOKIE ECHO skipped the tag check, so it gates the rest of the packet:
// an accepted cookie proves the header tag, since verify() matched it against
// the cookie's local tag, which every accepting path leaves in the TCB. An INIT
// carries no proof of origin, so it never moves where a path was last heard
// from. DATA is taken once per packet, after every other chunk, and skips the
// delayed SACK when it arrived with a COOKIE ECHO.
void SCTP_Socket::handle_recv_packet(const uint8_t* data, size_t n, const sockaddr_in& src, in_addr local) {
    if (n < SCTP_COMMON_HEADER_SIZE) {
        return;
    }
    Inbound_Datagram datagram{src, local};
    struct Handling {
        explicit Handling(const Inbound_Datagram* datagram) { inbound_datagram = datagram; }
        ~Handling() { inbound_datagram = nullptr; }
    } handling{&datagram};

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

    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    Association_Key key = association_at(peer_key(src, in_pkt.header.src_port));
    if (!associations.contains(key)) {
        for (const sockaddr_in& address : init_addresses(in_pkt, src)) {
            if (Association_Key listed = association_at(peer_key(address, in_pkt.header.src_port)); associations.contains(listed)) {
                key = listed;
                break;
            }
        }
    }

    if (!validate_verification_tag(in_pkt, key, src)) {
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

    bool carried_cookie_echo = !in_pkt.chunks.empty() && in_pkt.chunks[0].chunk_header.type == COOKIE_ECHO;
    if (carried_cookie_echo) {
        if (!handle_cookie_echo(in_pkt.header, in_pkt.chunks[0], key, src)) {
            return;
        }
    }

    if (in_pkt.chunks.empty() || in_pkt.chunks[0].chunk_header.type != INIT) {
        record_arrival(key, src, local);
    }

    if (Association_TCB* assoc = find_tcb(key); assoc != nullptr && assoc->state == SHUTDOWN_SENT) {
        assoc->paths.error_count = 0;
        restart_t2(key);
    }

    const SCTP_Common_Header& header = in_pkt.header;
    for (size_t i = carried_cookie_echo ? 1 : 0; i < in_pkt.chunks.size(); i++) {
        const SCTP_Chunk& chunk = in_pkt.chunks[i];
        switch (chunk.chunk_header.type) {
            case INIT: handle_init(header, chunk, key, src); break;
            case INIT_ACK: handle_init_ack(header, chunk, key, src); break;
            case COOKIE_ACK: handle_cookie_ack(header, chunk, key, src); break;
            case SACK: handle_sack(header, chunk, key, src); break;
            case OP_ERROR: handle_error(header, chunk, key, src); break;
            case ABORT: return handle_abort(header, chunk, key, src);
            case HEARTBEAT: handle_heartbeat(header, chunk, key, src); break;
            case HEARTBEAT_ACK: handle_heartbeat_ack(header, chunk, key, src); break;
            case SHUTDOWN: handle_shutdown(header, chunk, key, src); break;
            case SHUTDOWN_ACK: handle_shutdown_ack(header, chunk, key, src); break;
            case SHUTDOWN_COMPLETE: handle_shutdown_complete(header, chunk, key, src); break;
            default: break;
        }
    }

    handle_data_packet(in_pkt, key, src, carried_cookie_echo);

    if (!unrecognized.empty()) {
        report_unrecognized_chunks(in_pkt.header, key, src, std::move(unrecognized));
    }
}

// False if the packet goes no further, once answered as an out of the blue
// packet would be. Our SCTP port is our UDP port, so a packet for any other has
// no endpoint here. A COOKIE ECHO passes unchecked: its cookie is verified
// instead, and handle_recv_packet drops what is bundled behind it unless the
// cookie is accepted.
bool SCTP_Socket::validate_verification_tag(const SCTP_Packet& pkt, const Association_Key& key, const sockaddr_in& src) {
    if (pkt.chunks.empty()) {
        return false;
    }

    const SCTP_Chunk_Header& first = pkt.chunks[0].chunk_header;

    if (pkt.header.des_port != ntohs(local_address.sin_port)) {
        if (first.type != INIT) {
            answer_ootb(pkt, key, src);
            return false;
        }
        uint32_t initiate_tag = std::get<init_chunk_value>(pkt.chunks[0].chunk_value).initiate_tag;
        if (pkt.header.verification_tag == 0 && pkt.chunks.size() == 1 && initiate_tag != 0) {
            reply(pkt.header, key, src, initiate_tag, ABORT, error_chunk_value{});
        }
        return false;
    }

    if (first.type == INIT) {
        return pkt.header.verification_tag == 0 && pkt.chunks.size() == 1;
    }

    if (first.type == COOKIE_ECHO) {
        return true;
    }

    auto it = associations.find(key);
    if (it == associations.end()) {
        answer_ootb(pkt, key, src);
        return false;
    }

    if (first.type == ABORT || first.type == SHUTDOWN_COMPLETE) {
        uint32_t expected = (first.flag & CHUNK_FLAG_T_BIT)
            ? it->second.peer.peer_ver_tag
            : it->second.peer.this_ver_tag;
        return expected != 0 && pkt.header.verification_tag == expected;
    }

    if ((it->second.state == COOKIE_WAIT || it->second.state == COOKIE_ECHOED) && contains_chunk(pkt, SHUTDOWN_ACK)) {
        answer_ootb(pkt, key, src);
        return false;
    }

    return pkt.header.verification_tag == it->second.peer.this_ver_tag;
}

// An unattributable packet is answered with an ABORT, except where a reply
// would bounce forever or the sender is already tearing the association down.
// The rules are ordered: an ABORT anywhere in the packet outranks the rest.
void SCTP_Socket::answer_ootb(const SCTP_Packet& pkt, const Association_Key& key, const sockaddr_in& src) {
    if (contains_chunk(pkt, ABORT)) {
        return;
    }
    if (contains_chunk(pkt, SHUTDOWN_ACK)) {
        return reply(pkt.header, key, src, pkt.header.verification_tag, SHUTDOWN_COMPLETE, empty_chunk_value{}, CHUNK_FLAG_T_BIT);
    }
    bool stale_cookie = std::ranges::any_of(pkt.chunks, [](const SCTP_Chunk& chunk) {
        return chunk.chunk_header.type == OP_ERROR && carries_stale_cookie(chunk);
    });
    if (!stale_cookie && !contains_chunk(pkt, SHUTDOWN_COMPLETE) && !contains_chunk(pkt, COOKIE_ACK)) {
        reply(pkt.header, key, src, pkt.header.verification_tag, ABORT, error_chunk_value{}, CHUNK_FLAG_T_BIT);
    }
}

// After dispatch: a bundled COOKIE ECHO may have created the TCB. COOKIE_WAIT
// has no peer tag to address the report with.
void SCTP_Socket::report_unrecognized_chunks(const SCTP_Common_Header& header, const Association_Key& key, const sockaddr_in& src, std::vector<error_cause> causes) {
    Association_TCB* assoc = find_tcb(key);
    if (assoc == nullptr || assoc->state == COOKIE_WAIT) {
        return;
    }
    size_t size = SCTP_CHUNK_HEADER_SIZE;
    auto fits = causes.begin();
    for (; fits != causes.end(); ++fits) {
        size += (SCTP_CHUNK_HEADER_SIZE + fits->info.size() + 3) & ~size_t{3};
        if (size > amdcs(*assoc)) {
            break;
        }
    }
    causes.erase(fits, causes.end());
    if (!causes.empty()) {
        reply(header, key, reply_destination(*assoc, src), assoc->peer.peer_ver_tag, OP_ERROR, error_chunk_value{std::move(causes)});
    }
}

// An INIT carries no proof of origin, so an ABORT answering an invalid one is
// sent under the INIT's own Initiate Tag where it has one, closing only the
// association it asks for and never a TCB already held for the peer. In
// COOKIE_WAIT the INIT ACK goes to the primary path: the address the ULP gave,
// which the INIT must have listed to have found this TCB.
void SCTP_Socket::handle_init(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src) {
    const auto& init = std::get<init_chunk_value>(chunk.chunk_value);
    if (init.initiate_tag == 0) {
        reply(header, key, src, header.verification_tag, ABORT, error_chunk_value{{error_cause{CAUSE_INVALID_MANDATORY_PARAM, {}}}}, CHUNK_FLAG_T_BIT);
        return;
    }
    if (init.out_streams == 0 || init.in_streams == 0) {
        reply(header, key, src, init.initiate_tag, ABORT, error_chunk_value{{error_cause{CAUSE_INVALID_MANDATORY_PARAM, {}}}});
        return;
    }
    Parameter_Scan params = scan_init(init);
    std::vector<uint8_t> host_name;
    if (find_parameter(params.recognized, PARAM_HOST_NAME_ADDRESS, host_name)) {
        reply(header, key, src, init.initiate_tag, ABORT, error_chunk_value{{unresolvable_address_cause(host_name)}});
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
    if (Association_TCB* existing = find_tcb(key)) {
        Association_TCB& assoc = *existing;
        switch (assoc.state) {
            case SHUTDOWN_ACK_SENT:
                return reply(header, key, reply_destination(assoc, src), assoc.peer.peer_ver_tag, SHUTDOWN_ACK, empty_chunk_value{});
            case COOKIE_WAIT:
                local_tag = assoc.peer.this_ver_tag;
                local_tsn = assoc.send.next_tsn;
                destination = primary(assoc).udp_address;
                break;
            default: {
                auto added = addresses | std::views::filter([&](const sockaddr_in& address) {
                    return find_path(assoc, address) == nullptr;
                }) | std::ranges::to<std::vector>();
                if (!added.empty()) {
                    return reply(header, key, src, init.initiate_tag, ABORT, error_chunk_value{new_address_causes(added, params.recognized)});
                }
                if (assoc.state == COOKIE_ECHOED) {
                    local_tag = assoc.peer.this_ver_tag;
                    local_tsn = assoc.send.next_tsn;
                }
                if (assoc.peer.local_tie_tag == 0) {
                    assoc.peer.local_tie_tag = generate_nonzero_tag();
                    assoc.peer.peer_tie_tag = generate_nonzero_tag();
                }
                local_tie_tag = assoc.peer.local_tie_tag;
                peer_tie_tag = assoc.peer.peer_tie_tag;
            }
        }
    }

    auto other_addresses = addresses | std::views::drop(1) | std::views::transform([](const sockaddr_in& address) {
        return ntohl(address.sin_addr.s_addr);
    }) | std::ranges::to<std::vector<uint32_t>>();
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

    std::vector<in_addr> advertised = advertised_addresses();
    size_t init_ack_size = SCTP_CHUNK_HEADER_SIZE + 16 + SCTP_CHUNK_HEADER_SIZE + ((cookie.size() + 3) & ~size_t{3})
        + advertised.size() * (SCTP_CHUNK_HEADER_SIZE + 4);
    trim_reports(params.reported, BASE_PMDCS - std::min<size_t>(BASE_PMDCS, init_ack_size), SCTP_CHUNK_HEADER_SIZE);

    enqueue_packet(Deliverable{key, destination, build_init_ack(
        header.des_port,
        header.src_port,
        init.initiate_tag,
        local_tag,
        local_tsn,
        cookie,
        params.reported,
        advertised
    )});
}

// A refused INIT ACK takes the TCB with it whether or not the optional ABORT
// gets through; the ABORT follows remove_association's purge and, with no
// Initiate Tag to use, reflects our own. Unrecognized parameters are reported in
// an ERROR bundled behind the COOKIE ECHO, trimmed to fit beside it.
void SCTP_Socket::handle_init_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src) {
    const auto& init_ack = std::get<init_chunk_value>(chunk.chunk_value);

    Association_TCB* found = find_tcb(key);
    if (found == nullptr || found->state != COOKIE_WAIT) {
        return;
    }

    auto refuse = [&](error_cause cause) {
        remove_association(key, Assoc_Change_State::CANT_STR_ASSOC);
        bool reflected = init_ack.initiate_tag == 0;
        reply(header, key, src, reflected ? header.verification_tag : init_ack.initiate_tag, ABORT, error_chunk_value{{std::move(cause)}}, reflected ? CHUNK_FLAG_T_BIT : 0);
    };
    if (init_ack.initiate_tag == 0) {
        return refuse(error_cause{CAUSE_INVALID_MANDATORY_PARAM, {}});
    }
    Parameter_Scan params = scan_init_ack(init_ack);
    std::vector<uint8_t> cookie;
    if (!find_parameter(params.recognized, PARAM_STATE_COOKIE, cookie)) {
        return refuse(missing_parameter_cause(PARAM_STATE_COOKIE));
    }
    if (init_ack.out_streams == 0 || init_ack.in_streams == 0) {
        return refuse(error_cause{CAUSE_INVALID_MANDATORY_PARAM, {}});
    }
    std::vector<uint8_t> host_name;
    if (find_parameter(params.recognized, PARAM_HOST_NAME_ADDRESS, host_name)) {
        return refuse(unresolvable_address_cause(host_name));
    }

    Association_TCB& assoc = *found;
    add_peer_addresses(key, assoc, transport_addresses(src, params.recognized));
    sockaddr_in destination = reply_destination(assoc, src);
    assoc.receive.last_peer_tsn = init_ack.initial_tsn - 1;
    assoc.peer.peer_ver_tag = init_ack.initiate_tag;
    assoc.send.peer_rwnd = init_ack.a_rwnd;
    assoc.send.peer_max_rwnd = init_ack.a_rwnd;
    assoc.send.out_streams = std::min(LOCAL_OUT_STREAMS, init_ack.in_streams);
    assoc.receive.in_streams = std::min(LOCAL_MAX_IN_STREAMS, init_ack.out_streams);
    assoc.send.next_ssn.assign(assoc.send.out_streams, 0);
    assoc.state = COOKIE_ECHOED;
    trim_reports(params.reported, amdcs(assoc) - std::min<size_t>(amdcs(assoc), 3 * SCTP_CHUNK_HEADER_SIZE + ((cookie.size() + 3) & ~size_t{3})), 0);
    cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::T1_INIT});
    sends.remove_retransmissions_of_type(key, INIT);
    SCTP_Packet echo = build_packet(header.des_port, header.src_port, assoc.peer.peer_ver_tag, COOKIE_ECHO, cookie_echo_chunk_value{std::move(cookie)});
    if (!params.reported.empty()) {
        std::vector<uint8_t> info;
        for (const auto& parameter : params.reported) {
            info.append_range(parameter);
        }
        echo.chunks.push_back(SCTP_Chunk{{OP_ERROR, 0, 0}, error_chunk_value{{error_cause{CAUSE_UNRECOGNIZED_PARAMS, std::move(info)}}}});
    }
    enqueue_packet(Deliverable{key, destination, std::move(echo)});
}

void SCTP_Socket::reply(const SCTP_Common_Header& header, const Association_Key& key, const sockaddr_in& destination, uint32_t tag,
                        Chunk_Type type, Chunk_Value_Type value, uint8_t flag) {
    enqueue_packet(Deliverable{key, destination, build_packet(header.des_port, header.src_port, tag, type, std::move(value), flag)});
}

SCTP_Packet SCTP_Socket::packet_to(const Association_TCB& assoc, Chunk_Type type, Chunk_Value_Type value, uint8_t flag) const {
    return build_packet(ntohs(local_address.sin_port), assoc.peer.sctp_port, assoc.peer.peer_ver_tag, type, std::move(value), flag);
}

// Sets key to the association the cookie names, which the rest of the packet
// belongs to. Against an existing TCB the tags select a case of Table 12: the
// branches below are D, A and B in turn, and C or anything outside the table is
// dropped. A zero Tie-Tag means none and never matches, and a stale cookie whose
// tags both match is a retransmission rather than an error. A restart in
// SHUTDOWN-ACK-SENT answers under the old tag, which the restarted peer reflects
// back; a collision keeps any shutdown already under way.
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
    if (result == Cookie_Result::INVALID) {
        return false;
    }

    key = association_at(cookie_key(cookie));
    auto it = associations.find(key);
    if (it == associations.end()) {
        if (result == Cookie_Result::STALE) {
            reply(header, key, src, cookie.peer_ver_tag, OP_ERROR, error_chunk_value{{stale_cookie_cause(staleness_us)}});
            return false;
        }
        key = Association_Key{next_association_id++};
        auto created = associations.emplace(key, init_new_association(cookie));
        add_peer_addresses(key, created.first->second, cookie_addresses(cookie));
        notify_assoc_change(key, Assoc_Change_State::COMM_UP);
        start_heartbeats(key, created.first->second);
        reply(header, key, reply_destination(created.first->second, src), cookie.peer_ver_tag, COOKIE_ACK, empty_chunk_value{});
        return true;
    }

    Association_TCB& tcb = it->second;
    bool local_match = cookie.local_ver_tag == tcb.peer.this_ver_tag;
    bool peer_match = cookie.peer_ver_tag == tcb.peer.peer_ver_tag;
    bool tie_tags_match = cookie.local_tie_tag != 0
        && cookie.local_tie_tag == tcb.peer.local_tie_tag
        && cookie.peer_tie_tag == tcb.peer.peer_tie_tag;

    sockaddr_in destination = reply_destination(tcb, src);
    if (result == Cookie_Result::STALE && !(local_match && peer_match)) {
        reply(header, key, destination, cookie.peer_ver_tag, OP_ERROR, error_chunk_value{{stale_cookie_cause(staleness_us)}});
        return false;
    }

    if (local_match && peer_match) {
        if (tcb.state == COOKIE_ECHOED) {
            tcb.state = ESTABLISHED;
            notify_assoc_change(key, Assoc_Change_State::COMM_UP);
            start_heartbeats(key, tcb);
        }
    } else if (!local_match && !peer_match && tie_tags_match) {
        if (tcb.state == SHUTDOWN_ACK_SENT) {
            reply(header, key, destination, tcb.peer.peer_ver_tag, SHUTDOWN_ACK, empty_chunk_value{});
            reply(header, key, destination, cookie.peer_ver_tag, OP_ERROR, error_chunk_value{{error_cause{CAUSE_COOKIE_WHILE_SHUTTING_DOWN, {}}}});
            return false;
        }
        cancel_expirations(key);
        sends.purge(key);
        forget_peer_addresses(key, tcb);
        abandon_partial_delivery(key, tcb.receive);
        tcb = init_new_association(cookie);
        add_peer_addresses(key, tcb, cookie_addresses(cookie));
        destination = reply_destination(tcb, src);
        notify_assoc_change(key, Assoc_Change_State::RESTART);
        start_heartbeats(key, tcb);
    } else if (local_match) {
        add_peer_addresses(key, tcb, cookie_addresses(cookie));
        tcb.peer.peer_ver_tag = cookie.peer_ver_tag;
        tcb.receive.last_peer_tsn = cookie.peer_initial_tsn - 1;
        tcb.send.peer_rwnd = cookie.peer_a_rwnd;
        tcb.send.peer_max_rwnd = cookie.peer_a_rwnd;
        tcb.receive.ooo.clear();
        abandon_partial_delivery(key, tcb.receive);
        tcb.receive.reassembly = {};
        tcb.receive.streams.clear();
        tcb.receive.held_deliveries.clear();
        tcb.receive.duplicate_tsns.clear();
        if (is_forming(tcb.state)) {
            tcb.state = ESTABLISHED;
            notify_assoc_change(key, Assoc_Change_State::COMM_UP);
            start_heartbeats(key, tcb);
        } else if (transmits_data(tcb.state)) {
            arm_confirmation_probes(key, tcb);
        }
    } else {
        return false;
    }

    cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::T1_INIT});
    cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::T1_COOKIE});
    sends.remove_retransmissions_of_type(key, INIT);
    sends.remove_retransmissions_of_type(key, COOKIE_ECHO);
    reply(header, key, destination, cookie.peer_ver_tag, COOKIE_ACK, empty_chunk_value{});
    return true;
}

// Every cause is passed up raw, unknown codes included, unless the ERROR is a
// Stale Cookie consumed by handshake recovery.
void SCTP_Socket::handle_error(const SCTP_Common_Header&, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in&) {
    const auto& error = std::get<error_chunk_value>(chunk.chunk_value);
    Association_TCB* assoc = find_tcb(key);
    if (error.causes.empty() || assoc == nullptr) {
        return;
    }
    auto stale = std::ranges::find_if(error.causes, [](const error_cause& cause) {
        return cause.code == CAUSE_STALE_COOKIE && cause.info.size() == 4;
    });
    if (stale == error.causes.end() || assoc->state != COOKIE_ECHOED) {
        notifications.enqueue(Notification{Notification_Type::SCTP_REMOTE_ERROR, key, Remote_Error{error.causes}});
        return;
    }

    cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::T1_COOKIE});
    sends.remove_retransmissions_of_type(key, COOKIE_ECHO);
    if (assoc->handshake.stale_cookie_retries >= MAX_STALE_COOKIE_RETRIES) {
        return remove_association(key, Assoc_Change_State::CANT_STR_ASSOC);
    }
    uint32_t staleness_ms = read_be32(stale->info.data()) / 1000 + 1;
    ++assoc->handshake.stale_cookie_retries;
    assoc->state = COOKIE_WAIT;
    assoc->peer.peer_ver_tag = 0;
    assoc->handshake.init_retransmits = 0;
    assoc->handshake.cookie_retransmits = 0;
    enqueue_packet(Deliverable{key, primary(*assoc).udp_address, build_init(ntohs(local_address.sin_port), assoc->peer.sctp_port,
        assoc->peer.this_ver_tag, assoc->send.next_tsn, staleness_ms + std::min(staleness_ms, 1000U), advertised_addresses())});
}

void SCTP_Socket::handle_abort(const SCTP_Common_Header&, const SCTP_Chunk&, const Association_Key& key, const sockaddr_in&) {
    if (Association_TCB* assoc = find_tcb(key)) {
        remove_association(key, is_forming(assoc->state) ? Assoc_Change_State::CANT_STR_ASSOC : Assoc_Change_State::COMM_LOST);
    }
}

// Tears the association down locally, then tell the peer. The ABORT is
// enqueued after remove_association, whose purge would otherwise drop it along
// with the DATA that must not accompany it.
void SCTP_Socket::abort_association(const Association_Key& key, const SCTP_Common_Header& header, const sockaddr_in& src, std::vector<error_cause> causes) {
    Association_TCB* assoc = find_tcb(key);
    if (assoc == nullptr) {
        return;
    }
    uint32_t peer_tag = assoc->peer.peer_ver_tag;
    sockaddr_in destination = reply_destination(*assoc, src);
    remove_association(key, is_forming(assoc->state) ? Assoc_Change_State::CANT_STR_ASSOC : Assoc_Change_State::COMM_LOST);
    if (peer_tag != 0) {
        reply(header, key, destination, peer_tag, ABORT, error_chunk_value{std::move(causes)});
    }
}

// Cumulative against next_tsn rather than send.outstanding being empty: DATA
// still in the send queue has a TSN but no outstanding entry yet, and messages
// still in the outbound queue have no TSN at all.
void SCTP_Socket::do_next_shutdown_step(const Association_Key& key) {
    Association_TCB* assoc = find_tcb(key);
    if (assoc == nullptr || assoc->send.cumulative_tsn_ack != assoc->send.next_tsn - 1 || !assoc->send.outbound.empty()) {
        return;
    }
    SCTP_Packet packet;
    switch (assoc->state) {
        case SHUTDOWN_PENDING:
            packet = packet_to(*assoc, SHUTDOWN, shutdown_chunk_value{assoc->receive.last_peer_tsn});
            assoc->state = SHUTDOWN_SENT;
            schedule_expiration(Expiration_Key{key, Expiration_Timer_Type::T5_SHUTDOWN_GUARD}, std::chrono::steady_clock::now() + T5_SHUTDOWN_GUARD);
            break;
        case SHUTDOWN_RECEIVED:
            packet = packet_to(*assoc, SHUTDOWN_ACK, empty_chunk_value{});
            assoc->state = SHUTDOWN_ACK_SENT;
            break;
        default:
            return;
    }
    expirations.cancel_all(key, Expiration_Timer_Type::HEARTBEAT);
    cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::DELAYED_SACK});
    expirations.cancel_all(key, Expiration_Timer_Type::T3_RTX);
    enqueue_packet(Deliverable{key, data_path(*assoc).udp_address, std::move(packet)});
    restart_t2(key);
}

void SCTP_Socket::handle_cookie_ack(const SCTP_Common_Header&, const SCTP_Chunk&, const Association_Key& key, const sockaddr_in&) {
    Association_TCB* assoc = find_tcb(key);
    if (assoc == nullptr || assoc->state != COOKIE_ECHOED) {
        return;
    }
    assoc->state = ESTABLISHED;
    notify_assoc_change(key, Assoc_Change_State::COMM_UP);
    start_heartbeats(key, *assoc);
    cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::T1_COOKIE});
    sends.remove_retransmissions_of_type(key, COOKIE_ECHO);
}

// The Info is echoed verbatim and the peer chooses its length, so an oversized
// one would build a reply we cannot put on the wire.
void SCTP_Socket::handle_heartbeat(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src) {
    const auto& info = std::get<heartbeat_chunk_value>(chunk.chunk_value).info;
    Association_TCB* assoc = find_tcb(key);
    if (assoc == nullptr || assoc->state == SHUTDOWN_SENT || assoc->state == SHUTDOWN_ACK_SENT
            || 2 * SCTP_CHUNK_HEADER_SIZE + info.size() > amdcs(*assoc)) {
        return;
    }
    reply(header, key, src, assoc->peer.peer_ver_tag, HEARTBEAT_ACK, heartbeat_chunk_value{info});
}

// The ACK is credited to the path its Info names, which may not be the one it
// arrived from. The nonce tells it from one answering a heartbeat two intervals
// back, which would otherwise clear the error count of a failing path. Only the
// path carrying DATA answers for the association, or an idle alternate would
// keep alive one whose data path has failed.
void SCTP_Socket::handle_heartbeat_ack(const SCTP_Common_Header&, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in&) {
    const auto& info = std::get<heartbeat_chunk_value>(chunk.chunk_value).info;
    if (info.size() != HEARTBEAT_INFO_SIZE) {
        return;
    }

    Association_TCB* found = find_tcb(key);
    if (found == nullptr) {
        return;
    }

    Association_TCB& assoc = *found;
    Peer_Path* path = find_path(assoc, heartbeat_info_destination(info));
    if (path != nullptr && path->plpmtud.probe_outstanding && heartbeat_info_nonce(info) == path->plpmtud.probe_nonce) {
        handle_plpmtu_probe_ack(key, assoc, *path);
        return;
    }
    if (path == nullptr || !path->hb_outstanding || heartbeat_info_nonce(info) != path->hb_nonce) {
        return;
    }

    auto now = std::chrono::steady_clock::now();
    path->hb_outstanding = false;
    update_rto(*path, std::chrono::duration_cast<std::chrono::microseconds>(now - path->hb_sent_at));
    clear_path_errors(key, *path);
    if (&data_path(assoc) == path) {
        assoc.paths.error_count = 0;
    }
    if (!path->confirmed) {
        path->confirmed = true;
        notify_peer_addr_change(key, path->udp_address, Peer_Addr_State::ADDR_CONFIRMED);
        if (transmits_data(assoc.state)) {
            start_plpmtud(key, *path);
        }
        plan_next_probe(assoc, *path, now);
    }
    if (transmits_data(assoc.state)) {
        arm_heartbeat(key, assoc, *path);
        arm_confirmation_probes(key, assoc);
    }
}

// The Cumulative TSN Ack is applied as a SACK with no Gap Ack Blocks, except
// that the missing blocks are not a renege: gap-acked chunks stay so.
void SCTP_Socket::handle_shutdown(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src) {
    uint32_t cumulative_tsn_ack = std::get<shutdown_chunk_value>(chunk.chunk_value).cumulative_tsn_ack;
    Association_TCB* found = find_tcb(key);
    if (found == nullptr || is_forming(found->state)) {
        return;
    }
    Association_TCB& assoc = *found;
    switch (assoc.state) {
        case SHUTDOWN_SENT:
            assoc.state = SHUTDOWN_ACK_SENT;
            [[fallthrough]];
        case SHUTDOWN_ACK_SENT:
            reply(header, key, reply_destination(assoc, src), assoc.peer.peer_ver_tag, SHUTDOWN_ACK, empty_chunk_value{});
            return restart_t2(key);
        default:
            break;
    }
    if (!tsn_lt(cumulative_tsn_ack, assoc.send.next_tsn)) {
        return abort_association(key, header, src, {error_cause{CAUSE_PROTOCOL_VIOLATION, {}}});
    }

    assoc.state = SHUTDOWN_RECEIVED;
    if (tsn_gt(cumulative_tsn_ack, assoc.send.cumulative_tsn_ack)) {
        std::vector<bool> acked_on(assoc.paths.list.size(), false);
        for (auto entry = assoc.send.outstanding.begin(); entry != assoc.send.outstanding.end();) {
            if (!tsn_lte(entry->first, cumulative_tsn_ack)) {
                ++entry;
                continue;
            }
            if (!entry->second.gap_acked) {
                Peer_Path& path = destination_of(assoc, entry->second);
                acked_on[index_of(assoc, path)] = true;
                clear_path_errors(key, path);
                assoc.paths.error_count = 0;
            }
            entry = assoc.send.outstanding.erase(entry);
        }
        assoc.send.cumulative_tsn_ack = cumulative_tsn_ack;
        if (assoc.send.rtt_measurement_tsn && tsn_lte(*assoc.send.rtt_measurement_tsn, cumulative_tsn_ack)) {
            assoc.send.rtt_measurement_tsn.reset();
        }
        if (assoc.send.in_fast_recovery && tsn_gte(cumulative_tsn_ack, assoc.send.fast_recovery_exit_tsn)) {
            assoc.send.in_fast_recovery = false;
        }
        sends.remove_acked_retransmissions(key, sack_chunk_value{cumulative_tsn_ack, 0, {}, {}});
        for (auto&& [path, acked] : std::views::zip(assoc.paths.list, acked_on)) {
            if (acked) {
                restart_t3(key, path.udp_address);
            }
        }
    }
    do_next_shutdown_step(key);
}

void SCTP_Socket::handle_shutdown_ack(const SCTP_Common_Header& header, const SCTP_Chunk&, const Association_Key& key, const sockaddr_in& src) {
    Association_TCB* assoc = find_tcb(key);
    if (assoc == nullptr || (assoc->state != SHUTDOWN_SENT && assoc->state != SHUTDOWN_ACK_SENT)) {
        return;
    }
    uint32_t peer_tag = assoc->peer.peer_ver_tag;
    sockaddr_in destination = reply_destination(*assoc, src);
    remove_association(key, Assoc_Change_State::SHUTDOWN_COMP);
    reply(header, key, destination, peer_tag, SHUTDOWN_COMPLETE, empty_chunk_value{});
}

void SCTP_Socket::handle_shutdown_complete(const SCTP_Common_Header&, const SCTP_Chunk&, const Association_Key& key, const sockaddr_in&) {
    Association_TCB* assoc = find_tcb(key);
    if (assoc != nullptr && assoc->state == SHUTDOWN_ACK_SENT) {
        remove_association(key, Assoc_Change_State::SHUTDOWN_COMP);
    }
}

// send.outstanding is in TSN order, so the first chunk a destination has there
// is its lowest TSN and the last its highest. A reneged chunk's miss is counted
// where the renege is found and not again in the fast retransmit pass.
void SCTP_Socket::handle_sack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src) {
    const auto& sack = std::get<sack_chunk_value>(chunk.chunk_value);
    Association_TCB* found = find_tcb(key);
    if (found == nullptr || !transmits_data(found->state)) {
        return;
    }
    Association_TCB& assoc = *found;
    bool acks_unsent = !tsn_lt(sack.cumulative_tsn_ack, assoc.send.next_tsn)
        || std::ranges::any_of(sack.gap_ack_blocks, [&](const sack_gap_ack_block& block) {
            return !tsn_lt(sack.cumulative_tsn_ack + block.end, assoc.send.next_tsn);
        });
    if (acks_unsent) {
        return abort_association(key, header, src, {error_cause{CAUSE_PROTOCOL_VIOLATION, {}}});
    }
    if (tsn_lt(sack.cumulative_tsn_ack, assoc.send.cumulative_tsn_ack)) {
        return;
    }

    bool schedule_fast_retransmission = false;
    bool entered_fast_recovery = false;
    {
        bool cumulative_ack_advanced = tsn_gt(sack.cumulative_tsn_ack, assoc.send.cumulative_tsn_ack);

        std::vector<Peer_Path>& paths = assoc.paths.list;
        std::vector<Path_Ack> acks(paths.size());
        auto ack_of = [&](const Outstanding_Data& outstanding) -> Path_Ack& {
            return acks[index_of(assoc, destination_of(assoc, outstanding))];
        };
        for (auto&& [path, ack] : std::views::zip(paths, acks)) {
            ack.flight_before = bytes_in_flight(assoc, &path);
        }

        bool newly_acknowledged = false;
        std::vector<uint32_t> reneged_tsns;
        std::optional<uint32_t> htna;
        std::optional<uint32_t> highest_reported;
        auto now = std::chrono::steady_clock::now();
        for (auto it = assoc.send.outstanding.begin(); it != assoc.send.outstanding.end();) {
            uint32_t tsn = it->first;
            Outstanding_Data& outstanding = it->second;
            Path_Ack& ack = ack_of(outstanding);
            bool acknowledged = sack_acknowledges(sack, tsn);
            if (!outstanding.gap_acked && !ack.earliest) {
                ack.earliest = tsn;
            }
            if (acknowledged) {
                highest_reported = tsn;
            }
            if (acknowledged && !outstanding.gap_acked) {
                htna = tsn;
                newly_acknowledged = true;
                ack.newly_acknowledged = true;
                ack.bytes_acked += static_cast<uint32_t>(data_chunk_wire_size(outstanding.data));
                if (assoc.send.rtt_measurement_tsn == tsn && !outstanding.retransmitted) {
                    update_rto(destination_of(assoc, outstanding), std::chrono::duration_cast<std::chrono::microseconds>(now - outstanding.first_sent));
                    assoc.send.rtt_measurement_tsn.reset();
                }
            }

            if (tsn_lte(tsn, sack.cumulative_tsn_ack)) {
                if (outstanding.retransmitted) {
                    assoc.send.acked_retransmissions.push_back(Acked_Retransmission{
                        tsn, static_cast<uint32_t>(data_chunk_wire_size(outstanding.data)), outstanding.destination});
                    if (assoc.send.acked_retransmissions.size() > ACKED_RETRANSMISSION_MEMORY) {
                        assoc.send.acked_retransmissions.pop_front();
                    }
                }
                it = assoc.send.outstanding.erase(it);
                continue;
            }

            if (acknowledged) {
                outstanding.gap_acked = true;
                outstanding.pending_retransmission = false;
            } else if (outstanding.gap_acked) {
                outstanding.gap_acked = false;
                ack.reneged = true;
                reneged_tsns.push_back(tsn);
                if (!outstanding.fast_retransmitted) {
                    ++outstanding.missing_reports;
                }
            }
            ++it;
        }

        assoc.send.cumulative_tsn_ack = sack.cumulative_tsn_ack;
        std::vector<uint32_t> duplicates(paths.size(), 0);
        duplicate_bytes(assoc, sack, duplicates);
        if (newly_acknowledged) {
            assoc.paths.error_count = 0;
        }
        for (auto&& [path, ack, duplicate] : std::views::zip(paths, acks, duplicates)) {
            if (ack.newly_acknowledged) {
                clear_path_errors(key, path);
                path.single_packet_in_flight = false;
            }
            if (ack.newly_acknowledged || duplicate > 0) {
                grow_cwnd(assoc.send, path, ack.bytes_acked, duplicate, ack.flight_before);
            }
            bool sent_here = std::ranges::any_of(assoc.send.outstanding | std::views::values, [&](const Outstanding_Data& outstanding) {
                return &destination_of(assoc, outstanding) == &path;
            });
            if (!sent_here) {
                path.partial_bytes_acked = 0;
            }
        }

        for (auto& [tsn, outstanding] : assoc.send.outstanding) {
            if (outstanding.gap_acked || outstanding.fast_retransmitted) {
                continue;
            }

            const std::optional<uint32_t>& above = assoc.send.in_fast_recovery && cumulative_ack_advanced ? highest_reported : htna;
            bool was_reneged = std::ranges::contains(reneged_tsns, tsn);
            if (above && tsn_lt(tsn, *above) && !was_reneged) {
                ++outstanding.missing_reports;
            }
            if (outstanding.missing_reports >= 3) {
                outstanding.fast_retransmitted = true;
                outstanding.pending_retransmission = true;
                ack_of(outstanding).fast_retransmitted = true;
                schedule_fast_retransmission = true;
            }
        }

        if (schedule_fast_retransmission && !assoc.send.in_fast_recovery) {
            for (auto&& [path, ack] : std::views::zip(paths, acks)) {
                if (ack.fast_retransmitted) {
                    path.ssthresh = std::max(path.cwnd / 2, 4U * pmdcs(path));
                    path.cwnd = path.ssthresh;
                    path.partial_bytes_acked = 0;
                }
            }

            if (!assoc.send.outstanding.empty()) {
                assoc.send.in_fast_recovery = true;
                assoc.send.fast_recovery_exit_tsn = assoc.send.outstanding.rbegin()->first;
                entered_fast_recovery = true;
            }
        }

        if (assoc.send.in_fast_recovery && tsn_gte(sack.cumulative_tsn_ack, assoc.send.fast_recovery_exit_tsn)) {
            assoc.send.in_fast_recovery = false;
        }

        for (const auto& [tsn, outstanding] : assoc.send.outstanding) {
            if (assoc.send.rtt_measurement_tsn) {
                break;
            }
            if (!outstanding.gap_acked && !outstanding.retransmitted
                    && std::ranges::none_of(assoc.send.outstanding, [&](const auto& other) {
                        return other.second.retransmitted && tsn_lte(other.first, tsn) && other.second.last_sent >= outstanding.first_sent;
                    })) {
                assoc.send.rtt_measurement_tsn = tsn;
            }
        }

        size_t flight_size = bytes_in_flight(assoc);
        assoc.send.peer_rwnd = flight_size >= sack.a_rwnd ? 0 : sack.a_rwnd - static_cast<uint32_t>(flight_size);
        assoc.send.peer_max_rwnd = std::max(assoc.send.peer_max_rwnd, sack.a_rwnd);
        assoc.send.sack_since_t3 = true;
        if (sack.a_rwnd > 0) {
            assoc.send.zero_window_probing = false;
        }

        for (auto&& [path, ack] : std::views::zip(paths, acks)) {
            auto earliest = ack.earliest ? assoc.send.outstanding.find(*ack.earliest) : assoc.send.outstanding.end();
            bool retransmits_earliest = schedule_fast_retransmission && earliest != assoc.send.outstanding.end()
                && earliest->second.pending_retransmission;
            if (!has_unacknowledged_data(assoc, path)) {
                cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::T3_RTX, path_key(path.udp_address)});
            } else if ((ack.earliest && sack_acknowledges(sack, *ack.earliest)) || retransmits_earliest) {
                restart_t3(key, path.udp_address);
            } else if (ack.reneged) {
                start_t3_if_stopped(key, path.udp_address);
            }
        }
    }

    sends.remove_acked_retransmissions(key, sack);
    if (entered_fast_recovery) {
        schedule_pending_retransmission(key);
    }
    do_next_shutdown_step(key);
}

void SCTP_Socket::send_sack(const Association_Key& key) {
    Association_TCB* assoc = find_tcb(key);
    if (assoc == nullptr || !receives_data(assoc->state)) {
        return;
    }
    SCTP_Packet sack = make_sack(key, *assoc);
    cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::DELAYED_SACK});
    enqueue_packet(Deliverable{key, data_path(*assoc).udp_address, std::move(sack)});
}

// Receiver SWS avoidance: an opening too small to be worth a packet is held
// back until it grows, while a shrinking window is always advertised as it is.
SCTP_Packet SCTP_Socket::make_sack(const Association_Key& key, Association_TCB& assoc) {
    std::vector<sack_gap_ack_block> gaps;
    for (uint32_t tsn : assoc.receive.ooo | std::views::keys) {
        uint16_t offset = static_cast<uint16_t>(tsn - assoc.receive.last_peer_tsn);
        if (gaps.empty() || static_cast<uint32_t>(gaps.back().end) + 1 != offset) {
            gaps.push_back({offset, offset});
        } else {
            gaps.back().end = offset;
        }
    }

    uint32_t window = receive_window(key, assoc.receive);
    uint32_t believed = peer_view_of_window(assoc.receive);
    if (window > believed && window - believed < std::min<uint32_t>(RWND / 2, amdcs(assoc))) {
        window = believed;
    }
    assoc.receive.our_rwnd = window;
    assoc.receive.received_since_sack = 0;

    SCTP_Packet sack_packet = packet_to(assoc, SACK, sack_chunk_value{assoc.receive.last_peer_tsn, window, std::move(gaps), std::move(assoc.receive.duplicate_tsns)});
    assoc.receive.duplicate_tsns.clear();
    assoc.receive.delayed_sack_packet_count = 0;
    return sack_packet;
}

// A chunk is dropped past what a Gap Ack Block can report, or when the receive
// buffer is full and no room can be made. Once the window cannot take another
// full-size chunk, the rest of the open message could only arrive after the ULP
// reads, so it gets what there is; only the message next in its stream can go
// up early, and the ULP sees it through to its end before anything else.
// Deliveries are queued before any SACK is built so the window it advertises
// counts them.
void SCTP_Socket::handle_data_packet(const SCTP_Packet& packet, const Association_Key& key, const sockaddr_in& src, bool acknowledge_immediately) {
    for (const auto& chunk : packet.chunks) {
        if (chunk.chunk_header.type == DATA && std::get<data_chunk_value>(chunk.chunk_value).user_data.empty()) {
            return abort_association(key, packet.header, src, {error_cause{CAUSE_NO_USER_DATA, be32_bytes(std::get<data_chunk_value>(chunk.chunk_value).tsn)}});
        }
    }

    Association_TCB* found = find_tcb(key);
    if (found == nullptr || !receives_data(found->state)) {
        return;
    }
    Association_TCB& assoc = *found;
    bool have_data = false;
    bool send_immediately = acknowledge_immediately;
    std::vector<error_cause> invalid_streams;
    std::vector<Delivery> delivered;
    bool hole_existed = !assoc.receive.ooo.empty();
    bool saw_duplicate = false;
    bool dropped = false;
    size_t used = receives.buffered_bytes(key) + held_bytes(assoc.receive);

    for (const auto& chunk : packet.chunks) {
        if (chunk.chunk_header.type != DATA) {
            continue;
        }
        have_data = true;
        send_immediately = send_immediately || (chunk.chunk_header.flag & DATA_IMMEDIATE_SACK_FLAG) != 0;
        const auto& data = std::get<data_chunk_value>(chunk.chunk_value);
        assoc.receive.received_since_sack += static_cast<uint32_t>(data.user_data.size());
        uint32_t tsn = data.tsn;
        bool valid_stream = data.stream_identifier < assoc.receive.in_streams;
        if (tsn_lte(tsn, assoc.receive.last_peer_tsn) || assoc.receive.ooo.contains(tsn)) {
            assoc.receive.duplicate_tsns.push_back(tsn);
            saw_duplicate = true;
            continue;
        }
        if (tsn - assoc.receive.last_peer_tsn > UINT16_MAX || (used >= RWND && !make_room(assoc.receive, tsn, used)
                && !(tsn == assoc.receive.last_peer_tsn + 1 && blocked_on_cumulative_tsn(assoc.receive)))) {
            dropped = true;
            continue;
        }
        if (valid_stream) {
            used += data.user_data.size();
        } else {
            invalid_streams.push_back(invalid_stream_cause(data.stream_identifier));
        }
        bool framed;
        if (tsn == assoc.receive.last_peer_tsn + 1) {
            assoc.receive.last_peer_tsn = tsn;
            framed = reassemble(assoc.receive, data, valid_stream, delivered) && read_ooo_buffer(assoc.receive, delivered);
        } else {
            auto inserted = assoc.receive.ooo.emplace(tsn, Held_Chunk{data});
            if (!valid_stream) {
                inserted.first->second.data.user_data.clear();
            }
            framed = !valid_stream || assemble_early(assoc.receive, tsn, delivered);
        }
        if (!framed) {
            return abort_association(key, packet.header, src, {error_cause{CAUSE_PROTOCOL_VIOLATION, {}}});
        }
    }
    if (!have_data) {
        return;
    }

    Reassembly& message = assoc.receive.reassembly;
    if (message.open && !message.bytes.empty() && used + amdcs(assoc) > RWND
            && (message.unordered || message.ssn == assoc.receive.streams[message.stream].next_ssn)) {
        delivered.push_back(Delivery{std::move(message.bytes), false, message.stream, message.ppid});
        message.bytes.clear();
        message.partially_delivered = true;
        if (!message.unordered) {
            advance_stream(assoc.receive, message.stream, delivered);
        }
    }
    bool shutdown_sent = assoc.state == SHUTDOWN_SENT;
    SCTP_Packet shutdown;
    if (shutdown_sent) {
        shutdown = packet_to(assoc, SHUTDOWN, shutdown_chunk_value{assoc.receive.last_peer_tsn});
        if (!assoc.receive.ooo.empty() || !assoc.receive.duplicate_tsns.empty() || dropped) {
            shutdown.chunks.push_back(std::move(make_sack(key, assoc).chunks[0]));
        }
    }
    send_immediately = send_immediately || saw_duplicate || dropped || hole_existed || !assoc.receive.ooo.empty();
    if (!shutdown_sent && !send_immediately) {
        send_immediately = ++assoc.receive.delayed_sack_packet_count >= 2;
    }

    for (auto& delivery : delivered) {
        receives.push(key, std::move(delivery.bytes), delivery.complete, delivery.stream, delivery.ppid);
    }
    if (!invalid_streams.empty()) {
        reply(packet.header, key, reply_destination(assoc, src), assoc.peer.peer_ver_tag, OP_ERROR, error_chunk_value{std::move(invalid_streams)});
    }
    if (shutdown_sent) {
        cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::DELAYED_SACK});
        enqueue_packet(Deliverable{key, data_path(assoc).udp_address, std::move(shutdown)});
        restart_t2(key);
    } else if (send_immediately) {
        send_sack(key);
    } else {
        schedule_expiration(Expiration_Key{key, Expiration_Timer_Type::DELAYED_SACK}, std::chrono::steady_clock::now() + sctp_parameters::SACK_DELAY);
    }
}

// Receive buffer space not yet taken by messages waiting for the ULP or by DATA
// held for reordering or reassembly, in bytes of user data.
uint32_t SCTP_Socket::receive_window(const Association_Key& key, const TCB_Receive_Side& receive) {
    size_t used = receives.buffered_bytes(key) + held_bytes(receive);
    return used >= RWND ? 0 : static_cast<uint32_t>(RWND - used);
}

void SCTP_Socket::maybe_send_window_update(const Association_Key& key) {
    Association_TCB* assoc = find_tcb(key);
    if (assoc != nullptr && receives_data(assoc->state) && receive_window(key, assoc->receive) >= peer_view_of_window(assoc->receive) + RWND / 4) {
        send_sack(key);
    }
}

