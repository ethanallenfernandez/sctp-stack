// Inbound chunk handling: packet validation and dispatch, the four-way
// handshake (RFC 9260 5.1), SACK processing and fast retransmit (6.2, 7.2.4),
// SACK generation with gap ack blocks (3.3.4), and DATA reception with the
// out-of-order buffer.

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
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <vector>

namespace {
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
        std::cout << "Dropped packet with invalid checksum. Received: " << received_checksum
                  << ", Calculated: " << calculated_checksum << std::endl;
        return;
    }

    SCTP_Packet in_pkt;
    try {
        in_pkt = deserialize_sctp_packet(data, n);
    } catch (const std::exception& e) {
        std::cout << "Dropped malformed packet: " << e.what() << std::endl;
        return;
    }

    switch (validate_verification_tag(in_pkt, src)) {
        case Packet_Validation::ACCEPT:
            break;
        case Packet_Validation::ABORT_OOTB:
            std::cout << "Aborting out of the blue packet" << std::endl;
            send_abort(in_pkt.header, src, in_pkt.header.verification_tag, true, {});
            return;
        case Packet_Validation::DISCARD:
            std::cout << "Dropped packet with bad verification tag" << std::endl;
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
        std::cout << "Recieved COOKIE_ECHO" << std::endl;
        if (!handle_cookie_echo(in_pkt.header, in_pkt.chunks[0], src)) {
            return;
        }
    }

    for (size_t i = carried_cookie_echo ? 1 : 0; i < in_pkt.chunks.size(); i++) {
        switch(in_pkt.chunks[i].chunk_header.type) {
            case INIT:
                std::cout << "Recieved INIT" << std::endl;
                SCTP_Socket::handle_init(in_pkt.header, in_pkt.chunks[i], src);
                break;
            case INIT_ACK:
                std::cout << "Recieved INIT_ACK" << std::endl;
                SCTP_Socket::handle_init_ack(in_pkt.header, in_pkt.chunks[i], src);
                break;
            case COOKIE_ACK:
                std::cout << "Recieved COOKIE_ACK" << std::endl;
                SCTP_Socket::handle_cookie_ack(in_pkt.header, in_pkt.chunks[i], src);
                break;
            case DATA:
                // Special, needs to be handled once per packet, not once per chunk. Handler called after the loop.
                std::cout << "Recieved DATA" << std::endl;
                break;
            case SACK:
                std::cout << "Recieved SACK" << std::endl;
                SCTP_Socket::handle_sack(in_pkt.header, in_pkt.chunks[i], src);
                break;
            case OP_ERROR:
                std::cout << "Recieved ERROR" << std::endl;
                SCTP_Socket::handle_error(in_pkt.header, in_pkt.chunks[i], src);
                break;
            case ABORT:
                std::cout << "Recieved ABORT" << std::endl;
                SCTP_Socket::handle_abort(in_pkt.header, in_pkt.chunks[i], src);
                return; // ABORT so stop processing packets
            case HEARTBEAT:
                std::cout << "Recieved HEARTBEAT" << std::endl;
                SCTP_Socket::handle_heartbeat(in_pkt.header, in_pkt.chunks[i], src);
                break;
            case HEARTBEAT_ACK:
                std::cout << "Recieved HEARTBEAT_ACK" << std::endl;
                SCTP_Socket::handle_heartbeat_ack(in_pkt.header, in_pkt.chunks[i], src);
                break;
            default:
                break;
        }
    }

    // DATA bundled with a COOKIE ECHO must skip the delayed-SACK timer.
    handle_data_packet(in_pkt, src, carried_cookie_echo);

    if (!unrecognized.empty()) {
        report_unrecognized_chunks(in_pkt.header, src, std::move(unrecognized));
    }
}

Packet_Validation SCTP_Socket::validate_verification_tag(const SCTP_Packet& pkt, const sockaddr_in& src) {
    if (pkt.chunks.empty()) {
        return Packet_Validation::DISCARD;
    }

    const SCTP_Chunk_Header& first = pkt.chunks[0].chunk_header;

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
    auto it = associations.find(Association_Key{src});
    if (it == associations.end()) {
        return ootb_response(pkt);
    }

    // 8.5.1 B: the T bit says which tag the sender could reach for. Set, it had
    // no TCB and echoed ours back, so the match is against the tag we handed the
    // peer; clear, it held a TCB and addressed us under our own.
    if (first.type == ABORT) {
        uint32_t expected = (first.flag & CHUNK_FLAG_T_BIT)
            ? it->second.peer_ver_tag
            : it->second.this_ver_tag;
        return expected != 0 && pkt.header.verification_tag == expected
            ? Packet_Validation::ACCEPT
            : Packet_Validation::DISCARD;
    }

    return pkt.header.verification_tag == it->second.this_ver_tag
        ? Packet_Validation::ACCEPT
        : Packet_Validation::DISCARD;
}

// 8.4: an unattributable packet is answered with an ABORT, except where a reply
// would bounce forever or the sender is already tearing the association down.
Packet_Validation SCTP_Socket::ootb_response(const SCTP_Packet& pkt) {
    for (const auto& chunk : pkt.chunks) {
        switch (chunk.chunk_header.type) {
            case ABORT:
            case COOKIE_ACK:
            case SHUTDOWN_COMPLETE:
                return Packet_Validation::DISCARD;
            case SHUTDOWN_ACK:
                // Owed a SHUTDOWN COMPLETE with the T bit, which needs Tier 3 shutdown.
                return Packet_Validation::DISCARD;
            case OP_ERROR:
                if (carries_stale_cookie(chunk)) {
                    return Packet_Validation::DISCARD;
                }
                break;
            default:
                break;
        }
    }
    return Packet_Validation::ABORT_OOTB;
}

// After dispatch: a bundled COOKIE ECHO may have created the TCB. COOKIE_WAIT
// has no peer tag to address the report with.
void SCTP_Socket::report_unrecognized_chunks(const SCTP_Common_Header& header, const sockaddr_in& src, std::vector<error_cause> causes) {
    uint32_t peer_tag;
    size_t budget;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(Association_Key{src});
        if (it == associations.end() || it->second.state == COOKIE_WAIT) {
            return;
        }
        peer_tag = it->second.peer_ver_tag;
        budget = it->second.pmdcs;
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
        send_error(header, src, peer_tag, std::move(causes));
    }
}

void SCTP_Socket::handle_init(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src) {
    const auto& init = std::get<init_chunk_value>(chunk.chunk_value);
    // The association closed here is the one this INIT asks for. A TCB already
    // held for this peer survives: an INIT carries no proof of origin.
    if (init.initiate_tag == 0) {
        std::cout << "Aborting INIT with a zero Initiate Tag" << std::endl;
        send_abort(header, src, header.verification_tag, true, {error_cause{CAUSE_INVALID_MANDATORY_PARAM, {}}});
        return;
    }
    // The Initiate Tag is the peer's own, learned from the chunk rather than
    // reflected off the header, so the T bit stays clear.
    if (init.out_streams == 0 || init.in_streams == 0) {
        std::cout << "Aborting INIT advertising zero streams" << std::endl;
        send_abort(header, src, init.initiate_tag, false, {error_cause{CAUSE_INVALID_MANDATORY_PARAM, {}}});
        return;
    }
    std::vector<uint8_t> preservative;
    uint32_t lifespan_increment_ms = find_parameter(init.optional_parameters, PARAM_COOKIE_PRESERVATIVE, preservative)
        && preservative.size() == 4 ? read_be32(preservative.data()) : 0;

    uint32_t local_tag = generate_nonzero_tag();
    uint32_t local_tsn;
    generate_random(local_tsn);
    uint32_t local_tie_tag = 0;
    uint32_t peer_tie_tag = 0;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto existing = associations.find(Association_Key{src});
        if (existing != associations.end()) {
            Association& assoc = existing->second;

            switch (assoc.state) {
                case SHUTDOWN_ACK_SENT:
                    return;
                case COOKIE_WAIT:
                case COOKIE_ECHOED:
                    local_tag = assoc.this_ver_tag;
                    local_tsn = assoc.next_tsn;
                    if (assoc.state == COOKIE_WAIT) {
                        break;
                    }
                    [[fallthrough]];
                default:
                    if (assoc.local_tie_tag == 0) {
                        assoc.local_tie_tag = generate_nonzero_tag();
                        assoc.peer_tie_tag = generate_nonzero_tag();
                    }
                    local_tie_tag = assoc.local_tie_tag;
                    peer_tie_tag = assoc.peer_tie_tag;
            }
        }
    }

    std::vector<uint8_t> cookie = cookie_authorizer.generate(
        header, 
        init, 
        src, 
        local_tag, 
        local_tsn, 
        local_tie_tag, 
        peer_tie_tag,
        lifespan_increment_ms
    );

    enqueue_packet(Deliverable{src, build_init_ack(
        header.des_port,
        header.src_port,
        init.initiate_tag,
        local_tag,
        local_tsn,
        cookie
    )});
}

void SCTP_Socket::handle_init_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src) {
    const auto& init_ack = std::get<init_chunk_value>(chunk.chunk_value);

    std::unique_lock<std::mutex> assoc_lock(associations_mutex);
    Association_Key assoc_key{src};
    auto it = associations.find(assoc_key);
    if (it == associations.end() || it->second.state != COOKIE_WAIT) {
        return;
    }

    // 3.3.3: the TCB goes whether or not the optional ABORT does. That ABORT
    // follows the purge in remove_association, and reflects our own tag.
    if (init_ack.initiate_tag == 0) {
        assoc_lock.unlock();
        std::cout << "Aborting INIT_ACK with a zero Initiate Tag" << std::endl;
        remove_association(assoc_key);
        send_abort(header, src, header.verification_tag, true, {error_cause{CAUSE_INVALID_MANDATORY_PARAM, {}}});
        notify_assoc_change(assoc_key, Assoc_Change_State::CANT_STR_ASSOC);
        return;
    }

    std::vector<uint8_t> cookie;
    if (!find_parameter(init_ack.optional_parameters, PARAM_STATE_COOKIE, cookie)) {
        std::cout << "Dropped INIT_ACK with no State Cookie parameter" << std::endl;
        return;
    }
    if (init_ack.out_streams == 0 || init_ack.in_streams == 0) {
        assoc_lock.unlock();
        std::cout << "Aborting INIT_ACK advertising zero streams" << std::endl;
        remove_association(assoc_key);
        send_abort(header, src, init_ack.initiate_tag, false, {error_cause{CAUSE_INVALID_MANDATORY_PARAM, {}}});
        notify_assoc_change(assoc_key, Assoc_Change_State::CANT_STR_ASSOC);
        return;
    }

    Association& assoc = it->second;
    assoc.last_peer_tsn = init_ack.initial_tsn - 1;
    assoc.peer_ver_tag = init_ack.initiate_tag;
    assoc.peer_rwnd = init_ack.a_rwnd;
    assoc.out_streams = std::min(LOCAL_OUT_STREAMS, init_ack.in_streams);
    assoc.in_streams = std::min(LOCAL_MAX_IN_STREAMS, init_ack.out_streams);
    assoc.state = COOKIE_ECHOED;
    uint32_t peer_tag = assoc.peer_ver_tag;
    assoc_lock.unlock();
    cancel_expiration(Expiration_Key{assoc_key, Expiration_Timer_Type::T1_INIT});
    sends.remove_retransmissions_of_type(assoc_key, INIT);

    enqueue_packet(Deliverable{src, build_cookie_echo(
        header.des_port, header.src_port, peer_tag, std::move(cookie))});
}

void SCTP_Socket::send_cookie_ack(const SCTP_Common_Header& header, const sockaddr_in& src, uint32_t peer_tag) {
    enqueue_packet(Deliverable{src, build_cookie_ack(header.des_port, header.src_port, peer_tag)});
}

void SCTP_Socket::send_stale_cookie_error(
        const SCTP_Common_Header& header,
        const sockaddr_in& src,
        const State_Cookie& cookie,
        uint32_t staleness_us) {
    send_error(header, src, cookie.peer_ver_tag, {stale_cookie_cause(staleness_us)});
}

void SCTP_Socket::send_error(
        const SCTP_Common_Header& header,
        const sockaddr_in& src,
        uint32_t peer_tag,
        std::vector<error_cause> causes) {
    enqueue_packet(Deliverable{src, build_error(
        header.des_port, header.src_port, peer_tag, std::move(causes))});
}

void SCTP_Socket::send_abort(
    const SCTP_Common_Header& header,
    const sockaddr_in& src,
    uint32_t tag,
    bool reflected,
    std::vector<error_cause> causes
) {
    enqueue_packet(Deliverable{
        src,
        build_abort(header.des_port, header.src_port, tag, reflected, std::move(causes))
    });
}

bool SCTP_Socket::handle_cookie_echo(
    const SCTP_Common_Header& header,
    const SCTP_Chunk& chunk,
    const sockaddr_in& src
) {
    const auto& echo = std::get<cookie_echo_chunk_value>(chunk.chunk_value);

    State_Cookie cookie{};
    uint32_t staleness_us = 0;
    Cookie_Result result = cookie_authorizer.verify(echo.cookie_data, header, src, cookie, staleness_us);
    if (result != Cookie_Result::VALID && result != Cookie_Result::STALE) {
        std::cout << "Dropped COOKIE_ECHO with an unverifiable cookie" << std::endl;
        return false;
    }

    // Send and expiration queue locks are leaves, so it is safe to touch them
    // here. Holding the lock through a restart's purge keeps an API-thread send
    // on the new association from being purged with the old one's packets.
    Association_Key key{src};
    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    auto it = associations.find(key);
    if (it == associations.end()) {
        if (result == Cookie_Result::STALE) {
            send_stale_cookie_error(header, src, cookie, staleness_us);
            return false;
        }
        auto created = associations.insert_or_assign(key, init_new_association(cookie, key));
        notify_assoc_change(key, Assoc_Change_State::COMM_UP);
        schedule_heartbeat(key, created.first->second.rto);
        send_cookie_ack(header, src, cookie.peer_ver_tag);
        return true;
    }

    // RFC 9260 5.2.4, Table 12. A zero Tie-Tag means "none" and never matches.
    Association& tcb = it->second;
    bool local_match = cookie.local_ver_tag == tcb.this_ver_tag;
    bool peer_match = cookie.peer_ver_tag == tcb.peer_ver_tag;
    bool tie_tags_match = cookie.local_tie_tag != 0
        && cookie.local_tie_tag == tcb.local_tie_tag
        && cookie.peer_tie_tag == tcb.peer_tie_tag;

    // Step 3: a stale cookie whose tags both match is a retransmission (case E).
    if (result == Cookie_Result::STALE && !(local_match && peer_match)) {
        send_stale_cookie_error(header, src, cookie, staleness_us);
        return false;
    }

    if (local_match && peer_match) {
        // D
        if (tcb.state == COOKIE_ECHOED) {
            tcb.state = ESTABLISHED;
            notify_assoc_change(key, Assoc_Change_State::COMM_UP);
            schedule_heartbeat(key, tcb.rto);
        }
    } else if (!local_match && !peer_match && tie_tags_match) {
        // A: peer restart
        if (tcb.state == SHUTDOWN_ACK_SENT) {
            // TODO: also resend SHUTDOWN ACK. Needs Tier 3 shutdown.
            send_error(header, src, cookie.peer_ver_tag, {error_cause{CAUSE_COOKIE_WHILE_SHUTTING_DOWN, {}}});
            return false;
        }
        std::cout << "Peer restarted, association reset" << std::endl;
        cancel_expirations(key);
        sends.purge(key);
        tcb = init_new_association(cookie, key);
        notify_assoc_change(key, Assoc_Change_State::RESTART);
        schedule_heartbeat(key, tcb.rto);
    } else if (local_match) {
        // B: collision, peer's tag is new or not yet known
        tcb.peer_ver_tag = cookie.peer_ver_tag;
        tcb.last_peer_tsn = cookie.peer_initial_tsn - 1;
        tcb.peer_rwnd = cookie.peer_a_rwnd;
        tcb.tsn_ooo_buffer.clear();
        tcb.duplicate_tsns.clear();
        if (tcb.state == COOKIE_WAIT || tcb.state == COOKIE_ECHOED) {
            notify_assoc_change(key, Assoc_Change_State::COMM_UP);
            schedule_heartbeat(key, tcb.rto);
        }
        tcb.state = ESTABLISHED;
    } else {
        // C, and anything not in the table
        std::cout << "Dropped COOKIE_ECHO that does not match the existing association" << std::endl;
        return false;
    }

    cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::T1_INIT});
    cancel_expiration(Expiration_Key{key, Expiration_Timer_Type::T1_COOKIE});
    sends.remove_retransmissions_of_type(key, INIT);
    sends.remove_retransmissions_of_type(key, COOKIE_ECHO);
    send_cookie_ack(header, src, cookie.peer_ver_tag);
    return true;
}

void SCTP_Socket::handle_error(const SCTP_Common_Header&, const SCTP_Chunk& chunk, const sockaddr_in& src) {
    const auto& error = std::get<error_chunk_value>(chunk.chunk_value);
    if (error.causes.empty()) {
        return;
    }

    Association_Key assoc_key{src};
    SCTP_Packet retry_init;
    bool handshake_failed = false;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(assoc_key);
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
                    retry_init = build_init(
                        ntohs(local_address.sin_port),
                        ntohs(assoc_key.address.sin_port),
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
            notifications.enqueue(Notification{Notification_Type::SCTP_REMOTE_ERROR, assoc_key, 0, Remote_Error{error.causes}});
            return;
        }
    }

    cancel_expiration(Expiration_Key{assoc_key, Expiration_Timer_Type::T1_COOKIE});
    sends.remove_retransmissions_of_type(assoc_key, COOKIE_ECHO);
    if (!handshake_failed) {
        std::cout << "Retrying association with a Cookie Preservative" << std::endl;
        enqueue_packet(Deliverable{assoc_key, std::move(retry_init)});
        return;
    }

    std::cout << "Association failed: peer kept reporting a stale cookie" << std::endl;
    remove_association(assoc_key);
    notify_assoc_change(assoc_key, Assoc_Change_State::CANT_STR_ASSOC);
}

void SCTP_Socket::handle_abort(const SCTP_Common_Header&, const SCTP_Chunk& chunk, const sockaddr_in& src) {
    const auto& abort = std::get<error_chunk_value>(chunk.chunk_value);
    Association_Key assoc_key{src};

    bool forming;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(assoc_key);
        if (it == associations.end()) {
            return;
        }
        forming = it->second.state == COOKIE_WAIT || it->second.state == COOKIE_ECHOED;
    }

    if (!abort.causes.empty()) {
        notifications.enqueue(Notification{Notification_Type::SCTP_REMOTE_ERROR, assoc_key, 0, Remote_Error{abort.causes}});
    }
    remove_association(assoc_key);
    notify_assoc_change(assoc_key, forming ? Assoc_Change_State::CANT_STR_ASSOC : Assoc_Change_State::COMM_LOST);
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
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(key);
        if (it == associations.end()) {
            return;
        }
        peer_tag = it->second.peer_ver_tag;
        forming = it->second.state == COOKIE_WAIT || it->second.state == COOKIE_ECHOED;
    }

    remove_association(key);
    if (peer_tag != 0) {
        send_abort(header, src, peer_tag, false, std::move(causes));
    }
    notify_assoc_change(key, forming ? Assoc_Change_State::CANT_STR_ASSOC : Assoc_Change_State::COMM_LOST);
}

void SCTP_Socket::handle_cookie_ack(const SCTP_Common_Header&, const SCTP_Chunk&, const sockaddr_in& src) {
    std::unique_lock<std::mutex> assoc_lock(associations_mutex);
    Association_Key assoc_key{src};
    auto it = associations.find(assoc_key);
    if (it == associations.end() || it->second.state != COOKIE_ECHOED) {
        return;
    }

    Association& assoc = it->second;
    assoc.state = ESTABLISHED;
    notify_assoc_change(assoc_key, Assoc_Change_State::COMM_UP);
    std::chrono::microseconds rto = assoc.rto;
    assoc_lock.unlock();
    schedule_heartbeat(assoc_key, rto);
    cancel_expiration(
        Expiration_Key{assoc_key, Expiration_Timer_Type::T1_COOKIE});
    sends.remove_retransmissions_of_type(assoc_key, COOKIE_ECHO);
}

void SCTP_Socket::handle_heartbeat(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src) {
    const auto& info = std::get<heartbeat_chunk_value>(chunk.chunk_value).info;
    Association_Key key{src};
    uint32_t peer_tag;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(key);
        // The Info is echoed verbatim and the peer chooses its length, so an
        // oversized one would build a reply we cannot put on the wire.
        if (it == associations.end() || 2 * SCTP_CHUNK_HEADER_SIZE + info.size() > it->second.pmdcs) {
            return;
        }
        peer_tag = it->second.peer_ver_tag;
    }

    enqueue_packet(Deliverable{key, build_heartbeat_ack(header.des_port, header.src_port, peer_tag, info)});
}

void SCTP_Socket::handle_heartbeat_ack(const SCTP_Common_Header&, const SCTP_Chunk& chunk, const sockaddr_in& src) {
    const auto& info = std::get<heartbeat_chunk_value>(chunk.chunk_value).info;
    if (info.size() != HEARTBEAT_INFO_SIZE) {
        return;
    }

    std::lock_guard<std::mutex> assoc_lock(associations_mutex);
    auto it = associations.find(Association_Key{src});
    if (it == associations.end()) {
        return;
    }

    // The nonce tells this ACK from one answering a heartbeat two intervals
    // back, which would otherwise clear the error count of a failing path.
    Association& assoc = it->second;
    if (!assoc.hb_outstanding || read_be32(info.data()) != assoc.hb_nonce) {
        return;
    }

    assoc.hb_outstanding = false;
    assoc.error_count = 0;
    update_rto(assoc, std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - assoc.hb_sent_at));
}

void SCTP_Socket::handle_sack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src) {
    (void)header;
    const auto& sack = std::get<sack_chunk_value>(chunk.chunk_value);
    Association_Key key{src};
    bool stop = false;
    bool restart = false;
    bool start = false;
    bool schedule_fast_retransmission = false;
    bool fast_retransmits_lowest = false;

    { // Scope for association lock
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(key);
        if (association == associations.end() || (association->second.state != ESTABLISHED && association->second.state != SHUTDOWN_PENDING && association->second.state != SHUTDOWN_RECEIVED)) {
            return;
        }

        Association& assoc = association->second;
        if (tsn_lt(sack.cumulative_tsn_ack, assoc.cumulative_tsn_ack)) {
            return;
        }
        uint32_t previous_cumulative_tsn_ack = assoc.cumulative_tsn_ack;
        bool cumulative_ack_advanced =
            tsn_gt(sack.cumulative_tsn_ack, previous_cumulative_tsn_ack);

        bool have_earliest = false;
        uint32_t earliest_tsn = 0;
        uint32_t earliest_distance = 0;
        for (const auto& [tsn, outstanding] : assoc.outstanding_data) {
            if (outstanding.gap_acked) {
                continue;
            }
            uint32_t distance = tsn - assoc.cumulative_tsn_ack;
            if (!have_earliest || distance < earliest_distance) {
                have_earliest = true;
                earliest_tsn = tsn;
                earliest_distance = distance;
            }
        }
        bool earliest_acknowledged = have_earliest && sack_acknowledges(sack, earliest_tsn);

        bool newly_acknowledged = false;
        bool reneged = false;
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
                newly_acknowledged = true;
                if (assoc.has_rtt_measurement_tsn && tsn == assoc.rtt_measurement_tsn && !outstanding.retransmitted) {
                    update_rto(assoc, std::chrono::duration_cast<std::chrono::microseconds>(now - outstanding.first_sent));
                    assoc.has_rtt_measurement_tsn = false;
                }
            }

            if (cumulatively_acknowledged) {
                it = assoc.outstanding_data.erase(it);
                continue;
            }

            if (acknowledged) {
                outstanding.gap_acked = true;
            } else if (outstanding.gap_acked) {
                outstanding.gap_acked = false;
                reneged = true;
                reneged_tsns.push_back(tsn);
                if (!outstanding.fast_retransmitted) {
                    ++outstanding.missing_reports;
                }
            }
            ++it;
        }

        assoc.cumulative_tsn_ack = sack.cumulative_tsn_ack;
        if (newly_acknowledged) {
            assoc.error_count = 0;
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
                schedule_fast_retransmission = true;
            }
        }

        if (schedule_fast_retransmission) {
            auto lowest = assoc.outstanding_data.find(earliest_tsn);
            fast_retransmits_lowest = have_earliest
                && lowest != assoc.outstanding_data.end()
                && lowest->second.pending_retransmission;

            if (!assoc.in_fast_recovery) {
                assoc.ssthresh = std::max(assoc.cwnd / 2, 4U * assoc.pmdcs);
                assoc.cwnd = assoc.ssthresh;
                assoc.partial_bytes_acked = 0;

                bool have_exit = false;
                uint32_t exit_tsn = 0;
                for (const auto& [tsn, outstanding] : assoc.outstanding_data) {
                    (void)outstanding;
                    if (!have_exit || tsn_gt(tsn, exit_tsn)) {
                        have_exit = true;
                        exit_tsn = tsn;
                    }
                }
                if (have_exit) {
                    assoc.in_fast_recovery = true;
                    assoc.fast_recovery_exit_tsn = exit_tsn;
                }
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

        size_t outstanding_bytes = 0;
        for (const auto& [tsn, outstanding] : assoc.outstanding_data) {
            if (!outstanding.gap_acked) {
                size_t chunk_size = 16 + outstanding.data.user_data.size();
                outstanding_bytes += (chunk_size + 3) & ~size_t{3};
            }
            (void)tsn;
        }
        assoc.peer_rwnd = outstanding_bytes >= sack.a_rwnd ? 0 : sack.a_rwnd - static_cast<uint32_t>(outstanding_bytes);

        if (!has_unacknowledged_data(assoc)) {
            stop = true;
        } else if (earliest_acknowledged || fast_retransmits_lowest) {
            restart = true;
        } else if (reneged) {
            start = true;
        }
    }

    Expiration_Key timer{key, Expiration_Timer_Type::T3_RTX};
    sends.remove_acked_retransmissions(key, sack);
    if (schedule_fast_retransmission) {
        schedule_pending_retransmission(key);
    }
    if (stop) {
        cancel_expiration(timer);
    } else if (restart) {
        restart_t3(key);
    } else if (start) {
        start_t3_if_stopped(key);
    }
}

void SCTP_Socket::send_sack(const Association_Key& key) {
    SCTP_Packet sack_packet;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto association = associations.find(key);
        if (association == associations.end()
                || association->second.state != ESTABLISHED) {
            return;
        }
        Association& assoc = association->second;

        std::vector<uint16_t> offsets;
        offsets.reserve(assoc.tsn_ooo_buffer.size());
        for (const auto& [tsn, data] : assoc.tsn_ooo_buffer) {
            uint32_t offset = tsn - assoc.last_peer_tsn;
            if (offset > 0 && offset <= UINT16_MAX) {
                offsets.push_back(static_cast<uint16_t>(offset));
            }
            (void)data;
        }
        std::sort(offsets.begin(), offsets.end());
        offsets.erase(std::unique(offsets.begin(), offsets.end()), offsets.end()); // Should not be necessary, but nonetheless...

        std::vector<sack_gap_ack_block> gaps;
        for (uint16_t offset : offsets) {
            if (gaps.empty() || static_cast<uint32_t>(gaps.back().end) + 1 != offset) {
                gaps.push_back({offset, offset});
            } else {
                gaps.back().end = offset;
            }
        }

        sack_packet = build_sack(
            ntohs(local_address.sin_port),
            ntohs(key.address.sin_port),
            assoc.peer_ver_tag,
            assoc.last_peer_tsn,
            std::move(gaps),
            std::move(assoc.duplicate_tsns)
        );
        assoc.duplicate_tsns.clear();
        assoc.delayed_sack_packet_count = 0;
    }
    cancel_expiration(
        Expiration_Key{key, Expiration_Timer_Type::DELAYED_SACK});
    enqueue_packet(Deliverable{key, std::move(sack_packet)});
}

void SCTP_Socket::handle_delayed_sack_expiration(
        const Association_Key& location) {
    send_sack(location);
}

void SCTP_Socket::handle_data_packet(
    const SCTP_Packet& packet, 
    const sockaddr_in& src, 
    bool acknowledge_immediately
) {
    Association_Key assoc_key{src};

    // 3.3.1: a DATA chunk carrying no user data is fatal to the association.
    for (const auto& chunk : packet.chunks) {
        if (chunk.chunk_header.type != DATA) {
            continue;
        }
        const auto& data = std::get<data_chunk_value>(chunk.chunk_value);
        if (data.user_data.empty()) {
            std::cout << "Aborting association: DATA chunk with no user data" << std::endl;
            abort_association(assoc_key, packet.header, src, {error_cause{CAUSE_NO_USER_DATA, be32_bytes(data.tsn)}});
            return;
        }
    }

    bool have_data = false;
    bool send_immediately = acknowledge_immediately;
    bool start_delayed_timer = false;
    std::vector<error_cause> invalid_streams;
    uint32_t peer_tag = 0;
    {
        std::lock_guard<std::mutex> assoc_lock(associations_mutex);
        auto it = associations.find(assoc_key);
        if (it == associations.end() || it->second.state != ESTABLISHED) {
            return;
        }

        Association& assoc = it->second;
        peer_tag = assoc.peer_ver_tag;
        bool hole_existed = !assoc.tsn_ooo_buffer.empty();
        bool saw_duplicate = false;

        for (const auto& chunk : packet.chunks) {
            if (chunk.chunk_header.type != DATA) {
                continue;
            }
            have_data = true;
            send_immediately = send_immediately
                || (chunk.chunk_header.flag & DATA_IMMEDIATE_SACK_FLAG) != 0;
            const auto& data = std::get<data_chunk_value>(chunk.chunk_value);
            uint32_t tsn = data.tsn;
            // RFC 9260 6.5: an invalid stream is still acked, but reported and never delivered.
            bool valid_stream = data.stream_identifier < assoc.in_streams;
            if (tsn == assoc.last_peer_tsn + 1) {
                assoc.last_peer_tsn = tsn;
                if (valid_stream) {
                    assoc.ulp_buffer.push(data.user_data);
                } else {
                    invalid_streams.push_back(invalid_stream_cause(data.stream_identifier));
                }
                read_ooo_buffer(assoc);
            } else if (tsn_lt(assoc.last_peer_tsn + 1, tsn)) {
                auto inserted = assoc.tsn_ooo_buffer.emplace(tsn, data);
                if (!inserted.second) {
                    assoc.duplicate_tsns.push_back(tsn);
                    saw_duplicate = true;
                } else if (!valid_stream) {
                    inserted.first->second.user_data.clear();
                    invalid_streams.push_back(invalid_stream_cause(data.stream_identifier));
                }
            } else {
                assoc.duplicate_tsns.push_back(tsn);
                saw_duplicate = true;
            }
        }

        if (!have_data) {
            return;
        }
        send_immediately = send_immediately || saw_duplicate
            || hole_existed || !assoc.tsn_ooo_buffer.empty();
        if (!send_immediately) {
            ++assoc.delayed_sack_packet_count;
            send_immediately = assoc.delayed_sack_packet_count >= 2;
            start_delayed_timer = !send_immediately;
        }
    }

    if (!invalid_streams.empty()) {
        send_error(packet.header, src, peer_tag, std::move(invalid_streams));
    }
    if (send_immediately) {
        send_sack(assoc_key);
    } else if (start_delayed_timer) {
        schedule_expiration(
            Expiration_Key{assoc_key, Expiration_Timer_Type::DELAYED_SACK},
            std::chrono::steady_clock::now() + sctp_parameters::SACK_DELAY,
            Deliverable{assoc_key, SCTP_Packet{}});
    }
}

void SCTP_Socket::read_ooo_buffer(Association& assoc) {
    uint32_t tsn = assoc.last_peer_tsn + 1;
    for (auto it = assoc.tsn_ooo_buffer.find(tsn); it != assoc.tsn_ooo_buffer.end(); it = assoc.tsn_ooo_buffer.find(++tsn)) {
        if (it->second.stream_identifier < assoc.in_streams) {
            assoc.ulp_buffer.push(std::move(it->second.user_data));
        }
        assoc.tsn_ooo_buffer.erase(it);
    }
    assoc.last_peer_tsn = tsn - 1;
}
