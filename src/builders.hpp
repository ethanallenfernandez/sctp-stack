#ifndef SCTP_BUILDERS_HPP
#define SCTP_BUILDERS_HPP

#include <stdint.h>
#include <vector>
#include <sctp/sctp.hpp>

// One builder per packet type the stack emits (RFC 9260 3.3). Each takes plain
// scalars and returns a finished packet: no SCTP_Socket, no Association, no
// lock held. Callers read what they need out of the TCB under
// associations_mutex, then build outside the critical section.
//
// Ports are host byte order, as SCTP_Common_Header expects; a caller working
// from a sockaddr_in passes ntohs(...), one replying to a received header
// passes header.des_port / header.src_port to swap the direction.
//
// chunk_header.length is left 0 throughout: serialize_chunk recomputes it from
// the encoded body.

SCTP_Packet build_init(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t initiate_tag,
    uint32_t initial_tsn,
    uint32_t cookie_preservative_ms = 0);

SCTP_Packet build_init_ack(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t peer_tag,
    uint32_t initiate_tag,
    uint32_t initial_tsn,
    const std::vector<uint8_t>& cookie);

SCTP_Packet build_cookie_echo(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t peer_tag,
    std::vector<uint8_t> cookie);

SCTP_Packet build_cookie_ack(uint16_t src_port, uint16_t des_port, uint32_t peer_tag);

SCTP_Packet build_data(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t peer_tag,
    std::vector<data_chunk_value> chunks);

SCTP_Packet build_sack(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t peer_tag,
    uint32_t cumulative_tsn_ack,
    std::vector<sack_gap_ack_block> gaps,
    std::vector<uint32_t> duplicate_tsns);

SCTP_Packet build_error(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t peer_tag,
    std::vector<error_cause> causes);

SCTP_Packet build_abort(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t tag,
    bool reflected,
    std::vector<error_cause> causes);

// Padded wire footprint of one DATA chunk, for callers bundling against PMDCS.
size_t data_chunk_wire_size(const data_chunk_value& data);

#endif
