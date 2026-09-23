#ifndef SCTP_BUILDERS_HPP
#define SCTP_BUILDERS_HPP

#include <stdint.h>
#include <vector>
#include <sctp/sctp.hpp>

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

SCTP_Packet build_shutdown(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t peer_tag,
    uint32_t cumulative_tsn_ack);

SCTP_Packet build_shutdown_ack(uint16_t src_port, uint16_t des_port, uint32_t peer_tag);

SCTP_Packet build_shutdown_complete(uint16_t src_port, uint16_t des_port, uint32_t tag, bool reflected);

// The Heartbeat Info is opaque: the sender picks the bytes, the responder
// echoes back the ones it was given without reading them.
SCTP_Packet build_heartbeat(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t peer_tag,
    std::vector<uint8_t> info);

SCTP_Packet build_heartbeat_ack(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t peer_tag,
    std::vector<uint8_t> info);

// Padded wire footprint of one DATA chunk, for callers bundling against PMDCS.
size_t data_chunk_wire_size(const data_chunk_value& data);

#endif
