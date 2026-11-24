#ifndef SCTP_BUILDERS_HPP
#define SCTP_BUILDERS_HPP

#include <stdint.h>
#include <vector>
#include <sctp/protocol/sctp.hpp>
#include <sctp/platform/compat.hpp>

// What we advertise as OS and MIS in INIT and INIT ACK.
constexpr uint16_t LOCAL_OUT_STREAMS = 10;
constexpr uint16_t LOCAL_MAX_IN_STREAMS = 65535;

SCTP_Packet build_packet(uint16_t src_port, uint16_t des_port, uint32_t tag, Chunk_Type type, Chunk_Value_Type value, uint8_t flag = 0);

SCTP_Packet build_init(uint16_t src_port, uint16_t des_port, uint32_t initiate_tag, uint32_t initial_tsn,
                       uint32_t cookie_preservative_ms = 0, const std::vector<in_addr>& addresses = {});

SCTP_Packet build_init_ack(uint16_t src_port, uint16_t des_port, uint32_t peer_tag, uint32_t initiate_tag, uint32_t initial_tsn,
                           const std::vector<uint8_t>& cookie, const std::vector<std::vector<uint8_t>>& unrecognized = {},
                           const std::vector<in_addr>& addresses = {});

SCTP_Packet build_data(uint16_t src_port, uint16_t des_port, uint32_t peer_tag, std::vector<data_chunk_value> chunks);

// A HEARTBEAT and a PAD chunk filling the UDP datagram to exactly plpmtu bytes,
// which must be a multiple of 4.
SCTP_Packet build_plpmtu_probe(uint16_t src_port, uint16_t des_port, uint32_t peer_tag, std::vector<uint8_t> info, uint32_t plpmtu);

// Padded wire footprint of one DATA chunk, for callers bundling against PMDCS.
size_t data_chunk_wire_size(const data_chunk_value& data);

#endif
