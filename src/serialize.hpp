#ifndef SCTP_SERIALIZE_HPP
#define SCTP_SERIALIZE_HPP

#include <vector>
#include <stdint.h>
#include <sctp/sctp.hpp>

std::vector<uint8_t> serialize_sctp_packet(const SCTP_Packet& pkt);
void serialize_chunk(const SCTP_Chunk& chunk, std::vector<uint8_t>& out);
void serialize_init_chunk(const init_chunk_value& v,std::vector<uint8_t>& out);
void serialize_data_chunk(const data_chunk_value& v,std::vector<uint8_t>& out);
void serialize_sack_chunk(const sack_chunk_value& v, std::vector<uint8_t>& out);
void serialize_cookie_echo_chunk(const cookie_echo_chunk_value& v, std::vector<uint8_t>& out);
void serialize_cookie_ack_chunk(const cookie_ack_chunk_value& v, std::vector<uint8_t>& out);


// Wire-level checksum access. The checksum is little-endian on the wire (RFC
// 9260 §6.8), so callers must not byte-swap it themselves. Both require that
// `data` holds at least SCTP_COMMON_HEADER_SIZE bytes.
uint32_t sctp_read_wire_checksum(const uint8_t* data);
void sctp_clear_wire_checksum(uint8_t* data);

SCTP_Packet deserialize_sctp_packet(const uint8_t* data, size_t len);
void deserialize_chunk_value(
    Chunk_Type type, const uint8_t* data, size_t len,
    std::variant<init_chunk_value, cookie_echo_chunk_value,
                 cookie_ack_chunk_value, data_chunk_value,
                 sack_chunk_value>& out);
void deserialize_init_chunk(const uint8_t* data, size_t len,init_chunk_value& out);
void deserialize_data_chunk(const uint8_t* data, size_t len, data_chunk_value& out);
void deserialize_sack_chunk(const uint8_t* data, size_t len, sack_chunk_value& out);
void deserialize_cookie_echo_chunk(const uint8_t* data, size_t len, cookie_echo_chunk_value& out);
void deserialize_cookie_ack_chunk(const uint8_t* data, size_t len, cookie_ack_chunk_value& out);

#endif
