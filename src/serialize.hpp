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
void serialize_error_chunk(const error_chunk_value& v, std::vector<uint8_t>& out);
// MAC is a plain suffix, so callers can sign the first STATE_COOKIE_BODY_SIZE
// bytes of the result and write the digest straight into its tail.
std::vector<uint8_t> serialize_state_cookie(const State_Cookie& cookie);


void append_parameter(std::vector<uint8_t>& out, uint16_t type, const uint8_t* value, size_t len);
bool find_parameter(const std::vector<uint8_t>& params, uint16_t type, std::vector<uint8_t>& value_out);

uint32_t sctp_read_wire_checksum(const uint8_t* data);
void sctp_clear_wire_checksum(uint8_t* data);

bool deserialize_state_cookie(const std::vector<uint8_t>& data, State_Cookie& out);
SCTP_Packet deserialize_sctp_packet(const uint8_t* data, size_t len);
void deserialize_chunk_value(
    Chunk_Type type, 
    const uint8_t* data, 
    size_t len,
    Chunk_Value_Type& out
);
void deserialize_init_chunk(const uint8_t* data, size_t len,init_chunk_value& out);
void deserialize_data_chunk(const uint8_t* data, size_t len, data_chunk_value& out);
void deserialize_sack_chunk(const uint8_t* data, size_t len, sack_chunk_value& out);
void deserialize_cookie_echo_chunk(const uint8_t* data, size_t len, cookie_echo_chunk_value& out);
void deserialize_cookie_ack_chunk(const uint8_t* data, size_t len, cookie_ack_chunk_value& out);
void deserialize_error_chunk(const uint8_t* data, size_t len, error_chunk_value& out);

#endif
