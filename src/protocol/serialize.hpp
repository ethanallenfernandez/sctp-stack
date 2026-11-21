#ifndef SCTP_SERIALIZE_HPP
#define SCTP_SERIALIZE_HPP

#include <vector>
#include <initializer_list>
#include <stdint.h>
#include <sctp/protocol/sctp.hpp>

inline std::vector<uint8_t> be32_bytes(uint32_t v) {
    return {static_cast<uint8_t>(v >> 24), static_cast<uint8_t>(v >> 16), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v)};
}

inline uint32_t read_be32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1]) << 16 | static_cast<uint32_t>(p[2]) << 8 | p[3];
}

std::vector<uint8_t> serialize_sctp_packet(const SCTP_Packet& pkt);
SCTP_Packet deserialize_sctp_packet(const uint8_t* data, size_t len);
void serialize_sack_chunk(const sack_chunk_value& v, std::vector<uint8_t>& out);
void deserialize_sack_chunk(const uint8_t* data, size_t len, sack_chunk_value& out);
// MAC is a plain suffix, so callers can sign all but the last
// STATE_COOKIE_MAC_SIZE bytes of the result and write the digest into its tail.
std::vector<uint8_t> serialize_state_cookie(const State_Cookie& cookie);
bool deserialize_state_cookie(const std::vector<uint8_t>& data, State_Cookie& out);

void append_parameter(std::vector<uint8_t>& out, uint16_t type, const uint8_t* value, size_t len);
bool find_parameter(const std::vector<uint8_t>& params, uint16_t type, std::vector<uint8_t>& value_out);
// Every IPv4 Address parameter, host order.
std::vector<uint32_t> find_ipv4_addresses(const std::vector<uint8_t>& params);

struct Parameter_Scan {
    std::vector<uint8_t> recognized;              // only these are processed
    std::vector<std::vector<uint8_t>> reported;   // whole TLVs, padded
};
// A malformed Parameter Length ends the walk like a stop does.
Parameter_Scan scan_parameters(const std::vector<uint8_t>& params, std::initializer_list<uint16_t> recognized);

uint32_t sctp_read_wire_checksum(const uint8_t* data);
void sctp_clear_wire_checksum(uint8_t* data);

#endif
