#include "protocol/builders.hpp"

#include "protocol/serialize.hpp"

namespace {

void append_addresses(std::vector<uint8_t>& parameters, const std::vector<in_addr>& addresses) {
    for (const in_addr& address : addresses) {
        append_parameter(parameters, PARAM_IPV4_ADDRESS, reinterpret_cast<const uint8_t*>(&address.s_addr), 4);
    }
}

SCTP_Packet init_packet(Chunk_Type type, uint16_t src_port, uint16_t des_port, uint32_t tag, uint32_t initiate_tag,
                        uint32_t initial_tsn, std::vector<uint8_t> parameters) {
    return build_packet(src_port, des_port, tag, type,
        init_chunk_value{initiate_tag, RWND, LOCAL_OUT_STREAMS, LOCAL_MAX_IN_STREAMS, initial_tsn, std::move(parameters)});
}

}   // namespace

SCTP_Packet build_packet(uint16_t src_port, uint16_t des_port, uint32_t tag, Chunk_Type type, Chunk_Value_Type value, uint8_t flag) {
    SCTP_Packet packet{{src_port, des_port, tag, 0}, {}};
    packet.chunks.push_back(SCTP_Chunk{{type, flag, 0}, std::move(value)});
    return packet;
}

SCTP_Packet build_init(uint16_t src_port, uint16_t des_port, uint32_t initiate_tag, uint32_t initial_tsn,
                       uint32_t cookie_preservative_ms, const std::vector<in_addr>& addresses) {
    std::vector<uint8_t> parameters;
    append_addresses(parameters, addresses);
    if (cookie_preservative_ms != 0) {
        std::vector<uint8_t> increment = be32_bytes(cookie_preservative_ms);
        append_parameter(parameters, PARAM_COOKIE_PRESERVATIVE, increment.data(), increment.size());
    }
    // RFC 9260 8.5: a packet carrying INIT has a zero verification tag.
    return init_packet(INIT, src_port, des_port, 0, initiate_tag, initial_tsn, std::move(parameters));
}

SCTP_Packet build_init_ack(uint16_t src_port, uint16_t des_port, uint32_t peer_tag, uint32_t initiate_tag, uint32_t initial_tsn,
                           const std::vector<uint8_t>& cookie, const std::vector<std::vector<uint8_t>>& unrecognized,
                           const std::vector<in_addr>& addresses) {
    std::vector<uint8_t> parameters;
    append_parameter(parameters, PARAM_STATE_COOKIE, cookie.data(), cookie.size());
    append_addresses(parameters, addresses);
    for (const auto& parameter : unrecognized) {
        append_parameter(parameters, PARAM_UNRECOGNIZED, parameter.data(), parameter.size());
    }
    return init_packet(INIT_ACK, src_port, des_port, peer_tag, initiate_tag, initial_tsn, std::move(parameters));
}

SCTP_Packet build_data(uint16_t src_port, uint16_t des_port, uint32_t peer_tag, std::vector<data_chunk_value> chunks) {
    SCTP_Packet packet{{src_port, des_port, peer_tag, 0}, {}};
    for (data_chunk_value& data : chunks) {
        uint8_t flags = data.flags;
        packet.chunks.push_back(SCTP_Chunk{{DATA, flags, 0}, std::move(data)});
    }
    return packet;
}

SCTP_Packet build_plpmtu_probe(uint16_t src_port, uint16_t des_port, uint32_t peer_tag, std::vector<uint8_t> info, uint32_t plpmtu) {
    size_t heartbeat_size = SCTP_CHUNK_HEADER_SIZE + ((SCTP_CHUNK_HEADER_SIZE + info.size() + 3) & ~size_t{3});
    size_t used = UDP_HEADER_SIZE + SCTP_COMMON_HEADER_SIZE + heartbeat_size + SCTP_CHUNK_HEADER_SIZE;
    SCTP_Packet packet = build_packet(src_port, des_port, peer_tag, HEARTBEAT, heartbeat_chunk_value{std::move(info)});
    packet.chunks.push_back(SCTP_Chunk{{PAD, 0, 0}, unknown_chunk_value{std::vector<uint8_t>(plpmtu > used ? plpmtu - used : 0, 0)}});
    return packet;
}

size_t data_chunk_wire_size(const data_chunk_value& data) {
    return (DATA_CHUNK_HEADER_SIZE + data.user_data.size() + 3) & ~size_t{3};
}
