#include "builders.hpp"

#include "serialize.hpp"
#include "socket_internal.hpp"

namespace {

SCTP_Packet packet_with_header(uint16_t src_port, uint16_t des_port, uint32_t tag) {
    SCTP_Packet packet;
    packet.header = {
        .src_port = src_port,
        .des_port = des_port,
        .verification_tag = tag,
        .checksum = 0   // written by serialize_sctp_packet
    };
    return packet;
}

void append_chunk(SCTP_Packet& packet, Chunk_Type type, Chunk_Value_Type value, uint8_t flag = 0) {
    packet.chunks.push_back(SCTP_Chunk{
        .chunk_header = {.type = type, .flag = flag, .length = 0},
        .chunk_value = std::move(value)
    });
}

}   // namespace

SCTP_Packet build_init(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t initiate_tag,
    uint32_t initial_tsn,
    uint32_t cookie_preservative_ms
) {
    // RFC 9260 8.5: a packet carrying INIT has a zero verification tag.
    SCTP_Packet packet = packet_with_header(src_port, des_port, 0);

    std::vector<uint8_t> parameters;
    if (cookie_preservative_ms != 0) {
        std::vector<uint8_t> increment = be32_bytes(cookie_preservative_ms);
        append_parameter(parameters, PARAM_COOKIE_PRESERVATIVE, increment.data(), increment.size());
    }

    append_chunk(packet, INIT, init_chunk_value{
        .initiate_tag = initiate_tag,
        .a_rwnd = RWND,
        .out_streams = LOCAL_OUT_STREAMS,
        .in_streams = LOCAL_MAX_IN_STREAMS,
        .initial_tsn = initial_tsn,
        .optional_parameters = std::move(parameters)
    });
    return packet;
}

SCTP_Packet build_init_ack(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t peer_tag,
    uint32_t initiate_tag,
    uint32_t initial_tsn,
    const std::vector<uint8_t>& cookie
) {
    SCTP_Packet packet = packet_with_header(src_port, des_port, peer_tag);

    std::vector<uint8_t> parameters;
    append_parameter(parameters, PARAM_STATE_COOKIE, cookie.data(), cookie.size());

    append_chunk(packet, INIT_ACK, init_chunk_value{
        .initiate_tag = initiate_tag,
        .a_rwnd = RWND,
        .out_streams = LOCAL_OUT_STREAMS,
        .in_streams = LOCAL_MAX_IN_STREAMS,
        .initial_tsn = initial_tsn,
        .optional_parameters = std::move(parameters)
    });
    return packet;
}

SCTP_Packet build_cookie_echo(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t peer_tag,
    std::vector<uint8_t> cookie
) {
    SCTP_Packet packet = packet_with_header(src_port, des_port, peer_tag);
    append_chunk(packet, COOKIE_ECHO, cookie_echo_chunk_value{.cookie_data = std::move(cookie)});
    return packet;
}

SCTP_Packet build_cookie_ack(uint16_t src_port, uint16_t des_port, uint32_t peer_tag) {
    SCTP_Packet packet = packet_with_header(src_port, des_port, peer_tag);
    append_chunk(packet, COOKIE_ACK, empty_chunk_value{});
    return packet;
}

SCTP_Packet build_data(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t peer_tag,
    std::vector<data_chunk_value> chunks
) {
    SCTP_Packet packet = packet_with_header(src_port, des_port, peer_tag);
    packet.chunks.reserve(chunks.size());
    for (data_chunk_value& data : chunks) {
        uint8_t flags = data.flags;
        append_chunk(packet, DATA, std::move(data), flags);
    }
    return packet;
}

SCTP_Packet build_sack(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t peer_tag,
    uint32_t cumulative_tsn_ack,
    uint32_t a_rwnd,
    std::vector<sack_gap_ack_block> gaps,
    std::vector<uint32_t> duplicate_tsns
) {
    SCTP_Packet packet = packet_with_header(src_port, des_port, peer_tag);
    append_chunk(packet, SACK, sack_chunk_value{
        .cumulative_tsn_ack = cumulative_tsn_ack,
        .a_rwnd = a_rwnd,
        .number_of_gap_ack_blocks = static_cast<uint16_t>(gaps.size()),
        .number_of_duplicate_tsns = static_cast<uint16_t>(duplicate_tsns.size()),
        .gap_ack_blocks = std::move(gaps),
        .duplicate_tsns = std::move(duplicate_tsns)
    });
    return packet;
}

SCTP_Packet build_error(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t peer_tag,
    std::vector<error_cause> causes
) {
    SCTP_Packet packet = packet_with_header(src_port, des_port, peer_tag);
    append_chunk(packet, OP_ERROR, error_chunk_value{std::move(causes)});
    return packet;
}

SCTP_Packet build_abort(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t tag,
    bool reflected,
    std::vector<error_cause> causes
) {
    SCTP_Packet packet = packet_with_header(src_port, des_port, tag);
    append_chunk(
        packet,
        ABORT,
        error_chunk_value{std::move(causes)},
        static_cast<uint8_t>(reflected ? CHUNK_FLAG_T_BIT : 0)
    );
    return packet;
}

SCTP_Packet build_shutdown(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t peer_tag,
    uint32_t cumulative_tsn_ack
) {
    SCTP_Packet packet = packet_with_header(src_port, des_port, peer_tag);
    append_chunk(packet, SHUTDOWN, shutdown_chunk_value{cumulative_tsn_ack});
    return packet;
}

SCTP_Packet build_shutdown_ack(uint16_t src_port, uint16_t des_port, uint32_t peer_tag) {
    SCTP_Packet packet = packet_with_header(src_port, des_port, peer_tag);
    append_chunk(packet, SHUTDOWN_ACK, empty_chunk_value{});
    return packet;
}

SCTP_Packet build_shutdown_complete(uint16_t src_port, uint16_t des_port, uint32_t tag, bool reflected) {
    SCTP_Packet packet = packet_with_header(src_port, des_port, tag);
    append_chunk(packet, SHUTDOWN_COMPLETE, empty_chunk_value{}, static_cast<uint8_t>(reflected ? CHUNK_FLAG_T_BIT : 0));
    return packet;
}

SCTP_Packet build_heartbeat(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t peer_tag,
    std::vector<uint8_t> info
) {
    SCTP_Packet packet = packet_with_header(src_port, des_port, peer_tag);
    append_chunk(packet, HEARTBEAT, heartbeat_chunk_value{std::move(info)});
    return packet;
}

SCTP_Packet build_heartbeat_ack(
    uint16_t src_port,
    uint16_t des_port,
    uint32_t peer_tag,
    std::vector<uint8_t> info
) {
    SCTP_Packet packet = packet_with_header(src_port, des_port, peer_tag);
    append_chunk(packet, HEARTBEAT_ACK, heartbeat_chunk_value{std::move(info)});
    return packet;
}

size_t data_chunk_wire_size(const data_chunk_value& data) {
    return (DATA_CHUNK_HEADER_SIZE + data.user_data.size() + 3) & ~size_t{3};
}
