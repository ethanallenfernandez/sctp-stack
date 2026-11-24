#include "protocol/serialize.hpp"
#include <algorithm>
#include <cstring>
#include <cstddef>
#include <stdexcept>
#include <utility>
#include "protocol/checksum.hpp"
#include <sctp/platform/compat.hpp>

namespace {

void append16(std::vector<uint8_t>& out, uint16_t v) {
    uint16_t n = htons(v);
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&n);
    out.insert(out.end(), p, p + 2);
}

void append32(std::vector<uint8_t>& out, uint32_t v) {
    uint32_t n = htonl(v);
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&n);
    out.insert(out.end(), p, p + 4);
}

uint16_t read16(const uint8_t* p) {
    uint16_t n;
    std::memcpy(&n, p, 2);
    return ntohs(n);
}

uint32_t read32(const uint8_t* p) {
    uint32_t n;
    std::memcpy(&n, p, 4);
    return ntohl(n);
}

// The checksum is the one field not in network byte order: it goes on the wire
// little-endian, so it gets its own helpers.
void write_checksum_le(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v      );
    p[1] = static_cast<uint8_t>(v >>  8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

uint32_t read_checksum_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | static_cast<uint32_t>(p[1]) <<  8
         | static_cast<uint32_t>(p[2]) << 16
         | static_cast<uint32_t>(p[3]) << 24;
}

size_t padded(size_t length) {
    return (length + 3) & ~size_t{3};
}

// Calls visit(type, tlv, length) on each TLV until it returns false. False if a
// Length is malformed: below 4 the walk would never advance.
template <typename Visit>
bool walk_tlvs(const uint8_t* data, size_t len, Visit visit) {
    size_t offset = 0;
    while (offset + SCTP_CHUNK_HEADER_SIZE <= len) {
        uint16_t length = read16(data + offset + 2);
        if (length < SCTP_CHUNK_HEADER_SIZE || offset + length > len) {
            return false;
        }
        if (!visit(read16(data + offset), data + offset, length)) {
            break;
        }
        offset += padded(length);
    }
    return true;
}

Chunk_Value_Type deserialize_chunk_value(Chunk_Type type, const uint8_t* data, size_t len) {
    switch (type) {
        case INIT:
        case INIT_ACK:
            if (len < 16) {
                throw std::runtime_error("INIT chunk too short");
            }
            return init_chunk_value{read32(data), read32(data + 4), read16(data + 8), read16(data + 10), read32(data + 12),
                                    std::vector<uint8_t>(data + 16, data + len)};
        case COOKIE_ECHO:
            return cookie_echo_chunk_value{std::vector<uint8_t>(data, data + len)};
        case COOKIE_ACK:
        case SHUTDOWN_ACK:
        case SHUTDOWN_COMPLETE:
            return empty_chunk_value{};
        case SHUTDOWN:
            if (len != 4) {
                throw std::runtime_error("SHUTDOWN chunk has wrong length");
            }
            return shutdown_chunk_value{read32(data)};
        case HEARTBEAT:
        case HEARTBEAT_ACK: {
            heartbeat_chunk_value heartbeat;
            if (!find_parameter(std::vector<uint8_t>(data, data + len), PARAM_HEARTBEAT_INFO, heartbeat.info)) {
                throw std::runtime_error("HEARTBEAT chunk has no Heartbeat Info parameter");
            }
            return heartbeat;
        }
        case DATA:
            if (len < 12) {
                throw std::runtime_error("DATA chunk too short");
            }
            return data_chunk_value{read32(data), read16(data + 4), read16(data + 6), read32(data + 8),
                                    std::vector<uint8_t>(data + 12, data + len)};
        case SACK: {
            sack_chunk_value sack;
            deserialize_sack_chunk(data, len, sack);
            return sack;
        }
        case OP_ERROR:
        case ABORT: {
            error_chunk_value error;
            bool well_formed = walk_tlvs(data, len, [&](uint16_t code, const uint8_t* cause, uint16_t length) {
                error.causes.push_back(error_cause{code, std::vector<uint8_t>(cause + SCTP_CHUNK_HEADER_SIZE, cause + length)});
                return true;
            });
            if (!well_formed) {
                throw std::runtime_error("ERROR chunk has a malformed cause");
            }
            return error;
        }
        default:
            return unknown_chunk_value{std::vector<uint8_t>(data, data + len)};
    }
}

void serialize_chunk(const SCTP_Chunk& chunk, std::vector<uint8_t>& out) {
    size_t start = out.size();
    out.resize(start + SCTP_CHUNK_HEADER_SIZE);

    const Chunk_Value_Type& value = chunk.chunk_value;
    switch (chunk.chunk_header.type) {
        case INIT:
        case INIT_ACK: {
            const auto& init = std::get<init_chunk_value>(value);
            append32(out, init.initiate_tag);
            append32(out, init.a_rwnd);
            append16(out, init.out_streams);
            append16(out, init.in_streams);
            append32(out, init.initial_tsn);
            out.append_range(init.optional_parameters);
            break;
        }
        case COOKIE_ECHO:
            out.append_range(std::get<cookie_echo_chunk_value>(value).cookie_data);
            break;
        case COOKIE_ACK:
        case SHUTDOWN_ACK:
        case SHUTDOWN_COMPLETE:
            (void)std::get<empty_chunk_value>(value);
            break;
        case SHUTDOWN:
            append32(out, std::get<shutdown_chunk_value>(value).cumulative_tsn_ack);
            break;
        case HEARTBEAT:
        case HEARTBEAT_ACK: {
            const auto& info = std::get<heartbeat_chunk_value>(value).info;
            append_parameter(out, PARAM_HEARTBEAT_INFO, info.data(), info.size());
            break;
        }
        case OP_ERROR:
        case ABORT:
            for (const auto& cause : std::get<error_chunk_value>(value).causes) {
                append_parameter(out, cause.code, cause.info.data(), cause.info.size());
            }
            break;
        case DATA: {
            const auto& data = std::get<data_chunk_value>(value);
            append32(out, data.tsn);
            append16(out, data.stream_identifier);
            append16(out, data.stream_seq_num);
            append32(out, data.payload_protocal);
            out.append_range(data.user_data);
            break;
        }
        case SACK:
            serialize_sack_chunk(std::get<sack_chunk_value>(value), out);
            break;
        default:
            out.append_range(std::get<unknown_chunk_value>(value).body);
            break;
    }

    uint16_t length = static_cast<uint16_t>(out.size() - start);
    out[start] = chunk.chunk_header.type;
    out[start + 1] = chunk.chunk_header.flag;
    out[start + 2] = static_cast<uint8_t>(length >> 8);
    out[start + 3] = static_cast<uint8_t>(length);
    out.resize(start + padded(length), 0);
}

}

void append_parameter(std::vector<uint8_t>& out, uint16_t type, const uint8_t* value, size_t len) {
    size_t total = SCTP_CHUNK_HEADER_SIZE + len;
    if (total > UINT16_MAX) {
        throw std::runtime_error("parameter too long");
    }

    append16(out, type);
    append16(out, static_cast<uint16_t>(total));
    out.insert(out.end(), value, value + len);
    out.resize(out.size() + padded(total) - total, 0);
}

bool find_parameter(const std::vector<uint8_t>& params, uint16_t type, std::vector<uint8_t>& value_out) {
    bool found = false;
    walk_tlvs(params.data(), params.size(), [&](uint16_t candidate, const uint8_t* parameter, uint16_t length) {
        if (candidate == type) {
            value_out.assign(parameter + SCTP_CHUNK_HEADER_SIZE, parameter + length);
            found = true;
        }
        return !found;
    });
    return found;
}

std::vector<uint32_t> find_ipv4_addresses(const std::vector<uint8_t>& params) {
    std::vector<uint32_t> out;
    walk_tlvs(params.data(), params.size(), [&](uint16_t type, const uint8_t* parameter, uint16_t length) {
        if (type == PARAM_IPV4_ADDRESS && length == 8) {
            out.push_back(read32(parameter + 4));
        }
        return true;
    });
    return out;
}

Parameter_Scan scan_parameters(const std::vector<uint8_t>& params, std::initializer_list<uint16_t> recognized) {
    Parameter_Scan scan;
    const uint8_t* end = params.data() + params.size();
    walk_tlvs(params.data(), params.size(), [&](uint16_t type, const uint8_t* parameter, uint16_t length) {
        if (std::ranges::contains(recognized, type)) {
            scan.recognized.insert(scan.recognized.end(), parameter, parameter + std::min(padded(length), static_cast<size_t>(end - parameter)));
            return true;
        }
        if (type & 0x4000) {
            std::vector<uint8_t> tlv(parameter, parameter + length);
            tlv.resize(padded(length), 0);
            scan.reported.push_back(std::move(tlv));
        }
        return (type & 0x8000) != 0;
    });
    return scan;
}

std::vector<uint8_t> serialize_state_cookie(const State_Cookie& cookie) {
    std::vector<uint8_t> out;
    out.reserve(STATE_COOKIE_SIZE + 4 * cookie.peer_addresses.size());

    out.push_back(cookie.version);
    out.push_back(cookie.secret_generation);
    append16(out, 0); // reserved
    append32(out, static_cast<uint32_t>(cookie.created_us >> 32));
    append32(out, static_cast<uint32_t>(cookie.created_us));
    append32(out, cookie.lifespan_us);
    append16(out, cookie.sctp_src_port);
    append16(out, cookie.sctp_dst_port);
    append32(out, cookie.peer_ipv4);
    append16(out, cookie.peer_udp_port);
    append16(out, static_cast<uint16_t>(cookie.peer_addresses.size()));
    append32(out, cookie.local_ver_tag);
    append32(out, cookie.peer_ver_tag);
    append32(out, cookie.local_initial_tsn);
    append32(out, cookie.peer_initial_tsn);
    append32(out, cookie.peer_a_rwnd);
    append16(out, cookie.local_out_streams);
    append16(out, cookie.local_in_streams);
    append16(out, cookie.peer_out_streams);
    append16(out, cookie.peer_in_streams);
    append32(out, cookie.local_tie_tag);
    append32(out, cookie.peer_tie_tag);

    if (out.size() != STATE_COOKIE_BODY_SIZE) {
        throw std::runtime_error("state cookie body size does not match STATE_COOKIE_BODY_SIZE");
    }
    for (uint32_t address : cookie.peer_addresses) {
        append32(out, address);
    }

    out.append_range(cookie.mac);
    return out;
}

bool deserialize_state_cookie(const std::vector<uint8_t>& data, State_Cookie& out) {
    if (data.size() < STATE_COOKIE_SIZE) {
        return false;
    }
    const uint8_t* p = data.data();
    size_t address_count = read16(p + 26);
    if (p[0] != STATE_COOKIE_VERSION || data.size() != STATE_COOKIE_SIZE + 4 * address_count) {
        return false;
    }

    out.version           = p[0];
    out.secret_generation = p[1];
    out.created_us        = static_cast<uint64_t>(read32(p + 4)) << 32 | read32(p + 8);
    out.lifespan_us       = read32(p + 12);
    out.sctp_src_port     = read16(p + 16);
    out.sctp_dst_port     = read16(p + 18);
    out.peer_ipv4         = read32(p + 20);
    out.peer_udp_port     = read16(p + 24);
    out.local_ver_tag     = read32(p + 28);
    out.peer_ver_tag      = read32(p + 32);
    out.local_initial_tsn = read32(p + 36);
    out.peer_initial_tsn  = read32(p + 40);
    out.peer_a_rwnd       = read32(p + 44);
    out.local_out_streams = read16(p + 48);
    out.local_in_streams  = read16(p + 50);
    out.peer_out_streams  = read16(p + 52);
    out.peer_in_streams   = read16(p + 54);
    out.local_tie_tag     = read32(p + 56);
    out.peer_tie_tag      = read32(p + 60);
    out.peer_addresses.clear();
    for (size_t i = 0; i < address_count; ++i) {
        out.peer_addresses.push_back(read32(p + STATE_COOKIE_BODY_SIZE + 4 * i));
    }
    std::memcpy(out.mac, p + data.size() - STATE_COOKIE_MAC_SIZE, STATE_COOKIE_MAC_SIZE);
    return true;
}

uint32_t sctp_read_wire_checksum(const uint8_t* data) {
    return read_checksum_le(data + SCTP_CHECKSUM_OFFSET);
}

void sctp_clear_wire_checksum(uint8_t* data) {
    std::memset(data + SCTP_CHECKSUM_OFFSET, 0, 4);
}

SCTP_Packet deserialize_sctp_packet(const uint8_t* data, size_t len) {
    if (len < SCTP_COMMON_HEADER_SIZE) {
        throw std::runtime_error("buffer underflow");
    }
    SCTP_Packet out;
    out.header = {read16(data), read16(data + 2), read32(data + 4), read_checksum_le(data + SCTP_CHECKSUM_OFFSET)};
    size_t offset = SCTP_COMMON_HEADER_SIZE;
    while (offset < len) {
        if (len - offset < SCTP_CHUNK_HEADER_SIZE) {
            throw std::runtime_error("truncated chunk header");
        }
        SCTP_Chunk_Header header{static_cast<Chunk_Type>(data[offset]), data[offset + 1], read16(data + offset + 2)};
        if (header.length < SCTP_CHUNK_HEADER_SIZE || header.length > len - offset) {
            throw std::runtime_error("chunk length out of range");
        }
        SCTP_Chunk chunk{header, deserialize_chunk_value(header.type, data + offset + SCTP_CHUNK_HEADER_SIZE, header.length - SCTP_CHUNK_HEADER_SIZE)};
        if (header.type == DATA) {
            std::get<data_chunk_value>(chunk.chunk_value).flags = header.flag & (DATA_FLAG_U | DATA_FLAG_B | DATA_FLAG_E);
        }
        out.chunks.push_back(std::move(chunk));
        offset = std::min(len, offset + padded(header.length));
    }
    return out;
}

std::vector<uint8_t> serialize_sctp_packet(const SCTP_Packet& pkt) {
    std::vector<uint8_t> out;
    out.reserve(SCTP_COMMON_HEADER_SIZE + 64);

    append16(out, pkt.header.src_port);
    append16(out, pkt.header.des_port);
    append32(out, pkt.header.verification_tag);
    append32(out, 0);

    for (const auto& chunk : pkt.chunks) {
        serialize_chunk(chunk, out);
    }

    write_checksum_le(out.data() + SCTP_CHECKSUM_OFFSET, calculate_sctp_checksum(out.data(), out.size()));
    return out;
}

void deserialize_sack_chunk(const uint8_t* data, size_t len, sack_chunk_value& out) {
    if (len < 12) {
        throw std::runtime_error("SACK chunk too short");
    }
    uint16_t gap_count = read16(data + 8);
    uint16_t duplicate_count = read16(data + 10);
    if (12 + 4 * size_t{gap_count} + 4 * size_t{duplicate_count} != len) {
        throw std::runtime_error("SACK chunk has inconsistent counts");
    }

    sack_chunk_value sack{read32(data), read32(data + 4), {}, {}};
    const uint8_t* p = data + 12;
    for (uint16_t i = 0; i < gap_count; ++i, p += 4) {
        sack_gap_ack_block block{read16(p), read16(p + 2)};
        if (block.start == 0 || block.end < block.start || (i > 0 && block.start <= sack.gap_ack_blocks.back().end)) {
            throw std::runtime_error("SACK chunk has invalid gap ack block");
        }
        sack.gap_ack_blocks.push_back(block);
    }
    for (uint16_t i = 0; i < duplicate_count; ++i, p += 4) {
        sack.duplicate_tsns.push_back(read32(p));
    }
    out = std::move(sack);
}

void serialize_sack_chunk(const sack_chunk_value& v, std::vector<uint8_t>& out) {
    if (v.gap_ack_blocks.size() > UINT16_MAX || v.duplicate_tsns.size() > UINT16_MAX) {
        throw std::runtime_error("too many SACK entries");
    }
    append32(out, v.cumulative_tsn_ack);
    append32(out, v.a_rwnd);
    append16(out, static_cast<uint16_t>(v.gap_ack_blocks.size()));
    append16(out, static_cast<uint16_t>(v.duplicate_tsns.size()));
    for (const auto& block : v.gap_ack_blocks) {
        if (block.start == 0 || block.end < block.start) {
            throw std::runtime_error("invalid SACK gap ack block");
        }
        append16(out, block.start);
        append16(out, block.end);
    }
    for (uint32_t tsn : v.duplicate_tsns) {
        append32(out, tsn);
    }
}
