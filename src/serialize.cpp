#include "serialize.hpp"
#include <cstring>
#include <cstddef>
#include <stdexcept>
#include <utility>
#include "checksum.hpp"
#include <sctp/platform.hpp>   // htons/htonl/ntohs/ntohl

namespace {

/*----------------- Network byte order (big-endian) helpers -----------------*/

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

// The CRC32c checksum is the one field NOT in network byte order: RFC 9260 §6.8
// (via RFC 3309) places it on the wire in little-endian. Writing it big-endian
// like every other field is a classic interop bug, so it gets explicit helpers.
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

} // namespace

uint32_t sctp_read_wire_checksum(const uint8_t* data) {
    return read_checksum_le(data + SCTP_CHECKSUM_OFFSET);
}

void sctp_clear_wire_checksum(uint8_t* data) {
    std::memset(data + SCTP_CHECKSUM_OFFSET, 0, 4);
}

SCTP_Packet deserialize_sctp_packet(const uint8_t* data, size_t len) {
    SCTP_Packet out;

    /*--------------Deserializing Helpers--------------*/
    size_t offset = 0;

    auto can_read = [&](size_t read_len) {
        return read_len <= len - offset;   // offset <= len always holds
    };

    auto read_ptr = [&](size_t read_len) -> const uint8_t* {
        if (!can_read(read_len))
            throw std::runtime_error("buffer underflow");
        const uint8_t* p = data + offset;
        offset += read_len;
        return p;
    };
    /*--------------------------------------------*/

    const uint8_t* h = read_ptr(SCTP_COMMON_HEADER_SIZE);
    out.header.src_port         = read16(h + 0);
    out.header.des_port         = read16(h + 2);
    out.header.verification_tag = read32(h + 4);
    out.header.checksum         = read_checksum_le(h + 8);

    while (offset < len) {
        if (!can_read(SCTP_CHUNK_HEADER_SIZE))
            throw std::runtime_error("truncated chunk header");

        const uint8_t* ch_p = read_ptr(SCTP_CHUNK_HEADER_SIZE);
        SCTP_Chunk_Header ch;
        ch.type   = static_cast<Chunk_Type>(ch_p[0]);
        ch.flag   = ch_p[1];
        ch.length = read16(ch_p + 2);

        // Chunk Length counts the 4-byte header itself, so anything below that
        // is malformed. Without this check the subtraction wraps around.
        if (ch.length < SCTP_CHUNK_HEADER_SIZE)
            throw std::runtime_error("chunk length below header size");

        size_t body_len = ch.length - SCTP_CHUNK_HEADER_SIZE;
        if (!can_read(body_len))
            throw std::runtime_error("truncated chunk body");

        SCTP_Chunk chunk;
        chunk.chunk_header = ch;

        const uint8_t* body = read_ptr(body_len);
        deserialize_chunk_value(ch.type, body, body_len, chunk.chunk_value);

        out.chunks.push_back(std::move(chunk));

        // Padding to 4-byte boundary based on chunk.length. The final chunk in a
        // packet may omit its padding, so a short read here is not an error.
        size_t padded = (static_cast<size_t>(ch.length) + 3) & ~size_t{3};
        size_t pad = padded - ch.length;
        offset += (pad <= len - offset) ? pad : (len - offset);
    }
    return out;
}

void deserialize_chunk_value(
        Chunk_Type type, const uint8_t* data, size_t len,
        std::variant<init_chunk_value, cookie_echo_chunk_value,
                     cookie_ack_chunk_value, data_chunk_value,
                     sack_chunk_value>& out) {
    switch (type) {
        case INIT:
        case INIT_ACK: {
            init_chunk_value v;
            deserialize_init_chunk(data, len, v);
            out = std::move(v);
            break;
        }
        case COOKIE_ECHO: {
            cookie_echo_chunk_value v;
            deserialize_cookie_echo_chunk(data, len, v);
            out = std::move(v);
            break;
        }
        case COOKIE_ACK: {
            cookie_ack_chunk_value v;
            deserialize_cookie_ack_chunk(data, len, v);
            out = std::move(v);
            break;
        }
        case DATA: {
            data_chunk_value v;
            deserialize_data_chunk(data, len, v);
            out = std::move(v);
            break;
        }
        case SACK: {
            sack_chunk_value v;
            deserialize_sack_chunk(data, len, v);
            out = std::move(v);
            break;
        }
        default:
            throw std::runtime_error("unsupported chunk type");
    }
}

void deserialize_init_chunk(const uint8_t* data, size_t len, init_chunk_value& out) {
    if (len < 16)
        throw std::runtime_error("INIT chunk too short");

    out.initiate_tag = read32(data + 0);
    out.a_rwnd       = read32(data + 4);
    out.out_streams  = read16(data + 8);
    out.in_streams   = read16(data + 10);
    out.initial_tsn  = read32(data + 12);

    out.optional_parameters.assign(data + 16, data + len);
}

void deserialize_cookie_echo_chunk(const uint8_t* data, size_t len, cookie_echo_chunk_value& out) {
    out.cookie_data.assign(data, data + len);
}

void deserialize_cookie_ack_chunk(const uint8_t* data, size_t len, cookie_ack_chunk_value& out) {
    // COOKIE_ACK has no payload
    (void)data;
    (void)len;
    (void)out;
}
void deserialize_data_chunk(const uint8_t* data, size_t len, data_chunk_value& out) {
    if (len < 12)
        throw std::runtime_error("DATA chunk too short");

    out.tsn               = read32(data + 0);
    out.stream_identifier = read16(data + 4);
    out.stream_seq_num    = read16(data + 6);
    out.payload_protocal  = read32(data + 8);

    out.user_data.assign(data + 12, data + len);
}

void deserialize_sack_chunk(
        const uint8_t* data, size_t len, sack_chunk_value& out) {
    if (len < 12)
        throw std::runtime_error("SACK chunk too short");

    uint16_t gap_count = read16(data + 8);
    uint16_t duplicate_count = read16(data + 10);
    size_t required = 12
        + static_cast<size_t>(gap_count) * 4
        + static_cast<size_t>(duplicate_count) * 4;
    if (required != len)
        throw std::runtime_error("SACK chunk has inconsistent counts");

    std::vector<sack_gap_ack_block> gap_ack_blocks;
    gap_ack_blocks.reserve(gap_count);
    size_t offset = 12;
    uint16_t previous_end = 0;
    for (uint16_t i = 0; i < gap_count; ++i) {
        uint16_t start = read16(data + offset);
        uint16_t end = read16(data + offset + 2);
        if (start == 0 || end < start
                || (i > 0 && start <= previous_end))
            throw std::runtime_error("SACK chunk has invalid gap ack block");
        gap_ack_blocks.push_back({start, end});
        previous_end = end;
        offset += 4;
    }

    std::vector<uint32_t> duplicate_tsns;
    duplicate_tsns.reserve(duplicate_count);
    for (uint16_t i = 0; i < duplicate_count; ++i) {
        duplicate_tsns.push_back(read32(data + offset));
        offset += 4;
    }

    out = sack_chunk_value{
        .cumulative_tsn_ack = read32(data + 0),
        .a_rwnd = read32(data + 4),
        .number_of_gap_ack_blocks = gap_count,
        .number_of_duplicate_tsns = duplicate_count,
        .gap_ack_blocks = std::move(gap_ack_blocks),
        .duplicate_tsns = std::move(duplicate_tsns),
    };
}

std::vector<uint8_t> serialize_sctp_packet(const SCTP_Packet& pkt) {
    std::vector<uint8_t> out;
    out.reserve(SCTP_COMMON_HEADER_SIZE + 64);

    // Write header with checksum = 0, then fill it in once the body is known.
    append16(out, pkt.header.src_port);
    append16(out, pkt.header.des_port);
    append32(out, pkt.header.verification_tag);
    append32(out, 0);

    for (const auto& chunk : pkt.chunks) {
        serialize_chunk(chunk, out);
    }

    uint32_t checksum = calculate_sctp_checksum(out.data(), out.size());
    write_checksum_le(out.data() + SCTP_CHECKSUM_OFFSET, checksum);

    return out;
}

void serialize_chunk(const SCTP_Chunk& chunk, std::vector<uint8_t>& out) {
    size_t start = out.size();

    // Reserve space for header (written later)
    out.resize(start + SCTP_CHUNK_HEADER_SIZE);

    switch (chunk.chunk_header.type) {
        case INIT:
        case INIT_ACK:
            serialize_init_chunk(std::get<init_chunk_value>(chunk.chunk_value), out);
            break;
        case COOKIE_ECHO:
            serialize_cookie_echo_chunk(std::get<cookie_echo_chunk_value>(chunk.chunk_value), out);
            break;
        case COOKIE_ACK:
            serialize_cookie_ack_chunk(std::get<cookie_ack_chunk_value>(chunk.chunk_value), out);
            break;
        case DATA:
            serialize_data_chunk(std::get<data_chunk_value>(chunk.chunk_value), out);
            break;
        case SACK:
            serialize_sack_chunk(std::get<sack_chunk_value>(chunk.chunk_value), out);
            break;
        default:
            throw std::runtime_error("unsupported chunk type");
    }

    // Chunk Length covers the header and body but excludes trailing padding.
    uint16_t length = static_cast<uint16_t>(out.size() - start);

    out[start + 0] = static_cast<uint8_t>(chunk.chunk_header.type);
    out[start + 1] = chunk.chunk_header.flag;
    uint16_t len_be = htons(length);
    std::memcpy(out.data() + start + 2, &len_be, 2);

    // Pad to 4-byte boundary
    size_t padded = (static_cast<size_t>(length) + 3) & ~size_t{3};
    out.resize(start + padded, 0);
}

void serialize_init_chunk(const init_chunk_value& v, std::vector<uint8_t>& out) {
    append32(out, v.initiate_tag);
    append32(out, v.a_rwnd);
    append16(out, v.out_streams);
    append16(out, v.in_streams);
    append32(out, v.initial_tsn);

    out.insert(out.end(),
               v.optional_parameters.begin(),
               v.optional_parameters.end());
}

void serialize_cookie_echo_chunk(const cookie_echo_chunk_value& v, std::vector<uint8_t>& out) {
    out.insert(out.end(), v.cookie_data.begin(), v.cookie_data.end());
}

void serialize_cookie_ack_chunk(const cookie_ack_chunk_value& v, std::vector<uint8_t>& out) {
    // COOKIE_ACK has no payload
    (void)v;
    (void)out;
}

void serialize_data_chunk(const data_chunk_value& v,std::vector<uint8_t>& out) {
    append32(out, v.tsn);
    append16(out, v.stream_identifier);
    append16(out, v.stream_seq_num);
    append32(out, v.payload_protocal);

    out.insert(out.end(),
               v.user_data.begin(),
               v.user_data.end());
}

void serialize_sack_chunk(
        const sack_chunk_value& v, std::vector<uint8_t>& out) {
    if (v.gap_ack_blocks.size() > UINT16_MAX
            || v.duplicate_tsns.size() > UINT16_MAX) {
        throw std::runtime_error("too many SACK entries");
    }
    if (v.number_of_gap_ack_blocks != v.gap_ack_blocks.size()
            || v.number_of_duplicate_tsns != v.duplicate_tsns.size()) {
        throw std::runtime_error("SACK counts do not match entry lists");
    }

    append32(out, v.cumulative_tsn_ack);
    append32(out, v.a_rwnd);
    append16(out, v.number_of_gap_ack_blocks);
    append16(out, v.number_of_duplicate_tsns);
    for (const auto& block : v.gap_ack_blocks) {
        if (block.start == 0 || block.end < block.start)
            throw std::runtime_error("invalid SACK gap ack block");
        append16(out, block.start);
        append16(out, block.end);
    }
    for (uint32_t tsn : v.duplicate_tsns) {
        append32(out, tsn);
    }
}
