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

/*------------------- RFC 9260 3.2.1 parameters and 5.1.3 cookie ------------*/

void append_parameter(std::vector<uint8_t>& out, uint16_t type, const uint8_t* value, size_t len) {
    size_t total = SCTP_CHUNK_HEADER_SIZE + len;
    if (total > UINT16_MAX) {
        throw std::runtime_error("parameter too long");
    }

    append16(out, type);
    append16(out, static_cast<uint16_t>(total));
    out.insert(out.end(), value, value + len);
    out.resize(out.size() + ((4 - (total % 4)) % 4), 0);   // padding is not counted in Length
}

bool find_parameter(const std::vector<uint8_t>& params, uint16_t type, std::vector<uint8_t>& value_out) {
    size_t offset = 0;
    while (offset + SCTP_CHUNK_HEADER_SIZE <= params.size()) {
        uint16_t parameter_type = read16(&params[offset]);
        uint16_t length = read16(&params[offset + 2]);

        // Below 4 the advance stalls and the walk spins forever.
        if (length < SCTP_CHUNK_HEADER_SIZE || offset + length > params.size()) {
            return false;
        }
        if (parameter_type == type) {
            value_out.assign(params.begin() + static_cast<std::ptrdiff_t>(offset + SCTP_CHUNK_HEADER_SIZE),
                             params.begin() + static_cast<std::ptrdiff_t>(offset + length));
            return true;
        }
        offset += (static_cast<size_t>(length) + 3) & ~size_t{3};
    }
    return false;
}

std::vector<uint8_t> serialize_state_cookie(const State_Cookie& cookie) {
    std::vector<uint8_t> out;
    out.reserve(STATE_COOKIE_SIZE);

    out.push_back(cookie.version);
    out.push_back(cookie.secret_generation);
    append16(out, 0);                                                   // reserved
    append32(out, static_cast<uint32_t>(cookie.created_us >> 32));
    append32(out, static_cast<uint32_t>(cookie.created_us));
    append32(out, cookie.lifespan_us);
    append16(out, cookie.sctp_src_port);
    append16(out, cookie.sctp_dst_port);
    append32(out, cookie.peer_ipv4);
    append16(out, cookie.peer_udp_port);
    append16(out, 0);                                                   // reserved
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

    // A field added without bumping STATE_COOKIE_BODY_SIZE shifts the MAC
    // boundary and silently breaks every cookie.
    if (out.size() != STATE_COOKIE_BODY_SIZE) {
        throw std::runtime_error("state cookie body size does not match STATE_COOKIE_BODY_SIZE");
    }

    out.insert(out.end(), cookie.mac, cookie.mac + STATE_COOKIE_MAC_SIZE);
    return out;
}

bool deserialize_state_cookie(const std::vector<uint8_t>& data, State_Cookie& out) {
    if (data.size() != STATE_COOKIE_SIZE) {
        return false;
    }
    const uint8_t* p = data.data();
    if (p[0] != STATE_COOKIE_VERSION) {
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
    std::memcpy(out.mac, p + STATE_COOKIE_BODY_SIZE, STATE_COOKIE_MAC_SIZE);
    return true;
}

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
    Chunk_Type type, 
    const uint8_t* data, 
    size_t len,
    Chunk_Value_Type& out
) {
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
        case OP_ERROR: {
            error_chunk_value v;
            deserialize_error_chunk(data, len, v);
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

void deserialize_error_chunk(const uint8_t* data, size_t len, error_chunk_value& out) {
    // Causes are 3.2.1 TLVs. Throws rather than returning false, matching the
    // other chunk deserializers.
    size_t offset = 0;
    while (offset + SCTP_CHUNK_HEADER_SIZE <= len) {
        uint16_t code = read16(data + offset);
        uint16_t length = read16(data + offset + 2);

        if (length < SCTP_CHUNK_HEADER_SIZE)
            throw std::runtime_error("ERROR chunk cause length below header size");
        if (offset + length > len)
            throw std::runtime_error("ERROR chunk cause overruns chunk");

        out.causes.push_back(error_cause{
            code,
            std::vector<uint8_t>(data + offset + SCTP_CHUNK_HEADER_SIZE, data + offset + length),
        });
        offset += (static_cast<size_t>(length) + 3) & ~size_t{3};
    }
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
        case OP_ERROR:
            serialize_error_chunk(std::get<error_chunk_value>(chunk.chunk_value), out);
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

void serialize_error_chunk(const error_chunk_value& v, std::vector<uint8_t>& out) {
    for (const auto& cause : v.causes) {
        append_parameter(out, cause.code, cause.info.data(), cause.info.size());
    }
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
