#ifndef SCTP_HPP
#define SCTP_HPP

// Protocol data types and wire constants only. Deliberately free of any socket
// or platform dependency, so the codec and its tests can include this without
// pulling in the networking headers.
#include <stdint.h>
#include <cstddef>
#include <vector>
#include <variant>
#include <chrono>

// On-the-wire sizes and offsets from RFC 9260 §3.1. These are intentionally NOT
// sizeof() of the structs below: struct fields hold HOST byte order and are
// converted to/from network byte order during (de)serialization, so the structs
// are no longer a 1:1 image of the wire layout.
constexpr size_t SCTP_COMMON_HEADER_SIZE = 12;
constexpr size_t SCTP_CHUNK_HEADER_SIZE  = 4;
constexpr size_t SCTP_CHECKSUM_OFFSET    = 8;

// RFC 9260 section 16 recommended protocol parameter values.
namespace sctp_parameters {
// RTO.Initial: 1 second.
inline constexpr std::chrono::milliseconds RTO_INITIAL =
    std::chrono::seconds{1};
// RTO.Min: 1 second.
inline constexpr std::chrono::milliseconds RTO_MIN =
    std::chrono::seconds{1};
// RTO.Max: 60 seconds.
inline constexpr std::chrono::milliseconds RTO_MAX =
    std::chrono::seconds{60};
// Max.Burst: 4 packets.
inline constexpr uint32_t MAX_BURST = 4;
// RTO.Alpha: 1/8.
inline constexpr double RTO_ALPHA = 1.0 / 8.0;
// RTO.Beta: 1/4.
inline constexpr double RTO_BETA = 1.0 / 4.0;
// Valid.Cookie.Life: 60 seconds.
inline constexpr std::chrono::milliseconds VALID_COOKIE_LIFE =
    std::chrono::seconds{60};
// Association.Max.Retrans: 10 attempts.
inline constexpr uint16_t ASSOCIATION_MAX_RETRANS = 10;
// Path.Max.Retrans: 5 attempts per destination address.
inline constexpr uint16_t PATH_MAX_RETRANS = 5;
// Max.Init.Retransmits: 8 attempts.
inline constexpr uint16_t MAX_INIT_RETRANSMITS = 8;
// HB.interval: 30 seconds.
inline constexpr std::chrono::milliseconds HB_INTERVAL =
    std::chrono::seconds{30};
// HB.Max.Burst: 1 packet.
inline constexpr uint32_t HB_MAX_BURST = 1;
// SACK.Delay: 200 milliseconds.
inline constexpr std::chrono::milliseconds SACK_DELAY{200};
} // namespace sctp_parameters

// All multi-byte fields below are in HOST byte order.
struct SCTP_Common_Header {
    uint16_t src_port;
    uint16_t des_port;
    uint32_t verification_tag;
    uint32_t checksum;
};

enum Chunk_Type : uint8_t {
    DATA = 0,
    INIT = 1,
    INIT_ACK = 2,
    SACK = 3,
    HEARTBEAT = 4,
    HEARTBEAT_ACK = 5,
    ABORT = 6,
    SHUTDOWN = 7,
    SHUTDOWN_ACK = 8,
    //ERROR = 9,
    COOKIE_ECHO = 10,
    COOKIE_ACK = 11,
    ECNE = 12,
    CWR = 13, 
    SHUTDOWN_COMPLETE = 14,
};

struct init_chunk_value {
    uint32_t initiate_tag;
    uint32_t a_rwnd;
    uint16_t out_streams;
    uint16_t in_streams;
    uint32_t initial_tsn;
    std::vector<uint8_t> optional_parameters;
};

struct data_chunk_value {
    uint32_t tsn;
    uint16_t stream_identifier;
    uint16_t stream_seq_num;
    uint32_t payload_protocal;
    std::vector<uint8_t> user_data;
};

struct sack_gap_ack_block {
    uint16_t start;
    uint16_t end;
};

struct sack_chunk_value {
    uint32_t cumulative_tsn_ack;
    uint32_t a_rwnd;
    uint16_t number_of_gap_ack_blocks;
    uint16_t number_of_duplicate_tsns;
    std::vector<sack_gap_ack_block> gap_ack_blocks;
    std::vector<uint32_t> duplicate_tsns;
};

struct cookie_echo_chunk_value {
    std::vector<uint8_t> cookie_data;
};

struct cookie_ack_chunk_value {};

struct SCTP_Chunk_Header {
    Chunk_Type type; // uint8_t enum
    uint8_t flag;
    uint16_t length;
};

struct SCTP_Chunk {
    SCTP_Chunk_Header chunk_header;
    std::variant<init_chunk_value, cookie_echo_chunk_value,
                 cookie_ack_chunk_value, data_chunk_value,
                 sack_chunk_value> chunk_value;
}; 

struct SCTP_Packet {
    SCTP_Common_Header header;
    std::vector<SCTP_Chunk> chunks;
};

constexpr int RWND = 65535;

const SCTP_Packet INIT_PACKET = {
    .header = {
        .src_port = 0,          // set later if needed
        .des_port = 0,          // set later if needed
        .verification_tag = 0,     // MUST be 0 for INIT
        .checksum = 0              // computed after serialization
    },
    .chunks = {
        SCTP_Chunk {
            .chunk_header = {
                .type = INIT,
                .flag = 0,
                // Recomputed by serialize_chunk from the encoded body. sizeof()
                // on these structs does not give a wire length: they contain a
                // std::vector and are padded for host alignment.
                .length = 0
            },
            .chunk_value = init_chunk_value {
                .initiate_tag = 0,
                .a_rwnd = RWND,
                .out_streams = 1,
                .in_streams = 1,
                .initial_tsn = 0,
                .optional_parameters = {}
            }
        }
    }
};

#endif
