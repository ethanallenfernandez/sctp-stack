#ifndef SCTP_HPP
#define SCTP_HPP

#include <stdint.h>
#include <cstddef>
#include <vector>
#include <variant>
#include <chrono>

// These are intentionally NOT sizeof() of the structs below: struct fields hold HOST byte order.
constexpr size_t SCTP_COMMON_HEADER_SIZE = 12;
constexpr size_t SCTP_CHUNK_HEADER_SIZE  = 4;
constexpr size_t SCTP_CHECKSUM_OFFSET    = 8;

// RFC 9260 section 16 recommended values. Names match the RFC's.
namespace sctp_parameters {
    inline constexpr std::chrono::milliseconds RTO_INITIAL = std::chrono::seconds{1};
    inline constexpr std::chrono::milliseconds RTO_MIN = std::chrono::seconds{1};
    inline constexpr std::chrono::milliseconds RTO_MAX = std::chrono::seconds{60};
    inline constexpr uint32_t MAX_BURST = 4;
    inline constexpr double RTO_ALPHA = 1.0 / 8.0;
    inline constexpr double RTO_BETA = 1.0 / 4.0;
    inline constexpr std::chrono::milliseconds VALID_COOKIE_LIFE = std::chrono::seconds{60};
    inline constexpr uint16_t ASSOCIATION_MAX_RETRANS = 10;
    inline constexpr uint16_t PATH_MAX_RETRANS = 5;
    inline constexpr uint16_t MAX_INIT_RETRANSMITS = 8;
    inline constexpr std::chrono::milliseconds HB_INTERVAL =  std::chrono::seconds{30};
    inline constexpr uint32_t HB_MAX_BURST = 1;
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
    OP_ERROR = 9,
    COOKIE_ECHO = 10,
    COOKIE_ACK = 11,
    ECNE = 12,
    CWR = 13, 
    SHUTDOWN_COMPLETE = 14,
};

constexpr uint8_t CHUNK_FLAG_T_BIT = 0x01;   // ABORT, SHUTDOWN COMPLETE: tag is reflected

enum Param_Type : uint16_t {
    PARAM_HEARTBEAT_INFO = 1,
    PARAM_IPV4_ADDRESS = 5,
    PARAM_IPV6_ADDRESS = 6,
    PARAM_STATE_COOKIE = 7,
    PARAM_UNRECOGNIZED = 8,
    PARAM_COOKIE_PRESERVATIVE = 9,
};

enum Error_Cause_Code : uint16_t {
    CAUSE_INVALID_STREAM_ID = 1,
    CAUSE_MISSING_MANDATORY_PARAM = 2,
    CAUSE_STALE_COOKIE = 3,
    CAUSE_OUT_OF_RESOURCE = 4,
    CAUSE_UNRESOLVABLE_ADDRESS = 5,
    CAUSE_UNRECOGNIZED_CHUNK = 6,
    CAUSE_INVALID_MANDATORY_PARAM = 7,
    CAUSE_UNRECOGNIZED_PARAMS = 8,
    CAUSE_NO_USER_DATA = 9,
    CAUSE_COOKIE_WHILE_SHUTTING_DOWN = 10,
    CAUSE_RESTART_WITH_NEW_ADDRESSES = 11,
    CAUSE_USER_INITIATED_ABORT = 12,
    CAUSE_PROTOCOL_VIOLATION = 13,
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

// COOKIE ACK, SHUTDOWN ACK, SHUTDOWN COMPLETE.
struct empty_chunk_value {};

struct shutdown_chunk_value {
    uint32_t cumulative_tsn_ack;
};

// HEARTBEAT and HEARTBEAT ACK: the Heartbeat Info parameter's value, echoed verbatim.
struct heartbeat_chunk_value {
    std::vector<uint8_t> info;
};

// Body of a chunk type we do not implement; header fields stay in SCTP_Chunk_Header.
struct unknown_chunk_value {
    std::vector<uint8_t> body;
};

struct error_cause {
    uint16_t code;
    std::vector<uint8_t> info;
};

// ERROR and ABORT.
struct error_chunk_value {
    std::vector<error_cause> causes;
};

constexpr size_t STATE_COOKIE_BODY_SIZE = 64;
constexpr size_t STATE_COOKIE_MAC_SIZE = 32;
constexpr size_t STATE_COOKIE_SIZE = STATE_COOKIE_BODY_SIZE + STATE_COOKIE_MAC_SIZE;
constexpr uint8_t STATE_COOKIE_VERSION = 1;
constexpr size_t COOKIE_SECRET_SIZE = 32;

struct State_Cookie {
    uint8_t version;                  // STATE_COOKIE_VERSION
    uint8_t secret_generation;        // selects the rotating secret that signed this
    uint64_t created_us;              // steady_clock, microseconds
    uint32_t lifespan_us;             // Valid.Cookie.Life
    uint16_t sctp_src_port;           // peer's, from the INIT common header
    uint16_t sctp_dst_port;           // ours
    uint32_t peer_ipv4;               // host order; serializer applies htonl
    uint16_t peer_udp_port;           // host order; rebuilds the Association_Key
    uint32_t local_ver_tag;           // tag we advertised in INIT ACK
    uint32_t peer_ver_tag;            // INIT Initiate Tag
    uint32_t local_initial_tsn;
    uint32_t peer_initial_tsn;
    uint32_t peer_a_rwnd;
    uint16_t local_out_streams;
    uint16_t local_in_streams;
    uint16_t peer_out_streams;
    uint16_t peer_in_streams;
    uint32_t local_tie_tag;
    uint32_t peer_tie_tag;
    uint8_t mac[STATE_COOKIE_MAC_SIZE];
};

struct SCTP_Chunk_Header {
    Chunk_Type type; // uint8_t enum
    uint8_t flag;
    uint16_t length;
};

using Chunk_Value_Type = std::variant<
    init_chunk_value, 
    cookie_echo_chunk_value,
    empty_chunk_value,
    data_chunk_value,
    sack_chunk_value,
    error_chunk_value,
    shutdown_chunk_value,
    heartbeat_chunk_value,
    unknown_chunk_value
>;

struct SCTP_Chunk {
    SCTP_Chunk_Header chunk_header;
    Chunk_Value_Type chunk_value;
}; 

struct SCTP_Packet {
    SCTP_Common_Header header;
    std::vector<SCTP_Chunk> chunks;
};

constexpr int RWND = 65535;

#endif
