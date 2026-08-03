#ifndef SCTP_UTILS_HPP
#define SCTP_UTILS_HPP

#include <sctp/sctp.hpp>

#include <algorithm>
#include <cstdint>

inline bool tsn_lt(uint32_t a, uint32_t b) {
    constexpr uint32_t HALF_TSN_SPACE = uint32_t{1} << 31;
    uint32_t distance = b - a;
    return distance != 0 && distance < HALF_TSN_SPACE;
}

inline bool tsn_lte(uint32_t a, uint32_t b) {
    return a == b || tsn_lt(a, b);
}

inline bool tsn_gt(uint32_t a, uint32_t b) {
    return tsn_lt(b, a);
}

inline bool tsn_gte(uint32_t a, uint32_t b) {
    return a == b || tsn_gt(a, b);
}

// Whether a SACK reports this TSN as received, either below the cumulative ack
// point or inside one of the Gap Ack Blocks (RFC 9260 3.3.4). Gap Ack Block
// offsets are 16-bit relative to the cumulative TSN ack, so anything further
// out than UINT16_MAX cannot be covered by a block.
inline bool sack_acknowledges(const sack_chunk_value& sack, uint32_t tsn) {
    if (tsn_lte(tsn, sack.cumulative_tsn_ack)) {
        return true;
    }
    uint32_t offset = tsn - sack.cumulative_tsn_ack;
    if (offset > UINT16_MAX) {
        return false;
    }
    return std::any_of(
        sack.gap_ack_blocks.begin(),
        sack.gap_ack_blocks.end(),
        [offset](const sack_gap_ack_block& block) {
            return offset >= block.start && offset <= block.end;
        }
    );
}
#endif // SCTP_UTILS_HPP
