#ifndef SCTP_UTILS_HPP
#define SCTP_UTILS_HPP

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
#endif // SCTP_UTILS_HPP
