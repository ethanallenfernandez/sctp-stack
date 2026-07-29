#ifndef SCTP_UTILS_HPP
#define SCTP_UTILS_HPP

#include <cstdint>
#include <limits>

inline bool tsn_lt(uint32_t a, uint32_t b) {
    constexpr uint32_t HALF = std::numeric_limits<uint32_t>::max() / 2;
    uint32_t diff = static_cast<uint32_t>(b - a);
    return (diff > 0) && (diff <= HALF);
}
#endif // SCTP_UTILS_HPP