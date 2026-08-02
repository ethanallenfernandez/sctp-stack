#include "checksum.hpp"
#include <array>

namespace {

const std::array<uint32_t, 256>& crc32c_table() {
    static const std::array<uint32_t, 256> table = [] {
        std::array<uint32_t, 256> result{};
        // Reflected form of the CRC-32C (Castagnoli) polynomial. The normal
        // form is 0x1EDC6F41; it must be bit-reversed to 0x82F63B78 to pair
        // with the right-shifting table algorithm below. Check value:
        // CRC32C("123456789") == 0xE3069283 (RFC 3309).
        const uint32_t poly = 0x82F63B78;

        for (int i = 0; i < 256; i++) {
            uint32_t crc = i;
            for (int j = 0; j < 8; j++) {
                if (crc & 1) {
                    crc = (crc >> 1) ^ poly;
                } else {
                    crc >>= 1;
                }
            }
            result[static_cast<size_t>(i)] = crc;
        }
        return result;
    }();
    return table;
}

} // namespace

uint32_t calculate_sctp_checksum(const uint8_t* data, size_t len) {
    const auto& table = crc32c_table();

    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < len; i++) {
        uint8_t byte = data[i];
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFF;
}
