// Tests our wrapper, not the kernel's randomness: full fills, odd lengths, and
// generate_random covering the whole object. Statistical assertions are
// deliberately absent - any strong enough to matter are strong enough to flake.

#include <sctp/platform.hpp>
#include "socket_internal.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

constexpr uint8_t MARKER = 0xAA;
constexpr int TRIALS = 64;

// One trial cannot tell a short fill from a byte that happened to be 0xAA, so
// every position must change at least once across TRIALS. False failure odds
// are (1/256)^64.
bool every_position_filled(size_t length) {
    std::vector<bool> ever_changed(length, false);
    std::vector<uint8_t> buffer(length);

    for (int trial = 0; trial < TRIALS; ++trial) {
        std::memset(buffer.data(), MARKER, length);
        random_bytes(buffer.data(), length);
        for (size_t i = 0; i < length; ++i) {
            if (buffer[i] != MARKER) {
                ever_changed[i] = true;
            }
        }
    }

    for (size_t i = 0; i < length; ++i) {
        if (!ever_changed[i]) {
            std::printf("      position %zu of %zu never changed\n", i, length);
            return false;
        }
    }
    return true;
}

// Catches a write past the requested length.
bool stays_within_bounds(size_t length) {
    std::vector<uint8_t> buffer(length + 16);
    std::memset(buffer.data(), MARKER, buffer.size());
    random_bytes(buffer.data(), length);

    for (size_t i = length; i < buffer.size(); ++i) {
        if (buffer[i] != MARKER) {
            return false;
        }
    }
    return true;
}

void test_random_bytes() {
    std::printf("random_bytes:\n");

    // Odd lengths catch an off-by-one in the partial-read loop.
    for (size_t length : {size_t{1}, size_t{3}, size_t{4}, size_t{7}, size_t{31}, size_t{32}, size_t{64}}) {
        check(every_position_filled(length), "fills all " + std::to_string(length) + " bytes");
    }

    for (size_t length : {size_t{1}, size_t{7}, size_t{32}}) {
        check(stays_within_bounds(length), "writes no further than " + std::to_string(length) + " bytes");
    }

    uint8_t zeros[32]{};
    uint8_t drawn[32];
    random_bytes(drawn, sizeof(drawn));
    check(std::memcmp(drawn, zeros, sizeof(drawn)) != 0, "32-byte draw is not all zeros");

    uint8_t second[32];
    random_bytes(second, sizeof(second));
    check(std::memcmp(drawn, second, sizeof(drawn)) != 0, "successive draws differ");

    // Must be a no-op, not an underflow in `length - filled`.
    uint8_t untouched = MARKER;
    random_bytes(&untouched, 0);
    check(untouched == MARKER, "zero-length request writes nothing");
}

void test_generate_random() {
    std::printf("generate_random:\n");

    // sizeof(T) must reach every byte, not just the first word.
    bool all_four_bytes = true;
    bool all_eight_bytes = true;
    std::vector<bool> seen32(4, false);
    std::vector<bool> seen64(8, false);

    for (int trial = 0; trial < TRIALS; ++trial) {
        uint32_t narrow = 0xAAAAAAAAu;
        generate_random(narrow);
        for (int i = 0; i < 4; ++i) {
            if (static_cast<uint8_t>(narrow >> (i * 8)) != MARKER) seen32[i] = true;
        }

        uint64_t wide = 0xAAAAAAAAAAAAAAAAull;
        generate_random(wide);
        for (int i = 0; i < 8; ++i) {
            if (static_cast<uint8_t>(wide >> (i * 8)) != MARKER) seen64[i] = true;
        }
    }
    for (int i = 0; i < 4; ++i) if (!seen32[i]) all_four_bytes = false;
    for (int i = 0; i < 8; ++i) if (!seen64[i]) all_eight_bytes = false;

    check(all_four_bytes, "covers all 4 bytes of a uint32_t");
    check(all_eight_bytes, "covers all 8 bytes of a uint64_t");

    uint32_t value = 0;
    uint32_t& returned = generate_random(value);
    check(&returned == &value, "returns a reference to the argument");
}

// Tags run 1..2^32-1; 0 marks an INIT-bearing packet (RFC 9260 5.3.1, 8.5.1 A).
// The production loop is inline in init_new_association, so this re-implements
// it: proves the strategy, does NOT cover the real copy.
void test_verification_tag_strategy() {
    std::printf("verification tag strategy (RFC 9260 5.3.1):\n");

    bool saw_zero = false;
    for (int i = 0; i < 100000; ++i) {
        uint32_t tag;
        do {
            generate_random(tag);
        } while (tag == 0);
        if (tag == 0) {
            saw_zero = true;
            break;
        }
    }
    check(!saw_zero, "rejection loop never yields 0 over 100k draws");
}

} // namespace

int main() {
    std::printf("CSPRNG (RFC 9260 5.1.3, 5.3.1)\n");
    test_random_bytes();
    test_generate_random();
    test_verification_tag_strategy();

    if (failures == 0) {
        std::printf("All CSPRNG tests passed\n");
    } else {
        std::printf("%d CSPRNG test(s) failed\n", failures);
    }
    return failures == 0 ? 0 : 1;
}
