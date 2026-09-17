#ifndef SCTP_HMAC_HPP
#define SCTP_HMAC_HPP

#include <stdint.h>
#include <cstddef>

constexpr size_t SHA256_DIGEST_SIZE = 32;
constexpr size_t SHA256_BLOCK_SIZE = 64;

void sha256(const uint8_t* data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);
void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

// Branch- and timing-independent compare. memcmp returns at the first differing
// byte, which leaks how many leading bytes of a forged MAC were correct and
// turns 2^256 guesses into 32*256. Always use this on a MAC.
bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t len);

#endif
