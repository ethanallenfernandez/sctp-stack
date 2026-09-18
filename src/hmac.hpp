#ifndef SCTP_HMAC_HPP
#define SCTP_HMAC_HPP

#include <stdint.h>
#include <cstddef>

constexpr size_t SHA256_DIGEST_SIZE = 32;
constexpr size_t SHA256_BLOCK_SIZE = 64;

void sha256(const uint8_t* data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);
void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

// Always use this on a MAC: memcmp's early exit leaks how many leading bytes a
// forgery got right, turning 2^256 guesses into 32*256.
bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t len);

#endif
