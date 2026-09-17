// SHA-256 (FIPS 180-4) and HMAC (RFC 2104), used to authenticate the state
// cookie (RFC 9260 5.1.3, which mandates a MAC and cites RFC 2104 as the
// example). Implemented in-tree for the same reason the CRC-32C is: the library
// links nothing but pthreads, and a MAC is small enough that a dependency costs
// more than it saves. Verified against RFC 4231 in tests/test_hmac.cpp.

#include "hmac.hpp"

#include <cstring>
#include <vector>

namespace {

// Fractional parts of the cube roots of the first 64 primes. Derived from a
// fixed rule so nobody can claim they were chosen to hide a weakness.
constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

// One 64-byte block folded into the 256-bit state. Structurally a block cipher
// with the message block as the key and the state as the plaintext; the final
// addition of the incoming state (Davies-Meyer) is what makes it one-way,
// since the rounds on their own are invertible.
void compress(uint32_t h[8], const uint8_t block[64]) {
    // Message schedule. Stretching 16 words to 64 is what makes every round
    // depend on every input word; the shifts (not rotations) discard bits so
    // the expansion is not cheaply reversible.
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = static_cast<uint32_t>(block[i * 4]) << 24
             | static_cast<uint32_t>(block[i * 4 + 1]) << 16
             | static_cast<uint32_t>(block[i * 4 + 2]) << 8
             | static_cast<uint32_t>(block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

    for (int i = 0; i < 64; i++) {
        uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + s1 + ch + K[i] + w[i];
        uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;

        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

} // namespace

void sha256(const uint8_t* data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]) {
    // Fractional parts of the square roots of the first 8 primes.
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    size_t full_blocks = len / SHA256_BLOCK_SIZE;
    for (size_t i = 0; i < full_blocks; i++) {
        compress(h, data + i * SHA256_BLOCK_SIZE);
    }

    // Padding: 0x80, zeros, then the message length in BITS as 64-bit
    // big-endian. The length field is what stops "abc" and "abc\x80" hashing
    // alike. When the remainder is 56 or more the 0x80 plus the 8-byte length
    // no longer fit in one block and a second is needed - the case most
    // hand-written implementations get wrong, so tests/test_hmac.cpp covers a
    // 56-byte message explicitly. The buffer zero-initialises, which supplies
    // the zero padding for free.
    uint8_t tail[2 * SHA256_BLOCK_SIZE]{};
    size_t remainder = len - full_blocks * SHA256_BLOCK_SIZE;
    // Guarded because hashing an empty message passes a null `data`, and
    // memcpy(dst, nullptr, 0) is undefined even though it copies nothing -
    // compilers infer the argument is non-null and drop later null checks.
    if (remainder > 0) {
        std::memcpy(tail, data + full_blocks * SHA256_BLOCK_SIZE, remainder);
    }
    tail[remainder] = 0x80;

    size_t tail_len = remainder < 56 ? SHA256_BLOCK_SIZE : 2 * SHA256_BLOCK_SIZE;
    uint64_t bits = static_cast<uint64_t>(len) * 8;
    for (int i = 0; i < 8; i++) {
        tail[tail_len - 1 - static_cast<size_t>(i)] = static_cast<uint8_t>(bits >> (8 * i));
    }

    for (size_t offset = 0; offset < tail_len; offset += SHA256_BLOCK_SIZE) {
        compress(h, tail + offset);
    }

    for (int i = 0; i < 8; i++) {
        out[i * 4]     = static_cast<uint8_t>(h[i] >> 24);
        out[i * 4 + 1] = static_cast<uint8_t>(h[i] >> 16);
        out[i * 4 + 2] = static_cast<uint8_t>(h[i] >> 8);
        out[i * 4 + 3] = static_cast<uint8_t>(h[i]);
    }
}

// HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m)).
//
// The outer hash is not decoration. SHA-256's output IS its internal state, so
// a bare H(key || m) lets anyone holding the tag resume the computation and
// forge a tag for m || anything without knowing the key (length extension).
// The outer hash caps that state off. ipad/opad derive two effectively
// independent keys from one; they differ in 4 bits so the derived keys are far
// apart.
void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]) {
    // Keys longer than a block are hashed down first; shorter ones are
    // zero-extended. RFC 2104 recommends a key of at least SHA256_DIGEST_SIZE.
    uint8_t padded_key[SHA256_BLOCK_SIZE]{};
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256(key, key_len, padded_key);
    } else {
        std::memcpy(padded_key, key, key_len);
    }

    uint8_t inner_key[SHA256_BLOCK_SIZE];
    uint8_t outer_key[SHA256_BLOCK_SIZE];
    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        inner_key[i] = static_cast<uint8_t>(padded_key[i] ^ 0x36);
        outer_key[i] = static_cast<uint8_t>(padded_key[i] ^ 0x5c);
    }

    // Two-pass rather than a streaming context: the only caller MACs a 64-byte
    // cookie body, so the copy is irrelevant and an init/update/final API would
    // be more code to test than it saves.
    std::vector<uint8_t> inner_message;
    inner_message.reserve(SHA256_BLOCK_SIZE + len);
    inner_message.insert(inner_message.end(), inner_key, inner_key + SHA256_BLOCK_SIZE);
    inner_message.insert(inner_message.end(), data, data + len);

    uint8_t inner_digest[SHA256_DIGEST_SIZE];
    sha256(inner_message.data(), inner_message.size(), inner_digest);

    uint8_t outer_message[SHA256_BLOCK_SIZE + SHA256_DIGEST_SIZE];
    std::memcpy(outer_message, outer_key, SHA256_BLOCK_SIZE);
    std::memcpy(outer_message + SHA256_BLOCK_SIZE, inner_digest, SHA256_DIGEST_SIZE);
    sha256(outer_message, sizeof(outer_message), out);
}

bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t len) {
    // Accumulate rather than branch: every byte is always read, so the runtime
    // does not depend on where the first mismatch is.
    uint8_t difference = 0;
    for (size_t i = 0; i < len; i++) {
        difference |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return difference == 0;
}
