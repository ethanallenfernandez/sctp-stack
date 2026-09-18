// SHA-256 and HMAC-SHA-256 against published vectors: FIPS 180-4 and RFC 4231.
//
// Externally fixed on purpose. A round-trip test passes with a totally broken
// hash, and a cookie MAC'd with one validates against itself perfectly while
// being worthless - the CRC-32C polynomial bug again.

#include "hmac.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

int failures = 0;

std::string to_hex(const uint8_t* data, size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
}

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

void check_digest(const std::string& got, const std::string& want, const std::string& what) {
    bool ok = got == want;
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
    if (!ok) {
        std::printf("      got  %s\n", got.c_str());
        std::printf("      want %s\n", want.c_str());
        failures++;
    }
}

std::vector<uint8_t> bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> repeated(uint8_t value, size_t count) {
    return std::vector<uint8_t>(count, value);
}

std::string hash_of(const std::vector<uint8_t>& message) {
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256(message.data(), message.size(), digest);
    return to_hex(digest, sizeof(digest));
}

std::string mac_of(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message) {
    uint8_t tag[SHA256_DIGEST_SIZE];
    hmac_sha256(key.data(), key.size(), message.data(), message.size(), tag);
    return to_hex(tag, sizeof(tag));
}

/*------------------------------ SHA-256 (FIPS 180-4) -----------------------*/

void test_sha256() {
    std::printf("SHA-256 known-answer vectors (FIPS 180-4):\n");

    check_digest(hash_of(bytes("")),
                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                 "SHA256(\"\")");

    check_digest(hash_of(bytes("abc")),
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                 "SHA256(\"abc\")");

    // 56 bytes: 0x80 plus the length no longer fit in one block, so a second
    // is needed. Everything above passes without that branch.
    check_digest(hash_of(bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
                 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
                 "SHA256(56-byte message, two-block padding)");

    // Largest message that still pads into a single block.
    check_digest(hash_of(repeated('a', 55)),
                 "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
                 "SHA256(55 'a', single-block padding boundary)");

    // remainder == 0, so the tail is pure padding.
    check_digest(hash_of(repeated('a', 64)),
                 "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
                 "SHA256(64 'a', exact block multiple)");

    // FIPS long-message vector; exercises the multi-block loop.
    check_digest(hash_of(repeated('a', 1000000)),
                 "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
                 "SHA256(1,000,000 'a')");
}

/*--------------------------- HMAC-SHA-256 (RFC 4231) -----------------------*/

void test_hmac_sha256() {
    std::printf("HMAC-SHA-256 known-answer vectors (RFC 4231):\n");

    check_digest(mac_of(repeated(0x0b, 20), bytes("Hi There")),
                 "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                 "case 1: 20-byte key");

    // Short key: exercises zero-extension to a full block.
    check_digest(mac_of(bytes("Jefe"), bytes("what do ya want for nothing?")),
                 "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                 "case 2: 4-byte key");

    check_digest(mac_of(repeated(0xaa, 20), repeated(0xdd, 50)),
                 "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
                 "case 3: 50-byte message");

    std::vector<uint8_t> counting_key;
    for (uint8_t i = 1; i <= 25; i++) {
        counting_key.push_back(i);
    }
    check_digest(mac_of(counting_key, repeated(0xcd, 50)),
                 "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
                 "case 4: 25-byte key");

    // Only vector hitting key_len > SHA256_BLOCK_SIZE. The 32-byte cookie
    // secret never takes that branch.
    check_digest(mac_of(repeated(0xaa, 131), bytes("Test Using Larger Than Block-Size Key - Hash Key First")),
                 "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                 "case 6: 131-byte key is hashed first");

    check_digest(mac_of(repeated(0xaa, 131),
                        bytes("This is a test using a larger than block-size key and a larger "
                              "than block-size data. The key needs to be hashed before being "
                              "used by the HMAC algorithm.")),
                 "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
                 "case 7: 131-byte key and 152-byte message");
}

/*--------------------------- state cookie properties -----------------------*/

void test_cookie_shaped_usage() {
    std::printf("State cookie usage (RFC 9260 5.1.3):\n");

    std::vector<uint8_t> secret = repeated(0x5a, 32);
    std::vector<uint8_t> body = repeated(0x42, 64);

    uint8_t reference[SHA256_DIGEST_SIZE];
    hmac_sha256(secret.data(), secret.size(), body.data(), body.size(), reference);

    // What stops an attacker who knows the layout from forging a cookie.
    std::vector<uint8_t> other_secret = repeated(0x5b, 32);
    uint8_t under_other_secret[SHA256_DIGEST_SIZE];
    hmac_sha256(other_secret.data(), other_secret.size(), body.data(), body.size(), under_other_secret);
    check(!constant_time_equal(reference, under_other_secret, SHA256_DIGEST_SIZE),
          "a one-bit change in the secret changes the MAC");

    // A MAC reaching only the first block would leave the tie-tags at offsets
    // 56-63 unauthenticated.
    for (size_t i = 0; i < body.size(); i++) {
        std::vector<uint8_t> tampered = body;
        tampered[i] ^= 0x01;
        uint8_t tag[SHA256_DIGEST_SIZE];
        hmac_sha256(secret.data(), secret.size(), tampered.data(), tampered.size(), tag);
        if (constant_time_equal(reference, tag, SHA256_DIGEST_SIZE)) {
            check(false, "flipping body byte " + std::to_string(i) + " changes the MAC");
            return;
        }
    }
    check(true, "flipping any of the 64 body bytes changes the MAC");
}

void test_constant_time_equal() {
    std::printf("constant_time_equal:\n");

    uint8_t a[32];
    uint8_t b[32];
    std::memset(a, 0x37, sizeof(a));
    std::memcpy(b, a, sizeof(b));
    check(constant_time_equal(a, b, sizeof(a)), "identical buffers compare equal");

    // First and last byte both, to catch an inverted or truncated loop bound.
    b[sizeof(b) - 1] ^= 0x01;
    check(!constant_time_equal(a, b, sizeof(a)), "differing final byte compares unequal");

    std::memcpy(b, a, sizeof(b));
    b[0] ^= 0x80;
    check(!constant_time_equal(a, b, sizeof(a)), "differing first byte compares unequal");

    std::memcpy(b, a, sizeof(b));
    check(constant_time_equal(a, b, 0), "zero length compares equal");
}

} // namespace

int main() {
    test_sha256();
    test_hmac_sha256();
    test_cookie_shaped_usage();
    test_constant_time_equal();

    if (failures == 0) {
        std::printf("\nALL TESTS PASSED (0 failures)\n");
    } else {
        std::printf("\n%d FAILURE(S)\n", failures);
    }
    return failures == 0 ? 0 : 1;
}
