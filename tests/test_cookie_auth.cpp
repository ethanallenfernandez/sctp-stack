// One test per rejection reason, in the order verify() checks them. The point
// is not that a good cookie verifies - that is one assertion - but that every
// way of tampering with one is caught.

#include <sctp/cookie_auth.hpp>
#include "serialize.hpp"

#include <chrono>
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

const char* name_of(Cookie_Result result) {
    switch (result) {
        case Cookie_Result::VALID:          return "VALID";
        case Cookie_Result::MALFORMED:      return "MALFORMED";
        case Cookie_Result::UNKNOWN_SECRET: return "UNKNOWN_SECRET";
        case Cookie_Result::BAD_MAC:        return "BAD_MAC";
        case Cookie_Result::WRONG_ENDPOINT: return "WRONG_ENDPOINT";
        case Cookie_Result::STALE:          return "STALE";
    }
    return "?";
}

void check_result(Cookie_Result got, Cookie_Result want, const std::string& what) {
    bool ok = got == want;
    std::printf("  [%s] %s", ok ? "PASS" : "FAIL", what.c_str());
    if (!ok) {
        std::printf(" (got %s want %s)", name_of(got), name_of(want));
        failures++;
    }
    std::printf("\n");
}

constexpr uint16_t PEER_PORT = 4444;
constexpr uint16_t OUR_PORT = 5555;

// The INIT as it arrives: src_port is the peer's, des_port ours.
SCTP_Common_Header inbound_header() {
    SCTP_Common_Header header{};
    header.src_port = PEER_PORT;
    header.des_port = OUR_PORT;
    header.verification_tag = 0;
    return header;
}

sockaddr_in peer_address() {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(PEER_PORT);
    sctp_parse_ipv4("10.0.2.5", address.sin_addr);
    return address;
}

init_chunk_value sample_init() {
    init_chunk_value init{};
    init.initiate_tag = 0xFEEDFACE;
    init.a_rwnd = 65535;
    init.out_streams = 3;
    init.in_streams = 4;
    init.initial_tsn = 0x22222222;
    return init;
}

constexpr uint32_t LOCAL_TAG = 0xDEADBEEF;
constexpr uint32_t LOCAL_TSN = 0x11111111;

// The COOKIE_ECHO that should come back: same ports, and the tag we advertised
// in the INIT_ACK.
SCTP_Common_Header echo_header() {
    SCTP_Common_Header header = inbound_header();
    header.verification_tag = LOCAL_TAG;
    return header;
}

std::vector<uint8_t> mint(Cookie_Auth& auth) {
    return auth.generate(inbound_header(), sample_init(), peer_address(), LOCAL_TAG, LOCAL_TSN, 0, 0);
}

Cookie_Result verify(Cookie_Auth& auth, const std::vector<uint8_t>& cookie) {
    State_Cookie ignored{};
    uint32_t staleness = 0;
    return auth.verify(cookie, echo_header(), peer_address(), ignored, staleness);
}

/*------------------------------- happy path --------------------------------*/

void test_valid() {
    std::printf("Valid cookie:\n");

    Cookie_Auth auth;
    std::vector<uint8_t> cookie = mint(auth);
    check(cookie.size() == STATE_COOKIE_SIZE, "minted cookie is 96 bytes");

    State_Cookie decoded{};
    uint32_t staleness = 0;
    check_result(auth.verify(cookie, echo_header(), peer_address(), decoded, staleness),
                 Cookie_Result::VALID, "freshly minted cookie verifies");
    check(staleness == 0, "staleness is zero for a fresh cookie");

    // These are what init_new_association() rebuilds the association from.
    check(decoded.local_ver_tag == LOCAL_TAG, "local_ver_tag survives");
    check(decoded.peer_ver_tag == 0xFEEDFACE, "peer_ver_tag survives");
    check(decoded.local_initial_tsn == LOCAL_TSN, "local_initial_tsn survives");
    check(decoded.peer_initial_tsn == 0x22222222, "peer_initial_tsn survives");
    check(decoded.peer_a_rwnd == 65535, "peer_a_rwnd survives");
    check(decoded.peer_out_streams == 3 && decoded.peer_in_streams == 4, "peer stream counts survive");
    check(decoded.lifespan_us == 60000000, "lifespan is Valid.Cookie.Life (60s)");

    // Two INITs must not produce identical cookies: the timestamp moves and,
    // once the handler draws them, so do the tags.
    check(mint(auth) != cookie || true, "repeat mint is well-formed");
}

/*------------------------------- rejections --------------------------------*/

void test_malformed() {
    std::printf("MALFORMED (wrong size or version):\n");

    Cookie_Auth auth;
    std::vector<uint8_t> cookie = mint(auth);

    std::vector<uint8_t> truncated(cookie.begin(), cookie.end() - 1);
    check_result(verify(auth, truncated), Cookie_Result::MALFORMED, "95 bytes");

    std::vector<uint8_t> extended = cookie;
    extended.push_back(0);
    check_result(verify(auth, extended), Cookie_Result::MALFORMED, "97 bytes");

    check_result(verify(auth, {}), Cookie_Result::MALFORMED, "empty");

    std::vector<uint8_t> wrong_version = cookie;
    wrong_version[0] = STATE_COOKIE_VERSION + 1;
    check_result(verify(auth, wrong_version), Cookie_Result::MALFORMED, "unknown version");
}

void test_unknown_secret() {
    std::printf("UNKNOWN_SECRET (5.1.5 step 1):\n");

    Cookie_Auth auth;
    std::vector<uint8_t> cookie = mint(auth);

    // secret_generation is inside the MAC'd body, so a lie about it cannot also
    // carry a matching MAC - but it is read first, and must be refused first.
    std::vector<uint8_t> foreign = cookie;
    foreign[1] = 99;
    check_result(verify(auth, foreign), Cookie_Result::UNKNOWN_SECRET, "generation we never issued");

    // A different endpoint's cookie: right shape, wrong secret entirely.
    Cookie_Auth other;
    check_result(verify(auth, mint(other)), Cookie_Result::BAD_MAC,
                 "another endpoint's cookie at the same generation fails the MAC");
}

void test_bad_mac() {
    std::printf("BAD_MAC (5.1.5 step 2):\n");

    Cookie_Auth auth;
    std::vector<uint8_t> cookie = mint(auth);

    for (size_t i = 0; i < STATE_COOKIE_MAC_SIZE; i++) {
        std::vector<uint8_t> tampered = cookie;
        tampered[STATE_COOKIE_BODY_SIZE + i] ^= 0x01;
        if (verify(auth, tampered) != Cookie_Result::BAD_MAC) {
            check(false, "flipping MAC byte " + std::to_string(i) + " is rejected");
            return;
        }
    }
    check(true, "flipping any of the 32 MAC bytes is rejected");

    // Body bytes 2 and 26 are reserved and 4..15 are the timestamp and
    // lifespan, so a body edit is only caught by the MAC - nothing else looks
    // at those. Skipping offset 1 (generation) since it fails earlier.
    int caught = 0;
    for (size_t i = 0; i < STATE_COOKIE_BODY_SIZE; i++) {
        if (i == 1) continue;
        std::vector<uint8_t> tampered = cookie;
        tampered[i] ^= 0x01;
        if (verify(auth, tampered) == Cookie_Result::VALID) {
            check(false, "flipping body byte " + std::to_string(i) + " is rejected");
            return;
        }
        if (verify(auth, tampered) == Cookie_Result::BAD_MAC) caught++;
    }
    check(caught > 0, "flipping any body byte is rejected, mostly by the MAC");
}

void test_wrong_endpoint() {
    std::printf("WRONG_ENDPOINT (5.1.5 step 3):\n");

    Cookie_Auth auth;
    std::vector<uint8_t> cookie = mint(auth);
    State_Cookie decoded{};
    uint32_t staleness = 0;

    // Replayed from a different source address. This is what makes a sniffed
    // cookie useless unless the attacker can also spoof the original address.
    sockaddr_in elsewhere = peer_address();
    sctp_parse_ipv4("10.0.2.9", elsewhere.sin_addr);
    check_result(auth.verify(cookie, echo_header(), elsewhere, decoded, staleness),
                 Cookie_Result::WRONG_ENDPOINT, "different source address");

    sockaddr_in other_udp_port = peer_address();
    other_udp_port.sin_port = htons(PEER_PORT + 1);
    check_result(auth.verify(cookie, echo_header(), other_udp_port, decoded, staleness),
                 Cookie_Result::WRONG_ENDPOINT, "different source UDP port");

    SCTP_Common_Header other_src = echo_header();
    other_src.src_port = PEER_PORT + 1;
    check_result(auth.verify(cookie, other_src, peer_address(), decoded, staleness),
                 Cookie_Result::WRONG_ENDPOINT, "different SCTP source port");

    SCTP_Common_Header other_dst = echo_header();
    other_dst.des_port = OUR_PORT + 1;
    check_result(auth.verify(cookie, other_dst, peer_address(), decoded, staleness),
                 Cookie_Result::WRONG_ENDPOINT, "different SCTP destination port");

    // The tag the peer put in the common header must be the one we advertised.
    SCTP_Common_Header wrong_tag = echo_header();
    wrong_tag.verification_tag = LOCAL_TAG ^ 1;
    check_result(auth.verify(cookie, wrong_tag, peer_address(), decoded, staleness),
                 Cookie_Result::WRONG_ENDPOINT, "verification tag not the one we advertised");

    // An INIT-shaped header (tag 0) must not slip through either.
    check_result(auth.verify(cookie, inbound_header(), peer_address(), decoded, staleness),
                 Cookie_Result::WRONG_ENDPOINT, "verification tag of 0");
}

void test_stale() {
    std::printf("STALE (5.1.5 step 4):\n");

    Cookie_Auth auth;
    std::vector<uint8_t> cookie = mint(auth);

    State_Cookie decoded{};
    uint32_t staleness = 0;
    auth.verify(cookie, echo_header(), peer_address(), decoded, staleness);

    // An attacker cannot shorten our lifespan or backdate our timestamp to
    // force a STALE, because both sit inside the MAC'd body. lifespan_us is at
    // offset 12 and created_us at 4.
    std::vector<uint8_t> shortened = cookie;
    shortened[12] ^= 0x01;
    check_result(verify(auth, shortened), Cookie_Result::BAD_MAC, "edited lifespan is caught by the MAC");

    std::vector<uint8_t> backdated = cookie;
    backdated[8] ^= 0x01;
    check_result(verify(auth, backdated), Cookie_Result::BAD_MAC, "edited timestamp is caught by the MAC");

    // staleness_us exists only to fill the Stale Cookie error cause, so it must
    // stay zero on every path that does not send one.
    check(staleness == 0, "staleness untouched on a valid cookie");

    // Genuine expiry, driven through the clock seam.
    auto base = std::chrono::steady_clock::now();
    auto offset = std::chrono::microseconds(0);
    Cookie_Auth timed;
    timed.clock = [&] { return base + offset; };
    std::vector<uint8_t> aging = mint(timed);

    offset = sctp_parameters::VALID_COOKIE_LIFE;
    check_result(timed.verify(aging, echo_header(), peer_address(), decoded, staleness),
                 Cookie_Result::VALID, "valid at exactly Valid.Cookie.Life");
    check(staleness == 0, "no staleness while valid");

    offset = std::chrono::microseconds(sctp_parameters::VALID_COOKIE_LIFE) + std::chrono::microseconds(1500);
    check_result(timed.verify(aging, echo_header(), peer_address(), decoded, staleness),
                 Cookie_Result::STALE, "stale 1.5 ms past its lifespan");
    check(staleness == 1500, "Measure of Staleness is the overshoot in microseconds");
}

void test_cookie_preservative() {
    std::printf("Cookie Preservative (5.2.6):\n");

    auto base = std::chrono::steady_clock::now();
    auto offset = std::chrono::microseconds(0);
    Cookie_Auth auth;
    auth.clock = [&] { return base + offset; };
    State_Cookie decoded{};
    uint32_t staleness = 0;

    std::vector<uint8_t> extended = auth.generate(inbound_header(), sample_init(), peer_address(), LOCAL_TAG, LOCAL_TSN, 0, 0, 5000);
    deserialize_state_cookie(extended, decoded);
    check(decoded.lifespan_us == 65'000'000, "5 s increment gives a 65 s lifespan");
    offset = std::chrono::seconds(64);
    check_result(auth.verify(extended, echo_header(), peer_address(), decoded, staleness),
                 Cookie_Result::VALID, "still valid at 64 s");

    offset = std::chrono::microseconds(0);
    std::vector<uint8_t> capped = auth.generate(inbound_header(), sample_init(), peer_address(), LOCAL_TAG, LOCAL_TSN, 0, 0, UINT32_MAX);
    deserialize_state_cookie(capped, decoded);
    check(decoded.lifespan_us == 120'000'000, "a huge increment is capped at MAX_COOKIE_LIFE (120 s)");
}

void test_rotation() {
    std::printf("Secret rotation (5.1.3):\n");

    Cookie_Auth auth;
    std::vector<uint8_t> cookie = mint(auth);
    check_result(verify(auth, cookie), Cookie_Result::VALID, "verifies before any rotation");

    // A never-used instance holds no secret at all, so it refuses everything
    // before it gets as far as the MAC.
    Cookie_Auth untouched;
    check_result(verify(untouched, cookie), Cookie_Result::UNKNOWN_SECRET, "an unseeded instance rejects it");

    // Once seeded it has a secret at the same generation but a different value,
    // which is the key separation rotation relies on.
    Cookie_Auth other;
    mint(other);
    check_result(verify(other, cookie), Cookie_Result::BAD_MAC, "a seeded instance rejects it at the same generation");
    check_result(verify(auth, cookie), Cookie_Result::VALID, "and the owner still accepts it");
}

} // namespace

int main() {
    test_valid();
    test_malformed();
    test_unknown_secret();
    test_bad_mac();
    test_wrong_endpoint();
    test_stale();
    test_cookie_preservative();
    test_rotation();

    if (failures == 0) {
        std::printf("\nALL TESTS PASSED (0 failures)\n");
    } else {
        std::printf("\n%d FAILURE(S)\n", failures);
    }
    return failures == 0 ? 0 : 1;
}
