#include <sctp/cookie_auth.hpp>

#include <cstring>

#include "hmac.hpp"
#include "serialize.hpp"
#include "socket_internal.hpp"

uint64_t Cookie_Auth::now_us() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(clock().time_since_epoch()).count());
}

void Cookie_Auth::rotate_if_due() {
    auto now = clock();

    if (!initialized) {
        random_bytes(current, COOKIE_SECRET_SIZE);
        initialized = true;
        rotated_at = now;
        return;
    }
    if (now - rotated_at < COOKIE_SECRET_ROTATION) {
        return;
    }

    // Retaining the outgoing key is what keeps cookies still inside
    // VALID_COOKIE_LIFE verifying across a rotation.
    std::memcpy(previous, current, COOKIE_SECRET_SIZE);
    have_previous = true;
    random_bytes(current, COOKIE_SECRET_SIZE);
    generation++;
    rotated_at = now;
}

const uint8_t* Cookie_Auth::secret_for(uint8_t wanted_generation) {
    if (!initialized) {
        return nullptr;
    }
    if (wanted_generation == generation) {
        return current;
    }
    if (have_previous && wanted_generation == static_cast<uint8_t>(generation - 1)) {
        return previous;
    }
    return nullptr;
}

std::vector<uint8_t> Cookie_Auth::generate(
    const SCTP_Common_Header& header,
    const init_chunk_value& init,
    const sockaddr_in& src,
    uint32_t local_tag,
    uint32_t local_tsn,
    uint32_t local_tie_tag,
    uint32_t peer_tie_tag,
    uint32_t lifespan_increment_ms
) {
    rotate_if_due();
    auto lifespan = std::min<std::chrono::microseconds>(
        sctp_parameters::VALID_COOKIE_LIFE + std::chrono::milliseconds(lifespan_increment_ms),
        MAX_COOKIE_LIFE
    );

    State_Cookie cookie{};
    cookie.version = STATE_COOKIE_VERSION;
    cookie.secret_generation = generation;
    cookie.created_us = now_us();
    cookie.lifespan_us = static_cast<uint32_t>(lifespan.count());

    // src_port is the peer's and des_port ours in both the INIT and the
    // COOKIE_ECHO, so verify() can compare these directly without swapping.
    cookie.sctp_src_port = header.src_port;
    cookie.sctp_dst_port = header.des_port;
    cookie.peer_ipv4 = ntohl(src.sin_addr.s_addr);
    cookie.peer_udp_port = ntohs(src.sin_port);

    cookie.local_ver_tag = local_tag;
    cookie.peer_ver_tag = init.initiate_tag;
    cookie.local_initial_tsn = local_tsn;
    cookie.peer_initial_tsn = init.initial_tsn;
    cookie.peer_a_rwnd = init.a_rwnd;

    // What we advertised; init_new_association negotiates against the peer's.
    cookie.local_out_streams = LOCAL_OUT_STREAMS;
    cookie.local_in_streams = LOCAL_MAX_IN_STREAMS;
    cookie.peer_out_streams = init.out_streams;
    cookie.peer_in_streams = init.in_streams;

    cookie.local_tie_tag = local_tie_tag;
    cookie.peer_tie_tag = peer_tie_tag;

    // The MAC is a plain suffix covering the body only, so it can be written
    // straight into the tail of the serialized buffer.
    std::vector<uint8_t> out = serialize_state_cookie(cookie);
    hmac_sha256(
        current, 
        COOKIE_SECRET_SIZE, 
        out.data(), 
        STATE_COOKIE_BODY_SIZE, 
        out.data() + STATE_COOKIE_BODY_SIZE
    );
    return out;
}

Cookie_Result Cookie_Auth::verify(
    const std::vector<uint8_t>& cookie,
    const SCTP_Common_Header& header,
    const sockaddr_in& src,
    State_Cookie& out,
    uint32_t& staleness_us
) {
    staleness_us = 0;

    if (!deserialize_state_cookie(cookie, out)) {
        return Cookie_Result::MALFORMED;
    }

    const uint8_t* secret = secret_for(out.secret_generation);
    if (secret == nullptr) {
        return Cookie_Result::UNKNOWN_SECRET;
    }

    uint8_t expected[SHA256_DIGEST_SIZE];
    hmac_sha256(
        secret, 
        COOKIE_SECRET_SIZE, 
        cookie.data(), 
        STATE_COOKIE_BODY_SIZE, 
        expected
    );
    if (!constant_time_equal(expected, cookie.data() + STATE_COOKIE_BODY_SIZE, STATE_COOKIE_MAC_SIZE)) {
        return Cookie_Result::BAD_MAC;
    }

    if (out.sctp_src_port != header.src_port
        || out.sctp_dst_port != header.des_port
        || out.local_ver_tag != header.verification_tag
        || out.peer_ipv4 != ntohl(src.sin_addr.s_addr)
        || out.peer_udp_port != ntohs(src.sin_port)
    ) {
        return Cookie_Result::WRONG_ENDPOINT;
    }

    uint64_t now = now_us();
    if (now < out.created_us) {
        return Cookie_Result::STALE;
    }
    uint64_t age_us = now - out.created_us;
    if (age_us > out.lifespan_us) {
        uint64_t overshoot = age_us - out.lifespan_us;
        staleness_us = overshoot > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(overshoot);
        return Cookie_Result::STALE;
    }

    return Cookie_Result::VALID;
}
