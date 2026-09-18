#ifndef COOKIE_AUTH_HPP
#define COOKIE_AUTH_HPP

#include <cstdint>
#include <chrono>
#include <vector>
#include <sctp/sctp.hpp>
#include <sctp/platform.hpp>

enum class Cookie_Result {
    VALID,
    MALFORMED,        // wrong size or version
    UNKNOWN_SECRET,   // signed by a key we no longer hold
    BAD_MAC,
    WRONG_ENDPOINT,   // ports or address do not match the packet
    STALE,            // past its lifespan; caller sends an ERROR
};

class Cookie_Auth {
public:
    std::vector<uint8_t> generate(
        const SCTP_Common_Header& header,
        const init_chunk_value& init,
        const sockaddr_in& src,
        uint32_t local_tag,
        uint32_t local_tsn,
        uint32_t local_tie_tag,
        uint32_t peer_tie_tag);

    // staleness_us is only set when the result is STALE.
    Cookie_Result verify(
        const std::vector<uint8_t>& cookie,
        const SCTP_Common_Header& header,
        const sockaddr_in& src,
        State_Cookie& out,
        uint32_t& staleness_us);

private:
    void rotate_if_due();
    const uint8_t* secret_for(uint8_t wanted_generation);

    uint8_t current[COOKIE_SECRET_SIZE];
    uint8_t previous[COOKIE_SECRET_SIZE];
    uint8_t generation{0};
    bool have_previous{false};
    bool initialized{false};
    std::chrono::steady_clock::time_point rotated_at;
};

#endif
