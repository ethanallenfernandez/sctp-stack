// libFuzzer target for the State Cookie codec. The first byte picks the mode:
// even, the rest is a COOKIE ECHO's cookie, which must be rejected and, if it
// parses, serialize back byte for byte; odd, the rest is an INIT, whose cookie
// must verify and carry the INIT's addresses back intact.

#include <sctp/cookie_auth.hpp>
#include "serialize.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>

namespace {

Cookie_Auth authorizer;

uint32_t read32(const uint8_t* p) {
    return uint32_t{p[0]} << 24 | uint32_t{p[1]} << 16 | uint32_t{p[2]} << 8 | p[3];
}

void echoed(const uint8_t* data, size_t size) {
    std::vector<uint8_t> cookie(data, data + size);
    SCTP_Common_Header header{};
    sockaddr_in src{};
    if (size >= STATE_COOKIE_SIZE) {
        header.src_port = static_cast<uint16_t>(data[16] << 8 | data[17]);
        header.des_port = static_cast<uint16_t>(data[18] << 8 | data[19]);
        header.verification_tag = read32(data + 28);
        src.sin_family = AF_INET;
        src.sin_addr.s_addr = htonl(read32(data + 20));
        src.sin_port = htons(static_cast<uint16_t>(data[24] << 8 | data[25]));
    }
    State_Cookie out;
    uint32_t staleness_us;
    if (authorizer.verify(cookie, header, src, out, staleness_us) == Cookie_Result::VALID) {
        std::abort();
    }
    if (!deserialize_state_cookie(cookie, out)) {
        return;
    }
    std::vector<uint8_t> wire = serialize_state_cookie(out);
    wire[2] = cookie[2];
    wire[3] = cookie[3];
    if (wire != cookie) {
        std::abort();
    }
}

void generated(const uint8_t* data, size_t size) {
    if (size < 26) {
        return;
    }
    SCTP_Common_Header header{};
    header.src_port = static_cast<uint16_t>(data[0] << 8 | data[1]);
    header.des_port = static_cast<uint16_t>(data[2] << 8 | data[3]);
    sockaddr_in src{};
    src.sin_family = AF_INET;
    src.sin_addr.s_addr = htonl(read32(data + 4));
    src.sin_port = htons(static_cast<uint16_t>(data[8] << 8 | data[9]));
    init_chunk_value init{};
    init.initiate_tag = read32(data + 10);
    init.a_rwnd = read32(data + 14);
    init.out_streams = static_cast<uint16_t>(data[18] << 8 | data[19]);
    init.in_streams = static_cast<uint16_t>(data[20] << 8 | data[21]);
    init.initial_tsn = read32(data + 22);
    init.optional_parameters.assign(data + 26, data + size);

    std::vector<uint32_t> addresses;
    for (uint32_t address : find_ipv4_addresses(scan_parameters(init.optional_parameters, {PARAM_IPV4_ADDRESS}).recognized)) {
        if (address != ntohl(src.sin_addr.s_addr) && std::find(addresses.begin(), addresses.end(), address) == addresses.end()) {
            addresses.push_back(address);
        }
    }
    uint32_t local_tag = init.initiate_tag ^ 0x5A5A5A5A;
    std::vector<uint8_t> cookie = authorizer.generate(header, init, src, local_tag, ~init.initial_tsn, 0, 0, 0, addresses);

    header.verification_tag = local_tag;
    sockaddr_in from = src;
    if (!addresses.empty()) {
        from.sin_addr.s_addr = htonl(addresses[init.a_rwnd % addresses.size()]);
    }
    State_Cookie out;
    uint32_t staleness_us;
    if (authorizer.verify(cookie, header, from, out, staleness_us) != Cookie_Result::VALID
            || out.peer_addresses != addresses || out.peer_ver_tag != init.initiate_tag
            || out.peer_initial_tsn != init.initial_tsn || out.peer_in_streams != init.in_streams) {
        std::abort();
    }
    cookie[cookie.size() - 1 - init.a_rwnd % cookie.size()] ^= 1;
    if (authorizer.verify(cookie, header, from, out, staleness_us) == Cookie_Result::VALID) {
        std::abort();
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) {
        return 0;
    }
    if (data[0] % 2 == 0) {
        echoed(data + 1, size - 1);
    } else {
        generated(data + 1, size - 1);
    }
    return 0;
}
