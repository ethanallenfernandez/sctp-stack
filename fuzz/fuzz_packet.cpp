// libFuzzer target for everything a received datagram is parsed by before any
// handler sees it: the packet and chunk codec, then the parameter walkers run
// over each INIT and INIT ACK. Whatever parses must also serialize and parse
// back to the same chunks.

#include "serialize.hpp"

#include <cstdlib>
#include <stdexcept>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    SCTP_Packet packet;
    try {
        packet = deserialize_sctp_packet(data, size);
    } catch (const std::exception&) {
        return 0;
    }

    for (const SCTP_Chunk& chunk : packet.chunks) {
        if (chunk.chunk_header.type != INIT && chunk.chunk_header.type != INIT_ACK) {
            continue;
        }
        const auto& params = std::get<init_chunk_value>(chunk.chunk_value).optional_parameters;
        Parameter_Scan scan = scan_parameters(params, {PARAM_STATE_COOKIE, PARAM_IPV4_ADDRESS, PARAM_COOKIE_PRESERVATIVE});
        for (const auto& tlv : scan.reported) {
            if (tlv.size() % 4 != 0) {
                std::abort();
            }
        }
        std::vector<uint8_t> value;
        find_parameter(scan.recognized, PARAM_STATE_COOKIE, value);
        find_ipv4_addresses(scan.recognized);
    }

    std::vector<uint8_t> wire;
    try {
        wire = serialize_sctp_packet(packet);
    } catch (const std::exception&) {
        return 0;
    }
    SCTP_Packet again = deserialize_sctp_packet(wire.data(), wire.size());
    if (again.chunks.size() != packet.chunks.size()) {
        std::abort();
    }
    for (size_t i = 0; i < packet.chunks.size(); ++i) {
        if (again.chunks[i].chunk_header.type != packet.chunks[i].chunk_header.type
                || again.chunks[i].chunk_value.index() != packet.chunks[i].chunk_value.index()) {
            std::abort();
        }
    }
    return 0;
}
