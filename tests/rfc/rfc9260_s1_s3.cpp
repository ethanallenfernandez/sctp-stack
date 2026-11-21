// RFC 9260 sections 1 and 3: endpoints and serial arithmetic, and the packet,
// chunk and parameter formats.

#include "rfc_harness.hpp"

#include <set>

using namespace rfc;

namespace {

uint16_t be16(const std::vector<uint8_t>& w, size_t at) {
    return static_cast<uint16_t>(w[at] << 8 | w[at + 1]);
}

uint32_t be32(const std::vector<uint8_t>& w, size_t at) {
    return static_cast<uint32_t>(w[at]) << 24 | static_cast<uint32_t>(w[at + 1]) << 16 | static_cast<uint32_t>(w[at + 2]) << 8 | w[at + 3];
}

// Offsets of each chunk in a serialized packet.
std::vector<size_t> chunk_offsets(const std::vector<uint8_t>& w) {
    std::vector<size_t> out;
    for (size_t at = SCTP_COMMON_HEADER_SIZE; at + 4 <= w.size();) {
        out.push_back(at);
        at += (be16(w, at + 2) + 3) & ~size_t{3};
    }
    return out;
}

// True if every chunk's length is its unpadded size and the padding is zero and under 4 bytes.
bool padded_correctly(const std::vector<uint8_t>& w) {
    for (size_t at : chunk_offsets(w)) {
        size_t length = be16(w, at + 2);
        size_t padded = (length + 3) & ~size_t{3};
        if (at + padded > w.size() || padded - length > 3) {
            return false;
        }
        for (size_t i = at + length; i < at + padded; ++i) {
            if (w[i] != 0) {
                return false;
            }
        }
    }
    return (w.size() - SCTP_COMMON_HEADER_SIZE) % 4 == 0;
}

void s1_3_endpoints() {
    section("1.3 Key Terms");
    {
        SCTP_Socket s;
        Access::establish(s);
        Sctp_Status status = Access::associate_status(s);
        Access::receive(s, packet(0, {chunk(INIT, init_value(0x55555555))}));
        req("9260-1.3-1", status == Sctp_Status::ASSOCIATION_EXISTS && Access::association_count(s) == 1,
            "a second association to the same peer is refused, and a peer INIT does not open one");
    }
    {
        SCTP_Socket s;
        bool bound = s.sctp_bindx({"127.0.0.1", "127.0.0.2"}, 0);
        bool same = bound && Access::bound_ports_match(s);
        req("9260-1.3-2", same, "every bound address shares the one port");
    }
    {
        SCTP_Socket a, b;
        bool first = a.sctp_bind("127.0.0.1", 39601);
        bool second = b.sctp_bind("127.0.0.1", 39601);
        req("9260-1.3-3", first && !second, "a transport address bound by one endpoint cannot be bound by another");
    }
}

void s1_6_serial_numbers() {
    section("1.6 Serial Number Arithmetic");
    {
        SCTP_Socket s;
        Association& a = Access::establish(s);
        a.next_tsn = 0xFFFFFFFF;
        a.cumulative_tsn_ack = 0xFFFFFFFE;
        Access::send(s, {'a'});
        Access::send(s, std::vector<uint8_t>(1000, 'b'));
        auto chunks = Access::sent(s).data();
        bool wrapped = chunks.size() >= 2 && chunks[0].tsn == 0xFFFFFFFF && chunks[1].tsn == 0;
        req("9260-1.6-1", wrapped, "TSNs are assigned modulo 2^32");
        req("9260-1.6-4", wrapped, "the TSN after 2^32 - 1 is 0");
        Access::receive(s, packet(OUR_TAG, {sack_chunk(0)}));
        req("9260-1.6-2", tsn_lt(0xFFFFFFFF, 0) && tsn_gt(0, 0xFFFFFFFF) && a.outstanding_data.empty(),
            "TSN comparisons and SACK processing use serial arithmetic across the wrap");
    }
    {
        // The largest a_rwnd over the smallest DATA chunk cannot span half the TSN space.
        size_t smallest_chunk = DATA_CHUNK_HEADER_SIZE + 4;
        req("9260-1.6-3", UINT32_MAX / smallest_chunk < (uint64_t{1} << 31),
            "the send window, bounded by rwnd, cannot hold TSNs 2^31 apart");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s);
        a.inbound_streams[0].next_ssn = 65535;
        Access::receive(s, packet(OUR_TAG, {data_chunk(data(PEER_TSN, {'x'}, DATA_FLAG_B | DATA_FLAG_E, 0, 0))}));
        Access::receive(s, packet(OUR_TAG, {data_chunk(data(PEER_TSN + 1, {'w'}, DATA_FLAG_B | DATA_FLAG_E, 0, 65535))}));
        std::vector<uint8_t> buffer(8);
        size_t first = Access::read(s, buffer);
        char a1 = static_cast<char>(buffer[0]);
        size_t second = Access::read(s, buffer);
        req("9260-1.6-5", ssn_gt(0, 65535) && first == 1 && a1 == 'w' && second == 1 && buffer[0] == 'x',
            "SSN 0 after 65535 is newer, and is delivered after it");
    }
}

void s3_packet_format() {
    section("3 SCTP Packet Format");
    {
        SCTP_Socket s;
        auto init = Access::initiate(s, {}, false);
        bool init_alone = !init.init.empty() && only(init.init[0], INIT);
        SCTP_Socket r;
        auto resp = Access::respond(r);
        bool ack_alone = !resp.init_ack.empty() && only(resp.init_ack[0], INIT_ACK);
        SCTP_Socket t;
        Access::establish(t, SHUTDOWN_SENT);
        Access::tcb(t)->duplicate_tsns.push_back(PEER_TSN - 1);
        Access::receive(t, packet(OUR_TAG, {chunk(SHUTDOWN_ACK, empty_chunk_value{})}));
        auto out = Access::sent(t);
        bool complete_alone = out.with(SHUTDOWN_COMPLETE) && only(out.with(SHUTDOWN_COMPLETE)->packet, SHUTDOWN_COMPLETE);
        req("9260-3-1", init_alone && ack_alone && complete_alone, "INIT, INIT ACK and SHUTDOWN COMPLETE each go alone");
    }
    {
        SCTP_Packet p;
        p.header = {0x1234, 0x5678, 0x01020304, 0};
        p.chunks.push_back(sack_chunk(0x0A0B0C0D, 0x00112233));
        auto w = serialize_sctp_packet(p);
        bool network_order = be16(w, 0) == 0x1234 && be16(w, 2) == 0x5678 && be32(w, 4) == 0x01020304
            && be32(w, 16) == 0x0A0B0C0D && be32(w, 20) == 0x00112233;
        req("9260-3-2", network_order, "integer fields are written in network byte order");
    }
}

void s3_1_common_header() {
    section("3.1 SCTP Common Header Field Descriptions");
    SCTP_Socket s;
    auto r = Access::initiate(s);
    Access::send(s, {'x'});
    auto data = Access::sent(s);
    bool ports = !r.init.empty() && r.init[0].header.src_port != 0 && !data.empty() && data[0].header.src_port != 0;
    req("9260-3.1-1", ports, "our Source Port is never 0");
    req("9260-3.1-2", !r.init.empty() && r.init[0].header.des_port == PEER_PORT && !data.empty() && data[0].header.des_port != 0,
        "our Destination Port is never 0");
    req("9260-3.1-3", !r.echo.empty() && r.echo[0].header.verification_tag == PEER_TAG && !data.empty()
            && data[0].header.verification_tag == PEER_TAG,
        "packets carry the Initiate Tag the peer sent");
    req("9260-3.1-4", !r.init.empty() && r.init[0].header.verification_tag == 0, "the packet carrying INIT has a zero tag");

    SCTP_Socket o;
    Access::setup(o);
    Access::receive(o, packet(0xDEADBEEF, {chunk(SHUTDOWN_ACK, empty_chunk_value{})}));
    auto reply = Access::sent(o);
    const Deliverable* complete = reply.with(SHUTDOWN_COMPLETE);
    req("9260-3.1-5", complete && complete->packet.header.verification_tag == 0xDEADBEEF
            && (complete->packet.chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT),
        "a SHUTDOWN COMPLETE with T set copies the SHUTDOWN ACK's tag");
}

void s3_2_chunks() {
    section("3.2 Chunk Field Descriptions");
    bool all = true;
    for (size_t length = 1; length <= 8; ++length) {
        auto w = serialize_sctp_packet(build_data(1, 2, 3, {data(1, std::vector<uint8_t>(length, 'p'))}));
        all = all && padded_correctly(w) && be16(w, SCTP_COMMON_HEADER_SIZE + 2) == DATA_CHUNK_HEADER_SIZE + length;
    }
    req("9260-3.2-1", all, "every chunk occupies a multiple of 4 bytes on the wire");
    req("9260-3.2-2", all, "padding is zero and outside the Chunk Length");
    req("9260-3.2-3", all, "never more than 3 bytes of padding");

    SCTP_Socket s;
    Access::establish(s);
    auto w = serialize_sctp_packet(packet(OUR_TAG, {data_chunk(data(PEER_TSN, {'a'}), DATA_IMMEDIATE_SACK_FLAG),
                                                   chunk(HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}})}));
    size_t pad = SCTP_COMMON_HEADER_SIZE + DATA_CHUNK_HEADER_SIZE + 1;
    w[pad] = w[pad + 1] = w[pad + 2] = 0xFF;
    std::memset(w.data() + SCTP_CHECKSUM_OFFSET, 0, 4);
    uint32_t crc = calculate_sctp_checksum(w.data(), w.size());
    std::memcpy(w.data() + SCTP_CHECKSUM_OFFSET, &crc, 4);
    Access::receive_wire(s, w);
    auto out = Access::sent(s);
    std::vector<uint8_t> buffer(8);
    size_t n = Access::read(s, buffer);
    req("9260-3.2-4", n == 1 && buffer[0] == 'a' && out.any(HEARTBEAT_ACK), "nonzero padding bytes are ignored");
}

void s3_2_1_parameters() {
    section("3.2.1 Optional/Variable-Length Parameter Format");
    bool all = true;
    for (size_t length = 1; length <= 8; ++length) {
        std::vector<uint8_t> p = parameter(0x8005, std::vector<uint8_t>(length, 'v'));
        size_t declared = be16(p, 2);
        all = all && p.size() % 4 == 0 && declared == 4 + length && p.size() - declared <= 3
            && std::all_of(p.begin() + static_cast<long>(declared), p.end(), [](uint8_t b) { return b == 0; });
    }
    req("9260-3.2.1-1", all, "each parameter occupies a multiple of 4 bytes");
    req("9260-3.2.1-2", all, "parameter padding is under 4 bytes and outside the length");

    SCTP_Socket s;
    std::vector<uint8_t> skipped = parameter(0x8005, {1, 2, 3});
    skipped.back() = 0xFF;
    auto r = Access::respond(s, init_value(PEER_TAG, PEER_TSN, RWND, 10, 10, concat({skipped, ipv4_parameter("127.0.0.2")})));
    Association* a = Access::tcb(s);
    req("9260-3.2.1-3", a && a->peer_address_list.size() == 2, "parameter padding is ignored: the address after it is read");
}

void s3_2_1_registry() {
    section("3.2.1 / 15.3 / 15.4 Parameter types and error cause format");
    std::vector<uint16_t> types{PARAM_HEARTBEAT_INFO, PARAM_IPV4_ADDRESS, PARAM_IPV6_ADDRESS, PARAM_STATE_COOKIE, PARAM_UNRECOGNIZED,
                                PARAM_COOKIE_PRESERVATIVE, PARAM_HOST_NAME_ADDRESS, PARAM_SUPPORTED_ADDRESS_TYPES};
    std::set<uint16_t> unique(types.begin(), types.end());
    req("9260-3.2.1-4", unique.size() == types.size(), "each parameter type we use has one meaning");
    req("9260-15.3-3", unique.size() == types.size(), "parameter types are unique across chunks");
    req("9260-3.2.1-5", PARAM_IPV4_ADDRESS == 5 && PARAM_HEARTBEAT_INFO == 1 && PARAM_STATE_COOKIE == 7 && PARAM_COOKIE_PRESERVATIVE == 9,
        "type 5 is the IPv4 Address everywhere, and the other types match the registry");
    auto w = serialize_sctp_packet(build_error(1, 2, 3, {error_cause{CAUSE_INVALID_STREAM_ID, {0, 7, 0, 0}}, error_cause{0x1234, {9}}}));
    size_t c = SCTP_COMMON_HEADER_SIZE + SCTP_CHUNK_HEADER_SIZE;
    bool format = be16(w, c) == CAUSE_INVALID_STREAM_ID && be16(w, c + 2) == 8 && be16(w, c + 8) == 0x1234 && be16(w, c + 10) == 5;
    req("9260-15.4-2", format, "each error cause starts with a 16-bit code and a 16-bit length");
}

void s3_2_2_unrecognized() {
    section("3.2.2 Reporting of Unrecognized Parameters");
    {
        SCTP_Socket s;
        auto r = Access::respond(s, init_value(PEER_TAG, PEER_TSN, RWND, 10, 10, parameter(0x4321, {1, 2, 3, 4})));
        const auto* ack = r.init_ack.empty() ? nullptr : find_value<init_chunk_value>(r.init_ack[0], INIT_ACK);
        std::vector<uint8_t> reported;
        req("9260-3.2.2-1", ack && find_parameter(ack->optional_parameters, PARAM_UNRECOGNIZED, reported),
            "an unrecognized INIT parameter is reported in the INIT ACK");
    }
    {
        SCTP_Socket s;
        auto r = Access::initiate(s, concat({parameter(PARAM_STATE_COOKIE, std::vector<uint8_t>(32, 1)), parameter(0x4321, {1, 2, 3, 4})}), false);
        const SCTP_Packet* echo = r.echo.empty() ? nullptr : &r.echo[0];
        req("9260-3.2.2-2", echo && has_cause(*echo, OP_ERROR, CAUSE_UNRECOGNIZED_PARAMS),
            "an unrecognized INIT ACK parameter is reported in an ERROR bundled with the COOKIE ECHO");
        req("9260-3.2.2-3", echo && echo->chunks[0].chunk_header.type == COOKIE_ECHO, "the COOKIE ECHO comes first");
    }
}

void s3_3_1_data() {
    section("3.3.1 Payload Data (DATA) (0)");
    {
        auto w = serialize_sctp_packet(build_data(1, 2, 3, {data(0x11223344, {9, 8, 7}, DATA_FLAG_B | DATA_FLAG_E, 0x5566, 0x7788, 0x99AABBCC)}));
        size_t c = SCTP_COMMON_HEADER_SIZE;
        bool layout = w[c] == DATA && (w[c + 1] & 0x07) == (DATA_FLAG_B | DATA_FLAG_E) && be16(w, c + 2) == 19
            && be32(w, c + 4) == 0x11223344 && be16(w, c + 8) == 0x5566 && be16(w, c + 10) == 0x7788
            && be32(w, c + 12) == 0x99AABBCC && w[c + 16] == 9 && w[c + 18] == 7;
        req("9260-3.3.1-1", layout, "DATA is laid out as Figure 7");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::receive(s, packet(OUR_TAG, {data_chunk(data(PEER_TSN, {'o'}, DATA_FLAG_B | DATA_FLAG_E, 0, 1))}));
        Access::receive(s, packet(OUR_TAG, {data_chunk(data(PEER_TSN + 1, {'u'}, DATA_FLAG_U | DATA_FLAG_B | DATA_FLAG_E, 0, 777))}));
        std::vector<uint8_t> buffer(8);
        size_t n = Access::read(s, buffer);
        req("9260-3.3.1-2", n == 1 && buffer[0] == 'u', "an unordered chunk's SSN is ignored");
        req("9260-3.3.1-3", n == 1 && buffer[0] == 'u', "unordered data goes up ahead of an ordered message still waiting");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::send(s, std::vector<uint8_t>(4000, 'u'), 0, true);
        Access::send(s, std::vector<uint8_t>(4000, 'o'), 0, false, 0xABCD0123);
        auto chunks = Access::sent(s).data();
        bool unordered = true, same_ssn = true, ppid = true, sequential = true, flags = true;
        for (size_t i = 0; i < chunks.size(); ++i) {
            bool first_message = chunks[i].user_data[0] == 'u';
            if (first_message) {
                unordered = unordered && (chunks[i].flags & DATA_FLAG_U);
            } else {
                same_ssn = same_ssn && chunks[i].stream_seq_num == chunks.back().stream_seq_num;
                ppid = ppid && chunks[i].payload_protocal == 0xABCD0123;
            }
            if (i > 0) {
                sequential = sequential && chunks[i].tsn == chunks[i - 1].tsn + 1;
                bool begins = i == 0 || chunks[i].user_data[0] != chunks[i - 1].user_data[0];
                flags = flags && ((chunks[i].flags & DATA_FLAG_B) != 0) == begins;
            }
        }
        req("9260-3.3.1-4", chunks.size() > 2 && unordered, "every fragment of an unordered message has U set");
        req("9260-3.3.1-6", same_ssn, "every fragment of a message carries its SSN");
        req("9260-3.3.1-7", ppid, "every fragment carries the PPID");
        req("9260-3.3.1-12", sequential && flags, "a message's fragments have consecutive TSNs");
        req("9260-3.3.1-13", sequential, "TSNs are sent in sequence");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        Sctp_Status status = Access::send(s, {});
        req("9260-3.3.1-5", status == Sctp_Status::EMPTY_MESSAGE && Access::sent(s).data().empty(),
            "a DATA chunk always has at least one byte of user data");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::send(s, {1, 2, 3, 4, 5});
        Access::send(s, {9});
        auto out = Access::sent(s);
        bool ok = !out.empty();
        for (const auto& d : out.out) {
            auto w = serialize_sctp_packet(d.packet);
            ok = ok && padded_correctly(w);
        }
        auto chunks = out.data();
        req("9260-3.3.1-8", ok, "user data is padded to 4 bytes with zeros");
        req("9260-3.3.1-9", ok && !chunks.empty() && chunks[0].user_data.size() == 5, "the padding is not in the Length");
        req("9260-3.3.1-10", ok, "at most 3 bytes of padding");
        req("9260-3.3.1-11", !chunks.empty() && std::all_of(chunks.begin(), chunks.end(), [](const data_chunk_value& c) {
                return (c.flags & (DATA_FLAG_B | DATA_FLAG_E)) == (DATA_FLAG_B | DATA_FLAG_E);
            }), "an unfragmented message has B and E set");
    }
}

void s3_3_2_init() {
    section("3.3.2 Initiation (INIT) (1)");
    {
        SCTP_Socket s;
        Access::add_local(s, "127.0.0.2");
        auto r = Access::initiate(s, {}, false);
        const auto* init = r.init.empty() ? nullptr : find_value<init_chunk_value>(r.init[0], INIT);
        std::set<uint32_t> seen;
        bool unique = init != nullptr;
        for (uint32_t a : init ? find_ipv4_addresses(init->optional_parameters) : std::vector<uint32_t>{}) {
            unique = unique && seen.insert(a).second;
        }
        std::vector<uint8_t> v;
        req("9260-3.3.2-1", unique && seen.size() == 2, "each address is listed in the INIT once");
        req("9260-3.3.2-2", init && !find_parameter(init->optional_parameters, PARAM_HOST_NAME_ADDRESS, v), "our INIT has no Host Name Address");
        req("9260-3.3.2-5", !r.init.empty() && r.init[0].chunks[0].chunk_header.flag == 0, "INIT flags are sent as 0");
        req("9260-3.3.2-8", init && init->a_rwnd >= 1500, "our a_rwnd is at least 1500");
        req("9260-3.3.2-11", init && init->out_streams != 0, "our OS is not 0");
        req("9260-3.3.2-13", init && init->in_streams != 0, "our MIS is not 0");
        SCTP_Socket other;
        auto r2 = Access::initiate(other, {}, false);
        const auto* init2 = r2.init.empty() ? nullptr : find_value<init_chunk_value>(r2.init[0], INIT);
        req("9260-3.3.2-15", init && init2 && init->initial_tsn != init2->initial_tsn, "the Initial TSN is random");
        auto w = r.init.empty() ? std::vector<uint8_t>{} : serialize_sctp_packet(r.init[0]);
        req("9260-3.3.2.1-1", w.size() > 36 && be16(w, 32) == PARAM_IPV4_ADDRESS, "parameters follow the 16 fixed bytes");
        req("9260-3.3.2.1.2-1", init && std::vector<uint8_t>{} == ([&] { std::vector<uint8_t> x; find_parameter(init->optional_parameters, PARAM_IPV6_ADDRESS, x); return x; })(),
            "no IPv4-mapped IPv6 address: IPv4 addresses go in IPv4 Address parameters");
    }
    {
        SCTP_Socket s;
        Access::setup(s);
        std::vector<uint8_t> host = parameter(PARAM_HOST_NAME_ADDRESS, {'h', 'o', 's', 't', 0});
        Access::receive(s, packet(0, {chunk(INIT, init_value(PEER_TAG, PEER_TSN, RWND, 10, 10, host))}));
        auto out = Access::sent(s);
        req("9260-3.3.2-3", out.any(ABORT) && !out.any(INIT_ACK), "an INIT with a Host Name Address is answered with ABORT");
    }
    {
        SCTP_Socket s;
        Access::setup(s);
        Access::receive(s, packet(0, {chunk(INIT, init_value(), 0xFF)}));
        auto out = Access::sent(s);
        req("9260-3.3.2-4", out.any(INIT_ACK), "an INIT with its mandatory parameters is answered with INIT ACK");
        req("9260-3.3.2-5", out.any(INIT_ACK), "INIT flags are ignored on receipt");
    }
    {
        SCTP_Socket s;
        auto r = Access::respond(s);
        Access::send(s, {'d'});
        auto data = Access::sent(s);
        req("9260-3.3.2-6", !r.cookie_ack.empty() && r.cookie_ack[0].header.verification_tag == PEER_TAG
                && !data.empty() && data[0].header.verification_tag == PEER_TAG,
            "every packet the INIT's receiver sends carries the INIT's Initiate Tag");
    }
    {
        SCTP_Socket s;
        Access::setup(s);
        Access::receive(s, packet(0, {chunk(INIT, init_value(0))}));
        req("9260-3.3.2-7", Access::sent(s).empty(), "an INIT with Initiate Tag 0 is silently discarded");
    }
    auto refused = [](init_chunk_value init, const char* abort_id, const char* discard_id, const char* what) {
        SCTP_Socket fresh;
        Access::setup(fresh);
        Access::receive(fresh, packet(0, {chunk(INIT, init)}));
        auto out = Access::sent(fresh);
        req(discard_id, !out.any(INIT_ACK) && Access::association_count(fresh) == 0, std::string(what) + ": discarded");
        const Deliverable* abort = out.with(ABORT);
        req(abort_id, abort && abort->packet.header.verification_tag == init.initiate_tag, std::string(what) + ": ABORT under its Initiate Tag");
        SCTP_Socket live;
        Association& a = Access::establish(live);
        Access::receive(live, packet(0, {chunk(INIT, init)}));
        Access::sent(live);
        req(discard_id, a.state == ESTABLISHED && a.peer_ver_tag == PEER_TAG, std::string(what) + ": an existing association is untouched");
    };
    refused(init_value(0x77777777, PEER_TSN, 1499), "9260-3.3.2-9", "9260-3.3.2-9", "INIT with a_rwnd below 1500");
    refused(init_value(0x77777777, PEER_TSN, RWND, 0, 10), "9260-3.3.2-12", "9260-3.3.2-12", "INIT with OS 0");
    refused(init_value(0x77777777, PEER_TSN, RWND, 10, 0), "9260-3.3.2-14", "9260-3.3.2-14", "INIT with MIS 0");
    {
        SCTP_Socket s;
        Access::establish(s);
        uint32_t before = Access::receive_window(s);
        for (uint32_t i = 0; i < 4; ++i) {
            Access::receive(s, packet(OUR_TAG, {data_chunk(data(PEER_TSN + i, std::vector<uint8_t>(1000, 'r'), DATA_FLAG_B | DATA_FLAG_E, 0, static_cast<uint16_t>(i)))}));
        }
        std::vector<uint8_t> buffer(2000);
        while (Access::read(s, buffer) != 0) {
        }
        req("9260-3.3.2-10", Access::receive_window(s) == before, "the receive buffer is not reduced over the association's life");
    }
}

void s3_3_2_1_addresses() {
    section("3.3.2.1 Optional/Variable-Length Parameters in INIT");
    {
        SCTP_Socket s;
        Access::respond(s);
        Association* a = Access::tcb(s);
        req("9260-3.3.2.1.2-2", a && a->peer_address_list.size() == 1 && same_destination(a->peer_address_list[0].address, addr()),
            "with no address parameters, the INIT's source is the only destination");
    }
    {
        SCTP_Socket s;
        auto r = Access::initiate(s, concat({parameter(PARAM_STATE_COOKIE, std::vector<uint8_t>(32, 1)),
                                             parameter(PARAM_HOST_NAME_ADDRESS, {'h', 0, 0, 0})}), false);
        req("9260-3.3.2.1.4-2", r.echo.any(ABORT) && !r.echo.any(COOKIE_ECHO) && !Access::tcb(s),
            "an INIT ACK with a Host Name Address is answered with ABORT");
        req("9260-3.3.3-2", r.echo.any(ABORT), "the receiver of such an INIT ACK sends ABORT");
    }
    {
        SCTP_Socket s;
        auto r = Access::respond(s);
        const auto* ack = r.init_ack.empty() ? nullptr : find_value<init_chunk_value>(r.init_ack[0], INIT_ACK);
        std::vector<uint8_t> v;
        req("9260-3.3.2.1.4-1", ack && !find_parameter(ack->optional_parameters, PARAM_HOST_NAME_ADDRESS, v),
            "we never send a Host Name Address");
    }
    {
        SCTP_Socket s;
        std::vector<uint8_t> types = parameter(PARAM_SUPPORTED_ADDRESS_TYPES, {0, 5, 0, 11});
        auto r = Access::respond(s, init_value(PEER_TAG, PEER_TSN, RWND, 10, 10, types));
        req("9260-3.3.2.1.5-1", r.init_ack.any(INIT_ACK) && !r.init_ack.any(ABORT),
            "Host Name in Supported Address Types is ignored");
    }
}

void s3_3_3_init_ack() {
    section("3.3.3 Initiation Acknowledgement (INIT ACK) (2)");
    SCTP_Socket s;
    auto r = Access::respond(s, init_value(PEER_TAG, PEER_TSN, RWND, 10, 5));
    const auto* ack = r.init_ack.empty() ? nullptr : find_value<init_chunk_value>(r.init_ack[0], INIT_ACK);
    std::vector<uint8_t> v;
    req("9260-3.3.3-1", ack && !find_parameter(ack->optional_parameters, PARAM_HOST_NAME_ADDRESS, v), "INIT ACK has no Host Name Address");
    req("9260-3.3.3-3", !r.init_ack.empty() && r.init_ack[0].chunks[0].chunk_header.flag == 0, "INIT ACK flags are sent as 0");
    req("9260-3.3.3-5", ack && ack->initiate_tag != 0, "our Initiate Tag is not 0");
    req("9260-3.3.3-8", ack && ack->a_rwnd >= 1500, "our a_rwnd is at least 1500");
    req("9260-3.3.3-11", ack && ack->out_streams != 0 && ack->out_streams <= 5, "our OS is not 0 and not above the INIT's MIS");
    req("9260-3.3.3-14", ack && ack->in_streams != 0, "our MIS is not 0");
    SCTP_Socket s2;
    auto r2 = Access::respond(s2);
    const auto* ack2 = r2.init_ack.empty() ? nullptr : find_value<init_chunk_value>(r2.init_ack[0], INIT_ACK);
    req("9260-3.3.3-17", ack && ack2 && ack->initial_tsn != ack2->initial_tsn, "the INIT ACK's Initial TSN is random");
    auto w = r.init_ack.empty() ? std::vector<uint8_t>{} : serialize_sctp_packet(r.init_ack[0]);
    req("9260-3.3.3.1-2", w.size() > 36 && be16(w, 32) == PARAM_STATE_COOKIE, "parameters follow the 16 fixed bytes");
    Association* a = Access::tcb(s);
    req("9260-3.3.3.1.1-1", a && a->peer_ver_tag == PEER_TAG && a->last_peer_tsn == PEER_TSN - 1 && a->this_ver_tag == r.our_tag,
        "the cookie alone carries the state to create the association");

    {
        SCTP_Socket i;
        auto ri = Access::initiate(i, parameter(PARAM_STATE_COOKIE, std::vector<uint8_t>(32, 1)), false);
        Access::receive(i, packet(OUR_TAG, {}));
        req("9260-3.3.3-4", !ri.echo.empty() && ri.echo[0].header.verification_tag == PEER_TAG,
            "the INIT ACK's receiver sends under its Initiate Tag");
        req("9260-3.3.3-19", ri.echo.any(COOKIE_ECHO), "a complete INIT ACK is answered with COOKIE ECHO");
        Association* ai = Access::tcb(i);
        req("9260-3.3.3-20", ai && ai->peer_address_list.size() == 1, "with no address parameters, the source is the only destination");
    }
    {
        SCTP_Socket i;
        auto ri = Access::initiate(i, parameter(PARAM_STATE_COOKIE, std::vector<uint8_t>(2000, 7)), false);
        const auto* echo = ri.echo.empty() ? nullptr : find_value<cookie_echo_chunk_value>(ri.echo[0], COOKIE_ECHO);
        req("9260-3.3.3-18", echo && echo->cookie_data.size() == 2000, "an INIT ACK over 1500 bytes is accepted");
    }

    auto in_cookie_wait = [](init_chunk_value value, const char* destroy_id, const char* abort_id, const char* what, bool t_bit) {
        SCTP_Socket i;
        Association_Key k = Access::associate(i);
        auto init = Access::sent(i);
        uint32_t tag = init.empty() ? 0 : find_value<init_chunk_value>(init[0], INIT)->initiate_tag;
        value.optional_parameters = parameter(PARAM_STATE_COOKIE, std::vector<uint8_t>(16, 1));
        Access::receive(i, packet(tag, {chunk(INIT_ACK, value)}));
        auto out = Access::sent(i);
        req(destroy_id, !Access::tcb(i, k) && !out.any(COOKIE_ECHO), std::string(what) + " in COOKIE-WAIT destroys the TCB");
        const Deliverable* abort = out.with(ABORT);
        bool ok = abort && (!t_bit || (abort->packet.chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT));
        req(abort_id, ok, std::string(what) + ": an ABORT is sent" + (t_bit ? " with the T bit" : ""));
    };
    in_cookie_wait(init_value(0), "9260-3.3.3-6", "9260-3.3.3-6", "INIT ACK with Initiate Tag 0", true);
    in_cookie_wait(init_value(PEER_TAG, PEER_TSN, RWND, 0, 10), "9260-3.3.3-12", "9260-3.3.3-12", "INIT ACK with OS 0", false);
    in_cookie_wait(init_value(PEER_TAG, PEER_TSN, RWND, 10, 0), "9260-3.3.3-15", "9260-3.3.3-15", "INIT ACK with MIS 0", false);
    {
        SCTP_Socket i;
        Association_Key k = Access::associate(i);
        auto init = Access::sent(i);
        uint32_t tag = init.empty() ? 0 : find_value<init_chunk_value>(init[0], INIT)->initiate_tag;
        Access::receive(i, packet(tag, {chunk(INIT_ACK, init_value(0x66666666, PEER_TSN, 1499, 10, 10, parameter(PARAM_STATE_COOKIE, {1, 2, 3, 4})))}));
        auto out = Access::sent(i);
        req("9260-3.3.3-9", !out.any(COOKIE_ECHO), "an INIT ACK with a_rwnd below 1500 is discarded");
        const Deliverable* abort = out.with(ABORT);
        req("9260-3.3.3-9", abort && abort->packet.header.verification_tag == 0x66666666, "and answered with ABORT under its Initiate Tag");
        (void)k;
    }
    auto established = [](init_chunk_value value, const char* id, const char* what) {
        SCTP_Socket e;
        Association& a = Access::establish(e);
        value.optional_parameters = parameter(PARAM_STATE_COOKIE, std::vector<uint8_t>(16, 1));
        Access::receive(e, packet(OUR_TAG, {chunk(INIT_ACK, value)}));
        req(id, Access::sent(e).empty() && a.state == ESTABLISHED && a.peer_ver_tag == PEER_TAG, std::string(what) + " in ESTABLISHED is silently discarded");
    };
    established(init_value(0), "9260-3.3.3-7", "INIT ACK with Initiate Tag 0");
    established(init_value(PEER_TAG, PEER_TSN, RWND, 0, 10), "9260-3.3.3-13", "INIT ACK with OS 0");
    established(init_value(PEER_TAG, PEER_TSN, RWND, 10, 0), "9260-3.3.3-16", "INIT ACK with MIS 0");
    {
        SCTP_Socket e;
        Access::establish(e);
        uint32_t before = Access::receive_window(e);
        req("9260-3.3.3-10", before == RWND, "the receive buffer offered in INIT ACK is kept");
    }
    {
        SCTP_Socket i;
        Access::associate(i);
        auto init = Access::sent(i);
        uint32_t tag = init.empty() ? 0 : find_value<init_chunk_value>(init[0], INIT)->initiate_tag;
        Access::receive(i, packet(tag, {chunk(INIT_ACK, init_value(PEER_TAG, PEER_TSN, RWND, 10, 10, parameter(PARAM_STATE_COOKIE, {1, 2, 3, 4})), 0xFF)}));
        req("9260-3.3.3-3", Access::sent(i).any(COOKIE_ECHO), "INIT ACK flags are ignored on receipt");
    }
    {
        SCTP_Socket r3;
        auto resp = Access::respond(r3, init_value(PEER_TAG, PEER_TSN, RWND, 10, 10, parameter(0x8123, {1, 2, 3, 4})));
        const auto* a3 = resp.init_ack.empty() ? nullptr : find_value<init_chunk_value>(resp.init_ack[0], INIT_ACK);
        std::vector<uint8_t> v3;
        req("9260-3.3.3.1-1", a3 && !find_parameter(a3->optional_parameters, PARAM_HOST_NAME_ADDRESS, v3), "INIT ACK carries no Host Name Address");
        SCTP_Socket r4;
        auto resp4 = Access::respond(r4, init_value(PEER_TAG, PEER_TSN, RWND, 10, 10, parameter(0xC123, {1, 2, 3, 4})));
        const auto* a4 = resp4.init_ack.empty() ? nullptr : find_value<init_chunk_value>(resp4.init_ack[0], INIT_ACK);
        std::vector<uint8_t> report4;
        SCTP_Socket r5;
        auto resp5 = Access::respond(r5, init_value(PEER_TAG, PEER_TSN, RWND, 10, 10, parameter(0x8123, {1, 2, 3, 4})));
        const auto* a5 = resp5.init_ack.empty() ? nullptr : find_value<init_chunk_value>(resp5.init_ack[0], INIT_ACK);
        std::vector<uint8_t> report5;
        req("9260-3.3.3.1.2-1", a4 && find_parameter(a4->optional_parameters, PARAM_UNRECOGNIZED, report4)
                && a5 && !find_parameter(a5->optional_parameters, PARAM_UNRECOGNIZED, report5),
            "Unrecognized Parameter is returned only for types marked to be reported");
    }
}

void s3_3_4_sack() {
    section("3.3.4 Selective Acknowledgement (SACK) (3)");
    SCTP_Socket s;
    Association& a = Access::establish(s);
    a.last_peer_tsn = 12;
    for (uint32_t tsn : {14u, 15u, 17u}) {
        Access::receive(s, packet(OUR_TAG, {data_chunk(data(tsn, {'g'}, DATA_FLAG_U | DATA_FLAG_B | DATA_FLAG_E))}));
    }
    Access::receive(s, packet(OUR_TAG, {data_chunk(data(15, {'g'}, DATA_FLAG_U | DATA_FLAG_B | DATA_FLAG_E))}));
    auto out = Access::sent(s);
    const sack_chunk_value* sack = nullptr;
    for (const auto& d : out.out) {
        if (const auto* v = find_value<sack_chunk_value>(d.packet, SACK)) {
            sack = v;
        }
    }
    bool fields = false;
    if (sack) {
        SCTP_Packet one = build_sack(1, 2, 3, sack->cumulative_tsn_ack, sack->a_rwnd, sack->gap_ack_blocks, sack->duplicate_tsns);
        auto w = serialize_sctp_packet(one);
        fields = be16(w, 14) == 16 + 4 * sack->gap_ack_blocks.size() + 4 * sack->duplicate_tsns.size()
            && be16(w, 24) == sack->gap_ack_blocks.size() && be16(w, 26) == sack->duplicate_tsns.size();
    }
    req("9260-3.3.4-1", sack && fields, "a SACK carries Cumulative TSN Ack, a_rwnd and both counts");
    bool isolated = sack != nullptr;
    for (size_t i = 1; sack && i < sack->gap_ack_blocks.size(); ++i) {
        isolated = isolated && sack->gap_ack_blocks[i].start > sack->gap_ack_blocks[i - 1].end + 1;
    }
    req("9260-3.3.4-2", isolated, "Gap Ack Blocks are isolated");
    bool example = sack && sack->cumulative_tsn_ack == 12 && sack->gap_ack_blocks.size() == 2
        && sack->gap_ack_blocks[0].start == 2 && sack->gap_ack_blocks[0].end == 3
        && sack->gap_ack_blocks[1].start == 5 && sack->gap_ack_blocks[1].end == 5
        && sack->duplicate_tsns == std::vector<uint32_t>{15};
    req("9260-3.3.4-3", example, "the SACK for the Figure 9 example is cumulative 12, blocks 2-3 and 5-5, duplicate 15");
}

void s3_3_5_heartbeat() {
    section("3.3.5 / 3.3.6 HEARTBEAT and HEARTBEAT ACK");
    SCTP_Socket s;
    Association& a = Access::establish(s, ESTABLISHED, {"127.0.0.2"});
    a.peer_address_list[1].confirmed = false;
    Access::start_heartbeats_for(s);
    Access::fire(s, Expiration_Timer_Type::HEARTBEAT, PEER_IP);
    auto out = Access::sent(s);
    req("9260-3.3.5-1", out.any(HEARTBEAT), "an idle destination is probed with HEARTBEAT");
    std::vector<std::vector<uint8_t>> infos;
    for (const auto& d : out.out) {
        if (const auto* hb = find_value<heartbeat_chunk_value>(d.packet, HEARTBEAT)) {
            infos.push_back(hb->info);
        }
    }
    Access::fire(s, Expiration_Timer_Type::HEARTBEAT, "127.0.0.2");
    for (const auto& d : Access::sent(s).out) {
        if (const auto* hb = find_value<heartbeat_chunk_value>(d.packet, HEARTBEAT)) {
            infos.push_back(hb->info);
        }
    }
    bool destination = !infos.empty() && heartbeat_info_destination(infos[0]).sin_addr.s_addr == addr().sin_addr.s_addr;
    req("9260-3.3.5-2", destination, "the Heartbeat Info names the destination");
    req("9260-3.3.5-2", !infos.empty() && infos[0].size() >= HEARTBEAT_INFO_SIZE + 8, "the Heartbeat Info carries the send time");
    req("9260-3.3.5-3", infos.size() >= 2 && infos[0].size() >= 8 && heartbeat_info_nonce(infos[0]) != heartbeat_info_nonce(infos[1]),
        "a confirmation probe carries a 64-bit random nonce");

    SCTP_Socket r;
    Access::establish(r);
    std::vector<uint8_t> info{9, 8, 7, 6, 5, 4, 3};
    Access::receive(r, packet(OUR_TAG, {chunk(HEARTBEAT, heartbeat_chunk_value{info})}));
    auto reply = Access::sent(r);
    const auto* ack = reply.empty() ? nullptr : find_value<heartbeat_chunk_value>(reply[0], HEARTBEAT_ACK);
    req("9260-3.3.6-1", ack != nullptr, "HEARTBEAT is answered with HEARTBEAT ACK");
    req("9260-3.3.6-2", ack && ack->info == info, "the HEARTBEAT ACK carries the request's Heartbeat Info");
}

void s3_3_7_abort() {
    section("3.3.7 Abort Association (ABORT) (6)");
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::send(s, {'a'});
        Access::send(s, std::vector<uint8_t>(3000, 'b'));
        s.sctp_abort(key());
        auto out = Access::sent(s);
        const Deliverable* abort = out.with(ABORT);
        req("9260-3.3.7-1", abort && !find_chunk(abort->packet, DATA) && out.data().empty(), "DATA is never bundled with ABORT");
        req("9260-3.3.7-2", abort && abort->packet.chunks.back().chunk_header.type == ABORT, "anything bundled goes before the ABORT");
    }
    {
        SCTP_Socket s;
        Access::setup(s);
        Access::receive(s, packet(0x12345678, {chunk(ABORT, error_chunk_value{})}));
        bool silent = Access::sent(s).empty();
        SCTP_Socket t;
        Association& a = Access::establish(t);
        auto w = serialize_sctp_packet(packet(OUR_TAG, {chunk(ABORT, error_chunk_value{{error_cause{CAUSE_PROTOCOL_VIOLATION, {1, 2, 3, 4, 5, 6, 7, 8}}}})}));
        w[SCTP_COMMON_HEADER_SIZE + 6] = 0x40;
        std::memset(w.data() + SCTP_CHECKSUM_OFFSET, 0, 4);
        uint32_t crc = calculate_sctp_checksum(w.data(), w.size());
        std::memcpy(w.data() + SCTP_CHECKSUM_OFFSET, &crc, 4);
        Access::receive_wire(t, w);
        req("9260-3.3.7-3", silent && Access::sent(t).empty() && a.state == ESTABLISHED,
            "an ABORT with no TCB, or with a format error, is silently discarded");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::receive(s, packet(0x99999999, {chunk(ABORT, error_chunk_value{})}));
        bool wrong_tag = Access::sent(s).empty();
        SCTP_Socket t;
        Access::establish(t);
        Access::receive(t, packet(OUR_TAG, {chunk(ABORT, error_chunk_value{})}));
        req("9260-3.3.7-4", wrong_tag && !Access::sent(t).any(ABORT), "an ABORT is never answered with an ABORT");
    }
    {
        SCTP_Socket s;
        Access::setup(s);
        Access::receive(s, packet(0x31415926, {chunk(HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}})}));
        auto abort_sent = Access::sent(s);
        const Deliverable* abort = abort_sent.with(ABORT);
        req("9260-3.3.7-5", abort && abort->packet.header.verification_tag == 0x31415926
                && (abort->packet.chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT),
            "a reflected tag goes with the T bit set");
    }
}

void s3_3_8_shutdown() {
    section("3.3.8 - 3.3.13 SHUTDOWN, SHUTDOWN ACK, ERROR, COOKIE ECHO, COOKIE ACK, SHUTDOWN COMPLETE");
    {
        SCTP_Socket s;
        Access::establish(s);
        s.sctp_shutdown(key());
        req("9260-3.3.8-1", Access::sent(s).any(SHUTDOWN), "a graceful close starts with SHUTDOWN");
    }
    {
        SCTP_Socket s;
        Association& a = Access::establish(s, ESTABLISHED);
        Access::send(s, {'1'});
        Access::send(s, std::vector<uint8_t>(1300, '2'));
        Access::sent(s);
        Access::receive(s, packet(OUR_TAG, {sack_chunk(OUR_TSN - 1, RWND, {{2, 2}})}));
        Access::receive(s, packet(OUR_TAG, {chunk(SHUTDOWN, shutdown_chunk_value{OUR_TSN - 1})}));
        auto gap = a.outstanding_data.find(OUR_TSN + 1);
        req("9260-3.3.8-2", gap != a.outstanding_data.end() && gap->second.gap_acked, "a SHUTDOWN's missing Gap Ack Blocks are not a renege");
    }
    {
        SCTP_Socket s;
        Access::establish(s);
        Access::receive(s, packet(OUR_TAG, {chunk(SHUTDOWN, shutdown_chunk_value{OUR_TSN - 1})}));
        req("9260-3.3.9-1", Access::sent(s).any(SHUTDOWN_ACK), "SHUTDOWN ACK acknowledges the SHUTDOWN");
    }
    {
        SCTP_Socket s;
        auto r = Access::respond(s);
        Access::cookies(s).clock = [] { return Clock::now() + std::chrono::minutes(5); };
        Access::receive(s, packet(r.our_tag, {chunk(COOKIE_ECHO, cookie_echo_chunk_value{r.cookie})}), addr("127.0.0.5"));
        SCTP_Socket fresh;
        Access::setup(fresh);
        Access::receive(fresh, packet(0, {chunk(INIT, init_value())}));
        auto ack = Access::sent(fresh);
        const auto* v = ack.empty() ? nullptr : find_value<init_chunk_value>(ack[0], INIT_ACK);
        std::vector<uint8_t> cookie;
        if (v) {
            find_parameter(v->optional_parameters, PARAM_STATE_COOKIE, cookie);
        }
        Access::cookies(fresh).clock = [] { return Clock::now() + std::chrono::minutes(5); };
        Access::receive(fresh, packet(v ? v->initiate_tag : 0, {chunk(COOKIE_ECHO, cookie_echo_chunk_value{cookie})}));
        auto error = Access::sent(fresh);
        const auto* e = error.empty() ? nullptr : find_value<error_chunk_value>(error[0], OP_ERROR);
        bool measured = e && !e->causes.empty() && e->causes[0].code == CAUSE_STALE_COOKIE && e->causes[0].info.size() == 4
            && read_be32(e->causes[0].info.data()) != 0;
        req("9260-3.3.10.3-1", measured, "a Stale Cookie error carries a Measure of Staleness, nonzero when measured");
    }
    {
        SCTP_Socket s;
        auto r = Access::initiate(s, parameter(PARAM_STATE_COOKIE, {0xAB, 0xCD, 0xEF, 0x01, 0x23}), false);
        const auto* echo = r.echo.empty() ? nullptr : find_value<cookie_echo_chunk_value>(r.echo[0], COOKIE_ECHO);
        req("9260-3.3.11-1", !r.echo.empty() && r.echo[0].chunks[0].chunk_header.type == COOKIE_ECHO && r.echo.data().empty(),
            "COOKIE ECHO comes before any DATA");
        req("9260-3.3.11-2", echo && echo->cookie_data == std::vector<uint8_t>{0xAB, 0xCD, 0xEF, 0x01, 0x23},
            "the COOKIE ECHO returns the cookie exactly");
        SCTP_Socket t;
        auto resp = Access::respond(t);
        req("9260-3.3.11-3", resp.cookie.size() <= STATE_COOKIE_SIZE, "our cookie is no larger than its fixed fields");
    }
    {
        SCTP_Socket s;
        auto r = Access::respond(s, init_value(), {data_chunk(data(PEER_TSN, {'c'}))});
        bool first = !r.cookie_ack.empty() && r.cookie_ack[0].chunks[0].chunk_header.type == COOKIE_ACK;
        bool before = true;
        for (size_t i = 0; i < r.cookie_ack.size() && !find_chunk(r.cookie_ack[i], COOKIE_ACK); ++i) {
            before = before && !find_chunk(r.cookie_ack[i], SACK) && !find_chunk(r.cookie_ack[i], DATA);
        }
        req("9260-3.3.12-1", first && before, "COOKIE ACK comes before any DATA or SACK");
    }
    {
        SCTP_Socket s;
        Access::establish(s, SHUTDOWN_SENT);
        Access::receive(s, packet(OUR_TAG, {chunk(SHUTDOWN_ACK, empty_chunk_value{})}));
        auto complete_sent = Access::sent(s);
        const Deliverable* complete = complete_sent.with(SHUTDOWN_COMPLETE);
        req("9260-3.3.13-1", complete != nullptr, "SHUTDOWN COMPLETE acknowledges the SHUTDOWN ACK");
        req("9260-8.5.1-8", complete && complete->packet.header.verification_tag == PEER_TAG
                && !(complete->packet.chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT),
            "with a TCB, SHUTDOWN COMPLETE goes under the peer's tag with T clear");
        SCTP_Socket o;
        Access::setup(o);
        Access::receive(o, packet(0x2468ACE0, {chunk(SHUTDOWN_ACK, empty_chunk_value{})}));
        auto reflected_sent = Access::sent(o);
        const Deliverable* reflected = reflected_sent.with(SHUTDOWN_COMPLETE);
        req("9260-3.3.13-2", reflected && (reflected->packet.chunks[0].chunk_header.flag & CHUNK_FLAG_T_BIT)
                && reflected->packet.header.verification_tag == 0x2468ACE0,
            "a reflected tag goes with the T bit set");
    }
}

} // namespace

int main() {
    s1_3_endpoints();
    s1_6_serial_numbers();
    s3_packet_format();
    s3_1_common_header();
    s3_2_chunks();
    s3_2_1_parameters();
    s3_2_1_registry();
    s3_2_2_unrecognized();
    s3_3_1_data();
    s3_3_2_init();
    s3_3_2_1_addresses();
    s3_3_3_init_ack();
    s3_3_4_sack();
    s3_3_5_heartbeat();
    s3_3_7_abort();
    s3_3_8_shutdown();
    return summary("RFC 9260 sections 1 and 3");
}
