// RFC 6951: UDP encapsulation of SCTP packets. The UDP header checks use a
// real socket for the peer, since only the kernel writes UDP headers.

#include "rfc_harness.hpp"

#include <thread>

using namespace rfc;

namespace {

void s3_2_and_5_7_addresses() {
    section("3.2 / 5.7 Addresses in INIT and INIT ACK");
    SCTP_Socket s;
    auto r = Access::initiate(s, {}, false);
    const auto* init = r.init.empty() ? nullptr : find_value<init_chunk_value>(r.init[0], INIT);
    SCTP_Socket t;
    auto resp = Access::respond(t);
    const auto* ack = resp.init_ack.empty() ? nullptr : find_value<init_chunk_value>(resp.init_ack[0], INIT_ACK);
    bool none = init && ack && find_ipv4_addresses(init->optional_parameters).empty() && find_ipv4_addresses(ack->optional_parameters).empty();
    req("6951-3.2-1", none, "a single-homed association lists no addresses in INIT or INIT ACK");
    SCTP_Socket w;
    bool wildcard = w.sctp_bind("0.0.0.0", 0) && Access::advertised(w).empty();
    req("6951-5.7-1", none && wildcard, "no address that might need translation is put in a packet: single or wildcard binds list none");
}

void s5_1_and_5_4_ports() {
    section("5.1 / 5.4 Remote encapsulation port per destination");
    {
        SCTP_Socket s;
        Access::establish(s, ESTABLISHED, {"127.0.0.2"});
        Access::receive(s, packet(OUR_TAG, {chunk(HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}})}), addr("127.0.0.2", 5555));
        Peer_Path* one = Access::path(s, PEER_IP);
        Peer_Path* two = Access::path(s, "127.0.0.2");
        req("6951-5.1-1", one && two && ntohs(two->address.sin_port) == 5555 && ntohs(one->address.sin_port) == PEER_PORT,
            "each destination keeps its own remote UDP port");
        Access::receive(s, packet(OUR_TAG, {chunk(HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}})}), addr(PEER_IP, 6666));
        bool updated = one && ntohs(one->address.sin_port) == 6666;
        Access::receive(s, packet(OUR_TAG ^ 1, {chunk(HEARTBEAT, heartbeat_chunk_value{{1, 2, 3, 4}})}), addr(PEER_IP, 7777));
        req("6951-5.4-1", updated && ntohs(one->address.sin_port) == 6666,
            "the UDP source port is stored for its destination once the tag checks out, and not before");
        Access::send(s, {'p'});
        auto out = Access::sent(s);
        const Deliverable* d = out.with(DATA);
        req("6951-5.3-1", d && ntohs(d->destination.sin_port) == 6666, "packets go to the destination's stored UDP port");
    }
}

void s5_3_udp_header() {
    section("5.3 Encapsulation Procedure");
    int peer = static_cast<int>(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
    sockaddr_in at = addr(PEER_IP, 0);
    bind(peer, reinterpret_cast<sockaddr*>(&at), sizeof(at));
    socklen_t length = sizeof(at);
    getsockname(peer, reinterpret_cast<sockaddr*>(&at), &length);

    SCTP_Socket s;
    bool bound = Access::bind_real(s);
    Association& a = Access::establish(s);
    primary(a).address.sin_port = at.sin_port;
    Access::send(s, std::vector<uint8_t>(333, 'u'));
    Access::flush(s);

    std::vector<uint8_t> datagram(2048);
    sockaddr_in from{};
    socklen_t from_length = sizeof(from);
    ssize_t n = -1;
    for (int i = 0; i < 100 && n < 0; ++i) {
        n = recvfrom(peer, reinterpret_cast<char*>(datagram.data()), datagram.size(), MSG_DONTWAIT, reinterpret_cast<sockaddr*>(&from), &from_length);
        if (n < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }
    datagram.resize(n > 0 ? static_cast<size_t>(n) : 0);
    bool got = bound && n > 0;
    req("6951-5.3-1", got && ntohs(from.sin_port) == LOCAL_PORT, "the UDP source port is our encapsulation port");
    size_t expected = DATA_CHUNK_HEADER_SIZE + 336 + SCTP_COMMON_HEADER_SIZE;
    req("6951-5.3-2", got && datagram.size() == expected, "the UDP payload is exactly the SCTP packet");
    bool crc = false;
    if (got) {
        uint32_t stored = sctp_read_wire_checksum(datagram.data());
        sctp_clear_wire_checksum(datagram.data());
        crc = calculate_sctp_checksum(datagram.data(), datagram.size()) == stored;
    }
    req("6951-5.3-3", crc, "the SCTP checksum is computed");
    sctp_close_socket(peer);
}

void s5_5_and_5_6_pmtu() {
    section("5.5 / 5.6 PMTU without relying on ICMP");
    {
        SCTP_Socket s;
        Association& a = Access::establish(s);
        Access::start_heartbeats_for(s);
        Peer_Path& p = primary(a);
        bool raised = false;
        for (int i = 0; i < 3 && !raised; ++i) {
            Access::fire(s, Expiration_Timer_Type::PLPMTU_PROBE, PEER_IP);
            auto sent_d = Access::sent(s);
            for (const auto* d : sent_d.all(PAD)) {
                const auto* hb = find_value<heartbeat_chunk_value>(d->packet, HEARTBEAT);
                Access::receive(s, packet(OUR_TAG, {chunk(HEARTBEAT_ACK, heartbeat_chunk_value{hb->info})}));
                raised = p.plpmtud.plpmtu > plpmtud_parameters::BASE_PLPMTU;
            }
        }
        req("6951-5.5-2", raised, "PMTU discovery works with no ICMP at all");
        req("6951-5.6-3", raised, "PMTU probing does not rely on ICMP feedback");
    }
    {
        SCTP_Packet probe = build_plpmtu_probe(LOCAL_PORT, PEER_PORT, PEER_TAG, heartbeat_info(1, addr()), 1400);
        bool sized = serialize_sctp_packet(probe).size() + UDP_HEADER_SIZE == 1400;
        req("6951-5.6-1", sized && pmdcs_of(1480) == 1480 - UDP_HEADER_SIZE - SCTP_COMMON_HEADER_SIZE,
            "the path MTU is reduced by the UDP header");
    }
}

} // namespace

int main() {
    s3_2_and_5_7_addresses();
    s5_1_and_5_4_ports();
    s5_3_udp_header();
    s5_5_and_5_6_pmtu();
    return summary("RFC 6951");
}
