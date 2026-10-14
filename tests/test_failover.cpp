// Multi-homed data transfer (RFC 9260 6.4, 6.4.1, 6.3.2, 6.3.3, 7.2, 8.2): the
// destination new DATA goes to, retransmission of timed-out DATA to an
// alternate, and the T3-rtx timer, congestion window, error count and RTT
// kept for each destination apart.
//
// transmit() does what run_sending does minus the sendto(), so nothing here
// touches the network or waits on wall-clock time.

#include <sctp/socket.hpp>
#include <sctp/platform.hpp>
#include "serialize.hpp"
#include "socket_internal.hpp"

#include <chrono>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;

namespace {

constexpr uint32_t OUR_TAG = 0x0A0B0C0D;
constexpr uint32_t PEER_TAG = 0x11223344;
constexpr uint16_t PEER_PORT = 40000;
constexpr uint16_t LOCAL_PORT = 9899;
constexpr uint32_t INITIAL_TSN = 1000;

sockaddr_in address_of(const char* ip) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(PEER_PORT);
    sctp_parse_ipv4(ip, address.sin_addr);
    return address;
}

const sockaddr_in PRIMARY = address_of("127.0.0.1");
const sockaddr_in ALTERNATE = address_of("127.0.0.2");

} // namespace

struct SCTP_Socket_Test_Access {
    // Established with both addresses CONFIRMED.
    static void establish(SCTP_Socket& stack, const Association_Key& key) {
        stack.local_address.sin_family = AF_INET;
        stack.local_address.sin_port = htons(LOCAL_PORT);
        sctp_parse_ipv4("127.0.0.1", stack.local_address.sin_addr);

        Association assoc = stack.init_new_association(key);
        assoc.this_ver_tag = OUR_TAG;
        assoc.peer_ver_tag = PEER_TAG;
        assoc.state = ESTABLISHED;
        assoc.next_tsn = INITIAL_TSN;
        assoc.cumulative_tsn_ack = INITIAL_TSN - 1;
        assoc.peer_rwnd = 65535;
        assoc.peer_max_rwnd = 65535;
        assoc.primary_path = key.address;
        stack.associations.insert_or_assign(key, assoc);
        Association& stored = stack.associations.at(key);
        stack.add_peer_addresses(key, stored, {ALTERNATE});
        find_path(stored, ALTERNATE)->confirmed = true;
    }

    static std::optional<Deliverable> transmit(SCTP_Socket& stack) {
        stack.start_transmission_opportunity();
        auto pending = stack.next_packet();
        if (!pending) {
            return std::nullopt;
        }
        stack.packet_sent(*pending);
        return pending->deliverable;
    }

    // Records one DATA chunk as sent to `destination`, as transmit() would.
    static void sent_to(SCTP_Socket& stack, const Association_Key& key, const sockaddr_in& destination) {
        Association& assoc = stack.associations.at(key);
        data_chunk_value data{assoc.next_tsn++, 0, 0, 0, std::vector<uint8_t>(100, 'x')};
        data.flags = DATA_FLAG_B | DATA_FLAG_E;
        stack.record_data_sent(key, destination, data, Clock::now());
        stack.start_t3_if_stopped(key, destination);
    }

    static void deliver_sack(SCTP_Socket& stack, uint32_t cumulative_tsn_ack, std::vector<sack_gap_ack_block> gaps = {}) {
        SCTP_Packet sack = build_sack(PEER_PORT, LOCAL_PORT, OUR_TAG, cumulative_tsn_ack, 65535, std::move(gaps), {});
        std::vector<uint8_t> wire = serialize_sctp_packet(sack);
        stack.handle_recv_packet(wire.data(), wire.size(), PRIMARY);
    }

    static void fire_t3(SCTP_Socket& stack, const Association_Key& key, const sockaddr_in& destination) {
        stack.handle_t3_expiration(key, destination);
    }

    static bool t3_armed(SCTP_Socket& stack, const Association_Key& key, const sockaddr_in& destination) {
        return stack.expirations.is_active(Expiration_Key{key, Expiration_Timer_Type::T3_RTX, Association_Key{destination}});
    }

    static Association& tcb(SCTP_Socket& stack, const Association_Key& key) {
        return stack.associations.at(key);
    }

    static Peer_Path& path(SCTP_Socket& stack, const Association_Key& key, const sockaddr_in& address) {
        return *find_path(stack.associations.at(key), address);
    }
};

namespace {

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

using Access = SCTP_Socket_Test_Access;

const std::vector<uint8_t> MESSAGE(100, 'm');

bool goes_to(const std::optional<Deliverable>& sent, const sockaddr_in& address) {
    return sent && same_transport_address(sent->destination, address);
}

void test_new_data_follows_the_data_path() {
    std::printf("Where new DATA goes (6.4, 8.2):\n");

    SCTP_Socket stack;
    Association_Key key{PRIMARY};
    Access::establish(stack, key);

    stack.sctp_send_data(key, MESSAGE);
    check(goes_to(Access::transmit(stack), PRIMARY), "to the primary while it is active");

    Access::path(stack, key, PRIMARY).active = false;
    stack.sctp_send_data(key, MESSAGE);
    check(goes_to(Access::transmit(stack), ALTERNATE), "to the alternate once the primary is inactive");

    Access::path(stack, key, ALTERNATE).active = false;
    stack.sctp_send_data(key, MESSAGE);
    check(goes_to(Access::transmit(stack), PRIMARY), "back to the primary when no path is active");

    Access::path(stack, key, PRIMARY).active = true;
    Access::path(stack, key, ALTERNATE).active = true;
    stack.sctp_send_data(key, MESSAGE);
    check(goes_to(Access::transmit(stack), PRIMARY), "and to the primary again once it recovers");
}

void test_unconfirmed_alternate_is_not_used() {
    std::printf("An UNCONFIRMED alternate (5.4):\n");

    SCTP_Socket stack;
    Association_Key key{PRIMARY};
    Access::establish(stack, key);
    Access::path(stack, key, ALTERNATE).confirmed = false;
    Access::path(stack, key, PRIMARY).active = false;

    stack.sctp_send_data(key, MESSAGE);
    check(goes_to(Access::transmit(stack), PRIMARY), "is never chosen for DATA");
}

void test_t3_moves_timed_out_data_to_an_alternate() {
    std::printf("T3-rtx expiring on the primary (6.3.3, 6.4):\n");

    SCTP_Socket stack;
    Association_Key key{PRIMARY};
    Access::establish(stack, key);
    stack.sctp_send_data(key, MESSAGE);
    Access::transmit(stack);
    check(Access::t3_armed(stack, key, PRIMARY), "the primary's timer runs while its DATA is out");
    check(!Access::t3_armed(stack, key, ALTERNATE), "the alternate's does not");
    uint32_t alternate_cwnd = Access::path(stack, key, ALTERNATE).cwnd;

    Access::fire_t3(stack, key, PRIMARY);
    const Peer_Path& primary_path = Access::path(stack, key, PRIMARY);
    check(primary_path.cwnd == DEFAULT_PMDCS && primary_path.single_packet_in_flight, "E1: the primary's cwnd drops to one PMDCS");
    check(primary_path.rto == 2 * std::chrono::microseconds(sctp_parameters::RTO_INITIAL), "E2: its RTO backs off");
    check(primary_path.error_count == 1 && Access::tcb(stack, key).error_count == 1,
          "the expiry counts against the path and the association");
    check(Access::path(stack, key, ALTERNATE).cwnd == alternate_cwnd, "the alternate's cwnd is untouched");

    auto retransmission = Access::transmit(stack);
    check(goes_to(retransmission, ALTERNATE), "the chunk is retransmitted to the alternate");
    check(Access::t3_armed(stack, key, ALTERNATE), "F1: which starts the alternate's timer");
    check(bytes_in_flight(Access::tcb(stack, key), &Access::path(stack, key, ALTERNATE)) > 0
          && bytes_in_flight(Access::tcb(stack, key), &primary_path) == 0,
          "and moves the chunk's flight from the primary to it");

    Access::deliver_sack(stack, INITIAL_TSN);
    check(!Access::t3_armed(stack, key, ALTERNATE), "R2: the SACK stops the alternate's timer");
    check(Access::path(stack, key, ALTERNATE).error_count == 0 && primary_path.error_count == 1,
          "and clears the error count of the path the DATA went to, not the primary's");
    check(primary_path.single_packet_in_flight, "the primary stays at one packet until DATA sent to it is acked");
}

void test_t3_on_the_alternate_goes_back_to_the_primary() {
    std::printf("T3-rtx expiring on the alternate:\n");

    SCTP_Socket stack;
    Association_Key key{PRIMARY};
    Access::establish(stack, key);
    Access::sent_to(stack, key, ALTERNATE);
    Access::fire_t3(stack, key, ALTERNATE);

    check(goes_to(Access::transmit(stack), PRIMARY), "the chunk goes to a path other than the one it timed out on");
}

void test_cwnd_is_per_destination() {
    std::printf("cwnd per destination (7.2):\n");

    SCTP_Socket stack;
    Association_Key key{PRIMARY};
    Access::establish(stack, key);
    Access::path(stack, key, PRIMARY).cwnd = 200;
    Access::sent_to(stack, key, PRIMARY);
    Access::sent_to(stack, key, PRIMARY);

    const Association& assoc = Access::tcb(stack, key);
    check(!cwnd_open(assoc, Access::path(stack, key, PRIMARY)), "the primary's window is full");
    check(cwnd_open(assoc, Access::path(stack, key, ALTERNATE)), "the alternate's is not");
    stack.sctp_send_data(key, MESSAGE);
    check(!Access::transmit(stack), "new DATA waits on the primary's window");
}

void test_rtt_is_measured_per_destination() {
    std::printf("RTT measurement (6.3.1):\n");

    SCTP_Socket stack;
    Association_Key key{PRIMARY};
    Access::establish(stack, key);
    Access::sent_to(stack, key, ALTERNATE);
    Access::deliver_sack(stack, INITIAL_TSN);

    check(Access::path(stack, key, ALTERNATE).has_srtt, "a SACK of DATA sent to the alternate measures the alternate");
    check(!Access::path(stack, key, PRIMARY).has_srtt, "and not the primary");
}

void test_fast_retransmit_stays_on_its_path() {
    std::printf("Fast Retransmit (6.4, 7.2.4):\n");

    SCTP_Socket stack;
    Association_Key key{PRIMARY};
    Access::establish(stack, key);
    Access::sent_to(stack, key, ALTERNATE);
    for (int i = 0; i < 3; ++i) {
        Access::sent_to(stack, key, PRIMARY);
    }
    uint32_t primary_ssthresh = Access::path(stack, key, PRIMARY).ssthresh;

    for (uint16_t end = 2; end <= 4; ++end) {
        Access::deliver_sack(stack, INITIAL_TSN - 1, {sack_gap_ack_block{2, end}});
    }

    const Peer_Path& alternate = Access::path(stack, key, ALTERNATE);
    check(alternate.ssthresh == std::max(initial_cwnd(DEFAULT_PMDCS) / 2, 4U * DEFAULT_PMDCS),
          "the alternate, where the lost chunk went, adjusts ssthresh");
    check(Access::path(stack, key, PRIMARY).ssthresh == primary_ssthresh, "the primary does not");
    check(goes_to(Access::transmit(stack), ALTERNATE), "the chunk is resent to the address it was first sent to");
}

void test_failover_reaches_the_peer_through_inactive_primary() {
    std::printf("Primary failure end to end (8.2, 6.4.1):\n");

    SCTP_Socket stack;
    stack.sctp_subscribe(Notification_Type::SCTP_PEER_ADDR_CHANGE, true);
    Association_Key key{PRIMARY};
    Access::establish(stack, key);
    stack.sctp_send_data(key, MESSAGE);
    Access::transmit(stack);

    for (int i = 0; i <= sctp_parameters::PATH_MAX_RETRANS; ++i) {
        Access::sent_to(stack, key, PRIMARY);
        Access::fire_t3(stack, key, PRIMARY);
    }
    check(!Access::path(stack, key, PRIMARY).active, "the primary is marked inactive past Path.Max.Retrans");
    bool reported = false;
    while (auto notification = stack.sctp_recv_notification()) {
        const auto* change = std::get_if<Peer_Addr_Change>(&notification->payload);
        reported = reported || (change && change->state == Peer_Addr_State::ADDR_UNREACHABLE
                                && same_transport_address(change->address, PRIMARY));
    }
    check(reported, "and reported");
    check(&data_path(Access::tcb(stack, key)) == &Access::path(stack, key, ALTERNATE), "the alternate now carries DATA");
}

} // namespace

int main() {
    std::printf("Failover tests (RFC 9260 6.4, 7.2, 8.2)\n\n");

    test_new_data_follows_the_data_path();
    test_unconfirmed_alternate_is_not_used();
    test_t3_moves_timed_out_data_to_an_alternate();
    test_t3_on_the_alternate_goes_back_to_the_primary();
    test_cwnd_is_per_destination();
    test_rtt_is_measured_per_destination();
    test_fast_retransmit_stays_on_its_path();
    test_failover_reaches_the_peer_through_inactive_primary();

    if (failures == 0) {
        std::printf("\nALL TESTS PASSED (0 failures)\n");
        return 0;
    }
    std::printf("\n%d CHECK(S) FAILED\n", failures);
    return 1;
}
