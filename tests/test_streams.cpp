// Streams and ordering (RFC 9260 6.5, 6.6): stream choice and SSN assignment on
// send, ordered delivery within a stream and independence between streams on
// receive, unordered delivery, and the two end to end.

#include "builders.hpp"
#include "serialize.hpp"
#include <sctp/platform.hpp>
#include <sctp/socket.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <map>
#include <string>
#include <thread>
#include <vector>

static int failures = 0;

static void check(bool condition, const std::string& description) {
    std::printf("  [%s] %s\n", condition ? "PASS" : "FAIL", description.c_str());
    if (!condition) {
        ++failures;
    }
}

constexpr uint32_t PMDCS = 1200;
constexpr size_t FRAGMENT_SIZE = PMDCS - DATA_CHUNK_HEADER_SIZE;
constexpr uint32_t OUR_TAG = 0x0A0B0C0D;
constexpr uint32_t PEER_TAG = 0x10203040;
constexpr uint16_t LOCAL_PORT = 9897;
constexpr uint16_t PEER_PORT = 19005;
constexpr uint32_t PEER_TSN = 5000;
constexpr uint32_t INITIAL_TSN = 100;

static sockaddr_in peer_address() {
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(PEER_PORT);
    sctp_parse_ipv4("127.0.0.1", peer.sin_addr);
    return peer;
}

struct Received {
    std::string bytes;
    uint16_t stream;
};

struct SCTP_Socket_Test_Access {
    // An association that has received everything up to PEER_TSN - 1, with
    // three outbound and four inbound streams.
    static Association_Key add_association(SCTP_Socket& stack) {
        stack.local_address.sin_family = AF_INET;
        stack.local_address.sin_port = htons(LOCAL_PORT);
        sctp_parse_ipv4("127.0.0.1", stack.local_address.sin_addr);
        Association_Key key{peer_address()};
        Association association = stack.init_new_association(key);
        association.state = ESTABLISHED;
        association.this_ver_tag = OUR_TAG;
        association.peer_ver_tag = PEER_TAG;
        association.next_tsn = INITIAL_TSN;
        association.cumulative_tsn_ack = INITIAL_TSN - 1;
        association.last_peer_tsn = PEER_TSN - 1;
        association.out_streams = 3;
        association.next_ssn.assign(3, 0);
        association.in_streams = 4;
        association.pmdcs = PMDCS;
        association.peer_rwnd = 65535;
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        association.primary_path = key.address;
        stack.associations.insert_or_assign(key, association);
        return key;
    }

    static void deliver(SCTP_Socket& stack, uint32_t tsn, uint16_t stream, uint16_t ssn, std::string bytes,
                        uint8_t flags = DATA_FLAG_B | DATA_FLAG_E) {
        data_chunk_value data{PEER_TSN + tsn, stream, ssn, 0, std::vector<uint8_t>(bytes.begin(), bytes.end())};
        data.flags = flags;
        std::vector<uint8_t> wire = serialize_sctp_packet(build_data(PEER_PORT, LOCAL_PORT, OUR_TAG, {data}));
        stack.handle_recv_packet(wire.data(), wire.size(), peer_address());
    }

    // Every packet the stack would send with its windows wide open.
    static std::vector<SCTP_Packet> drain(SCTP_Socket& stack) {
        std::vector<SCTP_Packet> packets;
        for (;;) {
            Send_Allowances open;
            {
                std::lock_guard<std::mutex> lock(stack.associations_mutex);
                for (const auto& entry : stack.associations) {
                    open.emplace(entry.first, Send_Allowance{0, true, false, UINT32_MAX, false});
                }
            }
            stack.refill_new_data(open);
            auto pending = stack.sends.peek(std::chrono::steady_clock::now());
            if (!pending) {
                return packets;
            }
            packets.push_back(pending->deliverable.packet);
            stack.sends.commit(*pending);
        }
    }

    static bool has_association(SCTP_Socket& stack, const Association_Key& key) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        return stack.associations.count(key) != 0;
    }

    static Association tcb(SCTP_Socket& stack, const Association_Key& key) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        return stack.associations.at(key);
    }

    static void set_state(SCTP_Socket& stack, const Association_Key& key, Association_State state) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        stack.associations.at(key).state = state;
    }

    static void set_next_inbound_ssn(SCTP_Socket& stack, const Association_Key& key, uint16_t stream, uint16_t ssn) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        stack.associations.at(key).inbound_streams[stream].next_ssn = ssn;
    }

    static void do_next_shutdown_step(SCTP_Socket& stack, const Association_Key& key) {
        stack.do_next_shutdown_step(key);
    }
};

using Access = SCTP_Socket_Test_Access;

static std::vector<Received> read_all(SCTP_Socket& stack, const Association_Key& key) {
    std::vector<Received> received;
    std::vector<uint8_t> buffer(70000);
    bool partial = false;
    uint16_t stream = 0;
    std::string pending;
    while (size_t n = stack.sctp_recv_data_from(key, buffer, &partial, &stream)) {
        pending.append(buffer.begin(), buffer.begin() + static_cast<long>(n));
        if (!partial) {
            received.push_back(Received{pending, stream});
            pending.clear();
        }
    }
    return received;
}

static std::vector<std::string> bytes_of(const std::vector<Received>& received) {
    std::vector<std::string> out;
    for (const auto& message : received) {
        out.push_back(message.bytes);
    }
    return out;
}

static std::vector<data_chunk_value> data_chunks(const std::vector<SCTP_Packet>& packets) {
    std::vector<data_chunk_value> chunks;
    for (const auto& packet : packets) {
        for (const auto& chunk : packet.chunks) {
            if (chunk.chunk_header.type == DATA) {
                chunks.push_back(std::get<data_chunk_value>(chunk.chunk_value));
            }
        }
    }
    return chunks;
}

static bool abort_sent(const std::vector<SCTP_Packet>& packets, uint16_t cause) {
    return std::any_of(packets.begin(), packets.end(), [&](const SCTP_Packet& packet) {
        return !packet.chunks.empty() && packet.chunks[0].chunk_header.type == ABORT
            && std::get<error_chunk_value>(packet.chunks[0].chunk_value).causes.at(0).code == cause;
    });
}

static void test_send_streams() {
    std::printf("Sending on a chosen stream:\n");
    SCTP_Socket stack;
    Association_Key key = Access::add_association(stack);

    stack.sctp_send_data(key, {'a'}, 0);
    stack.sctp_send_data(key, {'b'}, 2);
    stack.sctp_send_data(key, {'c'}, 2);
    stack.sctp_send_data(key, {'d'}, 0);
    auto chunks = data_chunks(Access::drain(stack));
    check(chunks.size() == 4, "every message is sent");
    if (chunks.size() == 4) {
        check(chunks[0].stream_identifier == 0 && chunks[1].stream_identifier == 2
                  && chunks[2].stream_identifier == 2 && chunks[3].stream_identifier == 0,
              "each chunk carries its message's stream");
        check(chunks[0].stream_seq_num == 0 && chunks[1].stream_seq_num == 0
                  && chunks[2].stream_seq_num == 1 && chunks[3].stream_seq_num == 1,
              "each stream numbers its own messages from 0");
    }

    stack.sctp_send_data(key, {'x'}, 3);
    check(Access::drain(stack).empty() && Access::tcb(stack, key).outbound.empty(),
          "a stream past the negotiated outbound count is refused");
}

static void test_send_unordered() {
    std::printf("Sending unordered:\n");
    SCTP_Socket stack;
    Association_Key key = Access::add_association(stack);

    stack.sctp_send_data(key, {'o'}, 1);
    stack.sctp_send_data(key, std::vector<uint8_t>(2 * FRAGMENT_SIZE + 1, 'u'), 1, true);
    stack.sctp_send_data(key, {'o'}, 1);
    auto chunks = data_chunks(Access::drain(stack));
    check(chunks.size() == 5, "the unordered message is fragmented like any other");
    if (chunks.size() == 5) {
        bool all_unordered = true;
        for (size_t i = 1; i <= 3; ++i) {
            all_unordered = all_unordered && (chunks[i].flags & DATA_FLAG_U) != 0;
        }
        check(all_unordered && (chunks[0].flags & DATA_FLAG_U) == 0 && (chunks[4].flags & DATA_FLAG_U) == 0,
              "U is set on every fragment of the unordered message, and only there");
        check(chunks[1].flags == (DATA_FLAG_U | DATA_FLAG_B) && chunks[3].flags == (DATA_FLAG_U | DATA_FLAG_E),
              "alongside the usual B and E");
        check(chunks[0].stream_seq_num == 0 && chunks[4].stream_seq_num == 1,
              "it takes no SSN from the ordered messages around it");
    }
}

static void test_ordered_within_a_stream() {
    std::printf("Ordered delivery within a stream (6.6):\n");
    SCTP_Socket stack;
    Association_Key key = Access::add_association(stack);

    Access::deliver(stack, 1, 0, 1, "second");
    Access::deliver(stack, 2, 0, 2, "third");
    check(read_all(stack, key).empty(), "messages after a gap in their stream are held");
    Access::deliver(stack, 0, 0, 0, "first");
    check(bytes_of(read_all(stack, key)) == std::vector<std::string>{"first", "second", "third"},
          "filling the gap releases them in SSN order");
}

static void test_streams_are_independent() {
    std::printf("A gap holds back only its own stream:\n");
    SCTP_Socket stack;
    Association_Key key = Access::add_association(stack);

    Access::deliver(stack, 1, 1, 0, "stream 1, first");
    Access::deliver(stack, 2, 0, 1, "stream 0, second");
    Access::deliver(stack, 3, 1, 1, "stream 1, second");
    auto early = read_all(stack, key);
    check(bytes_of(early) == std::vector<std::string>{"stream 1, first", "stream 1, second"},
          "stream 1 is delivered though TSN +0 is missing");
    check(early.size() == 2 && early[0].stream == 1 && early[1].stream == 1, "and reported as stream 1");
    check(Access::tcb(stack, key).last_peer_tsn == PEER_TSN - 1, "the Cumulative TSN Ack has not moved");

    Access::deliver(stack, 0, 0, 0, "stream 0, first");
    auto late = read_all(stack, key);
    check(bytes_of(late) == std::vector<std::string>{"stream 0, first", "stream 0, second"},
          "stream 0 follows once its gap is filled");
    check(late.size() == 2 && late[0].stream == 0, "reported as stream 0");
    check(Access::tcb(stack, key).last_peer_tsn == PEER_TSN + 3, "and every TSN is acknowledged");
}

static void test_fragmented_message_above_a_gap() {
    std::printf("A fragmented message wholly above a gap:\n");
    SCTP_Socket stack;
    Association_Key key = Access::add_association(stack);

    Access::deliver(stack, 1, 1, 0, "ab", DATA_FLAG_B);
    Access::deliver(stack, 3, 1, 0, "ef", DATA_FLAG_E);
    check(read_all(stack, key).empty(), "is held while a fragment is missing");
    Access::deliver(stack, 2, 1, 0, "cd", 0);
    check(bytes_of(read_all(stack, key)) == std::vector<std::string>{"abcdef"},
          "is delivered when its last fragment arrives, the gap below it notwithstanding");

    Access::deliver(stack, 0, 0, 0, "zero");
    check(bytes_of(read_all(stack, key)) == std::vector<std::string>{"zero"},
          "and is not delivered again when the Cumulative TSN Ack passes it");
    check(Access::has_association(stack, key) && Access::tcb(stack, key).last_peer_tsn == PEER_TSN + 3,
          "its fragments still pass the framing checks");
}

static void test_unordered_delivery() {
    std::printf("Unordered delivery:\n");
    SCTP_Socket stack;
    Association_Key key = Access::add_association(stack);

    Access::deliver(stack, 2, 0, 1, "ordered");
    Access::deliver(stack, 1, 0, 0, "unordered", DATA_FLAG_U | DATA_FLAG_B | DATA_FLAG_E);
    check(bytes_of(read_all(stack, key)) == std::vector<std::string>{"unordered"},
          "an unordered message is delivered as soon as it arrives, gap or not");

    Access::deliver(stack, 0, 0, 0, "first");
    check(bytes_of(read_all(stack, key)) == std::vector<std::string>{"first", "ordered"},
          "it took no SSN, so the ordered messages are released by SSN 0 and 1");

    Access::deliver(stack, 4, 2, 0, "v", DATA_FLAG_U | DATA_FLAG_E);
    Access::deliver(stack, 3, 2, 9, "u", DATA_FLAG_U | DATA_FLAG_B);
    check(bytes_of(read_all(stack, key)) == std::vector<std::string>{"uv"},
          "a fragmented unordered message is reassembled first, whatever its SSN field");
}

static void test_ssn_wraps() {
    std::printf("SSN wrap on receive:\n");
    SCTP_Socket stack;
    Association_Key key = Access::add_association(stack);
    Access::set_next_inbound_ssn(stack, key, 0, 65535);

    Access::deliver(stack, 1, 0, 0, "after");
    check(read_all(stack, key).empty(), "SSN 0 is held behind 65535");
    Access::deliver(stack, 0, 0, 65535, "before");
    check(bytes_of(read_all(stack, key)) == std::vector<std::string>{"before", "after"},
          "65535 is followed by 0");
}

static void test_reused_ssn() {
    std::printf("A reused SSN aborts the association:\n");
    struct Case {
        const char* name;
        uint16_t first_ssn;
        uint16_t second_ssn;
        uint32_t second_tsn;
    };
    std::vector<Case> cases{
        {"an SSN already delivered", 0, 0, 1},
        {"an SSN already waiting", 1, 1, 2},
    };
    for (const auto& c : cases) {
        SCTP_Socket stack;
        Association_Key key = Access::add_association(stack);
        Access::deliver(stack, c.first_ssn == 0 ? 0 : 1, 0, c.first_ssn, "x");
        read_all(stack, key);
        Access::deliver(stack, c.second_tsn, 0, c.second_ssn, "x");
        check(!Access::has_association(stack, key) && abort_sent(Access::drain(stack), CAUSE_PROTOCOL_VIOLATION),
              std::string(c.name) + ": ABORT with Protocol Violation");
    }
}

static void test_partial_delivery_holds_other_messages() {
    std::printf("Messages completed during a partial delivery:\n");
    SCTP_Socket stack;
    Association_Key key = Access::add_association(stack);
    constexpr uint32_t FILLING = (RWND - PMDCS) / FRAGMENT_SIZE + 1;
    std::string fragment(FRAGMENT_SIZE, 'p');

    for (uint32_t i = 0; i < FILLING; ++i) {
        Access::deliver(stack, i, 0, 0, fragment, i == 0 ? DATA_FLAG_B : 0);
    }
    std::vector<uint8_t> buffer(RWND);
    bool partial = false;
    size_t first = stack.sctp_recv_data_from(key, buffer, &partial);
    check(first == FILLING * FRAGMENT_SIZE && partial, "a partial delivery is under way");

    Access::deliver(stack, FILLING + 1, 1, 0, "other stream");
    Access::deliver(stack, FILLING + 2, 2, 0, "unordered", DATA_FLAG_U | DATA_FLAG_B | DATA_FLAG_E);
    check(stack.sctp_recv_data_from(key, buffer, &partial) == 0,
          "complete messages are held rather than mixed into the partial one");

    Access::deliver(stack, FILLING, 0, 0, "end", DATA_FLAG_E);
    auto rest = read_all(stack, key);
    check(rest.size() == 3 && rest[0].bytes == "end" && rest[0].stream == 0,
          "the end of the partial message comes first");
    check(rest.size() == 3 && rest[1].bytes == "other stream" && rest[2].bytes == "unordered",
          "then the held messages, in the order they completed");
}

static void test_bundling() {
    std::printf("Bundling new DATA (6.10):\n");
    SCTP_Socket stack;
    Association_Key key = Access::add_association(stack);

    for (int i = 0; i < 5; ++i) {
        stack.sctp_send_data(key, std::vector<uint8_t>(100, static_cast<uint8_t>('a' + i)), static_cast<uint16_t>(i % 3));
    }
    auto packets = Access::drain(stack);
    check(packets.size() == 1 && packets[0].chunks.size() == 5, "small messages share one packet");
    auto chunks = data_chunks(packets);
    bool consecutive = chunks.size() == 5;
    for (size_t i = 0; consecutive && i < chunks.size(); ++i) {
        consecutive = chunks[i].tsn == INITIAL_TSN + i && chunks[i].user_data[0] == 'a' + i;
    }
    check(consecutive, "in the order they were sent, with consecutive TSNs");

    stack.sctp_send_data(key, std::vector<uint8_t>(700, 'x'));
    stack.sctp_send_data(key, std::vector<uint8_t>(700, 'y'));
    packets = Access::drain(stack);
    check(packets.size() == 2 && packets[0].chunks.size() == 1 && packets[1].chunks.size() == 1,
          "a message that fits a packet of its own is not fragmented to fill another");
    check(data_chunks(packets).size() == 2 && data_chunks(packets)[1].flags == (DATA_FLAG_B | DATA_FLAG_E), "and goes whole");

    stack.sctp_send_data(key, std::vector<uint8_t>(FRAGMENT_SIZE + 10, 'f'));
    stack.sctp_send_data(key, std::vector<uint8_t>(10, 's'));
    packets = Access::drain(stack);
    check(packets.size() == 2 && packets[1].chunks.size() == 2, "a message's last fragment is bundled with the next message");
    bool fits = true;
    for (const auto& packet : packets) {
        fits = fits && serialize_sctp_packet(packet).size() <= SCTP_COMMON_HEADER_SIZE + PMDCS;
    }
    check(fits, "no packet exceeds the PMDCS");
}

static void test_shutdown_waits_for_queued_messages() {
    std::printf("SHUTDOWN waits for messages not yet sent (9.2):\n");
    SCTP_Socket stack;
    Association_Key key = Access::add_association(stack);
    stack.sctp_send_data(key, {'q'});
    Access::set_state(stack, key, SHUTDOWN_PENDING);
    Access::do_next_shutdown_step(stack, key);
    check(Access::tcb(stack, key).state == SHUTDOWN_PENDING, "nothing is outstanding, but a message is still queued");
    auto chunks = data_chunks(Access::drain(stack));
    check(chunks.size() == 1, "the queued message is still sent in SHUTDOWN-PENDING");
}

static void test_end_to_end() {
    std::printf("Streams between two stacks:\n");
    SCTP_Socket a, b;
    constexpr int A_PORT = 39130, B_PORT = 39131;
    bool started = a.sctp_bind("127.0.0.1", A_PORT) && a.sctp_run() && b.sctp_bind("127.0.0.1", B_PORT) && b.sctp_run();
    Association_Key a_to_b = a.sctp_associate("127.0.0.1", B_PORT);
    Association_Key b_to_a = a.get_this_association_key();
    bool established = started && a.await_established_association(a_to_b, 3000) == 0
        && b.await_established_association(b_to_a, 3000) == 0;
    check(established, "association established");
    if (!established) {
        return;
    }

    constexpr int MESSAGES = 30;
    for (int i = 0; i < MESSAGES; ++i) {
        std::string text = std::to_string(i);
        a.sctp_send_data(a_to_b, std::vector<uint8_t>(text.begin(), text.end()), static_cast<uint16_t>(i % 10));
    }
    a.sctp_send_data(a_to_b, std::vector<uint8_t>(3000, 'u'), 4, true);

    std::map<uint16_t, std::vector<int>> by_stream;
    bool unordered_arrived = false;
    std::vector<uint8_t> buffer(4096);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    int received = 0;
    while (received < MESSAGES + 1 && std::chrono::steady_clock::now() < deadline) {
        bool partial = false;
        uint16_t stream = 0;
        size_t n = b.sctp_recv_data_from(b_to_a, buffer, &partial, &stream);
        if (n == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        ++received;
        if (n == 3000) {
            unordered_arrived = stream == 4;
            continue;
        }
        by_stream[stream].push_back(std::stoi(std::string(buffer.begin(), buffer.begin() + static_cast<long>(n))));
    }
    bool ordered = by_stream.size() == 10;
    for (const auto& [stream, values] : by_stream) {
        for (size_t i = 0; i < values.size(); ++i) {
            ordered = ordered && values[i] == static_cast<int>(stream + 10 * i);
        }
    }
    check(ordered, "every stream's messages arrive on it, in order");
    check(unordered_arrived, "the fragmented unordered message arrives whole, on its stream");
    a.sctp_close(0);
    b.sctp_close(0);
}

int main() {
    test_send_streams();
    std::printf("\n");
    test_send_unordered();
    std::printf("\n");
    test_ordered_within_a_stream();
    std::printf("\n");
    test_streams_are_independent();
    std::printf("\n");
    test_fragmented_message_above_a_gap();
    std::printf("\n");
    test_unordered_delivery();
    std::printf("\n");
    test_ssn_wraps();
    std::printf("\n");
    test_reused_ssn();
    std::printf("\n");
    test_partial_delivery_holds_other_messages();
    std::printf("\n");
    test_bundling();
    std::printf("\n");
    test_shutdown_waits_for_queued_messages();
    std::printf("\n");
    test_end_to_end();

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
