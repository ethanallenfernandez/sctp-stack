// Fragmentation and reassembly of user messages (RFC 9260 6.9): splitting on
// send, reassembly and partial delivery on receive, and the two end to end.

#include "builders.hpp"
#include "serialize.hpp"
#include <sctp/platform.hpp>
#include <sctp/socket.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
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
constexpr uint32_t INITIAL_TSN = 0xFFFFFFFE;
constexpr uint32_t OUR_TAG = 0x0A0B0C0D;
constexpr uint16_t LOCAL_PORT = 9898;
constexpr uint16_t PEER_PORT = 19004;
constexpr uint32_t PEER_TSN = 5000;

static sockaddr_in peer_address() {
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(PEER_PORT);
    sctp_parse_ipv4("127.0.0.1", peer.sin_addr);
    return peer;
}

struct SCTP_Socket_Test_Access {
    static Association_Key add_established_association(SCTP_Socket& stack) {
        sockaddr_in peer{};
        peer.sin_family = AF_INET;
        peer.sin_port = htons(19003);
        sctp_parse_ipv4("127.0.0.1", peer.sin_addr);
        Association_Key key{peer};

        Association association = stack.init_new_association(key);
        association.state = ESTABLISHED;
        association.peer_ver_tag = 0x10203040;
        association.next_tsn = INITIAL_TSN;
        association.pmdcs = PMDCS;
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        stack.associations.insert_or_assign(key, association);
        return key;
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

    // An association that has received everything up to PEER_TSN - 1.
    static Association_Key add_receiving_association(SCTP_Socket& stack) {
        stack.local_address.sin_family = AF_INET;
        stack.local_address.sin_port = htons(LOCAL_PORT);
        sctp_parse_ipv4("127.0.0.1", stack.local_address.sin_addr);
        Association_Key key{peer_address()};
        Association association = stack.init_new_association(key);
        association.state = ESTABLISHED;
        association.this_ver_tag = OUR_TAG;
        association.peer_ver_tag = 0x10203040;
        association.last_peer_tsn = PEER_TSN - 1;
        association.in_streams = 4;
        association.pmdcs = PMDCS;
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        stack.associations.insert_or_assign(key, association);
        return key;
    }

    static void deliver(SCTP_Socket& stack, uint32_t tsn, uint8_t flags, std::vector<uint8_t> bytes,
                        uint16_t ssn = 0, uint16_t stream = 0) {
        data_chunk_value data{tsn, stream, ssn, 0, std::move(bytes)};
        data.flags = flags;
        std::vector<uint8_t> wire = serialize_sctp_packet(build_data(PEER_PORT, LOCAL_PORT, OUR_TAG, {data}));
        stack.handle_recv_packet(wire.data(), wire.size(), peer_address());
    }

    static bool has_association(SCTP_Socket& stack, const Association_Key& key) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        return stack.associations.count(key) != 0;
    }

    static uint32_t last_peer_tsn(SCTP_Socket& stack, const Association_Key& key) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        return stack.associations.at(key).last_peer_tsn;
    }

    static uint32_t next_tsn(SCTP_Socket& stack, const Association_Key& key) {
        std::lock_guard<std::mutex> lock(stack.associations_mutex);
        return stack.associations.at(key).next_tsn;
    }
};

static std::vector<data_chunk_value> data_chunks(const std::vector<SCTP_Packet>& packets) {
    std::vector<data_chunk_value> chunks;
    for (const auto& packet : packets) {
        for (const auto& chunk : packet.chunks) {
            chunks.push_back(std::get<data_chunk_value>(chunk.chunk_value));
        }
    }
    return chunks;
}

static std::vector<uint8_t> message(size_t size) {
    std::vector<uint8_t> bytes(size);
    for (size_t i = 0; i < size; ++i) {
        bytes[i] = static_cast<uint8_t>(i * 7 + 3);
    }
    return bytes;
}

static void test_boundary_sizes() {
    std::printf("Fragment boundary:\n");
    SCTP_Socket stack;
    Association_Key key = SCTP_Socket_Test_Access::add_established_association(stack);

    stack.sctp_send_data(key, message(FRAGMENT_SIZE));
    auto chunks = data_chunks(SCTP_Socket_Test_Access::drain(stack));
    check(chunks.size() == 1 && chunks[0].flags == (DATA_FLAG_B | DATA_FLAG_E),
          "a message of exactly PMDCS minus the DATA header is sent whole");

    stack.sctp_send_data(key, message(FRAGMENT_SIZE + 1));
    chunks = data_chunks(SCTP_Socket_Test_Access::drain(stack));
    check(chunks.size() == 2, "one byte more is split in two");
    check(chunks.size() == 2 && chunks[0].flags == DATA_FLAG_B && chunks[1].flags == DATA_FLAG_E,
          "B/E = 10 then 01");
    check(chunks.size() == 2 && chunks[0].user_data.size() == FRAGMENT_SIZE && chunks[1].user_data.size() == 1,
          "the first fragment is full, the last carries the remainder");
}

static void test_fragment_series() {
    std::printf("Fragment series (6.9 steps 1-3):\n");
    SCTP_Socket stack;
    Association_Key key = SCTP_Socket_Test_Access::add_established_association(stack);

    std::vector<uint8_t> sent = message(3 * FRAGMENT_SIZE + 100);
    stack.sctp_send_data(key, sent);
    std::vector<SCTP_Packet> packets = SCTP_Socket_Test_Access::drain(stack);
    auto chunks = data_chunks(packets);

    check(chunks.size() == 4 && packets.size() == 4, "four fragments, one per packet");
    bool fits = true;
    for (const auto& packet : packets) {
        fits = fits && serialize_sctp_packet(packet).size() <= SCTP_COMMON_HEADER_SIZE + PMDCS;
    }
    check(fits, "every packet fits within the PMDCS");

    bool consecutive = true, same_ssn = true, same_sid = true;
    std::vector<uint8_t> joined;
    for (size_t i = 0; i < chunks.size(); ++i) {
        consecutive = consecutive && chunks[i].tsn == static_cast<uint32_t>(INITIAL_TSN + i);
        same_ssn = same_ssn && chunks[i].stream_seq_num == chunks[0].stream_seq_num;
        same_sid = same_sid && chunks[i].stream_identifier == chunks[0].stream_identifier;
        joined.insert(joined.end(), chunks[i].user_data.begin(), chunks[i].user_data.end());
    }
    check(consecutive, "TSNs are assigned in sequence, across the 2^32 wrap");
    check(same_ssn && same_sid, "every fragment carries the same SID and SSN");
    check(chunks.size() == 4 && chunks[0].flags == DATA_FLAG_B && chunks[1].flags == 0
              && chunks[2].flags == 0 && chunks[3].flags == DATA_FLAG_E,
          "B/E = 10, 00, 00, 01");
    check(joined == sent, "the fragments rejoin to the original message");
    check(packets.size() == 4 && packets[0].chunks[0].chunk_header.flag == DATA_FLAG_B
              && packets[3].chunks[0].chunk_header.flag == DATA_FLAG_E,
          "the flags reach the chunk headers");

    stack.sctp_send_data(key, message(10));
    chunks = data_chunks(SCTP_Socket_Test_Access::drain(stack));
    check(chunks.size() == 1 && chunks[0].stream_seq_num == 1, "the next message takes the next SSN");
}

static void test_empty_message() {
    std::printf("Empty message:\n");
    SCTP_Socket stack;
    Association_Key key = SCTP_Socket_Test_Access::add_established_association(stack);

    stack.sctp_send_data(key, {});
    check(SCTP_Socket_Test_Access::drain(stack).empty(), "nothing is queued");
    check(SCTP_Socket_Test_Access::next_tsn(stack, key) == INITIAL_TSN, "no TSN is consumed");
}

static void test_concurrent_senders() {
    std::printf("Concurrent senders:\n");
    SCTP_Socket stack;
    Association_Key key = SCTP_Socket_Test_Access::add_established_association(stack);

    constexpr int MESSAGES = 50;
    auto sender = [&](uint8_t fill) {
        for (int i = 0; i < MESSAGES; ++i) {
            stack.sctp_send_data(key, std::vector<uint8_t>(2 * FRAGMENT_SIZE + 1, fill));
        }
    };
    std::thread a(sender, 'a');
    std::thread b(sender, 'b');
    a.join();
    b.join();

    auto chunks = data_chunks(SCTP_Socket_Test_Access::drain(stack));
    check(chunks.size() == 2 * MESSAGES * 3, "every fragment was queued");
    bool in_tsn_order = true, whole_messages = true;
    for (size_t i = 0; i < chunks.size(); ++i) {
        in_tsn_order = in_tsn_order && chunks[i].tsn == static_cast<uint32_t>(INITIAL_TSN + i);
        const auto& first = chunks[i - i % 3];
        uint8_t expected = i % 3 == 0 ? DATA_FLAG_B : i % 3 == 2 ? DATA_FLAG_E : 0;
        whole_messages = whole_messages && chunks[i].flags == expected
            && chunks[i].user_data[0] == first.user_data[0]
            && chunks[i].stream_seq_num == first.stream_seq_num;
    }
    check(in_tsn_order, "the queue holds DATA in TSN order");
    check(whole_messages, "no message's fragments are interleaved with another's");
}

// Reads whatever is queued for `key`; `partial` reports the last read.
static std::vector<uint8_t> read_available(SCTP_Socket& stack, const Association_Key& key, bool& partial) {
    std::vector<uint8_t> received, buffer(4096);
    while (size_t n = stack.sctp_recv_data_from(key, buffer, &partial)) {
        received.insert(received.end(), buffer.begin(), buffer.begin() + static_cast<long>(n));
        if (!partial) {
            break;
        }
    }
    return received;
}

static bool abort_sent(const std::vector<SCTP_Packet>& packets, uint16_t cause) {
    return std::any_of(packets.begin(), packets.end(), [&](const SCTP_Packet& packet) {
        return !packet.chunks.empty() && packet.chunks[0].chunk_header.type == ABORT
            && std::get<error_chunk_value>(packet.chunks[0].chunk_value).causes.at(0).code == cause;
    });
}

static void test_reassembly_in_order() {
    std::printf("Reassembly in TSN order:\n");
    SCTP_Socket stack;
    Association_Key key = SCTP_Socket_Test_Access::add_receiving_association(stack);
    bool partial = false;

    SCTP_Socket_Test_Access::deliver(stack, PEER_TSN, DATA_FLAG_B, {'a', 'b'});
    SCTP_Socket_Test_Access::deliver(stack, PEER_TSN + 1, 0, {'c'});
    check(read_available(stack, key, partial).empty(), "nothing is delivered before the last fragment");
    SCTP_Socket_Test_Access::deliver(stack, PEER_TSN + 2, DATA_FLAG_E, {'d'});
    std::vector<uint8_t> got = read_available(stack, key, partial);
    check(got == std::vector<uint8_t>{'a', 'b', 'c', 'd'} && !partial, "the whole message is delivered once, complete");
    SCTP_Socket_Test_Access::deliver(stack, PEER_TSN + 3, DATA_FLAG_B | DATA_FLAG_E, {'e'}, 1);
    check(read_available(stack, key, partial) == std::vector<uint8_t>{'e'}, "an unfragmented message after it stands alone");
}

static void test_reassembly_out_of_order() {
    std::printf("Reassembly across reordering and loss:\n");
    SCTP_Socket stack;
    Association_Key key = SCTP_Socket_Test_Access::add_receiving_association(stack);
    bool partial = false;

    SCTP_Socket_Test_Access::deliver(stack, PEER_TSN + 2, DATA_FLAG_E, {'3'});
    SCTP_Socket_Test_Access::deliver(stack, PEER_TSN, DATA_FLAG_B, {'1'});
    check(read_available(stack, key, partial).empty(), "last and first fragments alone deliver nothing");
    SCTP_Socket_Test_Access::deliver(stack, PEER_TSN + 1, 0, {'2'});
    check(read_available(stack, key, partial) == std::vector<uint8_t>{'1', '2', '3'},
          "the missing middle fragment completes the message");
    check(SCTP_Socket_Test_Access::last_peer_tsn(stack, key) == PEER_TSN + 2, "every fragment is cumulatively acked");
}

static void test_window_counts_reassembly() {
    std::printf("a_rwnd while a message is incomplete:\n");
    SCTP_Socket stack;
    Association_Key key = SCTP_Socket_Test_Access::add_receiving_association(stack);

    SCTP_Socket_Test_Access::deliver(stack, PEER_TSN, DATA_FLAG_B, std::vector<uint8_t>(1000, 'x'));
    SCTP_Socket_Test_Access::deliver(stack, PEER_TSN + 1, 0, std::vector<uint8_t>(500, 'x'));
    uint32_t a_rwnd = 0;
    for (const auto& packet : SCTP_Socket_Test_Access::drain(stack)) {
        if (packet.chunks[0].chunk_header.type == SACK) {
            a_rwnd = std::get<sack_chunk_value>(packet.chunks[0].chunk_value).a_rwnd;
        }
    }
    check(a_rwnd == RWND - 1500, "bytes held for reassembly are taken off the window");
    (void)key;
}

static void test_partial_delivery() {
    std::printf("Partial delivery of a message larger than the receive buffer:\n");
    SCTP_Socket stack;
    Association_Key key = SCTP_Socket_Test_Access::add_receiving_association(stack);
    constexpr uint32_t FRAGMENTS = 100;
    constexpr uint32_t FILLING = (RWND - PMDCS) / FRAGMENT_SIZE + 1;
    std::vector<uint8_t> sent = message(FRAGMENTS * FRAGMENT_SIZE);
    auto fragment = [&](uint32_t i) {
        uint8_t flags = static_cast<uint8_t>((i == 0 ? DATA_FLAG_B : 0) | (i == FRAGMENTS - 1 ? DATA_FLAG_E : 0));
        auto begin = sent.begin() + static_cast<long>(i * FRAGMENT_SIZE);
        SCTP_Socket_Test_Access::deliver(stack, PEER_TSN + i, flags, std::vector<uint8_t>(begin, begin + FRAGMENT_SIZE));
    };

    bool partial = false;
    for (uint32_t i = 0; i + 1 < FILLING; ++i) {
        fragment(i);
    }
    check(read_available(stack, key, partial).empty(), "held while the window can take more");
    fragment(FILLING - 1);
    std::vector<uint8_t> got = read_available(stack, key, partial);
    check(got.size() == FILLING * FRAGMENT_SIZE && partial,
          "once it cannot, what has arrived is handed up marked partial");

    bool each_partial = true;
    for (uint32_t i = FILLING; i < FRAGMENTS; ++i) {
        fragment(i);
        std::vector<uint8_t> more = read_available(stack, key, partial);
        each_partial = each_partial && more.size() == FRAGMENT_SIZE && partial == (i + 1 < FRAGMENTS);
        got.insert(got.end(), more.begin(), more.end());
    }
    check(each_partial, "later fragments follow as they arrive, the last one ending the message");
    check(got == sent, "the pieces rejoin to the original message");
    check(SCTP_Socket_Test_Access::last_peer_tsn(stack, key) == PEER_TSN + FRAGMENTS - 1, "no fragment was dropped");
}

static void test_short_receive_buffer() {
    std::printf("A receive buffer smaller than the message:\n");
    SCTP_Socket stack;
    Association_Key key = SCTP_Socket_Test_Access::add_receiving_association(stack);
    SCTP_Socket_Test_Access::deliver(stack, PEER_TSN, DATA_FLAG_B | DATA_FLAG_E, {'0', '1', '2', '3', '4'});

    std::vector<uint8_t> buffer(2);
    bool first = false, last = true;
    size_t n1 = stack.sctp_recv_data_from(key, buffer, &first);
    stack.sctp_recv_data_from(key, buffer);
    size_t n3 = stack.sctp_recv_data_from(key, buffer, &last);
    check(n1 == 2 && first, "the first read is marked partial");
    check(n3 == 1 && !last && buffer[0] == '4', "the remainder is not lost, and the last read ends the message");
}

static void test_protocol_violations() {
    std::printf("Fragments out of place abort the association:\n");
    struct Case {
        const char* name;
        std::vector<std::pair<uint8_t, uint16_t>> chunks;   // flags, SSN
    };
    std::vector<Case> cases{
        {"a first fragment while a message is open", {{DATA_FLAG_B, 0}, {DATA_FLAG_B, 0}}},
        {"a middle fragment with no message open", {{0, 0}}},
        {"a last fragment with no message open", {{DATA_FLAG_E, 0}}},
        {"a fragment whose SSN differs from its message's", {{DATA_FLAG_B, 0}, {DATA_FLAG_E, 1}}},
        {"an unordered fragment continuing an ordered message", {{DATA_FLAG_B, 0}, {DATA_FLAG_U | DATA_FLAG_E, 0}}},
    };
    for (const auto& c : cases) {
        SCTP_Socket stack;
        Association_Key key = SCTP_Socket_Test_Access::add_receiving_association(stack);
        for (size_t i = 0; i < c.chunks.size(); ++i) {
            SCTP_Socket_Test_Access::deliver(stack, PEER_TSN + static_cast<uint32_t>(i), c.chunks[i].first, {'x'}, c.chunks[i].second);
        }
        bool partial = false;
        check(!SCTP_Socket_Test_Access::has_association(stack, key)
                  && abort_sent(SCTP_Socket_Test_Access::drain(stack), CAUSE_PROTOCOL_VIOLATION)
                  && read_available(stack, key, partial).empty(),
              std::string(c.name) + ": ABORT with Protocol Violation, nothing delivered");
    }

    SCTP_Socket stack;
    Association_Key key = SCTP_Socket_Test_Access::add_receiving_association(stack);
    SCTP_Socket_Test_Access::deliver(stack, PEER_TSN, DATA_FLAG_U | DATA_FLAG_B, {'u'}, 7);
    SCTP_Socket_Test_Access::deliver(stack, PEER_TSN + 1, DATA_FLAG_U | DATA_FLAG_E, {'v'}, 9);
    bool partial = false;
    check(read_available(stack, key, partial) == std::vector<uint8_t>{'u', 'v'},
          "an unordered message's fragments are not held to one SSN");
}

static void test_invalid_stream_message() {
    std::printf("A fragmented message on an invalid stream:\n");
    SCTP_Socket stack;
    Association_Key key = SCTP_Socket_Test_Access::add_receiving_association(stack);
    SCTP_Socket_Test_Access::deliver(stack, PEER_TSN, DATA_FLAG_B, {'x'}, 0, 5);
    SCTP_Socket_Test_Access::deliver(stack, PEER_TSN + 1, DATA_FLAG_E, {'x'}, 0, 5);
    SCTP_Socket_Test_Access::deliver(stack, PEER_TSN + 2, DATA_FLAG_B | DATA_FLAG_E, {'o', 'k'});
    bool partial = false;
    check(read_available(stack, key, partial) == std::vector<uint8_t>{'o', 'k'},
          "is discarded whole, and the message after it is delivered");
    check(SCTP_Socket_Test_Access::has_association(stack, key)
              && SCTP_Socket_Test_Access::last_peer_tsn(stack, key) == PEER_TSN + 2,
          "its fragments are still acked, without aborting");
}

static void test_end_to_end() {
    std::printf("A 200 kB message between two stacks:\n");
    SCTP_Socket a, b;
    constexpr int A_PORT = 39120, B_PORT = 39121;
    bool started = a.sctp_bind("127.0.0.1", A_PORT) && a.sctp_run() && b.sctp_bind("127.0.0.1", B_PORT) && b.sctp_run();
    Association_Key a_to_b = a.sctp_associate("127.0.0.1", B_PORT);
    Association_Key b_to_a = a.get_this_association_key();
    bool established = started && a.await_established_association(a_to_b, 3000) == 0
        && b.await_established_association(b_to_a, 3000) == 0;
    check(established, "association established");
    if (!established) {
        return;
    }

    std::vector<uint8_t> sent = message(200000);
    a.sctp_send_data(a_to_b, sent);
    a.sctp_send_data(a_to_b, message(10));

    std::vector<uint8_t> got, buffer(4096);
    bool partial = true, saw_partial = false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (partial && std::chrono::steady_clock::now() < deadline) {
        size_t n = b.sctp_recv_data_from(b_to_a, buffer, &partial);
        if (n == 0) {
            partial = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        saw_partial = saw_partial || partial;
        got.insert(got.end(), buffer.begin(), buffer.begin() + static_cast<long>(n));
    }
    check(got == sent, "it arrives intact, one message");
    check(saw_partial, "read in pieces, each but the last marked partial");

    size_t n = 0;
    while (n == 0 && std::chrono::steady_clock::now() < deadline) {
        n = b.sctp_recv_data_from(b_to_a, buffer, &partial);
    }
    check(n == 10 && !partial && std::equal(buffer.begin(), buffer.begin() + 10, message(10).begin()),
          "the message after it arrives separately");
    a.sctp_close(0);
    b.sctp_close(0);
}

int main() {
    test_boundary_sizes();
    std::printf("\n");
    test_fragment_series();
    std::printf("\n");
    test_empty_message();
    std::printf("\n");
    test_concurrent_senders();
    std::printf("\n");
    test_reassembly_in_order();
    std::printf("\n");
    test_reassembly_out_of_order();
    std::printf("\n");
    test_window_counts_reassembly();
    std::printf("\n");
    test_partial_delivery();
    std::printf("\n");
    test_short_receive_buffer();
    std::printf("\n");
    test_protocol_violations();
    std::printf("\n");
    test_invalid_stream_message();
    std::printf("\n");
    test_end_to_end();

    std::printf("\n%s (%d failure%s)\n",
                failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
