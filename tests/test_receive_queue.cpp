// Receive_Queue: per-association delivery that outlives the TCB, byte
// accounting per association.

#include <sctp/receive_queue.hpp>
#include <sctp/platform.hpp>

#include <cstdio>
#include <optional>
#include <utility>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(bool cond, const std::string& what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) failures++;
}

Association_Key key(uint16_t port) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    sctp_parse_ipv4("127.0.0.1", address.sin_addr);
    return Association_Key{address};
}

std::vector<uint8_t> message(char tag, size_t size = 1) {
    return std::vector<uint8_t>(size, static_cast<uint8_t>(tag));
}

// Whole-message reads, for tests that are not about partial ones.
std::optional<std::vector<uint8_t>> pop_from(Receive_Queue& queue, const Association_Key& k) {
    std::vector<uint8_t> buffer(4096);
    auto read = queue.read_from(k, buffer.data(), buffer.size());
    if (!read) return std::nullopt;
    buffer.resize(read->bytes);
    return buffer;
}

std::optional<std::pair<Association_Key, std::vector<uint8_t>>> pop_any(Receive_Queue& queue) {
    std::vector<uint8_t> buffer(4096);
    auto read = queue.read_any(buffer.data(), buffer.size());
    if (!read) return std::nullopt;
    buffer.resize(read->bytes);
    return std::make_pair(read->key, buffer);
}

void test_order_and_accounting() {
    std::printf("Per-association order and accounting:\n");
    Receive_Queue queue;
    Association_Key a = key(1000);
    queue.push(a, message('1', 3));
    queue.push(a, message('2', 5));
    check(queue.buffered_bytes(a) == 8, "two messages, eight bytes buffered");

    auto first = pop_from(queue, a);
    check(first && *first == message('1', 3), "messages come out in delivery order");
    check(queue.buffered_bytes(a) == 5, "bytes are released as they are read");
    pop_from(queue, a);
    check(queue.buffered_bytes(a) == 0 && !pop_from(queue, a), "empty once drained");
    check(!pop_any(queue), "and nothing left for read_any");
}

void test_isolation() {
    std::printf("Associations do not share accounting:\n");
    Receive_Queue queue;
    Association_Key a = key(1000);
    Association_Key b = key(2000);
    queue.push(a, message('a', 100));
    queue.push(b, message('b', 7));
    check(queue.buffered_bytes(a) == 100 && queue.buffered_bytes(b) == 7, "each association counts only its own bytes");
    check(!pop_from(queue, key(3000)), "an unknown association has nothing");
    auto from_b = pop_from(queue, b);
    check(from_b && *from_b == message('b', 7) && queue.buffered_bytes(a) == 100, "reading one leaves the other untouched");
}

void test_pop_any_reports_key() {
    std::printf("read_any names the association:\n");
    Receive_Queue queue;
    Association_Key b = key(2000);
    queue.push(b, message('b'));
    auto next = pop_any(queue);
    check(next && next->first == b, "the key comes back with the message");
}

void test_clear() {
    std::printf("clear:\n");
    Receive_Queue queue;
    queue.push(key(1000), message('a'));
    queue.push(key(2000), message('b'));
    queue.clear();
    check(!pop_any(queue) && queue.buffered_bytes(key(1000)) == 0, "everything is gone");
    queue.push(key(1000), message('a'));
    check(pop_any(queue).has_value(), "and the queue still works afterwards");
}

void test_short_buffer() {
    std::printf("A buffer smaller than the message:\n");
    Receive_Queue queue;
    Association_Key a = key(1000);
    std::vector<uint8_t> sent{'0', '1', '2', '3', '4'};
    queue.push(a, sent);
    queue.push(a, message('z'));

    uint8_t buffer[2];
    auto first = queue.read_from(a, buffer, sizeof(buffer));
    check(first && first->bytes == 2 && first->partial && buffer[0] == '0' && buffer[1] == '1',
          "the first read fills the buffer and is marked partial");
    check(queue.buffered_bytes(a) == 4, "the rest stays queued and counted");
    auto second = queue.read_from(a, buffer, sizeof(buffer));
    auto third = queue.read_from(a, buffer, sizeof(buffer));
    check(second && second->partial && third && third->bytes == 1 && !third->partial && buffer[0] == '4',
          "later reads continue the same message, the last one not partial");
    auto next = pop_from(queue, a);
    check(next && *next == message('z'), "then the next message");
}

void test_incomplete_message() {
    std::printf("A message pushed before it has fully arrived:\n");
    Receive_Queue queue;
    Association_Key a = key(1000);
    queue.push(a, message('a', 3), false);
    uint8_t buffer[16];
    auto read = queue.read_from(a, buffer, sizeof(buffer));
    check(read && read->bytes == 3 && read->partial, "what arrived is readable, marked partial");
    check(queue.buffered_bytes(a) == 0 && !queue.read_from(a, buffer, sizeof(buffer)), "nothing more until the rest arrives");

    queue.push(a, message('b', 2), false);
    queue.push(a, message('c', 1), true);
    queue.push(a, message('d', 1));
    check(queue.buffered_bytes(a) == 4, "later pieces continue the open message");
    read = queue.read_from(a, buffer, sizeof(buffer));
    check(read && read->bytes == 3 && !read->partial && buffer[0] == 'b' && buffer[2] == 'c',
          "and are read as one, ending the message");
    check(pop_from(queue, a) == message('d'), "the message after it is separate");
}

} // namespace

int main() {
    test_order_and_accounting();
    test_isolation();
    test_pop_any_reports_key();
    test_clear();
    test_short_buffer();
    test_incomplete_message();

    if (failures) {
        std::printf("\n%d check(s) FAILED\n", failures);
        return 1;
    }
    std::printf("\nAll receive queue tests passed\n");
    return 0;
}
