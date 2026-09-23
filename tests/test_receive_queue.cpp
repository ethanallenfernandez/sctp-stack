// Receive_Queue: per-association delivery that outlives the TCB, byte
// accounting per association, and round-robin service across associations.

#include <sctp/receive_queue.hpp>
#include <sctp/platform.hpp>

#include <cstdio>
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

void test_order_and_accounting() {
    std::printf("Per-association order and accounting:\n");
    Receive_Queue queue;
    Association_Key a = key(1000);
    queue.push(a, message('1', 3));
    queue.push(a, message('2', 5));
    check(queue.messages(a) == 2 && queue.buffered_bytes(a) == 8, "two messages, eight bytes buffered");

    auto first = queue.pop_from(a);
    check(first && *first == message('1', 3), "messages come out in delivery order");
    check(queue.buffered_bytes(a) == 5, "bytes are released as they are read");
    queue.pop_from(a);
    check(queue.messages(a) == 0 && queue.buffered_bytes(a) == 0 && !queue.pop_from(a), "empty once drained");
    check(!queue.pop_any(), "and nothing left for pop_any");
}

void test_isolation() {
    std::printf("Associations do not share accounting:\n");
    Receive_Queue queue;
    Association_Key a = key(1000);
    Association_Key b = key(2000);
    queue.push(a, message('a', 100));
    queue.push(b, message('b', 7));
    check(queue.buffered_bytes(a) == 100 && queue.buffered_bytes(b) == 7, "each association counts only its own bytes");
    check(!queue.pop_from(key(3000)), "an unknown association has nothing");
    auto from_b = queue.pop_from(b);
    check(from_b && *from_b == message('b', 7) && queue.messages(a) == 1, "reading one leaves the other untouched");
}

void test_round_robin() {
    std::printf("pop_any is round-robin:\n");
    Receive_Queue queue;
    Association_Key a = key(1000);
    Association_Key b = key(2000);
    Association_Key c = key(3000);
    for (int i = 0; i < 3; ++i) queue.push(a, message('a'));
    queue.push(b, message('b'));
    queue.push(c, message('c'));

    std::string order;
    while (auto next = queue.pop_any()) {
        order += static_cast<char>(next->second[0]);
    }
    check(order == "abcaa", "a busy association does not starve the others (" + order + ")");

    queue.push(a, message('a'));
    queue.push(b, message('b'));
    queue.pop_from(a);
    queue.push(a, message('a'));
    order.clear();
    while (auto next = queue.pop_any()) {
        order += static_cast<char>(next->second[0]);
    }
    check(order == "ba", "an association drained by pop_from rejoins at the back (" + order + ")");
}

void test_pop_any_reports_key() {
    std::printf("pop_any names the association:\n");
    Receive_Queue queue;
    Association_Key b = key(2000);
    queue.push(b, message('b'));
    auto next = queue.pop_any();
    check(next && next->first == b, "the key comes back with the message");
}

void test_clear() {
    std::printf("clear:\n");
    Receive_Queue queue;
    queue.push(key(1000), message('a'));
    queue.push(key(2000), message('b'));
    queue.clear();
    check(!queue.pop_any() && queue.messages(key(1000)) == 0, "everything is gone");
    queue.push(key(1000), message('a'));
    check(queue.pop_any().has_value(), "and the queue still works afterwards");
}

} // namespace

int main() {
    test_order_and_accounting();
    test_isolation();
    test_round_robin();
    test_pop_any_reports_key();
    test_clear();

    if (failures) {
        std::printf("\n%d check(s) FAILED\n", failures);
        return 1;
    }
    std::printf("\nAll receive queue tests passed\n");
    return 0;
}
