#include <sctp/queues/receive_queue.hpp>

#include <algorithm>

void Receive_Queue::push(const Association_Key& key, std::vector<uint8_t> bytes, bool complete, uint16_t stream, uint32_t ppid) {
    std::lock_guard<std::mutex> lock(mutex);
    Pending& entry = pending[key];
    entry.bytes += bytes.size();
    if (!entry.messages.empty() && !entry.messages.back().complete) {
        Message& tail = entry.messages.back();
        tail.bytes.append_range(bytes);
        tail.complete = complete;
    } else {
        entry.messages.push_back(Message{std::move(bytes), 0, complete, stream, ppid});
    }
}

std::optional<Receive_Queue::Read> Receive_Queue::read_any(uint8_t* out, size_t capacity) {
    std::lock_guard<std::mutex> lock(mutex);
    if (pending.empty()) {
        return std::nullopt;
    }
    return read_locked(pending.begin(), out, capacity);
}

std::optional<Receive_Queue::Read> Receive_Queue::read_from(const Association_Key& key, uint8_t* out, size_t capacity) {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = pending.find(key);
    if (it == pending.end()) {
        return std::nullopt;
    }
    return read_locked(it, out, capacity);
}

Receive_Queue::Read Receive_Queue::read_locked(std::unordered_map<Association_Key, Pending>::iterator it, uint8_t* out, size_t capacity) {
    Message& front = it->second.messages.front();
    size_t count = std::min(capacity, front.bytes.size() - front.offset);
    std::copy_n(front.bytes.begin() + static_cast<long>(front.offset), count, out);
    front.offset += count;
    it->second.bytes -= count;

    Read read{it->first, count, front.offset < front.bytes.size() || !front.complete, front.stream, front.ppid};
    if (front.offset == front.bytes.size()) {
        it->second.messages.pop_front();
        if (it->second.messages.empty()) {
            pending.erase(it);
        }
    }
    return read;
}

void Receive_Queue::abandon_open(const Association_Key& key) {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = pending.find(key);
    if (it == pending.end() || it->second.messages.back().complete) {
        return;
    }
    const Message& tail = it->second.messages.back();
    it->second.bytes -= tail.bytes.size() - tail.offset;
    it->second.messages.pop_back();
    if (it->second.messages.empty()) {
        pending.erase(it);
    }
}

void Receive_Queue::clear() {
    std::lock_guard<std::mutex> lock(mutex);
    pending.clear();
}

size_t Receive_Queue::buffered_bytes(const Association_Key& key) {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = pending.find(key);
    return it == pending.end() ? 0 : it->second.bytes;
}
