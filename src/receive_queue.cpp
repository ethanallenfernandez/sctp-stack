#include <sctp/receive_queue.hpp>

#include <algorithm>

void Receive_Queue::push(const Association_Key& key, std::vector<uint8_t> bytes, bool complete, uint16_t stream) {
    std::lock_guard<std::mutex> lock(mutex);
    Pending& entry = pending[key];
    if (entry.messages.empty()) {
        ready.push_back(key);
    }
    entry.bytes += bytes.size();
    if (!entry.messages.empty() && !entry.messages.back().complete) {
        Message& tail = entry.messages.back();
        tail.bytes.insert(tail.bytes.end(), bytes.begin(), bytes.end());
        tail.complete = complete;
    } else {
        entry.messages.push_back(Message{std::move(bytes), 0, complete, stream});
    }
}

std::optional<Receive_Queue::Read> Receive_Queue::read_any(uint8_t* out, size_t capacity) {
    std::lock_guard<std::mutex> lock(mutex);
    if (ready.empty()) {
        return std::nullopt;
    }
    Association_Key key = ready.front();
    ready.pop_front();
    Read read = read_locked(pending.find(key), out, capacity);
    if (pending.count(key) != 0) {
        if (read.partial) {
            ready.push_front(key);
        } else {
            ready.push_back(key);
        }
    }
    return read;
}

std::optional<Receive_Queue::Read> Receive_Queue::read_from(const Association_Key& key, uint8_t* out, size_t capacity) {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = pending.find(key);
    if (it == pending.end()) {
        return std::nullopt;
    }
    Read read = read_locked(it, out, capacity);
    if (pending.count(key) == 0) {
        ready.erase(std::find(ready.begin(), ready.end(), key));
    }
    return read;
}

Receive_Queue::Read Receive_Queue::read_locked(std::unordered_map<Association_Key, Pending, Association_Hash>::iterator it, uint8_t* out, size_t capacity) {
    Message& front = it->second.messages.front();
    size_t count = std::min(capacity, front.bytes.size() - front.offset);
    std::copy_n(front.bytes.begin() + static_cast<long>(front.offset), count, out);
    front.offset += count;
    it->second.bytes -= count;

    Read read{it->first, count, front.offset < front.bytes.size() || !front.complete, front.stream};
    if (front.offset == front.bytes.size()) {
        it->second.messages.pop_front();
        if (it->second.messages.empty()) {
            pending.erase(it);
        }
    }
    return read;
}

void Receive_Queue::clear() {
    std::lock_guard<std::mutex> lock(mutex);
    pending.clear();
    ready.clear();
}

size_t Receive_Queue::messages(const Association_Key& key) {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = pending.find(key);
    return it == pending.end() ? 0 : it->second.messages.size();
}

size_t Receive_Queue::buffered_bytes(const Association_Key& key) {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = pending.find(key);
    return it == pending.end() ? 0 : it->second.bytes;
}
