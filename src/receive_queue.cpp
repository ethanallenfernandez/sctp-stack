#include <sctp/receive_queue.hpp>

#include <algorithm>

void Receive_Queue::push(const Association_Key& key, std::vector<uint8_t> message) {
    std::lock_guard<std::mutex> lock(mutex);
    Pending& entry = pending[key];
    if (entry.messages.empty()) {
        ready.push_back(key);
    }
    entry.bytes += message.size();
    entry.messages.push(std::move(message));
}

std::optional<std::pair<Association_Key, std::vector<uint8_t>>> Receive_Queue::pop_any() {
    std::lock_guard<std::mutex> lock(mutex);
    if (ready.empty()) {
        return std::nullopt;
    }
    Association_Key key = ready.front();
    ready.pop_front();
    auto it = pending.find(key);
    std::vector<uint8_t> message = pop_locked(it);
    if (pending.count(key) != 0) {
        ready.push_back(key);
    }
    return std::make_pair(key, std::move(message));
}

std::optional<std::vector<uint8_t>> Receive_Queue::pop_from(const Association_Key& key) {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = pending.find(key);
    if (it == pending.end()) {
        return std::nullopt;
    }
    std::vector<uint8_t> message = pop_locked(it);
    if (pending.count(key) == 0) {
        ready.erase(std::find(ready.begin(), ready.end(), key));
    }
    return message;
}

std::vector<uint8_t> Receive_Queue::pop_locked(std::unordered_map<Association_Key, Pending, Association_Hash>::iterator it) {
    std::vector<uint8_t> message = std::move(it->second.messages.front());
    it->second.messages.pop();
    it->second.bytes -= message.size();
    if (it->second.messages.empty()) {
        pending.erase(it);
    }
    return message;
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
