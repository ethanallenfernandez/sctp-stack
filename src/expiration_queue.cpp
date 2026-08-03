// Timer heap backing Expiration_Queue.
//
// Bodies moved verbatim out of SCTP_Socket::{schedule,cancel}_expiration,
// cancel_expirations, and the two halves of run_expire / next_poll_timeout that
// touched the heap.

#include <sctp/expiration_queue.hpp>

void Expiration_Queue::schedule(
        const Expiration_Key& key,
        std::chrono::steady_clock::time_point expiration,
        const Deliverable& retry) {
    std::lock_guard<std::mutex> lock(mutex);
    uint64_t generation = next_generation++;
    active.insert_or_assign(key, generation);
    queue.push(Expiration_Fallback{key, expiration, generation, retry});
}

void Expiration_Queue::cancel(const Expiration_Key& key) {
    std::lock_guard<std::mutex> lock(mutex);
    active.erase(key);
}

void Expiration_Queue::cancel_all(const Association_Key& location) {
    std::lock_guard<std::mutex> lock(mutex);
    for (auto it = active.begin(); it != active.end();) {
        if (it->first.location == location) {
            it = active.erase(it);
        } else {
            ++it;
        }
    }
}

bool Expiration_Queue::is_active(const Expiration_Key& key) {
    std::lock_guard<std::mutex> lock(mutex);
    return active.find(key) != active.end();
}

bool Expiration_Queue::has_any_for(const Association_Key& location) {
    std::lock_guard<std::mutex> lock(mutex);
    for (const auto& entry : active) {
        if (entry.first.location == location) {
            return true;
        }
    }
    return false;
}

uint64_t Expiration_Queue::generation_of(const Expiration_Key& key) {
    std::lock_guard<std::mutex> lock(mutex);
    auto live = active.find(key);
    return live == active.end() ? 0 : live->second;
}

void Expiration_Queue::clear() {
    std::lock_guard<std::mutex> lock(mutex);
    while (!queue.empty()) {
        queue.pop();
    }
    active.clear();
}

std::vector<Expiration_Fallback> Expiration_Queue::drain_expired(
        std::chrono::steady_clock::time_point now) {
    std::vector<Expiration_Fallback> expired;
    std::lock_guard<std::mutex> lock(mutex);
    while (!queue.empty() && queue.top().expiration <= now) {
        Expiration_Fallback fallback = queue.top();
        queue.pop();

        auto live = active.find(fallback.key);
        if (live == active.end() || live->second != fallback.generation) {
            continue;
        }
        active.erase(live);
        expired.push_back(std::move(fallback));
    }
    return expired;
}

std::optional<std::chrono::steady_clock::time_point>
Expiration_Queue::next_deadline() {
    std::lock_guard<std::mutex> lock(mutex);
    while (!queue.empty()) {
        const Expiration_Fallback& fallback = queue.top();
        auto live = active.find(fallback.key);
        if (live != active.end() && live->second == fallback.generation) {
            return fallback.expiration;
        }
        queue.pop();
    }
    return std::nullopt;
}
