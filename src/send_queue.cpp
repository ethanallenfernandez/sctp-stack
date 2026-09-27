// Three-tier outbound scheduling backing Send_Queue.
//
// Bodies moved verbatim out of SCTP_Socket::{enqueue_packet,
// purge_queued_packets, remove_retransmissions} and the queue-touching halves
// of run_sending and next_poll_timeout.

#include <sctp/send_queue.hpp>
#include <sctp/utils.hpp>
#include "builders.hpp"

#include <algorithm>
#include <utility>

namespace {
    size_t data_bytes(const SCTP_Packet& packet) {
        size_t total = 0;
        for (const auto& chunk : packet.chunks) {
            if (chunk.chunk_header.type == DATA) {
                total += data_chunk_wire_size(std::get<data_chunk_value>(chunk.chunk_value));
            }
        }
        return total;
    }

    bool admits(Send_Allowance& allowance, const SCTP_Packet& packet) {
        if (!allowance.cwnd_open || allowance.burst_spent) {
            return false;
        }
        if (allowance.zero_window_probe || data_bytes(packet) <= allowance.rwnd) {
            return true;
        }
        allowance.rwnd_blocked = true;
        return false;
    }
}

std::deque<Send_Queue::Queued>& Send_Queue::queue_for(Send_Priority priority) {
    if (priority == Send_Priority::CONTROL) {
        return control;
    }
    if (priority == Send_Priority::RETRANSMISSION) {
        return retransmission;
    }
    return new_data;
}

void Send_Queue::enqueue(Deliverable deliverable, Send_Priority priority) {
    std::lock_guard<std::mutex> lock(mutex);
    queue_for(priority).push_back(Queued{next_id++, std::move(deliverable)});
    new_data_blocked = false;
}

std::optional<Send_Queue::Pending> Send_Queue::peek(std::chrono::steady_clock::time_point now, Send_Allowances& allowances) {
    std::lock_guard<std::mutex> lock(mutex);
    return peek_locked(now, &allowances);
}

std::optional<Send_Queue::Pending> Send_Queue::peek(std::chrono::steady_clock::time_point now) {
    std::lock_guard<std::mutex> lock(mutex);
    return peek_locked(now, nullptr);
}

std::optional<Send_Queue::Pending> Send_Queue::peek_locked(std::chrono::steady_clock::time_point now, Send_Allowances* allowances) {
    if (now < next_send_attempt) {
        return std::nullopt;
    }
    if (!control.empty()) {
        return Pending{Send_Priority::CONTROL, control.front().deliverable, control.front().id};
    }
    if (!retransmission.empty()) {
        return Pending{Send_Priority::RETRANSMISSION, retransmission.front().deliverable, retransmission.front().id};
    }

    std::vector<Association_Key> refused;
    for (const auto& queued : new_data) {
        const Association_Key& location = queued.deliverable.location;
        if (allowances == nullptr) {
            return Pending{Send_Priority::NEW_DATA, queued.deliverable, queued.id};
        }
        if (std::find(refused.begin(), refused.end(), location) != refused.end()) {
            continue;
        }
        auto allowance = allowances->find(location);
        if (allowance != allowances->end() && admits(allowance->second, queued.deliverable.packet)) {
            return Pending{Send_Priority::NEW_DATA, queued.deliverable, queued.id};
        }
        refused.push_back(location);
    }
    new_data_blocked = !new_data.empty();
    return std::nullopt;
}

void Send_Queue::commit(const Pending& pending) {
    std::lock_guard<std::mutex> lock(mutex);
    // The lock is released between peek() and commit(), so a purge() landing in
    // that window can leave nothing to remove. Finding nothing is the correct
    // outcome and not merely a guard: purge() dropped that packet because the
    // association it belonged to was abandoned.
    std::deque<Queued>& queue = queue_for(pending.priority);
    auto it = std::find_if(queue.begin(), queue.end(), [&](const Queued& queued) {
        return queued.id == pending.id;
    });
    if (it != queue.end()) {
        queue.erase(it);
    }
    next_send_attempt = {};
}

void Send_Queue::defer(std::chrono::steady_clock::time_point retry_at) {
    std::lock_guard<std::mutex> lock(mutex);
    next_send_attempt = retry_at;
}

void Send_Queue::purge(const Association_Key& location) {
    std::lock_guard<std::mutex> lock(mutex);
    auto purge_one = [&](std::deque<Queued>& queue) {
        queue.erase(
            std::remove_if(queue.begin(), queue.end(), [&](const Queued& queued) {
                return queued.deliverable.location == location;
            }),
            queue.end()
        );
    };
    purge_one(control);
    purge_one(retransmission);
    purge_one(new_data);
}

void Send_Queue::remove_acked_retransmissions(const Association_Key& location, const sack_chunk_value& sack) {
    std::lock_guard<std::mutex> lock(mutex);
    std::deque<Queued> retained;
    while (!retransmission.empty()) {
        Queued queued = std::move(retransmission.front());
        retransmission.pop_front();
        if (queued.deliverable.location == location) {
            auto& chunks = queued.deliverable.packet.chunks;
            chunks.erase(
                std::remove_if(
                    chunks.begin(),
                    chunks.end(),
                    [&](const SCTP_Chunk& chunk) {
                        return chunk.chunk_header.type == DATA && sack_acknowledges(sack, std::get<data_chunk_value>(chunk.chunk_value).tsn);
                    }
                ),
                chunks.end()
            );
        }
        if (!queued.deliverable.packet.chunks.empty()) {
            retained.push_back(std::move(queued));
        }
    }
    retransmission = std::move(retained);
}

void Send_Queue::remove_retransmissions_of_type(const Association_Key& location, Chunk_Type type) {
    std::lock_guard<std::mutex> lock(mutex);
    std::deque<Queued> retained;
    while (!retransmission.empty()) {
        Queued queued = std::move(retransmission.front());
        retransmission.pop_front();
        if (queued.deliverable.location == location) {
            auto& chunks = queued.deliverable.packet.chunks;
            chunks.erase(
                std::remove_if(
                    chunks.begin(),
                    chunks.end(),
                    [&](const SCTP_Chunk& chunk) {
                        return chunk.chunk_header.type == type;
                    }
                ),
                chunks.end()
            );
        }
        if (!queued.deliverable.packet.chunks.empty()) {
            retained.push_back(std::move(queued));
        }
    }
    retransmission = std::move(retained);
}

void Send_Queue::clear() {
    std::lock_guard<std::mutex> lock(mutex);
    control = {};
    retransmission = {};
    new_data = {};
    new_data_blocked = false;
    next_send_attempt = {};
}

std::optional<std::chrono::steady_clock::time_point>
Send_Queue::next_deadline() {
    std::lock_guard<std::mutex> lock(mutex);
    if (control.empty() && retransmission.empty() && (new_data.empty() || new_data_blocked)) {
        return std::nullopt;
    }
    return next_send_attempt;
}

size_t Send_Queue::size() {
    std::lock_guard<std::mutex> lock(mutex);
    return control.size() + retransmission.size() + new_data.size();
}

bool Send_Queue::has_packets_for(const Association_Key& location) {
    std::lock_guard<std::mutex> lock(mutex);
    auto contains = [&](const std::deque<Queued>& queue) {
        return std::any_of(queue.begin(), queue.end(), [&](const Queued& queued) {
            return queued.deliverable.location == location;
        });
    };
    return contains(control)
        || contains(retransmission)
        || contains(new_data);
}

bool Send_Queue::has_retransmission_for(const Association_Key& location) {
    std::lock_guard<std::mutex> lock(mutex);
    return std::any_of(retransmission.begin(), retransmission.end(), [&](const Queued& queued) {
        return queued.deliverable.location == location;
    });
}

std::vector<uint32_t> Send_Queue::front_data_tsns(Send_Priority priority) {
    std::lock_guard<std::mutex> lock(mutex);
    std::vector<uint32_t> result;
    std::deque<Queued>& queue = queue_for(priority);
    if (queue.empty()) {
        return result;
    }
    for (const auto& chunk : queue.front().deliverable.packet.chunks) {
        if (chunk.chunk_header.type == DATA) {
            result.push_back(
                std::get<data_chunk_value>(chunk.chunk_value).tsn);
        }
    }
    return result;
}

size_t Send_Queue::front_chunk_count(Send_Priority priority) {
    std::lock_guard<std::mutex> lock(mutex);
    std::deque<Queued>& queue = queue_for(priority);
    return queue.empty() ? 0 : queue.front().deliverable.packet.chunks.size();
}
