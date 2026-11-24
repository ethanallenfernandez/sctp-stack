#include <sctp/queues/send_queue.hpp>
#include <sctp/protocol/tsn.hpp>
#include "protocol/builders.hpp"

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
    if (priority == Send_Priority::CONTROL && control.size() >= MAX_QUEUED_CONTROL) {
        return;
    }
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
        if (std::ranges::contains(refused, location)) {
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

// A purge() between peek() and commit() may already have dropped the packet
// along with its abandoned association; finding nothing then is correct.
void Send_Queue::commit(const Pending& pending) {
    std::lock_guard<std::mutex> lock(mutex);
    std::deque<Queued>& queue = queue_for(pending.priority);
    auto it = std::ranges::find(queue, pending.id, &Queued::id);
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
    for (auto* queue : {&control, &retransmission, &new_data}) {
        std::erase_if(*queue, [&](const Queued& queued) { return queued.deliverable.location == location; });
    }
}

void Send_Queue::remove_acked_retransmissions(const Association_Key& location, const sack_chunk_value& sack) {
    std::lock_guard<std::mutex> lock(mutex);
    for (Queued& queued : retransmission) {
        if (queued.deliverable.location == location) {
            std::erase_if(queued.deliverable.packet.chunks, [&](const SCTP_Chunk& chunk) {
                return chunk.chunk_header.type == DATA && sack_acknowledges(sack, std::get<data_chunk_value>(chunk.chunk_value).tsn);
            });
        }
    }
    std::erase_if(retransmission, [](const Queued& queued) { return queued.deliverable.packet.chunks.empty(); });
}

// The only ERROR retransmitted is one bundled behind a COOKIE ECHO, so it goes
// whenever the chunk it rides with does.
void Send_Queue::remove_retransmissions_of_type(const Association_Key& location, Chunk_Type type, const sockaddr_in* destination) {
    std::lock_guard<std::mutex> lock(mutex);
    for (Queued& queued : retransmission) {
        if (queued.deliverable.location == location
                && (destination == nullptr || destination->sin_addr.s_addr == queued.deliverable.destination.sin_addr.s_addr)) {
            auto& chunks = queued.deliverable.packet.chunks;
            bool carried = std::ranges::any_of(chunks, [&](const SCTP_Chunk& chunk) {
                return chunk.chunk_header.type == type;
            });
            if (carried) {
                std::erase_if(chunks, [&](const SCTP_Chunk& chunk) {
                    return chunk.chunk_header.type == type || chunk.chunk_header.type == OP_ERROR;
                });
            }
        }
    }
    std::erase_if(retransmission, [](const Queued& queued) { return queued.deliverable.packet.chunks.empty(); });
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

bool Send_Queue::has_retransmission_for(const Association_Key& location) {
    std::lock_guard<std::mutex> lock(mutex);
    return std::ranges::any_of(retransmission, [&](const Queued& queued) {
        return queued.deliverable.location == location;
    });
}

bool Send_Queue::has_new_data_for(const Association_Key& location) {
    std::lock_guard<std::mutex> lock(mutex);
    return std::ranges::any_of(new_data, [&](const Queued& queued) {
        return queued.deliverable.location == location;
    });
}
