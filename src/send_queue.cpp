// Three-tier outbound scheduling backing Send_Queue.
//
// Bodies moved verbatim out of SCTP_Socket::{enqueue_packet,
// purge_queued_packets, remove_retransmissions} and the queue-touching halves
// of run_sending and next_poll_timeout.

#include <sctp/send_queue.hpp>
#include <sctp/utils.hpp>

#include <algorithm>
#include <utility>

std::queue<Deliverable>& Send_Queue::queue_for(Send_Priority priority) {
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
    queue_for(priority).push(std::move(deliverable));
}

std::optional<Send_Queue::Pending> Send_Queue::peek(std::chrono::steady_clock::time_point now) {
    std::lock_guard<std::mutex> lock(mutex);
    if (now < next_send_attempt) {
        return std::nullopt;
    }
    if (!control.empty()) {
        return Pending{Send_Priority::CONTROL, control.front()};
    }
    if (!retransmission.empty()) {
        return Pending{Send_Priority::RETRANSMISSION, retransmission.front()};
    }
    if (!new_data.empty()) {
        return Pending{Send_Priority::NEW_DATA, new_data.front()};
    }
    return std::nullopt;
}

void Send_Queue::commit(Send_Priority priority) {
    std::lock_guard<std::mutex> lock(mutex);
    // The lock is released between peek() and commit(), so a purge() landing in
    // that window can leave nothing to pop. pop() on an empty std::queue is
    // undefined and in practice destroys a Deliverable that was never there,
    // crashing in ~SCTP_Packet on the event-loop thread. Skipping the pop is
    // the correct outcome and not merely a guard: purge() dropped that packet
    // because the association it belonged to was abandoned.
    std::queue<Deliverable>& queue = queue_for(priority);
    if (!queue.empty()) {
        queue.pop();
    }
    next_send_attempt = {};
}

void Send_Queue::defer(std::chrono::steady_clock::time_point retry_at) {
    std::lock_guard<std::mutex> lock(mutex);
    next_send_attempt = retry_at;
}

void Send_Queue::purge(const Association_Key& location) {
    std::lock_guard<std::mutex> lock(mutex);
    auto purge_one = [&](std::queue<Deliverable>& queue) {
        std::queue<Deliverable> retained;
        while (!queue.empty()) {
            Deliverable packet = std::move(queue.front());
            queue.pop();
            if (!(packet.location == location)) {
                retained.push(std::move(packet));
            }
        }
        queue = std::move(retained);
    };
    purge_one(control);
    purge_one(retransmission);
    purge_one(new_data);
}

void Send_Queue::remove_acked_retransmissions(const Association_Key& location, const sack_chunk_value& sack) {
    std::lock_guard<std::mutex> lock(mutex);
    std::queue<Deliverable> retained;
    while (!retransmission.empty()) {
        Deliverable packet = std::move(retransmission.front());
        retransmission.pop();
        if (packet.location == location) {
            auto& chunks = packet.packet.chunks;
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
        if (!packet.packet.chunks.empty()) {
            retained.push(std::move(packet));
        }
    }
    retransmission = std::move(retained);
}

void Send_Queue::remove_retransmissions_of_type(const Association_Key& location, Chunk_Type type) {
    std::lock_guard<std::mutex> lock(mutex);
    std::queue<Deliverable> retained;
    while (!retransmission.empty()) {
        Deliverable packet = std::move(retransmission.front());
        retransmission.pop();
        if (packet.location == location) {
            auto& chunks = packet.packet.chunks;
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
        if (!packet.packet.chunks.empty()) {
            retained.push(std::move(packet));
        }
    }
    retransmission = std::move(retained);
}

void Send_Queue::clear() {
    std::lock_guard<std::mutex> lock(mutex);
    control = {};
    retransmission = {};
    new_data = {};
    next_send_attempt = {};
}

std::optional<std::chrono::steady_clock::time_point>
Send_Queue::next_deadline() {
    std::lock_guard<std::mutex> lock(mutex);
    if (control.empty() && retransmission.empty() && new_data.empty()) {
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
    auto contains = [&](std::queue<Deliverable> queue) {
        while (!queue.empty()) {
            if (queue.front().location == location) {
                return true;
            }
            queue.pop();
        }
        return false;
    };
    return contains(control)
        || contains(retransmission)
        || contains(new_data);
}

std::vector<uint32_t> Send_Queue::front_data_tsns(Send_Priority priority) {
    std::lock_guard<std::mutex> lock(mutex);
    std::vector<uint32_t> result;
    std::queue<Deliverable>& queue = queue_for(priority);
    if (queue.empty()) {
        return result;
    }
    for (const auto& chunk : queue.front().packet.chunks) {
        if (chunk.chunk_header.type == DATA) {
            result.push_back(
                std::get<data_chunk_value>(chunk.chunk_value).tsn);
        }
    }
    return result;
}

size_t Send_Queue::front_chunk_count(Send_Priority priority) {
    std::lock_guard<std::mutex> lock(mutex);
    std::queue<Deliverable>& queue = queue_for(priority);
    return queue.empty() ? 0 : queue.front().packet.chunks.size();
}
