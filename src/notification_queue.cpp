#include <sctp/notification_queue.hpp>

namespace {
    // Bounded by association lifetimes, so never dropped at the cap.
    bool is_lifecycle(Notification_Type type) {
        return type == Notification_Type::SCTP_ASSOC_CHANGE || type == Notification_Type::SCTP_SHUTDOWN_EVENT;
    }
}

Notification_Queue::Notification_Queue() {
    subscribed[static_cast<size_t>(Notification_Type::SCTP_ASSOC_CHANGE)] = true;
}

void Notification_Queue::enqueue(Notification notification) {
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (!subscribed[static_cast<size_t>(notification.type)]) {
            return;
        }
        if (queue.size() >= MAX_QUEUED_NOTIFICATIONS && !is_lifecycle(notification.type)) {
            ++dropped_count;
            return;
        }
        notification.sequence_number = next_sequence_number++;
        queue.push(std::move(notification));
    }
    available.notify_one();
}

std::optional<Notification> Notification_Queue::dequeue() {
    std::lock_guard<std::mutex> lock(mutex);
    if (queue.empty()) {
        return std::nullopt;
    }
    return pop_front();
}

std::optional<Notification> Notification_Queue::wait_dequeue(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex);
    available.wait_for(
        lock, 
        timeout, 
        [this] { 
            return !queue.empty() || closed; 
        }
    );
    if (queue.empty()) {
        return std::nullopt;
    }
    return pop_front();
}

std::optional<Notification> Notification_Queue::pop_front() {
    std::optional<Notification> front{std::move(queue.front())};
    queue.pop();
    return front;
}

void Notification_Queue::set_subscribed(Notification_Type type, bool on) {
    std::lock_guard<std::mutex> lock(mutex);
    subscribed[static_cast<size_t>(type)] = on;
}

bool Notification_Queue::is_subscribed(Notification_Type type) {
    std::lock_guard<std::mutex> lock(mutex);
    return subscribed[static_cast<size_t>(type)];
}

void Notification_Queue::close() {
    {
        std::lock_guard<std::mutex> lock(mutex);
        closed = true;
    }
    available.notify_all();
}

void Notification_Queue::clear() {
    std::lock_guard<std::mutex> lock(mutex);
    queue = {};
}

size_t Notification_Queue::size() {
    std::lock_guard<std::mutex> lock(mutex);
    return queue.size();
}

uint64_t Notification_Queue::dropped() {
    std::lock_guard<std::mutex> lock(mutex);
    return dropped_count;
}
