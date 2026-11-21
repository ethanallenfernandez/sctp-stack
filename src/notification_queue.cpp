#include <sctp/notification_queue.hpp>

void Notification_Queue::enqueue(Notification notification) {
    std::lock_guard<std::mutex> lock(mutex);
    queue.push(std::move(notification));
}

std::optional<Notification> Notification_Queue::dequeue() {
    std::lock_guard<std::mutex> lock(mutex);
    if (queue.empty()) {
        return std::nullopt;
    }
    std::optional<Notification> front{std::move(queue.front())};
    queue.pop();
    return front;
}
