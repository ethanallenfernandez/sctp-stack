#ifndef SCTP_SOCKET_HPP
#define SCTP_SOCKET_HPP

#include <sctp/platform.hpp>
#include <string_view>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <unordered_map>
#include <sctp/sctp.hpp>
#include <sctp/association.hpp>
#include <chrono>
#include <cstdint>

struct Deliverable {
    Association_Key location;
    SCTP_Packet packet;
}; 

enum class Send_Priority {
    CONTROL,
    RETRANSMISSION,
    NEW_DATA,
};

enum class Expiration_Timer_Type {
    T1_INIT,
    T1_COOKIE,
    T3_RTX,
    DELAYED_SACK,
};

struct Expiration_Key {
    Association_Key location;
    Expiration_Timer_Type type;

    bool operator==(const Expiration_Key& other) const {
        return location == other.location && type == other.type;
    }
};

struct Expiration_Key_Hash {
    size_t operator()(const Expiration_Key& key) const {
        size_t location_hash = Association_Hash{}(key.location);
        size_t type_hash = std::hash<uint8_t>{}(static_cast<uint8_t>(key.type));
        return location_hash ^ (type_hash + 0x9e3779b9U + (location_hash << 6) + (location_hash >> 2));
    }
};

struct Expiration_Fallback {
    Expiration_Key key;
    std::chrono::steady_clock::time_point expiration;
    uint64_t generation;
    Deliverable retry;
};

struct Compare_Expiration {
    bool operator()(const Expiration_Fallback& lhs, const Expiration_Fallback& rhs) const {
        return lhs.expiration > rhs.expiration;
    }
};

class SCTP_Socket {
    friend struct SCTP_Socket_Test_Access;

    public:
        SCTP_Socket(); 
        ~SCTP_Socket();
    
    public:
        bool sctp_bind(std::string_view ip_address, int port);
        bool sctp_run();
        void sctp_close();
        Association_Key sctp_associate(std::string_view ip_address, int port);
        int await_established_association(const Association_Key& association_id, int timeout_ms);
        void sctp_send_data(const sockaddr_in& association_id, const std::vector<uint8_t>& data);
        void sctp_send_data(const Association_Key& association_id, const std::vector<uint8_t>& data);
        size_t sctp_recv_data(std::vector<uint8_t>& buffer, Association_Key* out_association_id = nullptr);
        size_t sctp_recv_data_from(const sockaddr_in& association_id, std::vector<uint8_t>& buffer);
        size_t sctp_recv_data_from(const Association_Key& association_id, std::vector<uint8_t>& buffer);
        Association_Key get_this_association_key();

    private:
        std::atomic<bool> running{false};
        bool platform_started{false};
        int receive_buffer_size;
        sockaddr_in local_address;
        sctp_socket_t udp_socket;
        sctp_socket_t wakeup_reader{INVALID_SOCKET};
        sctp_socket_t wakeup_writer{INVALID_SOCKET};
        std::unordered_map<Association_Key, Association, Association_Hash> associations;
        std::mutex associations_mutex;
        std::queue<Deliverable> control_queue;
        std::queue<Deliverable> retransmission_queue;
        std::queue<Deliverable> new_data_queue;
        std::chrono::steady_clock::time_point next_send_attempt{};
        std::mutex sending_queue_mutex;
        std::priority_queue<Expiration_Fallback, std::vector<Expiration_Fallback>, Compare_Expiration> expiration_queue;
        std::unordered_map<Expiration_Key, uint64_t, Expiration_Key_Hash> active_expirations;
        uint64_t next_expiration_generation{1};
        std::mutex expiration_queue_mutex;
        std::thread event_loop_thread;

        void event_loop();
        Association init_new_association(const Association_Key& key);
        void remove_association(const Association_Key& key);
        void run_expire();
        void run_sending();
        void run_receiving();
        void enqueue_packet(
            Deliverable deliverable,
            Send_Priority priority = Send_Priority::CONTROL);
        bool initialize_wakeup_sockets();
        void close_wakeup_sockets();
        void wake_event_loop();
        void drain_wakeup();
        int next_poll_timeout();
        void purge_queued_packets(const Association_Key& location);
        void remove_retransmissions(const Association_Key& location, const sack_chunk_value& sack);
        void remove_retransmissions(const Association_Key& location, Chunk_Type type);
        bool handle_send_packet(const Deliverable& deliverable);
        void schedule_expirations_after_send(
            const Deliverable& deliverable,
            std::chrono::steady_clock::time_point sent_at);
        void schedule_expiration(
            const Expiration_Key& key,
            std::chrono::steady_clock::time_point expiration,
            const Deliverable& retry);
        void cancel_expiration(const Expiration_Key& key);
        void cancel_expirations(const Association_Key& location);
        void handle_expiration(const Expiration_Fallback& fallback);
        void handle_t3_expiration(const Association_Key& location);
        void handle_delayed_sack_expiration(const Association_Key& location);
        void record_data_sent(
            const Association_Key& location,
            const data_chunk_value& data,
            std::chrono::steady_clock::time_point sent_at);
        void start_t3_if_stopped(const Association_Key& location);
        void restart_t3(const Association_Key& location);
        void handle_sack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
        SCTP_Packet build_sack(const Association_Key& key, Association& assoc);
        void send_sack(const Association_Key& key);
        void schedule_pending_retransmission(const Association_Key& key);
        void update_rto(Association& assoc, std::chrono::microseconds measurement);
        void handle_recv_packet(const uint8_t* data, size_t n, const sockaddr_in& src);
        bool validate_verification_tag(const SCTP_Packet& pkt, const sockaddr_in& src);
        void read_ooo_buffer(Association& assoc);

        void handle_init(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
        void handle_init_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
        void handle_cookie_echo(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
        void handle_cookie_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
        void handle_data_packet(const SCTP_Packet& packet, const sockaddr_in& src);
};

#endif
