#ifndef SCTP_SOCKET_HPP
#define SCTP_SOCKET_HPP

#include <sctp/platform.hpp>
#include <sctp/wakeup_pair.hpp>
#include <sctp/deliverable.hpp>
#include <sctp/expiration_queue.hpp>
#include <sctp/send_queue.hpp>
#include <sctp/cookie_auth.hpp>
#include <sctp/notification_queue.hpp>

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

// RFC 9260 8.5: a packet that cannot be attributed to an association is not
// always merely dropped. 8.4 answers most of them with an ABORT.
enum class Packet_Validation {
    ACCEPT,
    DISCARD,
    ABORT_OOTB,
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
    void sctp_abort(const sockaddr_in& association_id, const std::vector<uint8_t>& reason = {});
    void sctp_abort(const Association_Key& association_id, const std::vector<uint8_t>& reason = {});
    size_t sctp_recv_data(std::vector<uint8_t>& buffer, Association_Key* out_association_id = nullptr);
    size_t sctp_recv_data_from(const sockaddr_in& association_id, std::vector<uint8_t>& buffer);
    size_t sctp_recv_data_from(const Association_Key& association_id, std::vector<uint8_t>& buffer);
    Association_Key get_this_association_key();
    std::optional<Notification> sctp_recv_notification(int timeout_ms = 0);
    void sctp_subscribe(Notification_Type type, bool on);

private:
    std::atomic<bool> running{false};
    bool platform_started{false};
    int receive_buffer_size;
    sockaddr_in local_address;
    sctp_socket_t udp_socket;
    Wakeup_Pair wakeup;
    std::unordered_map<Association_Key, Association, Association_Hash> associations;
    std::mutex associations_mutex;
    Send_Queue sends;
    Expiration_Queue expirations;
    Notification_Queue notifications;
    std::thread event_loop_thread;
    Cookie_Auth cookie_authorizer;

private:
    void event_loop();
    Association init_new_association(const Association_Key& key);
    Association init_new_association(const State_Cookie& cookie, const Association_Key& key);
    SCTP_Packet build_init(const Association_Key& key, const Association& assoc, uint32_t cookie_preservative_ms = 0);
    void remove_association(const Association_Key& key);
    void notify_assoc_change(const Association_Key& key, Assoc_Change_State state);
    void run_expire();
    void run_sending();
    void run_receiving();
    void enqueue_packet(Deliverable deliverable, Send_Priority priority = Send_Priority::CONTROL);
    void wake_event_loop();
    int next_poll_timeout();
    bool handle_send_packet(const Deliverable& deliverable);
    void schedule_expirations_after_send(const Deliverable& deliverable, std::chrono::steady_clock::time_point sent_at);
    void schedule_expiration(const Expiration_Key& key, std::chrono::steady_clock::time_point expiration, const Deliverable& retry);
    void cancel_expiration(const Expiration_Key& key);
    void cancel_expirations(const Association_Key& location);
    void handle_expiration(const Expiration_Fallback& fallback);
    void handle_t3_expiration(const Association_Key& location);
    void handle_delayed_sack_expiration(const Association_Key& location);
    void record_data_sent(const Association_Key& location, const data_chunk_value& data, std::chrono::steady_clock::time_point sent_at);
    void start_t3_if_stopped(const Association_Key& location);
    void restart_t3(const Association_Key& location);
    void handle_sack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    SCTP_Packet build_sack(const Association_Key& key, Association& assoc);
    void send_sack(const Association_Key& key);
    void schedule_pending_retransmission(const Association_Key& key);
    void update_rto(Association& assoc, std::chrono::microseconds measurement);
    void handle_recv_packet(const uint8_t* data, size_t n, const sockaddr_in& src);
    Packet_Validation validate_verification_tag(const SCTP_Packet& pkt, const sockaddr_in& src);
    Packet_Validation ootb_response(const SCTP_Packet& pkt);
    void read_ooo_buffer(Association& assoc);

    void handle_init(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    void handle_init_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    bool handle_cookie_echo(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    void handle_cookie_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    void handle_error(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    void handle_abort(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    void abort_association(const Association_Key& key, const SCTP_Common_Header& header, const sockaddr_in& src, std::vector<error_cause> causes);
    void send_cookie_ack(const SCTP_Common_Header& header, const sockaddr_in& src, uint32_t peer_tag);
    void send_stale_cookie_error(const SCTP_Common_Header& header, const sockaddr_in& src, const State_Cookie& cookie, uint32_t staleness_us);
    void send_error(const SCTP_Common_Header& header, const sockaddr_in& src, uint32_t peer_tag, std::vector<error_cause> causes);
    SCTP_Packet build_abort(uint16_t src_port, uint16_t des_port, uint32_t tag, bool reflected, std::vector<error_cause> causes);
    void send_abort(const SCTP_Common_Header& header, const sockaddr_in& src, uint32_t tag, bool reflected, std::vector<error_cause> causes);
    void report_unrecognized_chunks(const SCTP_Common_Header& header, const sockaddr_in& src, std::vector<error_cause> causes);
    void handle_data_packet(const SCTP_Packet& packet, const sockaddr_in& src, bool acknowledge_immediately = false);
};

#endif
