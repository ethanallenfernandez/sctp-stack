#ifndef SCTP_SOCKET_HPP
#define SCTP_SOCKET_HPP

#include <sctp/platform.hpp>
#include <sctp/wakeup_pair.hpp>
#include <sctp/deliverable.hpp>
#include <sctp/expiration_queue.hpp>
#include <sctp/send_queue.hpp>
#include <sctp/cookie_auth.hpp>
#include <sctp/notification_queue.hpp>
#include <sctp/receive_queue.hpp>

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
    SHUTDOWN_COMPLETE_OOTB,
};

// How long sctp_close waits for associations to shut down gracefully before
// aborting the rest. 0 aborts everything at once.
constexpr int DEFAULT_CLOSE_LINGER_MS = 5000;
constexpr int USE_SOCKET_LINGER = -1;

class SCTP_Socket {
friend struct SCTP_Socket_Test_Access;

public:
    SCTP_Socket(); 
    ~SCTP_Socket();

public:
    bool sctp_bind(std::string_view ip_address, int port);
    bool sctp_run();
    // linger_ms defaults to the socket's own, as sctp_set_linger left it.
    void sctp_close(int linger_ms = USE_SOCKET_LINGER);
    void sctp_set_linger(int linger_ms);
    Association_Key sctp_associate(std::string_view ip_address, int port);
    int await_established_association(const Association_Key& association_id, int timeout_ms);
    // Refused if the stream is not one the association negotiated. An unordered
    // message takes no SSN and may be delivered ahead of others on its stream.
    void sctp_send_data(const sockaddr_in& association_id, const std::vector<uint8_t>& data, uint16_t stream = 0, bool unordered = false);
    void sctp_send_data(const Association_Key& association_id, const std::vector<uint8_t>& data, uint16_t stream = 0, bool unordered = false);
    void sctp_abort(const sockaddr_in& association_id, const std::vector<uint8_t>& reason = {});
    void sctp_abort(const Association_Key& association_id, const std::vector<uint8_t>& reason = {});
    // Reads at most one message. *out_partial is set when more of it remains: the
    // buffer was too small, or the message is being handed up before all of it
    // has arrived. The rest is returned by the following reads.
    size_t sctp_recv_data(std::vector<uint8_t>& buffer, Association_Key* out_association_id = nullptr, bool* out_partial = nullptr, uint16_t* out_stream = nullptr);
    size_t sctp_recv_data_from(const sockaddr_in& association_id, std::vector<uint8_t>& buffer, bool* out_partial = nullptr, uint16_t* out_stream = nullptr);
    size_t sctp_recv_data_from(const Association_Key& association_id, std::vector<uint8_t>& buffer, bool* out_partial = nullptr, uint16_t* out_stream = nullptr);
    void sctp_shutdown(const sockaddr_in& association_id);
    void sctp_shutdown(const Association_Key& association_id);
    std::optional<Notification> sctp_recv_notification(int timeout_ms = 0);
    void sctp_subscribe(Notification_Type type, bool on);
    
    inline Association_Key get_this_association_key() {
        return Association_Key{local_address};
    }

private:
    std::atomic<bool> running{false};
    std::atomic<int> linger_ms{DEFAULT_CLOSE_LINGER_MS};
    bool platform_started{false};
    int receive_buffer_size;
    sockaddr_in local_address;
    sctp_socket_t udp_socket;
    Wakeup_Pair wakeup;
    std::unordered_map<Association_Key, Association, Association_Hash> associations;
    std::mutex associations_mutex;
    Send_Queue sends;
    Receive_Queue receives;
    Expiration_Queue expirations;
    Notification_Queue notifications;
    std::thread event_loop_thread;
    Cookie_Auth cookie_authorizer;

private:
    void event_loop();
    Association init_new_association(const Association_Key& key);
    Association init_new_association(const State_Cookie& cookie, const Association_Key& key);
    void remove_association(const Association_Key& key);
    void close_associations(std::chrono::milliseconds linger);
    void notify_assoc_change(const Association_Key& key, Assoc_Change_State state);
    void run_expire();
    void run_sending();
    void start_transmission_opportunity();
    std::optional<Send_Queue::Pending> next_packet();
    void packet_sent(const Send_Queue::Pending& pending);
    void requeue_bundled_sack(const Send_Queue::Pending& pending);
    Send_Allowances send_allowances();
    void arm_zero_window_probes(const Send_Allowances& allowances);
    void refill_retransmissions(const Send_Allowances& allowances);
    void refill_new_data(Send_Allowances& allowances);
    void prepare_data_packet(Deliverable& deliverable, bool new_data);
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
    void handle_heartbeat_expiration(const Association_Key& location);
    void handle_zero_window_probe_expiration(const Association_Key& location);
    void schedule_heartbeat(const Association_Key& location, std::chrono::microseconds rto);
    void record_heartbeat_sent(const Association_Key& location, std::chrono::steady_clock::time_point sent_at);
    void record_data_sent(const Association_Key& location, const data_chunk_value& data, std::chrono::steady_clock::time_point sent_at);
    void start_t3_if_stopped(const Association_Key& location);
    void restart_t3(const Association_Key& location);
    void handle_t2_expiration(const Association_Key& location);
    void handle_t5_expiration(const Association_Key& location);
    void restart_t2(const Association_Key& location);
    void schedule_pending_retransmission(const Association_Key& key);
    void update_rto(Association& assoc, std::chrono::microseconds measurement);
    void handle_recv_packet(const uint8_t* data, size_t n, const sockaddr_in& src);
    Packet_Validation validate_verification_tag(const SCTP_Packet& pkt, const sockaddr_in& src);
    Packet_Validation ootb_response(const SCTP_Packet& pkt);
    bool read_ooo_buffer(Association& assoc, std::vector<Delivery>& delivered);
    void abort_association(const Association_Key& key, const SCTP_Common_Header& header, const sockaddr_in& src, std::vector<error_cause> causes);
    void do_next_shutdown_step(const Association_Key& key);

    void handle_init(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    void handle_init_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    bool handle_cookie_echo(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    void handle_cookie_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    void handle_error(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    void handle_abort(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    void handle_sack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    void handle_data_packet(const SCTP_Packet& packet, const sockaddr_in& src, bool acknowledge_immediately = false);
    void handle_heartbeat(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    void handle_heartbeat_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    void handle_shutdown(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    void handle_shutdown_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    void handle_shutdown_complete(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const sockaddr_in& src);
    void send_sack(const Association_Key& key);
    SCTP_Packet make_sack(const Association_Key& key, Association& assoc);
    uint32_t receive_window(const Association_Key& key, const Association& assoc);
    void maybe_send_window_update(const Association_Key& key);
    void send_cookie_ack(const SCTP_Common_Header& header, const sockaddr_in& src, uint32_t peer_tag);
    void send_stale_cookie_error(const SCTP_Common_Header& header, const sockaddr_in& src, const State_Cookie& cookie, uint32_t staleness_us);
    void send_error(const SCTP_Common_Header& header, const sockaddr_in& src, uint32_t peer_tag, std::vector<error_cause> causes);
    void send_abort(const SCTP_Common_Header& header, const sockaddr_in& src, uint32_t tag, bool reflected, std::vector<error_cause> causes);
    void report_unrecognized_chunks(const SCTP_Common_Header& header, const sockaddr_in& src, std::vector<error_cause> causes);
};

#endif
