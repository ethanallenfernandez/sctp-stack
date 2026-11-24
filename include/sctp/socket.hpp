#ifndef SCTP_SOCKET_HPP
#define SCTP_SOCKET_HPP

#include <sctp/platform/compat.hpp>
#include <sctp/platform/wakeup_pair.hpp>
#include <sctp/queues/deliverable.hpp>
#include <sctp/queues/expiration_queue.hpp>
#include <sctp/queues/send_queue.hpp>
#include <sctp/crypto/cookie_auth.hpp>
#include <sctp/queues/notification_queue.hpp>
#include <sctp/queues/receive_queue.hpp>
#include <sctp/status.hpp>

#include <optional>
#include <string_view>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <unordered_map>
#include <sctp/protocol/sctp.hpp>
#include <sctp/protocol/association.hpp>
#include <chrono>
#include <cstdint>

class SCTP_Socket {
friend struct SCTP_Socket_Test_Access;

public:
    SCTP_Socket(); 
    ~SCTP_Socket();

public:
    // port is both our SCTP port and the UDP port it is encapsulated on.
    bool sctp_bind(std::string_view ip_address, int port);
    // Every address at the one port, each on its own UDP socket. When there is
    // more than one, all are listed in INIT and INIT ACK. A wildcard address
    // must be bound alone. Port 0 takes an ephemeral port for all of them.
    bool sctp_bindx(const std::vector<std::string>& ip_addresses, int port);
    bool sctp_run();
    // Aborts every association still open.
    void sctp_close();
    // udp_port is the UDP encapsulation port to reach the peer at, by default
    // its SCTP port; once the peer answers, each of its addresses is sent to
    // whatever UDP port it last sent from. out_association_id is set only on OK.
    Sctp_Status sctp_associate(std::string_view ip_address, int sctp_port, Association_Key& out_association_id, std::optional<int> udp_port = std::nullopt);
    // Refused if the stream is not one the association negotiated. An unordered
    // message takes no SSN and may be delivered ahead of others on its stream.
    // ppid goes on every DATA chunk of the message, unchanged.
    Sctp_Status sctp_send_data(const Association_Key& association_id, const std::vector<uint8_t>& data, uint16_t stream = 0, bool unordered = false, uint32_t ppid = 0);
    Sctp_Status sctp_abort(const Association_Key& association_id, const std::vector<uint8_t>& reason = {});
    // Reads at most one message. *out_partial is set when more of it remains: the
    // buffer was too small, or the message is being handed up before all of it
    // has arrived. The rest is returned by the following reads. *out_ppid is
    // the message's Payload Protocol Identifier, as the peer sent it.
    size_t sctp_recv_data(std::vector<uint8_t>& buffer, Association_Key* out_association_id = nullptr, bool* out_partial = nullptr, uint16_t* out_stream = nullptr, uint32_t* out_ppid = nullptr);
    size_t sctp_recv_data_from(const Association_Key& association_id, std::vector<uint8_t>& buffer, bool* out_partial = nullptr, uint16_t* out_stream = nullptr, uint32_t* out_ppid = nullptr);
    // SHUTTING_DOWN if a shutdown is already under way.
    Sctp_Status sctp_shutdown(const Association_Key& association_id);
    std::optional<Notification> sctp_recv_notification();
    // A new interval applies to every destination of the association.
    Sctp_Status sctp_change_heartbeat(const Association_Key& association_id, const sockaddr_in& destination, bool enabled, std::optional<std::chrono::milliseconds> interval = std::nullopt);
    Sctp_Status sctp_request_heartbeat(const Association_Key& association_id, const sockaddr_in& destination);
    // Refused for an UNCONFIRMED destination, which nothing may be sent to.
    Sctp_Status sctp_set_primary(const Association_Key& association_id, const sockaddr_in& destination);

private:
    std::atomic<bool> running{false};
    bool platform_started{false};
    struct Local_Address {
        sockaddr_in address;
        sctp_socket_t socket;
    };
    sockaddr_in local_address;
    sctp_socket_t udp_socket;
    // Bound beside local_address, at its port.
    std::vector<Local_Address> other_local_addresses;
    Wakeup_Pair wakeup;
    std::unordered_map<Association_Key, Association_TCB> associations;
    // Every transport address of every peer, to its association.
    std::unordered_map<Peer_Key, Association_Key, Peer_Key_Hash> peer_addresses;
    uint32_t next_association_id{1};
    std::mutex associations_mutex;
    Send_Queue sends;
    Receive_Queue receives;
    Expiration_Queue expirations;
    Notification_Queue notifications;
    std::thread event_loop_thread;
    Cookie_Auth cookie_authorizer;

private:
    // The public API and these lock associations_mutex. Every other member
    // that touches an association takes it as held.
    void handle_recv_packet(const uint8_t* data, size_t n, const sockaddr_in& src, in_addr local = {});
    void handle_expiration(const Expiration_Fallback& fallback);
    // ptb_size is the next-hop MTU the PTB reports, an IP packet size.
    void handle_icmp_ptb(const sockaddr_in& destination, const uint8_t* quoted, size_t length, uint32_t ptb_size);
    void start_transmission_opportunity();
    std::optional<Send_Queue::Pending> next_packet();
    void packet_sent(const Send_Queue::Pending& pending);
    sctp_socket_t sending_socket(const Deliverable& deliverable);
    size_t finish_read(const std::optional<Receive_Queue::Read>& read, Association_Key* out_association_id, bool* out_partial, uint16_t* out_stream, uint32_t* out_ppid);
    void close_associations();

    void event_loop();
    void run_expire();
    void run_sending();
    void run_receiving(sctp_socket_t socket, in_addr local);
    void run_icmp_errors(sctp_socket_t socket);
    int next_poll_timeout();
    bool handle_send_packet(const Deliverable& deliverable);
    void requeue_bundled_sack(const Send_Queue::Pending& pending);
    void enqueue_packet(Deliverable deliverable, Send_Priority priority = Send_Priority::CONTROL);
    void wake_event_loop();
    void schedule_expiration(const Expiration_Key& key, std::chrono::steady_clock::time_point expiration, const Deliverable& retry = {});
    void cancel_expiration(const Expiration_Key& key);
    void cancel_expirations(const Association_Key& location);
    void notify_assoc_change(const Association_Key& key, Assoc_Change_State state);
    void notify_peer_addr_change(const Association_Key& key, const sockaddr_in& address, Peer_Addr_State state);
    // Empty when only one address is bound.
    std::vector<in_addr> advertised_addresses() const;
    Association_TCB init_new_association(const sockaddr_in& udp_address, uint16_t peer_sctp_port);
    Association_TCB init_new_association(const State_Cookie& cookie);

    Association_TCB* find_tcb(const Association_Key& key);
    // Id 0 if no association has this address.
    Association_Key association_at(const Peer_Key& peer);
    // Purges what the association has queued, then reports state if given.
    void remove_association(const Association_Key& key, std::optional<Assoc_Change_State> state = std::nullopt);
    // src is where a packet that passed the tag check came from, local the
    // address of ours it arrived at.
    void record_arrival(const Association_Key& key, const sockaddr_in& src, in_addr local);
    // Appends the addresses the association lacks, as UNCONFIRMED, and maps each to key.
    void add_peer_addresses(const Association_Key& key, Association_TCB& assoc, const std::vector<sockaddr_in>& addresses);
    void forget_peer_addresses(const Association_Key& key, const Association_TCB& assoc);
    // For a TCB being discarded or reset.
    void abandon_partial_delivery(const Association_Key& key, const TCB_Receive_Side& receive);
    Send_Allowances send_allowances();
    void arm_zero_window_probes(const Send_Allowances& allowances);
    void refill_retransmissions(const Send_Allowances& allowances);
    void refill_new_data(Send_Allowances& allowances);
    void prepare_data_packet(Deliverable& deliverable, bool new_data);
    void schedule_expirations_after_send(const Deliverable& deliverable, std::chrono::steady_clock::time_point sent_at);
    void handle_t3_expiration(const Association_Key& location, const sockaddr_in& destination);
    void handle_heartbeat_expiration(const Association_Key& location, const sockaddr_in& destination);
    void handle_zero_window_probe_expiration(const Association_Key& location);
    void handle_plpmtu_probe_expiration(const Association_Key& location, const sockaddr_in& destination);
    void handle_pmtu_raise_expiration(const Association_Key& location, const sockaddr_in& destination);
    void handle_t2_expiration(const Association_Key& location);
    void handle_t5_expiration(const Association_Key& location);
    void start_heartbeats(const Association_Key& key, Association_TCB& assoc);
    void arm_heartbeat(const Association_Key& key, const Association_TCB& assoc, const Peer_Path& path);
    void arm_confirmation_probes(const Association_Key& key, Association_TCB& assoc);
    void plan_next_probe(const Association_TCB& assoc, Peer_Path& path, std::chrono::steady_clock::time_point now);
    Deliverable build_probe(const Association_Key& key, const Association_TCB& assoc, Peer_Path& path);
    void count_path_error(const Association_Key& key, Peer_Path& path);
    void clear_path_errors(const Association_Key& key, Peer_Path& path);
    void start_plpmtud(const Association_Key& key, Peer_Path& path);
    void stop_plpmtud(const Association_Key& key, Peer_Path& path);
    void schedule_plpmtu_probe(const Association_Key& key, Peer_Path& path, std::chrono::microseconds delay = std::chrono::microseconds{0});
    void complete_plpmtu_search(const Association_Key& key, Peer_Path& path);
    void continue_plpmtu_search(const Association_Key& key, Peer_Path& path);
    void check_for_black_hole(const Association_Key& key, Peer_Path& path);
    Deliverable make_plpmtu_probe(const Association_Key& key, const Association_TCB& assoc, Peer_Path& path);
    void handle_plpmtu_probe_ack(const Association_Key& key, Association_TCB& assoc, Peer_Path& path);
    void record_heartbeat_sent(const Association_Key& location, const sockaddr_in& destination, const std::vector<uint8_t>& info, std::chrono::steady_clock::time_point sent_at);
    void record_data_sent(const Association_Key& location, const sockaddr_in& destination, const data_chunk_value& data, std::chrono::steady_clock::time_point sent_at);
    void start_t3_if_stopped(const Association_Key& location, const sockaddr_in& destination);
    void restart_t3(const Association_Key& location, const sockaddr_in& destination);
    void restart_t2(const Association_Key& location);
    // Gated, it waits for the destination's cwnd; T3-rtx and Fast Retransmit send their first packet regardless.
    void schedule_pending_retransmission(const Association_Key& key, bool gated = false);
    void update_rto(Peer_Path& path, std::chrono::microseconds measurement);
    // False if the packet goes no further, once answered as 8.4 says.
    bool validate_verification_tag(const SCTP_Packet& pkt, const Association_Key& key, const sockaddr_in& src);
    void answer_ootb(const SCTP_Packet& pkt, const Association_Key& key, const sockaddr_in& src);
    void abort_association(const Association_Key& key, const SCTP_Common_Header& header, const sockaddr_in& src, std::vector<error_cause> causes);
    void do_next_shutdown_step(const Association_Key& key);

    void handle_init(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src);
    void handle_init_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src);
    // Sets key to the association the cookie names, which the rest of the packet belongs to.
    bool handle_cookie_echo(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, Association_Key& key, const sockaddr_in& src);
    void handle_cookie_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src);
    void handle_error(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src);
    void handle_abort(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src);
    void handle_sack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src);
    void handle_data_packet(const SCTP_Packet& packet, const Association_Key& key, const sockaddr_in& src, bool acknowledge_immediately = false);
    void handle_heartbeat(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src);
    void handle_heartbeat_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src);
    void handle_shutdown(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src);
    void handle_shutdown_ack(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src);
    void handle_shutdown_complete(const SCTP_Common_Header& header, const SCTP_Chunk& chunk, const Association_Key& key, const sockaddr_in& src);
    void send_sack(const Association_Key& key);
    SCTP_Packet make_sack(const Association_Key& key, Association_TCB& assoc);
    uint32_t receive_window(const Association_Key& key, const TCB_Receive_Side& receive);
    void maybe_send_window_update(const Association_Key& key);
    // Sent back the way header came, under tag.
    void reply(const SCTP_Common_Header& header, const Association_Key& key, const sockaddr_in& destination, uint32_t tag, Chunk_Type type, Chunk_Value_Type value, uint8_t flag = 0);
    // From our port to the peer's, under its tag.
    SCTP_Packet packet_to(const Association_TCB& assoc, Chunk_Type type, Chunk_Value_Type value, uint8_t flag = 0) const;
    void report_unrecognized_chunks(const SCTP_Common_Header& header, const Association_Key& key, const sockaddr_in& src, std::vector<error_cause> causes);
};

#endif
