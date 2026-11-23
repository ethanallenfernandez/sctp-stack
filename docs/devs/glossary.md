# Glossary and constants

- [Terms](#terms)
- [Code names that are easy to confuse](#code-names-that-are-easy-to-confuse)
- [Constants](#constants)

---

## Terms

| Term | Meaning | In code |
|---|---|---|
| **a_rwnd** | Advertised Receiver Window Credit: free receive buffer, carried in INIT, INIT ACK and SACK | `sack_chunk_value::a_rwnd`, `init_chunk_value::a_rwnd` |
| **AMDCS** | Association Maximum DATA Chunk Size: the smallest PMDCS over usable destinations | `amdcs(assoc)` |
| **Association** | an SCTP connection between two endpoints | `Association` |
| **B / E / U / I bits** | DATA flags: Beginning fragment, Ending fragment, Unordered, Immediate SACK requested | `DATA_FLAG_B/E/U`, `DATA_IMMEDIATE_SACK_FLAG` |
| **cwnd** | congestion window, per destination | `Peer_Path::cwnd` |
| **Cumulative TSN Ack** | highest TSN below which everything has been received | ours: `last_peer_tsn`. The peer's: `cumulative_tsn_ack` |
| **Data path** | the destination new DATA currently goes to: the primary, or an alternate while the primary is inactive | `data_path(assoc)` |
| **Deliverable** | one outbound packet plus where it goes | `Deliverable` |
| **DPLPMTUD** | Datagram Packetization Layer PMTU Discovery (RFC 8899) | `plpmtud.cpp` |
| **Fast recovery** | the period after a fast retransmit during which cwnd is not reduced again | `in_fast_recovery` |
| **Flight size** | bytes sent and neither acked nor marked for retransmission | `bytes_in_flight()` |
| **Gap Ack Block** | a range of TSNs received above the Cumulative TSN Ack, as offsets from it | `sack_gap_ack_block` |
| **HTNA** | Highest TSN Newly Acknowledged by a SACK, used to count miss indications | `htna` in `handle_sack` |
| **Initiate Tag** | the tag an endpoint asks the peer to put on every packet it sends | `this_ver_tag` (ours), `peer_ver_tag` (theirs) |
| **Max.Burst** | maximum new-DATA packets per association per transmission opportunity | `MAX_BURST`, `burst_count` |
| **Miss indication** | a SACK reporting a TSN above an outstanding one, which suggests loss | `missing_reports` |
| **OOTB** | Out Of The Blue: a packet that matches no association | `answer_ootb()` |
| **OS / MIS** | Number of Outbound Streams / Maximum Inbound Streams offered in INIT | `out_streams`, `in_streams` |
| **Path** | one destination transport address of the peer | `Peer_Path` |
| **PLPMTU** | the largest packet (here: UDP datagram) the path carries | `Plpmtud::plpmtu` |
| **PMDCS** | Path Maximum DATA Chunk Size = PLPMTU - UDP header - SCTP common header | `pmdcs(path)` |
| **PPID** | Payload Protocol Identifier: opaque per-message tag passed through to the peer's ULP | `payload_protocal`, `ppid` |
| **Primary path** | the destination the ULP prefers | `primary_path`, `primary(assoc)` |
| **PTB** | ICMP Packet Too Big (IPv4: Destination Unreachable, Fragmentation Needed) | `handle_icmp_ptb()` |
| **Reneging** | a receiver dropping data it had already gap-acknowledged | the renege branch in `handle_sack` |
| **RTO** | Retransmission TimeOut, per destination | `Peer_Path::rto` |
| **rwnd** | the peer's receive window as we estimate it | `peer_rwnd` |
| **SRTT / RTTVAR** | smoothed RTT and RTT variation | `Peer_Path::srtt`, `rttvar` |
| **SSN** | Stream Sequence Number: per-stream order of ordered messages | `stream_seq_num`, `next_ssn` |
| **ssthresh** | slow-start threshold | `Peer_Path::ssthresh` |
| **State Cookie** | the signed blob that lets the responder avoid holding state before COOKIE ECHO | `State_Cookie`, `Cookie_Auth` |
| **SWS** | Silly Window Syndrome: sending or advertising tiny windows | `cut_new_data` (sender), `make_sack` (receiver) |
| **T1-init / T1-cookie** | handshake retransmission timers | `T1_INIT`, `T1_COOKIE` |
| **T2-shutdown** | SHUTDOWN / SHUTDOWN ACK retransmission timer | `T2_SHUTDOWN` |
| **T3-rtx** | DATA retransmission timer, per destination | `T3_RTX` |
| **T5-shutdown-guard** | overall bound on a shutdown | `T5_SHUTDOWN_GUARD` |
| **TCB** | Transmission Control Block: all per-association state | `Association` |
| **Tie-Tag** | random values copied into cookies so a restart can be told from a stale cookie | `local_tie_tag`, `peer_tie_tag` |
| **Transmission opportunity** | one pass of `run_sending()`. Max.Burst is counted per pass. | `start_transmission_opportunity()` |
| **TSN** | Transmission Sequence Number: per-chunk sequence number, 32-bit serial | `tsn`, `next_tsn` |
| **ULP** | Upper Layer Protocol: the application using the library | |
| **UNCONFIRMED** | a peer address not yet proven reachable by HEARTBEAT ACK | `Peer_Path::confirmed == false` |
| **Verification Tag** | the 32-bit value in every packet's common header proving it belongs to the association | `SCTP_Common_Header::verification_tag` |
| **Zero window probe** | one DATA chunk sent with the peer's window closed, so its SACK can reopen it | `zero_window_probe_allowed`, `zero_window_probing` |

---

## Code names that are easy to confuse

| Pair | Difference |
|---|---|
| `cumulative_tsn_ack` vs `last_peer_tsn` | The peer's ack of **our** DATA (send side), vs **our** ack point for the peer's DATA (receive side). The SACKs we send carry `last_peer_tsn`. |
| `this_ver_tag` vs `peer_ver_tag` | Tag the peer puts on packets **to us**, vs tag we put on packets **to the peer**. |
| `Association_Key` vs `path_key()` vs `Peer_Path.address` | Primary IP + SCTP port (association identity), vs IP only (per-path timer identity), vs IP + **UDP** port (where to send). See [Architecture](01-architecture.md#identity-keys-aliases-and-path-keys). |
| `zero_window_probe_allowed` vs `zero_window_probing` | Permission to send the next probe (set by its timer), vs a probe is outstanding (changes how T3 reacts). |
| `retransmitted` vs `fast_retransmitted` vs `pending_retransmission` | Sent more than once, vs already fast-retransmitted (not again), vs marked to be sent again. |
| `transmits_data()` vs `receives_data()` | States that send DATA and process SACKs, vs states that accept DATA and send SACKs. They differ in `SHUTDOWN_SENT` and `SHUTDOWN_RECEIVED`. |
| `peer_rwnd` vs `our_rwnd` | Our estimate of the peer's window, vs the window we last advertised. |
| `Send_Priority::RETRANSMISSION` | Holds both DATA retransmissions and T1 resends of INIT / COOKIE ECHO. |
| `OP_ERROR` | The ERROR chunk (type 9). Named so to avoid clashing with platform `ERROR` macros. |

---

## Constants

### RFC 9260 §16 protocol parameters

`include/sctp/protocol/sctp.hpp`, `namespace sctp_parameters`:

| Name | Value |
|---|---|
| `RTO_INITIAL` | 1 s |
| `RTO_MIN` | 1 s |
| `RTO_MAX` | 60 s |
| `MAX_BURST` | 4 |
| `RTO_ALPHA` | 1/8 |
| `RTO_BETA` | 1/4 |
| `VALID_COOKIE_LIFE` | 60 s |
| `ASSOCIATION_MAX_RETRANS` | 10 |
| `PATH_MAX_RETRANS` | 5 |
| `MAX_INIT_RETRANSMITS` | 8 |
| `HB_INTERVAL` | 30 s |
| `HB_MAX_BURST` | 1 |
| `SACK_DELAY` | 200 ms |

### PLPMTUD (RFC 8899)

`namespace plpmtud_parameters`: see [PMTU](08-pmtu.md#parameters).

### Implementation constants

| Name | Value | Where | Meaning |
|---|---|---|---|
| `RWND` | 65535 | `sctp.hpp` | receive buffer per association, and the a_rwnd we offer |
| `LOCAL_OUT_STREAMS` | 10 | `builders.hpp` | OS we offer |
| `LOCAL_MAX_IN_STREAMS` | 65535 | `builders.hpp` | MIS we offer |
| `SEND_BUFFER` | 256 KiB | `internal.hpp` | unsent bytes before `QUEUE_FULL` |
| `CLOCK_GRANULARITY` | 1 ms | `internal.hpp` | RTTVAR floor |
| `T5_SHUTDOWN_GUARD` | 5 × RTO_MAX | `internal.hpp` | |
| `SEND_RETRY_DELAY` | 10 ms | `internal.hpp` | back-off after a failed `sendto` |
| `CLOSE_POLL_INTERVAL` / `CLOSE_DRAIN_TIMEOUT` | 10 ms / 100 ms | `internal.hpp` | `sctp_close` waiting for ABORTs to leave |
| `SLOW_START_INCREASE_PMDCS` | 1 | `internal.hpp` | slow start grows at most one PMDCS per SACK |
| `ACKED_RETRANSMISSION_MEMORY` | 64 | `internal.hpp` | retransmitted TSNs remembered for duplicate accounting |
| `MAX_RECEIVE_BATCH` / `MAX_SEND_BATCH` | 64 / 64 | `internal.hpp` | per socket / per pass |
| `MAX_UDP_DATAGRAM` | 65535 | `internal.hpp` | receive buffer |
| `MAX_STALE_COOKIE_RETRIES` | 2 | `internal.hpp` | new INITs after Stale Cookie errors |
| `HEARTBEAT_INFO_SIZE` | 14 | `internal.hpp` | nonce + IPv4 + UDP port |
| `MAX_QUEUED_CONTROL` | 256 | `send_queue.hpp` | control packets queued before new ones are dropped |
| `COOKIE_SECRET_ROTATION` | 60 min | `cookie_auth.cpp` | |
| `MAX_COOKIE_LIFE` | 120 s | `cookie_auth.cpp` | cap on lifespan including Cookie Preservative |
| `STATE_COOKIE_BODY_SIZE` / `MAC_SIZE` | 64 / 32 | `sctp.hpp` | |
| `COOKIE_SECRET_SIZE` | 32 | `sctp.hpp` | |
