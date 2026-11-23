# 3. Association lifecycle

Sources: `src/socket/handlers.cpp` (`handle_init`, `handle_init_ack`,
`handle_cookie_echo`, `handle_cookie_ack`, `handle_error`, `handle_shutdown*`,
`handle_abort`, `abort_association`, `do_next_shutdown_step`),
`src/socket/api.cpp` (`sctp_associate`, `sctp_shutdown`, `sctp_abort`,
`init_new_association`, `remove_association`), `src/socket/timers.cpp` (T1, T2, T5).

- [State machine](#state-machine)
- [Which Verification Tag each chunk carries](#which-verification-tag-each-chunk-carries)
- [Initiating: the four-way handshake](#initiating-the-four-way-handshake)
- [Responding: no state until the cookie returns](#responding-no-state-until-the-cookie-returns)
- [`handle_init` in detail](#handle_init-in-detail)
- [`handle_init_ack` in detail](#handle_init_ack-in-detail)
- [`handle_cookie_echo`: Table 12](#handle_cookie_echo-table-12)
- [INIT collision](#init-collision)
- [Peer restart](#peer-restart)
- [Stale cookie recovery](#stale-cookie-recovery)
- [Graceful shutdown](#graceful-shutdown)
- [Abort and teardown](#abort-and-teardown)

---

## State machine

`Association_State` in `association.hpp`. CLOSED is not a state in the code:
it means "no entry in `associations`".

```mermaid
stateDiagram-v2
    direction TB
    [*] --> COOKIE_WAIT : sctp_associate / INIT, T1-init
    [*] --> ESTABLISHED : valid COOKIE ECHO / COOKIE ACK, COMM_UP

    COOKIE_WAIT --> COOKIE_ECHOED : INIT ACK / COOKIE ECHO, T1-cookie
    COOKIE_WAIT --> ESTABLISHED : COOKIE ECHO case B / COMM_UP
    COOKIE_ECHOED --> ESTABLISHED : COOKIE ACK or COOKIE ECHO case B or D / COMM_UP
    COOKIE_ECHOED --> COOKIE_WAIT : ERROR Stale Cookie / INIT with Preservative

    ESTABLISHED --> SHUTDOWN_PENDING : sctp_shutdown
    ESTABLISHED --> SHUTDOWN_RECEIVED : SHUTDOWN
    SHUTDOWN_PENDING --> SHUTDOWN_RECEIVED : SHUTDOWN
    SHUTDOWN_PENDING --> SHUTDOWN_SENT : all DATA acked / SHUTDOWN, T2, T5
    SHUTDOWN_RECEIVED --> SHUTDOWN_ACK_SENT : all DATA acked / SHUTDOWN ACK, T2
    SHUTDOWN_SENT --> SHUTDOWN_ACK_SENT : SHUTDOWN, collision / SHUTDOWN ACK

    SHUTDOWN_SENT --> [*] : SHUTDOWN ACK / SHUTDOWN COMPLETE, SHUTDOWN_COMP
    SHUTDOWN_ACK_SENT --> [*] : SHUTDOWN COMPLETE or SHUTDOWN ACK / SHUTDOWN_COMP

    COOKIE_WAIT --> [*] : T1 exhausted, ABORT, refused INIT ACK / CANT_STR_ASSOC
    COOKIE_ECHOED --> [*] : T1 exhausted, ABORT, stale retries spent / CANT_STR_ASSOC
```

Not drawn, to keep the diagram readable: from **every** state, a valid ABORT,
`sctp_abort()`, a protocol violation, or Association.Max.Retrans being exceeded
removes the TCB. The notification is `COMM_LOST`, or `CANT_STR_ASSOC` while
forming. From `SHUTDOWN_SENT` and `SHUTDOWN_ACK_SENT`, T5 does the same.

### What each state allows

The predicates in `internal.hpp` are the single source of truth:

| State | `is_forming` | `transmits_data` (send DATA, process SACK, heartbeats) | `receives_data` (accept DATA, send SACK) | `sctp_send_data` |
|---|:-:|:-:|:-:|:-:|
| `COOKIE_WAIT` | ✔ | | | `NOT_ESTABLISHED` |
| `COOKIE_ECHOED` | ✔ | | | `NOT_ESTABLISHED` |
| `ESTABLISHED` | | ✔ | ✔ | ✔ |
| `SHUTDOWN_PENDING` | | ✔ | ✔ | `SHUTTING_DOWN` |
| `SHUTDOWN_SENT` | | | ✔ | `SHUTTING_DOWN` |
| `SHUTDOWN_RECEIVED` | | ✔ | | `SHUTTING_DOWN` |
| `SHUTDOWN_ACK_SENT` | | | | `SHUTTING_DOWN` |

---

## Which Verification Tag each chunk carries

| Sent chunk | Header Verification Tag | T bit | Built in |
|---|---|:-:|---|
| INIT | `0` | | `build_init` |
| INIT ACK | the peer's Initiate Tag from the INIT | | `handle_init` |
| COOKIE ECHO, COOKIE ACK, DATA, SACK, HEARTBEAT, HEARTBEAT ACK, SHUTDOWN, SHUTDOWN ACK, ERROR | `peer_ver_tag` | | `packet_to`, `reply` |
| ABORT inside an association | `peer_ver_tag` | 0 | `sctp_abort`, `abort_association`, T5 |
| ABORT answering an OOTB packet | the received header's tag, reflected | 1 | `answer_ootb` |
| ABORT answering an INIT with Initiate Tag 0 | the received header's tag, reflected | 1 | `handle_init` |
| ABORT refusing an INIT ACK with Initiate Tag 0 | the received header's tag, reflected | 1 | `handle_init_ack` |
| SHUTDOWN COMPLETE inside an association | `peer_ver_tag` | 0 | `handle_shutdown_ack` |
| SHUTDOWN COMPLETE answering an OOTB SHUTDOWN ACK | the received header's tag, reflected | 1 | `answer_ootb` |

On the receive side these are checked by `validate_verification_tag()`. See
[Inbound: tag validation](04-inbound.md#verification-tag-validation).

---

## Initiating: the four-way handshake

```mermaid
sequenceDiagram
    autonumber
    participant U as ULP
    participant A as Us (initiator)
    participant Z as Peer (responder)

    U->>A: sctp_associate(ip, port)
    Note over A: init_new_association()<br/>random this_ver_tag (non-zero), next_tsn<br/>out_streams=10, in_streams=65535 (upper bounds)<br/>state = COOKIE_WAIT
    A->>Z: INIT [tag 0] Initiate Tag, a_rwnd, OS, MIS, TSN, our IPv4 list
    Note over A: on send: T1-init = RTO.Initial × 2^n (≤ RTO.Max), keeps INIT for retry
    Z->>A: INIT ACK [our tag] peer tag, TSN, State Cookie, its IPv4 list
    Note over A: validate, add_peer_addresses (UNCONFIRMED)<br/>negotiate streams: min(ours, theirs)<br/>cancel T1-init, drop queued INIT retransmissions<br/>state = COOKIE_ECHOED
    A->>Z: COOKIE ECHO [peer tag] (+ ERROR: Unrecognized Parameters)
    Note over A: on send: T1-cookie armed the same way
    Z->>A: COOKIE ACK [our tag]
    Note over A: state = ESTABLISHED<br/>cancel T1-cookie<br/>start_heartbeats(): HB timers, PLPMTUD
    A-->>U: notification COMM_UP
```

### T1 retransmission

T1 does **not** use the path RTO. It uses `RTO_INITIAL` (1 s), doubled per
retransmission and capped at `RTO_MAX` (60 s). The doubling is applied when
the timer is armed in `schedule_expirations_after_send`:

```
retransmits:  0    1    2    3    4     5     6     7     8
T1 delay:     1s   2s   4s   8s   16s   32s   60s   60s   60s   -> then CANT_STR_ASSOC
```

When it expires, `handle_expiration` checks that the TCB is still in the state
the timer belongs to (`COOKIE_WAIT` for T1-init, `COOKIE_ECHOED` for
T1-cookie). If `MAX_INIT_RETRANSMITS` (8) has been reached, the association is
removed with `CANT_STR_ASSOC`. Otherwise the stored packet is re-enqueued at
`RETRANSMISSION` priority.

---

## Responding: no state until the cookie returns

```mermaid
sequenceDiagram
    autonumber
    participant Z as Peer (initiator)
    participant B as Us (responder)
    participant C as Cookie_Auth

    Z->>B: INIT [tag 0]
    Note over B: handle_init(): validate<br/>random local tag + TSN<br/>NO TCB is created
    B->>C: generate(header, init, src, tags, TSN, tie-tags, preservative, addresses)
    C-->>B: 64-byte body + 4 per extra address + 32-byte HMAC
    B->>Z: INIT ACK [peer tag] local tag, TSN, State Cookie, our IPv4 list
    Z->>B: COOKIE ECHO [our tag] (+ DATA ...)
    B->>C: verify(cookie, header, src)
    C-->>B: VALID + decoded State_Cookie
    Note over B: init_new_association(cookie): ESTABLISHED<br/>add_peer_addresses from cookie<br/>start_heartbeats()
    B-->>B: notification COMM_UP
    B->>Z: COOKIE ACK [peer tag]
    Note over B: bundled DATA is processed and SACKed at once
```

The responder holds no memory per INIT, which is the SYN-flood defence of
§5.1.3. The cookie carries everything `init_new_association(const
State_Cookie&)` needs: both tags, both initial TSNs, the peer's a_rwnd, the
stream counts both sides offered, the tie-tags, and the peer's address list.
See [State cookies](10-cookies-and-crypto.md).

---

## `handle_init` in detail

```mermaid
flowchart TD
    in["INIT arrives, tag check passed<br/>(header tag 0, chunk alone)"] --> z{"Initiate Tag == 0?"}
    z -- "yes" --> ab1["ABORT, reflected tag, T bit<br/>Invalid Mandatory Parameter"]
    z -- "no" --> s{"OS == 0 or MIS == 0?"}
    s -- "yes" --> ab2["ABORT under Initiate Tag<br/>Invalid Mandatory Parameter"]
    s -- "no" --> hn{"Host Name Address<br/>parameter?"}
    hn -- "yes" --> ab3["ABORT under Initiate Tag<br/>Unresolvable Address"]
    hn -- "no" --> prep["collect addresses: source + IPv4 params<br/>read Cookie Preservative<br/>fresh local tag + TSN, tie-tags = 0"]
    prep --> tcb{"TCB for this peer?"}
    tcb -- "no" --> mk
    tcb -- "SHUTDOWN_ACK_SENT" --> sa["resend SHUTDOWN ACK<br/>(no INIT ACK)"]
    tcb -- "COOKIE_WAIT" --> cw["reuse our tag + TSN<br/>reply to primary path"]
    tcb -- "any other state" --> na{"INIT lists an address<br/>the TCB lacks?"}
    na -- "yes" --> ab4["ABORT under Initiate Tag<br/>Restart With New Addresses"]
    na -- "no" --> ce{"COOKIE_ECHOED?"}
    ce -- "yes" --> reuse["reuse our tag + TSN"]
    ce -- "no" --> tie
    reuse --> tie["tie-tags: generate once per TCB, then reuse"]
    cw --> mk
    tie --> mk["Cookie_Auth::generate()<br/>trim Unrecognized Parameter reports to fit BASE_PMDCS"]
    mk --> ack["INIT ACK"]
```

An existing TCB is **never changed** by an INIT, apart from generating its
tie-tags once. An INIT carries no proof of where it came from, so all
decisions are deferred to the COOKIE ECHO.

---

## `handle_init_ack` in detail

Accepted only in `COOKIE_WAIT`. Any other INIT ACK is silently dropped.

```mermaid
flowchart TD
    ia["INIT ACK, tag matched this_ver_tag"] --> st{"TCB in COOKIE_WAIT?"}
    st -- "no" --> drop(["discard"])
    st -- "yes" --> v1{"Initiate Tag 0?"}
    v1 -- "yes" --> ref["refuse:<br/>remove TCB, CANT_STR_ASSOC<br/>ABORT with the cause"]
    v1 -- "no" --> v2{"State Cookie missing?"}
    v2 -- "yes" --> ref
    v2 -- "no" --> v3{"OS or MIS 0?"}
    v3 -- "yes" --> ref
    v3 -- "no" --> v4{"Host Name Address?"}
    v4 -- "yes" --> ref
    v4 -- "no" --> ok["add_peer_addresses (UNCONFIRMED)<br/>peer_ver_tag, last_peer_tsn, peer_rwnd<br/>out = min(10, peer MIS), in = min(65535, peer OS)<br/>state = COOKIE_ECHOED<br/>cancel T1-init, drop queued INIT"]
    ok --> echo["COOKIE ECHO<br/>+ ERROR Unrecognized Parameters if any<br/>(trimmed to fit the AMDCS)"]
```

The refusal ABORT goes out under the INIT ACK's Initiate Tag. If that tag is
0, the ABORT reflects the received header tag and sets the T bit.

---

## `handle_cookie_echo`: Table 12

The COOKIE ECHO is the only chunk that may arrive under a tag the TCB does not
hold. `validate_verification_tag()` lets it through, and
`handle_recv_packet` runs it **first**. If it returns `false`, the rest of the
packet is discarded. `handle_cookie_echo` also *re-keys* the packet: `key`
becomes the association named in the cookie.

```mermaid
flowchart TD
    ce["COOKIE ECHO"] --> ver["Cookie_Auth::verify()"]
    ver -- "INVALID" --> drop(["discard packet"])
    ver -- "VALID or STALE" --> key["key = association_key_for(cookie_key(cookie))"]
    key --> ex{"TCB exists?"}
    ex -- "no, STALE" --> stale1["ERROR Stale Cookie<br/>discard rest"]
    ex -- "no, VALID" --> new["new TCB, ESTABLISHED<br/>COMM_UP, heartbeats<br/>COOKIE ACK"]
    ex -- "yes" --> cmp["compare cookie tags with TCB:<br/>L = local tag match<br/>P = peer tag match<br/>T = tie-tags match (non-zero)"]
    cmp --> st2{"STALE and not (L and P)?"}
    st2 -- "no" --> d{"L and P"}
    st2 -- "yes" --> stale2["ERROR Stale Cookie<br/>discard rest"]
    d -- "yes: case D" --> D["if COOKIE_ECHOED: ESTABLISHED, COMM_UP<br/>else nothing: duplicate echo"]
    d -- "no" --> a{"not L, not P, T"}
    a -- "yes: case A" --> A{"SHUTDOWN_ACK_SENT?"}
    A -- "yes" --> A1["resend SHUTDOWN ACK under old tag<br/>ERROR Cookie Received While Shutting Down<br/>discard rest"]
    A -- "no" --> A2["peer restart:<br/>cancel timers, purge queues, drop aliases<br/>abandon partial delivery<br/>TCB = init_new_association(cookie)<br/>RESTART"]
    a -- "no" --> b{"L only"}
    b -- "yes: case B" --> B["collision: adopt peer tag, TSN, rwnd<br/>clear receive-side state<br/>if forming: ESTABLISHED, COMM_UP<br/>else: re-arm confirmation probes"]
    b -- "no: case C, other" --> drop2(["discard packet"])
    D & A2 & B --> fin["cancel T1-init and T1-cookie<br/>drop queued INIT / COOKIE ECHO<br/>COOKIE ACK"]
```

| Case | Local tag | Peer tag | Tie-tags | Meaning | Action |
|:-:|:-:|:-:|:-:|---|---|
| A | ✗ | ✗ | match | Peer restarted | Replace the TCB, notify `RESTART` |
| B | ✔ | ✗ | any | Simultaneous INITs crossed | Adopt the peer's new parameters |
| C | ✗ | ✔ | 0 | Late cookie from an old attempt | Silently discard |
| D | ✔ | ✔ | any | Our COOKIE ACK was lost | Re-ACK, and enter `ESTABLISHED` if still `COOKIE_ECHOED` |

A Tie-Tag of 0 means "none" and never matches.

---

## INIT collision

Both ends call `sctp_associate()` at the same time:

```mermaid
sequenceDiagram
    autonumber
    participant A as Endpoint A
    participant B as Endpoint B
    Note over A,B: both in COOKIE_WAIT, tags Ta and Tb
    A->>B: INIT (Initiate Tag Ta)
    B->>A: INIT (Initiate Tag Tb)
    Note over A: handle_init, COOKIE_WAIT branch:<br/>reuse Ta and our TSN
    A->>B: INIT ACK [Tb] tag Ta, cookie(Ta, Tb)
    Note over B: same, reuses Tb
    B->>A: INIT ACK [Ta] tag Tb, cookie(Tb, Ta)
    Note over A: handle_init_ack: COOKIE_ECHOED, peer tag Tb
    A->>B: COOKIE ECHO [Tb] cookie(Tb, Ta)
    B->>A: COOKIE ECHO [Ta] cookie(Ta, Tb)
    Note over A: verify cookie(Ta, Tb):<br/>local Ta matches, peer Tb matches: case D<br/>COOKIE_ECHOED to ESTABLISHED
    A->>B: COOKIE ACK
    Note over B: symmetric: case D
    B->>A: COOKIE ACK
    Note over A,B: COOKIE ACK in ESTABLISHED is ignored
```

Because both sides reuse their tags in `COOKIE_WAIT`, the crossing cookies
match as case D. Case B handles the orderings where one side has already
learned a different peer tag.

---

## Peer restart

The peer crashes and comes back while we still hold an `ESTABLISHED` TCB:

```mermaid
sequenceDiagram
    autonumber
    participant Z as Peer (restarted)
    participant B as Us (old TCB: tags Lo, Po)
    Z->>B: INIT (new tag Pn), same addresses
    Note over B: handle_init, default branch:<br/>no new addresses<br/>generate tie-tags once: Lt, Pt
    B->>Z: INIT ACK [Pn] fresh tag Ln, cookie(Ln, Pn, Lt, Pt)
    Z->>B: COOKIE ECHO [Ln]
    Note over B: Ln≠Lo, Pn≠Po, tie-tags match: case A<br/>cancel timers, purge send queue,<br/>forget aliases, abandon partial delivery<br/>TCB = init_new_association(cookie)
    B-->>B: notification RESTART
    B->>Z: COOKIE ACK [Pn]
```

If the restarted peer lists an address the old TCB does not have, `handle_init`
refuses with ABORT + *Restart of an Association with New Addresses* (cause 11).
The ABORT lists the new addresses.

---

## Stale cookie recovery

```mermaid
sequenceDiagram
    autonumber
    participant A as Us (initiator)
    participant Z as Peer
    A->>Z: COOKIE ECHO
    Z->>A: ERROR: Stale Cookie, staleness = s µs
    Note over A: handle_error in COOKIE_ECHOED:<br/>cancel T1-cookie, drop queued COOKIE ECHO
    alt stale_cookie_retries below 2
        Note over A: ++retries, state = COOKIE_WAIT<br/>peer_ver_tag = 0, T1 counters reset
        A->>Z: INIT + Cookie Preservative = s_ms + min(s_ms, 1000)
        Note over Z: lifespan = 60 s + preservative, capped at 120 s
    else retries spent
        Note over A: remove TCB, CANT_STR_ASSOC
    end
```

`s_ms` is `staleness_us / 1000 + 1`. The INIT reuses our original tag and TSN.
Every other ERROR is passed to the ULP as `SCTP_REMOTE_ERROR` with all its
causes raw, including codes the stack does not act on.

---

## Graceful shutdown

```mermaid
sequenceDiagram
    autonumber
    participant U as ULP
    participant A as Us
    participant Z as Peer

    U->>A: sctp_shutdown(key)
    Note over A: SHUTDOWN_PENDING<br/>new sends refused, queued data still goes
    A->>Z: remaining DATA (last chunk I bit set)
    Z->>A: SACK (immediate, I bit)
    Note over A: do_next_shutdown_step():<br/>cumulative_tsn_ack == next_tsn - 1<br/>and outbound empty
    A->>Z: SHUTDOWN (Cumulative TSN Ack = last_peer_tsn)
    Note over A: SHUTDOWN_SENT<br/>cancel HEARTBEAT, DELAYED_SACK, T3<br/>arm T2 (RTO) and T5 (5 × RTO.Max)
    Note over Z: SHUTDOWN_RECEIVED<br/>applies cum ack, finishes its own DATA
    Z->>A: DATA ...
    A->>Z: SHUTDOWN (+ SACK if gaps, dups or drops)
    Z->>A: SHUTDOWN ACK
    Note over A: remove TCB
    A->>Z: SHUTDOWN COMPLETE
    A-->>U: notification SHUTDOWN_COMP
```

Details that are easy to miss:

- **Readiness is cumulative.** `do_next_shutdown_step` compares
  `cumulative_tsn_ack` against `next_tsn - 1` and requires `outbound` to be
  empty. Checking that `outstanding_data` is empty would not be enough: DATA
  can be in the send queue with a TSN but no outstanding entry yet.
- **SHUTDOWN is treated as a SACK without gap blocks.** `handle_shutdown`
  removes outstanding data up to the Cumulative TSN Ack. Chunks that were
  gap-acked stay gap-acked: a missing block is not reneging (§3.3.8). If the
  ack covers TSNs we never sent, the association is aborted with Protocol
  Violation.
- **In `SHUTDOWN_SENT`, every packet from the peer resets the clock.**
  `error_count = 0` and T2 restarts. T5 is armed once and never pushed back,
  so it is the bound the peer cannot extend.
- **A resent SHUTDOWN is rebuilt.** T2 builds a new SHUTDOWN with the current
  `last_peer_tsn`, backs off the data path's RTO, and counts an association
  error.
- **Shutdowns can collide.** A SHUTDOWN arriving in `SHUTDOWN_SENT` moves to
  `SHUTDOWN_ACK_SENT` and answers with SHUTDOWN ACK. A SHUTDOWN ACK arriving in
  `SHUTDOWN_ACK_SENT` completes the shutdown in the same way as in
  `SHUTDOWN_SENT`.
- **No HEARTBEAT ACK is sent** in `SHUTDOWN_SENT` or `SHUTDOWN_ACK_SENT`.

---

## Abort and teardown

### `remove_association(key, state?)`

Every teardown goes through this function, in this order:

```mermaid
flowchart LR
    a["abandon_partial_delivery()<br/>drop the half-delivered message<br/>from Receive_Queue"] --> b["erase TCB"] --> c["forget_peer_addresses()<br/>drop aliases"] --> d["cancel_expirations()<br/>every timer of the association"] --> e["Send_Queue::purge()"] --> f["notify ASSOC_CHANGE<br/>if a state was given"]
```

Any ABORT is enqueued **after** `remove_association()` returns. Otherwise the
purge would drop it together with the DATA that must not be sent alongside it.
Messages already complete in `Receive_Queue` survive, so the ULP can still
read them.

### What triggers an abort

| Trigger | Where | Cause sent | Notification |
|---|---|---|---|
| ULP `sctp_abort(key, reason)` | `api.cpp` | User-Initiated Abort (12) with the reason | none |
| SACK acknowledges a TSN not yet sent | `handle_sack` | Protocol Violation (13) | `COMM_LOST` |
| SHUTDOWN Cumulative TSN Ack ≥ `next_tsn` | `handle_shutdown` | Protocol Violation (13) | `COMM_LOST` |
| DATA chunk with no user data | `handle_data_packet` | No User Data (9) + the TSN | `COMM_LOST` |
| DATA framing broken (B/E bits, stream or SSN mismatch inside a message) | `handle_data_packet` | Protocol Violation (13) | `COMM_LOST` |
| T5 shutdown guard | `handle_t5_expiration` | none | `COMM_LOST` |
| Association.Max.Retrans exceeded (T3, data-path heartbeat, T2) | `timers.cpp` | **no ABORT**: the peer is unreachable | `COMM_LOST` |
| ABORT received | `handle_abort` | | `COMM_LOST`, or `CANT_STR_ASSOC` while forming |

`abort_association()` sends the ABORT only when `peer_ver_tag != 0`. In
`COOKIE_WAIT` there is no tag the peer would accept.
