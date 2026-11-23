# 7. Paths, multi-homing and encapsulation

Sources: `src/socket/internal.hpp` (path selection helpers),
`src/socket/api.cpp` (`add_peer_addresses`, `record_arrival`, `sctp_bindx`,
heartbeat and primary controls), `src/socket/timers.cpp` (heartbeats, error
counting), `src/socket/handlers.cpp` (`handle_heartbeat_ack`,
`transport_addresses`), `src/socket/event_loop.cpp` (`sending_socket`).

- [Addresses, ports and keys](#addresses-ports-and-keys)
- [Learning the peer's addresses](#learning-the-peers-addresses)
- [Path states](#path-states)
- [Choosing a destination](#choosing-a-destination)
- [Heartbeats](#heartbeats)
- [Failover, end to end](#failover-end-to-end)
- [ULP controls](#ulp-controls)
- [Multiple local addresses](#multiple-local-addresses)
- [UDP encapsulation ports](#udp-encapsulation-ports)

---

## Addresses, ports and keys

A multi-homed peer reached over UDP encapsulation. The peer has one SCTP port,
and each of its addresses may send from a different UDP port (NATs, for
example):

```mermaid
flowchart LR
    subgraph US["Us: SCTP port = UDP port = 9899"]
        L1["10.0.0.1:9899"]
        L2["10.0.1.1:9899"]
    end
    subgraph PEER["Peer: SCTP port 5000"]
        P1["192.0.2.1<br/>UDP 40001"]
        P2["198.51.100.7<br/>UDP 40777"]
    end
    L1 <--> P1
    L2 <--> P2
```

How that peer is represented:

```
associations        key = {192.0.2.1, SCTP 5000}           ← primary address + SCTP port
peer_addresses      {198.51.100.7, SCTP 5000} → {192.0.2.1, SCTP 5000}

Association.peer_address_list
  [0] Peer_Path{ address = 192.0.2.1:40001    confirmed, source = 10.0.0.1 }
  [1] Peer_Path{ address = 198.51.100.7:40777 confirmed, source = 10.0.1.1 }
                         └── sin_port is the UDP port, not the SCTP port

per-path timers     Expiration_Key{ location = key, type, path = {198.51.100.7, port 0} }
```

Two `sockaddr_in` values are the same destination when their IPs match
(`same_destination`). Ports are never compared at the path level.

---

## Learning the peer's addresses

```mermaid
flowchart TD
    subgraph I["We initiate"]
        i1["sctp_associate(ip): path[0] = ip, CONFIRMED"]
        i2["INIT ACK: source + its IPv4 Address params<br/>added UNCONFIRMED"]
        i1 --> i2
    end
    subgraph R["We respond"]
        r1["INIT: source + IPv4 params go into the cookie<br/>(peer_ipv4 + peer_addresses)"]
        r2["COOKIE ECHO: path[0] = INIT source, CONFIRMED<br/>the rest UNCONFIRMED"]
        r1 --> r2
    end
    i2 & r2 --> add["add_peer_addresses():<br/>append missing paths (make_path)<br/>alias each non-primary IP in peer_addresses"]
```

`transport_addresses(src, params)` always puts the packet's source first, then
each IPv4 Address parameter once. Every new path starts with the **source's**
UDP port, until that address sends a packet itself. Host Name Address
parameters are refused with an ABORT (*Unresolvable Address*). IPv6 is not
implemented.

The first path is CONFIRMED because we have a reason to trust it: either the
ULP asked us to connect to it, or it is where the INIT came from and the cookie
came back through it. Every other address must be confirmed by heartbeat
before DATA can go there (§5.4).

---

## Path states

Each `Peer_Path` has two independent booleans:

```mermaid
stateDiagram-v2
    direction LR
    state "UNCONFIRMED, active" as UA
    state "UNCONFIRMED, inactive" as UI
    state "CONFIRMED, active" as CA
    state "CONFIRMED, inactive" as CI

    [*] --> UA : learned from INIT / INIT ACK / cookie
    [*] --> CA : first path
    UA --> CA : HEARTBEAT ACK, nonce matches / ADDR_CONFIRMED
    UA --> UI : errors above Path.Max.Retrans / ADDR_UNREACHABLE
    UI --> CA : HEARTBEAT ACK / ADDR_AVAILABLE, ADDR_CONFIRMED
    CA --> CI : errors above Path.Max.Retrans / ADDR_UNREACHABLE
    CI --> CA : any ack credited to the path / ADDR_AVAILABLE
```

| | DATA | Heartbeats | `sctp_set_primary` | Counts toward AMDCS | PLPMTUD |
|---|:-:|:-:|:-:|:-:|:-:|
| UNCONFIRMED | never | confirmation probes, every RTO | refused | no | off |
| CONFIRMED, active | ✔ | every HB.interval + RTO ± jitter, when idle | ✔ | ✔ | running |
| CONFIRMED, inactive | only if no active path exists | keep probing | ✔ | no | stopped |

---

## Choosing a destination

All helpers are in `internal.hpp`:

```mermaid
flowchart TD
    subgraph DP["data_path(assoc): where new DATA, SACK, SHUTDOWN go"]
        d1{"primary active?"} -- "yes" --> d2(["primary"])
        d1 -- "no" --> d3{"any CONFIRMED and active path?"}
        d3 -- "yes, first in list order" --> d4(["that path"])
        d3 -- "no" --> d2
    end
    subgraph RP["retransmission_path(assoc, last): where timed-out DATA goes"]
        r1{"data_path ≠ last?"} -- "yes" --> r2(["data_path"])
        r1 -- "no" --> r3{"next CONFIRMED and active path<br/>after it in list order (wrapping)?"}
        r3 -- "yes" --> r4(["that path"])
        r3 -- "no" --> r2
    end
    subgraph RD["reply_destination(assoc, src): where replies go"]
        q1{"src is a CONFIRMED path?"} -- "yes" --> q2(["src"])
        q1 -- "no" --> q3(["data_path"])
    end
```

`primary(assoc)` is the path matching `primary_path`. If it is missing, the
first path in the list is used. `amdcs(assoc)` is the smallest PMDCS over
CONFIRMED, active paths (`BASE_PMDCS` if there are none). New DATA is cut to
this size so it fits whichever path a retransmission ends up on.

---

## Heartbeats

### Scheduling

`plan_next_probe(assoc, path, now)` sets the next probe time:

```
hb_period_start = now
CONFIRMED path:            hb_next = now + HB.interval + RTO + U(-RTO/2, +RTO/2)
path being confirmed:      hb_next = now + RTO
```

`arm_heartbeat()` then sets the path's HEARTBEAT timer:

```mermaid
flowchart LR
    a{"probe outstanding?"} -- "yes" --> o(["fire at hb_sent_at + RTO"])
    a -- "no" --> b{"disabled, or UNCONFIRMED + active<br/>but not its turn to be probed?"}
    b -- "yes" --> c(["cancel"])
    b -- "no" --> n(["fire at hb_next"])
```

**Confirmation in turns.** `probes_for_confirmation()` lets only
`HB_MAX_BURST` (1) UNCONFIRMED, active, enabled path be probed at a time, in
list order. When that path confirms or fails, `arm_confirmation_probes()`
starts the next one at once.

### When the HEARTBEAT timer fires

```mermaid
flowchart TD
    f["HEARTBEAT timer for path P"] --> st{"TCB transmits_data?"}
    st -- "no" --> x(["ignore"])
    st -- "yes" --> out{"probe outstanding?"}
    out -- "yes: unanswered" --> fail["outstanding = false<br/>back_off(P)<br/>count_path_error(P)"]
    fail --> dp{"P is the CONFIRMED data path?"}
    dp -- "yes" --> ae{"++assoc error_count above 10?"}
    ae -- "yes" --> lost(["remove, COMM_LOST"])
    ae -- "no" --> turn
    dp -- "no" --> turn["if P was being confirmed and went inactive:<br/>arm_confirmation_probes() (next one's turn)"]
    turn --> due{"P's turn to be confirmed,<br/>or now ≥ hb_next?"}
    due -- "no" --> arm
    out -- "no" --> en
    due -- "yes" --> en{"heartbeats enabled on P?"}
    en -- "no" --> arm
    en -- "yes" --> idle{"new DATA sent to P since<br/>hb_period_start?"}
    idle -- "no: idle" --> send["enqueue HEARTBEAT (fresh nonce)"]
    idle -- "yes: busy" --> plan
    send --> plan["plan_next_probe(P)"]
    plan --> arm["arm_heartbeat(P)"]
```

A path that carried new DATA during the period is already proving itself
through SACKs, so it is not probed (§8.3).

### The Heartbeat Info

The HEARTBEAT chunk carries a 14-byte Heartbeat Info that only we interpret:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     nonce, high 32 bits                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     nonce, low 32 bits                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               destination IPv4 address (as in sin_addr)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  destination UDP port (as in  |
|  sin_port)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- The **nonce** is random per probe (`build_probe`). It tells this ACK apart
  from one answering an older probe, which would otherwise clear a failing
  path's error count.
- The **destination** says which path the ACK is for. It may arrive on a
  different path (§5.4 / §8.3).
- There is **no timestamp**. The send time is recorded on the path when the
  packet leaves (`record_heartbeat_sent`), which is more accurate and cannot be
  forged.

### HEARTBEAT ACK

```mermaid
flowchart TD
    a["HEARTBEAT ACK"] --> s{"Info is 14 bytes and TCB exists?"}
    s -- "no" --> x(["ignore"])
    s -- "yes" --> p["P = path named in the Info"]
    p --> pm{"P has a PLPMTU probe out<br/>with this nonce?"}
    pm -- "yes" --> pp(["handle_plpmtu_probe_ack()"])
    pm -- "no" --> m{"P has a heartbeat out<br/>with this nonce?"}
    m -- "no" --> x
    m -- "yes" --> ok["outstanding = false<br/>update_rto(P, now - hb_sent_at)<br/>clear_path_errors(P)<br/>if P is the data path: assoc error_count = 0"]
    ok --> c{"P UNCONFIRMED?"}
    c -- "yes" --> cf["confirmed = true, ADDR_CONFIRMED<br/>start PLPMTUD<br/>plan_next_probe"]
    c -- "no" --> re
    cf --> re["arm_heartbeat(P)<br/>arm_confirmation_probes()"]
```

---

## Failover, end to end

```mermaid
sequenceDiagram
    autonumber
    participant A as Us
    participant P1 as Peer addr 1 (primary)
    participant P2 as Peer addr 2 (confirmed)

    A->>P1: DATA
    Note over P1: path 1 goes dark
    Note over A: T3 on path 1: cwnd = 1 PMDCS, RTO doubles<br/>path errors 1, assoc errors 1<br/>timed-out chunks moved to retransmission_path = path 2
    A->>P2: retransmitted DATA
    P2->>A: SACK
    Note over A: assoc error_count = 0 (data acked)<br/>new DATA still goes to the primary while it is active
    A->>P1: DATA ... T3 again ... and again
    Note over A: path 1 error_count above 5:<br/>inactive, ADDR_UNREACHABLE, PLPMTUD stopped<br/>data_path() now returns path 2
    A->>P2: all new DATA
    A->>P1: HEARTBEATs continue (backed-off RTO)
    P1->>A: HEARTBEAT ACK (path recovered)
    Note over A: clear_path_errors: active, ADDR_AVAILABLE<br/>PLPMTUD restarts<br/>data_path() is the primary again
    A->>P1: new DATA
```

---

## ULP controls

| Call | Effect |
|---|---|
| `sctp_change_heartbeat(key, dest, enabled, interval?)` | Sets `hb_enabled` on that path. A new `interval` replaces `hb_interval` for **every** path. Each affected path without a probe out is re-planned (probed at once if it is its turn for confirmation) and re-armed, then the confirmation turns are re-armed. In forming or closing states the settings are stored but no timers are armed. |
| `sctp_request_heartbeat(key, dest)` | Sends a HEARTBEAT to that path now (fresh nonce) and arms its timer for the answer. Only in `transmits_data` states. |
| `sctp_set_primary(key, dest)` | Sets `primary_path`. Refused (`UNCONFIRMED_DESTINATION`) for a path that is not CONFIRMED. |

Destinations are matched by IP only, so the port in the `sockaddr_in` the ULP
passes does not matter.

---

## Multiple local addresses

```mermaid
flowchart LR
    subgraph S["SCTP_Socket after sctp_bindx({A, B, C}, 9899)"]
        u["udp_socket<br/>bound A:9899<br/>(local_address)"]
        o1["other_local_addresses[0]<br/>bound B:9899"]
        o2["other_local_addresses[1]<br/>bound C:9899"]
    end
    EL["event_loop polls all three"] --> u & o1 & o2
    u & o1 & o2 -- "run_receiving(socket, local)" --> H["handle_recv_packet(..., local)"]
```

- **Advertised.** When more than one address is bound,
  `advertised_addresses()` lists all of them as IPv4 Address parameters in
  INIT and INIT ACK. With one address it returns an empty list, so the peer
  uses the packet's source.
- **Same port.** Extra addresses are bound at the first socket's port, even
  when port 0 asked for an ephemeral one (§1.3: one port per endpoint).
- **Wildcard.** `0.0.0.0` must be bound alone.

### Which socket sends

```mermaid
flowchart TD
    d["Deliverable"] --> one{"only one address bound?"}
    one -- "yes" --> u(["udp_socket"])
    one -- "no" --> s{"deliverable.source set?<br/>(a reply: set by enqueue_packet<br/>from inbound_datagram)"}
    s -- "yes" --> m
    s -- "no" --> ps["source = Peer_Path.source<br/>(where that path's packets last arrived)"]
    ps --> m{"an extra socket bound<br/>to that source?"}
    m -- "yes" --> o(["that socket"])
    m -- "no" --> u
```

`Peer_Path.source` is set by `record_arrival()` for every packet that passes the
tag check, except one led by an INIT.

---

## UDP encapsulation ports

RFC 6951 puts SCTP inside UDP. The UDP port and the SCTP port are separate:

| | SCTP port | UDP port |
|---|---|---|
| Ours | `local_address.sin_port`. Our SCTP port **is** our UDP port. | same |
| Peer | in `Association_Key`, fixed for the association | per path in `Peer_Path.address.sin_port`, learned |

- `sctp_associate(ip, port, out, udp_port)`: `port` is the peer's SCTP port.
  `udp_port` (default: the same as `port`) is where to send the INIT.
- A path's UDP port is updated by `record_arrival()` from the source port of
  each packet that **passed the Verification Tag check**. An attacker therefore
  cannot redirect a path with a forged packet.
- The State Cookie records the UDP port the INIT came from
  (`peer_udp_port`), so the responder's first path starts with the right one.
- Notifications report a peer address with the **SCTP** port
  (`notify_peer_addr_change` swaps it in), not the UDP port.
