# 4. Inbound path

Sources: `src/socket/handlers.cpp`. Entry point: `SCTP_Socket::handle_recv_packet`.

- [Pipeline](#pipeline)
- [Finding the association](#finding-the-association)
- [Verification Tag validation](#verification-tag-validation)
- [Out-of-the-blue packets](#out-of-the-blue-packets)
- [Unrecognized chunk types](#unrecognized-chunk-types)
- [Dispatch](#dispatch)
- [DATA reception](#data-reception)
  - [Receive-side data structures](#receive-side-data-structures)
  - [Per-chunk processing](#per-chunk-processing)
  - [Receive buffer and drop policy](#receive-buffer-and-drop-policy)
  - [Reassembly and ordering](#reassembly-and-ordering)
  - [Early assembly: a gap blocks only its own stream](#early-assembly-a-gap-blocks-only-its-own-stream)
  - [Partial delivery](#partial-delivery)
  - [Worked example](#worked-example)
- [Acknowledging: when to SACK](#acknowledging-when-to-sack)
- [Building a SACK](#building-a-sack)
- [The advertised window](#the-advertised-window)
- [HEARTBEAT](#heartbeat)

---

## Pipeline

```mermaid
flowchart TD
    rx["datagram (buf, n, src, local)"] --> len{"n ≥ 12?"}
    len -- "no" --> drop(["drop"])
    len -- "yes" --> tl["set thread_local inbound_datagram"]
    tl --> crc{"CRC-32C matches?<br/>(computed over a copy with<br/>checksum field zeroed)"}
    crc -- "no" --> drop
    crc -- "yes" --> parse{"deserialize_sctp_packet()"}
    parse -- "throws" --> drop
    parse -- "ok" --> lock["lock associations_mutex"]
    lock --> find["find association<br/>by source address, then INIT addresses"]
    find --> tag{"validate_verification_tag()"}
    tag -- "false: answered or dropped" --> stop(["return"])
    tag -- "true" --> unk["strip unrecognized chunk types<br/>by upper two bits, collect reports"]
    unk --> ce{"first chunk COOKIE ECHO?"}
    ce -- "yes" --> hce{"handle_cookie_echo()<br/>may re-key the packet"}
    hce -- "false" --> stop
    hce -- "true" --> arr
    ce -- "no" --> arr{"first chunk INIT?"}
    arr -- "no" --> rec["record_arrival(): path UDP port<br/>and local address"]
    arr -- "yes" --> ss
    rec --> ss{"TCB in SHUTDOWN_SENT?"}
    ss -- "yes" --> t2["error_count = 0, restart T2"]
    ss -- "no" --> disp
    t2 --> disp["dispatch each non-DATA chunk in order<br/>(ABORT ends processing)"]
    disp --> data["handle_data_packet(): all DATA at once"]
    data --> rep{"unrecognized reports?"}
    rep -- "yes" --> err["ERROR, trimmed to the AMDCS"]
    rep -- "no" --> done(["return"])
    err --> done
```

The checksum and parse happen **before** the lock is taken. Corrupt input
therefore never touches association state and never contends for the lock.

---

## Finding the association

```mermaid
flowchart LR
    a["peer_key(src, header.src_port)<br/>UDP port dropped"] --> b{"association_at():<br/>in peer_addresses?"}
    b -- "yes" --> k(["its id"])
    b -- "no" --> d{"packet leads with<br/>INIT or INIT ACK?"}
    d -- "no" --> k3(["id 0: no TCB"])
    d -- "yes" --> e["for each address the chunk lists<br/>(source + IPv4 parameters):<br/>association_at(address)"]
    e -- "one maps to a TCB" --> k4(["that id"])
    e -- "none" --> k3
```

Every peer address is in `peer_addresses`, so one lookup covers all of them.
The INIT step means that an INIT or INIT ACK sent from a peer address we have
not seen yet still finds the TCB, as long as it lists an address we know.
That is how a restart or collision arriving from an alternate address is
matched to the existing association.

---

## Verification Tag validation

`validate_verification_tag(pkt, key, src)` returns `true` ("accept" below) when
the packet goes on to dispatch, and `false` ("drop") when it goes no further. Where §8.4 or §8.5 requires an answer, it has already been
enqueued by then.

```mermaid
flowchart TD
    p["packet"] --> e{"any chunks?"}
    e -- "no" --> F0(["drop"])
    e -- "yes" --> port{"dest port == our port?"}
    port -- "no" --> pi{"first chunk INIT?"}
    pi -- "no" --> oo1["answer_ootb()"] --> F1(["drop"])
    pi -- "yes" --> pz{"tag 0, alone,<br/>Initiate Tag ≠ 0?"}
    pz -- "yes" --> ab["ABORT under Initiate Tag"] --> F2(["drop"])
    pz -- "no" --> F3(["drop"])
    port -- "yes" --> i{"first chunk INIT?"}
    i -- "yes" --> iv{"tag == 0 and<br/>INIT alone?"}
    iv -- "yes" --> T1(["accept"])
    iv -- "no" --> F4(["drop"])
    i -- "no" --> c{"first chunk COOKIE ECHO?"}
    c -- "yes" --> T2(["accept: the cookie decides"])
    c -- "no" --> t{"TCB exists?"}
    t -- "no" --> oo2["answer_ootb()"] --> F5(["drop"])
    t -- "yes" --> at{"first chunk ABORT or<br/>SHUTDOWN COMPLETE?"}
    at -- "yes" --> tb{"T bit set?"}
    tb -- "yes" --> m1{"tag == peer_ver_tag,<br/>non-zero?"}
    tb -- "no" --> m2{"tag == this_ver_tag,<br/>non-zero?"}
    m1 -- "yes" --> T3(["accept"])
    m1 -- "no" --> F6(["drop"])
    m2 -- "yes" --> T4(["accept"])
    m2 -- "no" --> F7(["drop"])
    at -- "no" --> fsa{"TCB forming and packet<br/>has SHUTDOWN ACK?"}
    fsa -- "yes" --> oo3["answer_ootb()"] --> F8(["drop"])
    fsa -- "no" --> m3{"tag == this_ver_tag?"}
    m3 -- "yes" --> T5(["accept"])
    m3 -- "no" --> F9(["drop"])

    classDef ok fill:#e3f4e6,stroke:#3a7d44,color:#1a1a1a
    classDef no fill:#fbe7e7,stroke:#b03a3a,color:#1a1a1a
    class T1,T2,T3,T4,T5 ok
    class F0,F1,F2,F3,F4,F5,F6,F7,F8,F9 no
```

The SCTP port equals the UDP port this endpoint is bound to: no endpoint here
listens on any other SCTP port.

---

## Out-of-the-blue packets

`answer_ootb()` applies the §8.4 rules in order. The first rule that matches
wins:

| Packet contains | Response |
|---|---|
| an ABORT anywhere | nothing |
| a SHUTDOWN ACK | SHUTDOWN COMPLETE, reflected tag, T bit |
| an ERROR with Stale Cookie, a SHUTDOWN COMPLETE, or a COOKIE ACK | nothing |
| anything else | ABORT, reflected tag, T bit |

---

## Unrecognized chunk types

The deserializer turns any chunk type it does not model into
`unknown_chunk_value`. That includes PAD (0x84), which is only ever sent as
part of a PLPMTU probe. Before dispatch, `handle_recv_packet` acts on the
upper two bits of each such chunk's type:

```
  type bits 7 6     action
  ─────────────     ─────────────────────────────────────────────────
      0 0           stop: drop this chunk and every chunk after it
      0 1           stop, and report it in an ERROR
      1 0           skip this chunk, keep processing        (PAD: 0x84)
      1 1           skip, keep processing, and report it
```

Reports become *Unrecognized Chunk Type* causes (cause 6, carrying the whole
chunk). They are sent **after** dispatch, so that a COOKIE ECHO bundled
earlier in the same packet has already created the TCB. Nothing is reported
without a TCB, or in `COOKIE_WAIT` where there is no peer tag. The list is
trimmed so the ERROR fits in the AMDCS.

Parameters inside INIT and INIT ACK follow the same pattern, using bits
`0x8000` and `0x4000`. See [`scan_parameters`](09-wire-format.md#parameters-and-the-upper-bit-rules).

---

## Dispatch

Non-DATA chunks are handled in packet order. All DATA chunks in the packet are
then handled together by one `handle_data_packet()` call, which builds one
SACK decision for the whole packet.

| Chunk | Handler | Acted on when |
|---|---|---|
| INIT | `handle_init` | always (tag already checked: 0, chunk alone) |
| INIT ACK | `handle_init_ack` | TCB in `COOKIE_WAIT` |
| COOKIE ECHO | `handle_cookie_echo` | only as the first chunk, before everything else |
| COOKIE ACK | `handle_cookie_ack` | `COOKIE_ECHOED` |
| SACK | `handle_sack` | `transmits_data(state)`. See [Outbound](05-outbound.md#processing-a-sack). |
| ERROR | `handle_error` | TCB exists |
| ABORT | `handle_abort`, **then stop processing the packet** | TCB exists |
| HEARTBEAT | `handle_heartbeat` | TCB, not `SHUTDOWN_SENT` / `SHUTDOWN_ACK_SENT`, and the echoed Info fits the AMDCS |
| HEARTBEAT ACK | `handle_heartbeat_ack` | 14-byte Info whose nonce matches. See [Paths](07-paths.md#heartbeats). |
| SHUTDOWN | `handle_shutdown` | not forming |
| SHUTDOWN ACK | `handle_shutdown_ack` | `SHUTDOWN_SENT` or `SHUTDOWN_ACK_SENT` |
| SHUTDOWN COMPLETE | `handle_shutdown_complete` | `SHUTDOWN_ACK_SENT` |
| DATA | `handle_data_packet` | `receives_data(state)` |

> Handling DATA after the control chunks is a deliberate simplification. It
> is listed against §6.10 in `tests/rfc/rfc_requirements.md`.

---

## DATA reception

### Receive-side data structures

```mermaid
flowchart LR
    wire["DATA chunks<br/>any TSN order"] --> ooo
    wire --> cum

    subgraph TCB["Association (receive side)"]
        cum["last_peer_tsn<br/>Cumulative TSN Ack point"]
        ooo["tsn_ooo_buffer<br/>TSN to Held_Chunk<br/>(above the ack point)"]
        re["reassembly<br/>the one message being<br/>consumed in TSN order"]
        st["inbound_streams[id]<br/>next_ssn + early: SSN to Delivery"]
        hd["held_deliveries<br/>complete messages waiting<br/>out a partial delivery"]
        dup["duplicate_tsns"]
    end

    cum -- "in-order TSN" --> re
    ooo -- "read_ooo_buffer()" --> re
    ooo -- "assemble_early()" --> st
    re -- "message complete" --> st
    st -- "SSN == next_ssn or unordered" --> out["delivered"]
    re -- "partial delivery" --> out
    hd --> out
    out --> rq[("Receive_Queue<br/>outlives the TCB")]
    rq --> ulp["sctp_recv_data()"]
```

| Structure | Holds | Emptied by |
|---|---|---|
| `last_peer_tsn` | highest TSN with no gaps below it | advanced in place |
| `tsn_ooo_buffer` | chunks above `last_peer_tsn`. An entry whose message was taken out early stays with `assembled = true` and no bytes, so the SACK keeps reporting it. | `read_ooo_buffer()` once the gap fills |
| `reassembly` | the message currently open in TSN order (`open`, `partially_delivered`, stream, SSN, PPID, bytes) | completing the message |
| `inbound_streams[id]` | `next_ssn` and `early`: complete ordered messages ahead of `next_ssn` | `advance_stream()` |
| `held_deliveries` | messages completed while a different message is in partial delivery | the end of that partial delivery |
| `Receive_Queue` | delivered bytes the ULP has not read | `sctp_recv_data*` |

### Per-chunk processing

```mermaid
flowchart TD
    pk["handle_data_packet(packet)"] --> nu{"any DATA with<br/>empty user data?"}
    nu -- "yes" --> abort1["ABORT: No User Data"]
    nu -- "no" --> st{"receives_data(state)?"}
    st -- "no" --> ret(["return"])
    st -- "yes" --> loop["for each DATA chunk"]
    loop --> ib["note I bit<br/>received_since_sack += size"]
    ib --> dup{"TSN ≤ last_peer_tsn or<br/>already in tsn_ooo_buffer?"}
    dup -- "yes" --> rd["record duplicate"] --> loop
    dup -- "no" --> room{"TSN - last_peer_tsn > 65535, or<br/>buffer full and no room?"}
    room -- "yes" --> dr["dropped = true"] --> loop
    room -- "no" --> vs{"stream < in_streams?"}
    vs -- "no" --> inv["queue Invalid Stream cause<br/>keep TSN, discard bytes"]
    vs -- "yes" --> used["used += size"]
    inv & used --> nx{"TSN == last_peer_tsn + 1?"}
    nx -- "yes" --> adv["last_peer_tsn = TSN<br/>reassemble() then read_ooo_buffer()"]
    nx -- "no" --> hold["insert into tsn_ooo_buffer<br/>assemble_early(TSN)"]
    adv & hold --> fr{"framing valid?"}
    fr -- "no" --> abort2["ABORT: Protocol Violation"]
    fr -- "yes" --> loop
    loop -- "done" --> pd["partial delivery check"]
    pd --> push["push deliveries to Receive_Queue"]
    push --> errs["ERROR: Invalid Stream Identifier causes"]
    errs --> ack["SACK decision"]
```

An invalid stream is still acknowledged, because its TSN advances
`last_peer_tsn`, but it is reported and never delivered.
`reassemble(..., keep_bytes = false)` still checks its framing.

### Receive buffer and drop policy

The receive buffer is a fixed `RWND` (65535) bytes of user data per
association. Occupancy is:

```
used = Receive_Queue::buffered_bytes(key)          delivered, unread
     + reassembly.bytes                            open message
     + Σ tsn_ooo_buffer user_data                  held for reordering
     + Σ inbound_streams[*].early bytes            complete, out of SSN order
     + Σ held_deliveries bytes                     waiting out a partial delivery
```

When a new chunk arrives with `used ≥ RWND`:

```mermaid
flowchart TD
    f["buffer full"] --> mr{"make_room():<br/>is the new TSN below the highest<br/>non-assembled TSN held?"}
    mr -- "yes" --> evict["evict that highest held chunk<br/>(even if a Gap Ack Block reported it)<br/>accept the new one"]
    mr -- "no" --> nb{"new TSN == last_peer_tsn + 1<br/>and something complete is<br/>blocked on it?"}
    nb -- "yes" --> acc["accept anyway:<br/>it unblocks delivery"]
    nb -- "no" --> drop["drop, SACK at once"]
```

Evicting a chunk that was already gap-acked is reneging. The sender handles
this case: see [Outbound: reneging](05-outbound.md#outstanding-data-lifecycle).

### Reassembly and ordering

Two stages: **framing** in TSN order (B/E bits), then **ordering** by SSN within
a stream.

```mermaid
stateDiagram-v2
    direction LR
    [*] --> Closed
    Closed --> Open : chunk with B, no E
    Closed --> Closed : chunk with B and E / order_message
    Open --> Open : chunk without B or E, same stream, U and SSN
    Open --> Closed : chunk with E, same stream, U and SSN / order_message
    Closed --> Violation : chunk without B
    Open --> Violation : chunk with B, or mismatched stream, U or SSN
    Violation --> [*] : ABORT Protocol Violation
```

`order_message(stream, ssn, unordered, bytes)`:

```mermaid
flowchart LR
    m["complete message"] --> u{"unordered?"}
    u -- "yes" --> hu["hand_up()"]
    u -- "no" --> s{"SSN == next_ssn?"}
    s -- "yes" --> hu2["hand_up(), then advance_stream():<br/>++next_ssn, release early[next_ssn] while present"]
    s -- "SSN ahead" --> e["early[SSN] = message"]
    s -- "SSN behind or<br/>already waiting" --> bad["false: framing violation<br/>(peer reused an SSN)"]
    hu & hu2 --> h{"partial delivery open<br/>for another message?"}
    h -- "yes" --> held["held_deliveries"]
    h -- "no" --> del["delivered"]
```

SSN comparison uses `ssn_gt`, 16-bit serial arithmetic.

### Early assembly: a gap blocks only its own stream

If only TSN-order reassembly were used, a single missing TSN would hold back
every stream. `assemble_early(tsn)` runs each time a chunk is stored above the
ack point. It walks backwards from the new chunk to a B and forwards to an E,
through **contiguous** held TSNs of the same stream, U flag and SSN:

```
 last_peer_tsn = 99           tsn_ooo_buffer
                    ┌─────┬─────┬─────┬─────┐
      (100 missing) │ 101 │ 102 │ 103 │ 104 │
                    │ s0  │ s1  │ s1  │ s1  │
                    │ B E │ B   │     │   E │  ← 104 arrives
                    └─────┴─────┴─────┴─────┘
                           ◄─── walk back to B
                           ───────────────► walk forward to E
                     102..104 form one complete message on stream 1:
                     bytes moved out, entries marked assembled
                     (they stay so the SACK still reports them)
```

The assembled message goes to `order_message()`. If stream 1 was waiting for
exactly this SSN, it is delivered even though TSN 100 is still missing. When
100 finally arrives, `read_ooo_buffer()` walks the assembled entries with
`keep_bytes = false`: their framing is still checked, but their bytes have
already been delivered.

### Partial delivery

A message larger than what the buffer can hold would deadlock: its end
cannot arrive until the ULP reads, and the ULP cannot read until it is
complete. After each packet, `handle_data_packet` checks:

```
reassembly.open  and  reassembly.bytes non-empty
and  used + AMDCS > RWND                       (no room for another full chunk)
and  (unordered  or  reassembly.ssn == inbound_streams[stream].next_ssn)
```

If this holds, the bytes collected so far are delivered with `complete =
false`, `partially_delivered` is set, and (for ordered) the stream advances.
From then on:

```mermaid
sequenceDiagram
    participant R as reassembly
    participant H as held_deliveries
    participant Q as Receive_Queue
    participant U as ULP
    R->>Q: first part (complete=false)
    U->>Q: sctp_recv_data: partial=true
    Note over R: next fragment in TSN order
    R->>Q: appended to the same message
    Note over H: another stream completes a message<br/>hand_up() parks it here
    R->>Q: last fragment (complete=true)
    H->>Q: released in order
    U->>Q: reads finish the message, then the held ones
```

`Receive_Queue::push()` appends to the tail message while it is incomplete, so
the ULP sees one message read across several calls, each reporting
`partial = true` until the last. If the association goes away mid-message,
`abandon_partial_delivery()` drops the incomplete tail
(`Receive_Queue::abandon_open`).

### Worked example

`last_peer_tsn = 99`. Stream 0 expects SSN 0, and stream 1 expects SSN 0.

| Arrives | Chunk | What happens | Delivered | SACK |
|---|---|---|---|---|
| 1 | TSN 101, s0 SSN 1, B E | held. `assemble_early`: complete, so `early[1]` on s0 | | immediate: cum 99, gap 2-2 |
| 2 | TSN 102, s1 SSN 0, B | held, no E yet | | immediate: cum 99, gap 2-3 |
| 3 | TSN 103, s1 SSN 0, E | held. `assemble_early`: 102 to 103 complete, s1 SSN 0 == next | **s1 #0** | immediate: cum 99, gap 2-4 |
| 4 | TSN 100, s0 SSN 0, B E | in order: delivers s0 #0, `advance_stream` releases `early[1]`. `read_ooo_buffer` consumes 101 to 103 (already assembled) | **s0 #0, s0 #1** | immediate (a hole existed): cum 103 |

Stream 1 was delivered at step 3, before the gap at TSN 100 filled.

---

## Acknowledging: when to SACK

After the chunks are processed, one decision is made for the whole packet:

```mermaid
flowchart TD
    s{"state SHUTDOWN_SENT?"} -- "yes" --> sh["send SHUTDOWN (cum ack)<br/>+ SACK chunk if gaps, duplicates or drops<br/>cancel DELAYED_SACK, restart T2"]
    s -- "no" --> im{"any of:<br/>bundled with COOKIE ECHO<br/>a chunk had the I bit<br/>a duplicate was seen<br/>a chunk was dropped<br/>a gap existed before this packet<br/>a gap exists now"}
    im -- "yes" --> now["send_sack() now"]
    im -- "no" --> cnt{"++delayed_sack_packet_count ≥ 2?"}
    cnt -- "yes" --> now
    cnt -- "no" --> dl["arm DELAYED_SACK: 200 ms"]
```

A delayed SACK is also sent early when outgoing DATA has room for it:
`prepare_data_packet()` bundles it and cancels the timer. See
[Outbound](05-outbound.md#preparing-a-data-packet).

---

## Building a SACK

`make_sack()` walks `tsn_ooo_buffer` in TSN order and merges consecutive TSNs
into blocks. Offsets are relative to `last_peer_tsn`.

```
last_peer_tsn = 1000
held TSNs:     1002 1003 1004       1007       1009 1010
offsets:          2    3    4          7          9   10
Gap Ack Blocks: [2-4]              [7-7]      [9-10]
```

The SACK carries:

| Field | Value |
|---|---|
| Cumulative TSN Ack | `last_peer_tsn` |
| a_rwnd | the [advertised window](#the-advertised-window) |
| Gap Ack Blocks | as above |
| Duplicate TSNs | `duplicate_tsns`, moved out and cleared |

It also resets `delayed_sack_packet_count`, and sets `our_rwnd` and
`received_since_sack = 0`. `send_sack()` cancels the delayed-SACK timer and
sends to `data_path()`.

---

## The advertised window

```mermaid
flowchart LR
    w["window = RWND - used"] --> b["believed = our_rwnd - received_since_sack<br/>(what the peer thinks is left)"]
    b --> sws{"window > believed and<br/>increase below min(RWND/2, AMDCS)?"}
    sws -- "yes" --> hold["advertise believed<br/>(receiver SWS avoidance)"]
    sws -- "no" --> adv["advertise window"]
```

- **A shrinking window is always advertised as it is.** Only small *increases*
  are held back.
- **Window updates**: after every ULP read, `maybe_send_window_update()` sends
  a SACK if `receive_window ≥ believed + RWND/4`, so a peer stalled on a closed
  window learns that it has opened.

---

## HEARTBEAT

`handle_heartbeat` echoes the Heartbeat Info back unchanged in a HEARTBEAT ACK,
sent to the source address of the HEARTBEAT. It does not answer in
`SHUTDOWN_SENT` / `SHUTDOWN_ACK_SENT`, or when the Info is too large to echo
within the AMDCS (the peer picks the Info's length). HEARTBEAT ACK handling is
covered in [Paths](07-paths.md#heartbeats).
