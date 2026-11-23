# sctp_stack: developer documentation

These docs explain how the stack is built: first the overall architecture, then
each subsystem in detail. They are written for someone who knows RFC 9260 and
wants to learn how this code implements it. If you are reading the code for the
first time, read the documents in order. If you are looking into a specific
behaviour, use the index below.

> **What the stack is.** A userspace SCTP implementation (RFC 9260) carried over
> UDP encapsulation (RFC 6951), written in C++23. It builds as one static library
> (`libsctp.a`) for Linux and Windows and links nothing except pthreads. CRC-32C,
> SHA-256 and HMAC are implemented in-tree.

Diagrams are [Mermaid](https://mermaid.js.org/), which renders natively on
GitHub, GitLab and in most editors. Wire layouts use RFC-style ASCII.

---

## The whole system on one page

```mermaid
flowchart TB
    ULP["Application threads (ULP)"]
    subgraph LIB["SCTP_Socket"]
        API["Public API: api.cpp<br/>lock, edit TCB, enqueue, wake"]
        RQ["Receive_Queue"]
        NQ["Notification_Queue"]
        TCB[("associations<br/>one TCB per peer<br/>under associations_mutex")]
        SQ["Send_Queue<br/>control / rtx / new data"]
        EQ["Expiration_Queue<br/>timer heap"]
        RX["run_receiving<br/>handlers.cpp"]
        TM["run_expire<br/>timers.cpp, plpmtud.cpp"]
        TX["run_sending<br/>event_loop.cpp"]
    end
    NET(("UDP sockets"))

    ULP -- "associate / send /<br/>shutdown / abort" --> API
    RQ -- "sctp_recv_data" --> ULP
    NQ -- "sctp_recv_notification" --> ULP
    API --> TCB
    API --> SQ
    NET -- "datagrams, ICMP" --> RX
    RX --> TCB
    RX --> RQ
    RX --> NQ
    RX --> SQ
    EQ --> TM
    TM --> TCB
    TM --> SQ
    SQ --> TX
    TX -- "sendto" --> NET

    classDef loop fill:#e8f4ea,stroke:#3a7d44,color:#1a1a1a
    class RX,TM,TX loop
```

Green boxes run on the event loop thread. Everything else is shared state, or code that runs on
the caller's thread.

---

## Index

| # | Document | Covers | Main sources |
|---|---|---|---|
| 1 | [Architecture](01-architecture.md) | Module layers, ownership, the TCB, API-to-internals map, notifications | `include/sctp/*`, `src/socket/api.cpp` |
| 2 | [Concurrency and the event loop](02-concurrency.md) | Threads, the lock model, one loop pass, wakeups, the peek/commit send cycle, close | `src/socket/event_loop.cpp`, `src/platform/` |
| 3 | [Association lifecycle](03-association-lifecycle.md) | State machine, four-way handshake, collisions and restarts, stale cookies, shutdown, abort | `src/socket/handlers.cpp`, `api.cpp` |
| 4 | [Inbound path](04-inbound.md) | Packet validation, tag rules, OOTB handling, dispatch, DATA reception, reassembly, ordering, SACK generation | `src/socket/handlers.cpp` |
| 5 | [Outbound path and congestion control](05-outbound.md) | Send queue tiers, late TSN assignment, bundling and fragmentation, SACK processing, cwnd/rwnd, fast retransmit, T3-rtx | `event_loop.cpp`, `handlers.cpp`, `timers.cpp`, `src/queues/send_queue.cpp` |
| 6 | [Timers](06-timers.md) | The generation-stamped timer heap, every timer type, RTO estimation, back-off, error counters | `src/queues/expiration_queue.cpp`, `timers.cpp` |
| 7 | [Paths, multi-homing and encapsulation](07-paths.md) | Keys and aliases, path selection, confirmation, heartbeats, failover, multiple local addresses, UDP ports | `src/socket/internal.hpp`, `timers.cpp`, `api.cpp` |
| 8 | [PMTU discovery](08-pmtu.md) | DPLPMTUD state machine, search, black holes, ICMP Packet Too Big, PMDCS/AMDCS | `src/socket/plpmtud.cpp` |
| 9 | [Wire format](09-wire-format.md) | In-memory packet model, codec, checksum byte order, TLVs, builders, serial arithmetic | `src/protocol/` |
| 10 | [State cookies and crypto](10-cookies-and-crypto.md) | Cookie layout, signing and verification, secret rotation, tie-tags, randomness | `src/crypto/` |
| 11 | [Testing](11-testing.md) | Test tiers, the in-process RFC harness, requirement traceability, interop, fuzzing, sanitizers | `tests/`, `fuzz/` |
| 12 | [Build and platform](12-build-and-platform.md) | Makefile, build tree, Winsock/POSIX compatibility layer | `Makefile`, `include/sctp/platform/` |
| - | [Glossary](glossary.md) | Abbreviations and names used in the code and these docs | |

## Suggested reading paths

```mermaid
flowchart LR
    A["New to the codebase"] --> A1["1 Architecture"] --> A2["2 Concurrency"] --> A3["3 Lifecycle"] --> A4["4 Inbound"] --> A5["5 Outbound"]
    B["Debugging lost or<br/>duplicated data"] --> B1["5 Outbound"] --> B2["6 Timers"] --> B3["4 Inbound"]
    C["Multi-homing or<br/>failover issue"] --> C1["7 Paths"] --> C2["6 Timers"] --> C3["8 PMTU"]
    D["Interop or<br/>parsing bug"] --> D1["9 Wire format"] --> D2["4 Inbound"] --> D3["11 Testing"]
    E["Adding a feature"] --> E1["1 Architecture"] --> E2["2 Concurrency"] --> E3["11 Testing"]
```

## Conventions in these docs

- **§x.y** refers to a section of RFC 9260 unless another RFC is named
  (RFC 6951 is UDP encapsulation, RFC 8899 is DPLPMTUD, RFC 4820 is the PAD chunk).
- `file.cpp: function()` points at code. Paths are relative to the repository root.
- "TCB" and `Association` mean the same thing: the per-association state of
  §14.
- "ULP" is the application using the library.
- Identifiers such as `COOKIE_ECHOED` or `T3_RTX` are spelled as they are in the code.
