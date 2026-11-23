# 11. Testing

Sources: `tests/`, `fuzz/`, `Makefile`.

- [Test tiers](#test-tiers)
- [How tests are built and run](#how-tests-are-built-and-run)
- [The in-process harness](#the-in-process-harness)
- [Requirement traceability](#requirement-traceability)
- [Integration tests and `Raw_Peer`](#integration-tests-and-raw_peer)
- [Kernel interop](#kernel-interop)
- [Fuzzing](#fuzzing)
- [Sanitizers](#sanitizers)
- [Adding a test](#adding-a-test)

---

## Test tiers

```mermaid
flowchart BT
    unit["<b>unit/</b><br/>SHA-256, HMAC, CRC-32C, codec, CSPRNG wrapper<br/>published vectors and hand-computed bytes"]
    protocol["<b>protocol/</b><br/>shutdown, flow control, heartbeat, PMTU,<br/>unknown chunks, encapsulation<br/>in-process: packets in, send queue out"]
    rfc["<b>rfc/</b><br/>one check per MUST / SHOULD of RFC 9260 and 6951<br/>in-process harness, IDs traced in rfc_requirements.md"]
    integ["<b>integration/</b><br/>real UDP sockets on loopback, real event loop thread<br/>two stacks, or a stack and a Raw_Peer"]
    interop["<b>interop/</b><br/>this stack against the Linux kernel's SCTP/UDP<br/>in a private user + network namespace"]
    fuzz["<b>fuzz/</b><br/>libFuzzer: packet codec, State Cookie codec"]

    unit --> protocol --> rfc --> integ --> interop
    unit -.-> fuzz
```

| Directory | Peer | Event loop | Clock | What it catches |
|---|---|---|---|---|
| `unit/` | none | no | n/a | encoding errors that would be symmetric (both ends equally wrong) |
| `protocol/` | packets built in the test | no: drained by hand | timers fired by hand | a behaviour's details, deterministically |
| `rfc/` | packets built in the test | no | timers fired by hand | each normative sentence, by ID |
| `integration/` | a second `SCTP_Socket`, or `Raw_Peer` | yes | real | threading, wakeups, real sockets |
| `interop/` | Linux kernel SCTP | yes | real | bugs our encoder and our tests agree on |
| `fuzz/` | random bytes | no | n/a | parser crashes, round-trip mismatches |

Why "externally fixed" matters: `tests/unit/wire.cpp` and `tests/unit/hmac.cpp`
compare against RFC check vectors and hand-computed byte layouts, never
against the library's own output. A CRC-32C polynomial bug once survived
loopback tests because both ends shared it.

---

## How tests are built and run

```mermaid
flowchart LR
    src["src/*/*.cpp"] --> objs["build/src/.../*.o"] --> lib["build/libsctp.a"]
    t["tests/TIER/NAME.cpp<br/>+ tests/support.hpp (-Itests)"] --> bin["build/tests/TIER/NAME<br/>one binary per file"]
    lib --> bin
    bin --> run["make test:<br/>runs every binary even after a failure,<br/>then lists the ones that failed"]
```

- Every `tests/*/*.cpp` is a standalone program with its own `main()`. The
  Makefile picks new files up automatically by wildcard.
- A binary prints `[PASS]` / `[FAIL]` lines and exits non-zero on any failure.
- Tests may include internal headers (`"socket/internal.hpp"`,
  `"protocol/serialize.hpp"`), because `-Isrc` is on the include path.
- White-box access goes through `struct SCTP_Socket_Test_Access`, which
  `SCTP_Socket`, `Send_Queue`, `Receive_Queue` and `Expiration_Queue` declare
  as a `friend`. Each test tier defines its own version of that struct.

---

## The in-process harness

`tests/rfc/rfc_harness.hpp` drives a real `SCTP_Socket` **without** its
event loop, sockets, or wall-clock waits:

```mermaid
sequenceDiagram
    autonumber
    participant T as Test
    participant A as SCTP_Socket_Test_Access
    participant S as SCTP_Socket internals

    T->>A: establish(s, state, extra addresses)
    A->>S: insert a TCB as the handshake would leave it
    T->>A: receive(s, packet(PEER_TAG, chunks))
    A->>S: serialize, then handle_recv_packet()
    T->>A: sent(s)
    loop until nothing more is sendable
        A->>S: start_transmission_opportunity()
        A->>S: next_packet() / packet_sent()
    end
    A-->>T: rfc::Sent: every Deliverable, in order, windows applied
    T->>A: fire(s, T3_RTX, "10.0.0.2")
    A->>S: handle_expiration() for that live timer only
    T->>T: req("9260-6.3.3-1", condition, "what is checked")
```

`sent()` runs the same `next_packet()` / `packet_sent()` pair that
`run_sending()` uses, minus `sendto()`. Windows, Max.Burst, bundling, the I
bit, and every timer armed on send behave exactly as they do on the wire.

Useful helpers:

| Helper | Does |
|---|---|
| `establish(s, state, others, peer_rwnd)` | creates a TCB with fixed tags (`OUR_TAG`, `PEER_TAG`) and TSNs (`OUR_TSN`, `PEER_TSN`). Extra peer addresses start CONFIRMED. |
| `key(s, ip, port)` | the id `s` holds for that peer, or the last one it held once the association is gone, so teardown checks still look under the right id. Helpers that take an `Association_Key` default to the default peer's. |
| `initiate(s, ...)` / `respond(s, init, bundled)` | runs a real handshake in either role and returns each step's packets |
| `receive(s, packet)` / `receive_wire(s, bytes)` | feed a parsed or raw packet in |
| `sent(s)` / `sent_once(s)` | drain the send queue: all passes, or one transmission opportunity |
| `armed(s, type, ip)`, `remaining(...)`, `generation(...)` | inspect timers. A restart changes the generation. |
| `fire(s, type, ip)` | expire one running timer now |
| `cookies(s)` | the `Cookie_Auth`, for moving its clock |
| `handle_icmp_ptb(...)`, `icmp(s)` | inject or receive a real PTB |
| `notifications(s)`, `notified(ns, state)` | read and check notifications |
| `rfc::packet`, `chunk`, `data`, `sack_chunk`, `init_value`, `parameter`, `ipv4_parameter` | build peer packets |
| `rfc::Sent::any(type)`, `count(type)`, `data()`, `with(type)` | search what was sent |

`tests/protocol/*.cpp` use the same approach with their own smaller access
structs.

---

## Requirement traceability

```mermaid
flowchart LR
    rfc["RFC 9260 / 6951 sentence<br/>with MUST, SHOULD, REQUIRED, SHALL, RECOMMENDED"] --> id["ID: 9260-6.2-16<br/>(RFC - section - n-th such sentence)"]
    id --> md["tests/rfc/rfc_requirements.md<br/>ID, level, result, test file or n/a reason"]
    id --> chk["req('9260-6.2-16', ok, what)<br/>in tests/rfc/rfc9260_s6.cpp"]
    chk --> out["[PASS] 9260-6.2-16 Cumulative TSN Ack is the latest in-sequence TSN"]
```

- Every normative sentence has a row. Section 11 is informational and has none.
- `n/a` rows give the reason the stack can neither satisfy nor violate the
  requirement.
- Test files are split by RFC section: `rfc9260_s1_s3.cpp`, `_s4_s5`, `_s6`,
  `_s7_s8`, `_s9_s16`, and `rfc6951.cpp`.
- At the time of writing the totals were 526 requirements: 466 passing, 29
  failing, 31 n/a. The **Failing** list at the top of `rfc_requirements.md` is
  the current list of known gaps. Its main themes are: per-PMTU limits on Gap Ack
  Blocks; processing chunks strictly in packet order; some INIT validation
  edge cases (Initiate Tag 0, a_rwnd below 1500, OS above MIS); retransmitting
  INIT and COOKIE ECHO to alternate addresses; parts of ICMP handling; and
  surfacing the ABORT reason to the ULP.

---

## Integration tests and `Raw_Peer`

`tests/support.hpp` provides:

| Helper | Does |
|---|---|
| `check(cond, what)` / `report()` | PASS/FAIL line, exit status |
| `wait_until(pred, ms)` | poll every 1 ms until true or timeout. The library's calls never block. |
| `accepted_association(s, ms)` | the id of an association the peer started, from its COMM UP notification |
| `await_established(s, key, ms)` | uses `sctp_send_data(key, {})`: `EMPTY_MESSAGE` means ESTABLISHED, and nothing is sent |
| `send_wait`, `recv_wait`, `recv_from_wait`, `notification_wait` | retry wrappers |
| `Raw_Peer` | a real UDP socket on 127.0.0.1 that speaks SCTP by hand |

`Raw_Peer` takes either role in the handshake (`establish_initiator`,
`establish_responder`), sends exactly the chunks a test wants
(`send_data_packet(tsns, flags)`, `send_sack(cum, gaps)`), and waits for a
specific chunk type (`receive_until`). This is how retransmission tests decide
precisely which TSNs get acknowledged.

---

## Kernel interop

`tests/interop/kernel.cpp` is the only test whose peer was not written here.

```mermaid
flowchart TD
    s["main(), before any thread starts"] --> u{"unshare(CLONE_NEWUSER | CLONE_NEWNET)?"}
    u -- "ok" --> ns["private namespace:<br/>lo up, net.sctp.udp_port = 9899,<br/>net.sctp.encap_port = 9900<br/>sctp module autoloaded by socket()"]
    u -- "refused" --> host{"host already configured?<br/>(modprobe sctp + sysctls)"}
    host -- "yes" --> run
    host -- "no" --> skip(["SKIPPED, exit 0"])
    ns --> run["both roles: handshake, DATA, streams,<br/>fragmentation, heartbeats,<br/>every way an association ends"]
    run --> wire["packet socket on lo:<br/>checks unrecognized-parameter reports<br/>straight off the wire"]
```

No root is needed, and nothing touches the host's sysctls or port 9899. To
capture traffic, run it with `SCTP_INTEROP_NETNS=current` inside a namespace
you created yourself; the file header has the `unshare ... tcpdump` command.
On Windows it reports SKIPPED.

---

## Fuzzing

| Target | Input | Invariant |
|---|---|---|
| `fuzz/fuzz_packet.cpp` | one datagram | parses or throws. If it parses, it re-serializes and re-parses to the same chunks. INIT / INIT ACK parameters go through `scan_parameters`, and the reported TLVs must be well-formed. |
| `fuzz/fuzz_state_cookie.cpp` | first byte selects the mode | even: random bytes as a COOKIE ECHO must be rejected, and if they parse they round-trip byte for byte. Odd: random bytes as an INIT: the generated cookie must verify and carry the INIT's addresses back. |

```sh
make fuzz                 # clang, ASan + UBSan, FUZZ_TIME=60 s per target
make fuzz FUZZ_TIME=600
```

The corpora persist under `build/fuzz/corpus/<target>/`, and crashes are
written to `build/fuzz/crashes/`.

---

## Sanitizers

```sh
make asan    # -fsanitize=address,undefined into build/asan, then the test suite
make tsan    # -fsanitize=thread into build/tsan, then the test suite
```

Each instrumented build has its own tree, so objects never mix. TSan is the
check for the [lock model](02-concurrency.md#locks): any handler that touches a
TCB without `associations_mutex` shows up there.

---

## Adding a test

```mermaid
flowchart TD
    q{"What are you testing?"}
    q -- "a MUST / SHOULD" --> r["find its ID in rfc_requirements.md<br/>add req(ID, ...) to the matching rfc9260_sN.cpp section"]
    q -- "a behaviour detail" --> p["tests/protocol/: feed packets,<br/>drain with sent(), fire timers"]
    q -- "threads, sockets, timing" --> i["tests/integration/: two SCTP_Sockets<br/>on loopback, or Raw_Peer"]
    q -- "an encoding" --> u["tests/unit/wire.cpp:<br/>compare against hand-computed bytes"]
    q -- "a parser invariant" --> f["fuzz/: extend a target's checks"]
```

1. Prefer in-process tiers. They are deterministic and fast: no sleeps, and
   timers are fired by hand.
2. Assert against **external** truth (RFC text, vectors, hand-computed bytes),
   not against what the code currently produces.
3. A new `tests/<tier>/<name>.cpp` is built and run by `make test` with no
   Makefile change. Return `report()` or `summary(...)` from `main`.
4. If the test covers a requirement, update its row in `rfc_requirements.md`.
