# sctp_stack

A userspace SCTP implementation (RFC 9260) over UDP encapsulation (RFC 6951).
Builds on Linux and Windows from one source tree.

## Layout

```
include/sctp/     public API — what a consumer of the library includes
  sctp.hpp          protocol types and wire constants (no platform deps)
  association.hpp   per-association state (the TCB)
  socket.hpp        SCTP_Socket, the entry point
  platform.hpp      Winsock/POSIX socket compatibility layer
  send_queue.hpp    outbound scheduling and per-association send gating
  receive_queue.hpp messages delivered but not yet read by the application
  expiration_queue.hpp  timer heap
  notification_queue.hpp, cookie_auth.hpp, wakeup_pair.hpp, ...
src/              implementation + internal headers (not installed)
  socket_api.cpp        public API, association setup and teardown
  socket_event_loop.cpp poll loop, send path, flow and congestion gating
  socket_handlers.cpp   inbound chunks: handshake, DATA, SACK, shutdown, ...
  socket_timers.cpp     T1/T2/T3/T5, heartbeat, zero window probe, RTO
  builders.{hpp,cpp}    outbound packet construction
  serialize.{hpp,cpp}   wire codec — byte order lives here
  checksum.{hpp,cpp}    CRC-32C
examples/         runnable demos, linked against the library
tests/            conformance tests, one binary per area
build/            all build output (gitignored, never written in-tree)
```

Public headers are included as `<sctp/socket.hpp>`; internal headers as
`"serialize.hpp"`. If a header under `src/` ever needs to be included from
`include/sctp/`, that is a sign the split is wrong.

## Build

```sh
make            # library + examples + tests -> build/
make test       # build and run wire-conformance tests
make run        # run the loopback example
make asan       # rebuild under ASan+UBSan into build/asan, run tests + example
make clean      # remove build/
make help       # target list
```

Overrides: `make CXX=clang++`, `make OPT=-O0`, `make BUILD=/tmp/out`.

Sanitized objects build into `build/asan` so they never mix with the plain ones.

## Status

Implemented:

- Association setup: four-way handshake with signed state cookies, INIT
  collision and peer restart handling (§5).
- Reliable DATA transfer: SACK with gap ack blocks and duplicate TSNs, delayed
  SACK, T3-rtx, fast retransmit and fast recovery, RTO estimation (§6).
- Flow and congestion control (§6.1, §6.2, §7.2): cwnd and rwnd gating per
  association, zero window probing, Max.Burst, slow start, congestion avoidance,
  idle cwnd decay, an advertised receive window with receiver SWS avoidance and
  window updates, SACKs bundled with outgoing DATA.
- Path heartbeats and failure detection (§8.1, §8.3), ABORT and ERROR handling,
  graceful shutdown (§9), verification tag rules (§8.5), CRC-32C.
- Fragmentation and reassembly (§6.9): messages larger than the PMDCS are split
  on send and reassembled on receive, with partial delivery when a message
  outgrows the receive buffer. Receive calls report a partial flag (§11.1.7).
- Streams (§6.5, §6.6): ordered delivery per stream, with a gap blocking only
  its own stream, and unordered delivery. Messages are chunked at send time and
  bundled (§6.10), with sender SWS avoidance (§6.1).

Not yet implemented: multi-homing (§6.4), PMTU discovery (§7.3), and IPv6.
