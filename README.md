# sctp_stack

A userspace SCTP implementation (RFC 9260) over UDP encapsulation (RFC 6951).
Builds on Linux and Windows from one source tree.

## Layout

```
include/sctp/     public API — what a consumer of the library includes
  sctp.hpp          protocol types and wire constants (no platform deps)
  association.hpp   per-association state
  socket.hpp        SCTP_Socket, the entry point
  platform.hpp      Winsock/POSIX socket compatibility layer
src/              implementation + internal headers (not installed)
  socket.cpp        event loop, handshake, association handling
  serialize.{hpp,cpp}  wire codec — byte order lives here
  checksum.{hpp,cpp}   CRC-32C
examples/         runnable demos, linked against the library
tests/            wire-format conformance tests
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

Implemented: four-way handshake (INIT / INIT_ACK / COOKIE_ECHO / COOKIE_ACK),
DATA transfer with TSN ordering and an out-of-order buffer, CRC-32C, verification
tag validation (RFC 9260 §8.5).

**DATA is not yet reliable** — there are no timers, so nothing is acknowledged or
retransmitted. That is the next major piece of work.
