# Guided tour of the multiple-local-address change, over examples/local_addresses.
#
#   make BUILD=build/debug OPT="-O0 -g" build/debug/examples/local_addresses
#   gdb -x examples/local_addresses.gdb build/debug/examples/local_addresses
#
# Each stop happens once, prints what the function is for and what changed,
# then waits. `continue` goes to the next stop; `next`/`step` walk the body.
# [NEW] new function, [CHANGED] existing function edited, [CONTEXT] untouched
# code the change feeds into. `ip <in_addr>` prints an address.

set breakpoint pending on
set print pretty on
set pagination off
set confirm off

define ip
    printf "%d.%d.%d.%d\n", ($arg0.s_addr) & 0xff, (($arg0.s_addr) >> 8) & 0xff, (($arg0.s_addr) >> 16) & 0xff, (($arg0.s_addr) >> 24) & 0xff
end

# ---- startup: sockets ------------------------------------------------------

tbreak SCTP_Socket::SCTP_Socket if demo_multihomed == 0
commands
echo \n[CHANGED] SCTP_Socket::SCTP_Socket   (src/socket_api.cpp) - the multihomed stack being constructed\n
echo | Before: created udp_socket inline, then set DF and enabled ICMP errors on it;\n
echo | sctp_run made it non-blocking later.\n
echo | Now: all of that is in open_udp_socket() (new, file-local), because sctp_bindx needs\n
echo | identical sockets for every extra address. The constructor still makes exactly one\n
echo | socket, udp_socket, not yet bound. Failing to set non-blocking now fails here, at\n
echo | construction, rather than in sctp_run.\n
end

tbreak SCTP_Socket::sctp_bindx if this == demo_multihomed
commands
echo \n[NEW] SCTP_Socket::sctp_bindx   (src/socket_api.cpp) - multihomed: {127.0.0.1, 127.0.0.2} : 9900\n
echo | Binds several IPv4 addresses at one SCTP port. This is the body the old sctp_bind had,\n
echo | generalised:\n
echo |   1. Parse every address first; refuse a wildcard (0.0.0.0) beside any other address.\n
echo |   2. Bind the first address on the constructor's udp_socket and read it back with\n
echo |      getsockname into local_address, so port 0 resolves to the real ephemeral port.\n
echo |   3. Each further address gets its own socket from open_udp_socket(), bound to the\n
echo |      same port, and is stored in other_local_addresses (new member: {address, socket}).\n
echo | local_address/udp_socket keep their old meaning (the first address, the endpoint's\n
echo | port), so every existing use of them is untouched. On any failure, `fail` closes\n
echo | everything, exactly as the old single bind did.\n
echo | Watch: p addresses   p local_address   p other_local_addresses\n
end

tbreak socket_api.cpp:104 if this == demo_multihomed
commands
echo \n[NEW] open_udp_socket() for the second address   (src/socket_api.cpp)\n
echo | A non-blocking UDP socket with DF set and (on Linux) IP_RECVERR, exactly as the\n
echo | constructor's. Non-blocking matters because the event loop drains it until\n
echo | recvfrom would block.\n
echo | It is bound to 127.0.0.2 at local_address's port right after this line.\n
end

tbreak SCTP_Socket::sctp_bind if this == demo_peer
commands
echo \n[CHANGED] SCTP_Socket::sctp_bind   (src/socket_api.cpp) - the peer stack, 127.0.0.3 : 5000\n
echo | Now a one-line wrapper: sctp_bindx({ip_address}, port). A single address leaves\n
echo | other_local_addresses empty, and everything below then behaves as it did before.\n
end

tbreak SCTP_Socket::sctp_run if this == demo_multihomed
commands
echo \n[CHANGED] SCTP_Socket::sctp_run   (src/socket_api.cpp) - multihomed\n
echo | No longer sets udp_socket non-blocking: open_udp_socket() already did, for every\n
echo | socket. What is left is unchanged: open the wakeup pair, start the event loop thread.\n
end

tbreak SCTP_Socket::event_loop if this == demo_multihomed
commands
echo \n[CHANGED] SCTP_Socket::event_loop   (src/socket_event_loop.cpp) - multihomed's loop thread\n
echo | Before: poll() on two fds, [0] udp_socket and [1] the wakeup pair.\n
echo | Now: `locals` = {local_address, udp_socket} plus other_local_addresses, polled as\n
echo | [0] wakeup, [1..] one per local address. The wakeup handling is the same code, now\n
echo | on index 0. For each readable socket it calls run_receiving(socket, its address),\n
echo | so the handlers learn which of our addresses a datagram reached. ICMP errors are\n
echo | read per socket the same way (run_icmp_errors(socket)); a fatal error on any\n
echo | socket stops the loop, as it did for the one.\n
echo | Watch: p locals   p descriptors\n
end

# ---- step 2: peer -> 127.0.0.1, INIT ACK lists both ------------------------

tbreak SCTP_Socket::run_receiving if this == demo_multihomed
commands
echo \n[CHANGED] SCTP_Socket::run_receiving   (src/socket_event_loop.cpp) - multihomed\n
echo | Before: recvfrom(udp_socket), then handle_recv_packet(buffer, n, src).\n
echo | Now: takes the socket that poll() found readable and the local address it is bound\n
echo | to, reads from that socket, and passes `local` on to handle_recv_packet. The batch\n
echo | loop and error handling are unchanged.\n
echo | Watch: ip local\n
end

tbreak SCTP_Socket::handle_recv_packet if this == demo_multihomed
commands
echo \n[CHANGED] SCTP_Socket::handle_recv_packet   (src/socket_handlers.cpp) - multihomed\n
echo | The entry point for every inbound packet: checksum, parse, find the TCB, tag check,\n
echo | dispatch to handle_init / handle_sack / ... (all unchanged). Two additions:\n
echo |   1. New `local` parameter. At the top, Inbound_Datagram{src, local} is published\n
echo |      through the thread_local `inbound_datagram` (socket_internal.hpp) for the length\n
echo |      of this call; `Handling` clears it on every return path. enqueue_packet reads it.\n
echo |   2. After the tag check, record_encapsulation_port(key, src) is now\n
echo |      record_arrival(key, src, local), which also stores `local` on the path.\n
echo | The packet here is the peer's INIT, so there is no TCB yet.\n
echo | Watch: ip src.sin_addr   ip local\n
end

tbreak SCTP_Socket::handle_init if this == demo_multihomed
commands
echo \n[CHANGED] SCTP_Socket::handle_init   (src/socket_handlers.cpp) - multihomed answering the peer's INIT\n
echo | Unchanged up to the cookie: validation, collision handling, minting the State Cookie.\n
echo | Change at the end: advertised_addresses() is fetched once and\n
echo |   - its parameters (8 bytes each) are counted in init_ack_size, so the room left for\n
echo |     reporting unrecognized parameters (trim_reports) stays correct;\n
echo |   - it is passed to build_init_ack as the new last argument.\n
echo | The INIT ACK is enqueued with destination = src, the peer: enqueue_packet will\n
echo | stamp it with the address the INIT arrived at.\n
end

tbreak SCTP_Socket::advertised_addresses if this == demo_multihomed
commands
echo \n[NEW] SCTP_Socket::advertised_addresses   (src/socket_api.cpp)\n
echo | The addresses to list in INIT and INIT ACK: empty when only one is bound (as before,\n
echo | so single-homed packets are byte-for-byte unchanged), else local_address followed by\n
echo | every other_local_addresses entry. Called by handle_init, sctp_associate, and the\n
echo | Stale Cookie retry INIT in handle_error.\n
end

tbreak build_init_ack if addresses._M_impl._M_start != addresses._M_impl._M_finish
commands
echo \n[CHANGED] build_init_ack   (src/builders.cpp)\n
echo | New last parameter `addresses` (default {}): after the State Cookie parameter, each\n
echo | is appended as an IPv4 Address parameter (type 5, length 8) by append_addresses.\n
echo | Watch: p addresses.size()   then finish, and p $.chunks\n
end

tbreak builders.cpp:20 if addresses._M_impl._M_start != addresses._M_impl._M_finish
commands
echo \n[NEW] append_addresses   (src/builders.cpp, file-local)\n
echo | One IPv4 Address parameter per address, via the existing append_parameter.\n
echo | s_addr is already network order, so its 4 bytes are copied as they are.\n
echo | Watch: p parameters (before and after `next`)\n
end

tbreak socket_event_loop.cpp:408 if this == demo_multihomed
commands
echo \n[CHANGED] SCTP_Socket::enqueue_packet   (src/socket_event_loop.cpp) - this line is new\n
echo | Every control packet goes through here (unchanged: sends.enqueue, then wake the loop).\n
echo | New: if the packet has no source yet, this thread is handling a datagram, and the\n
echo | packet goes back to that datagram's sender, it is a reply: give it the local address\n
echo | the datagram arrived at. That covers replies with no TCB to remember anything on:\n
echo | INIT ACK, COOKIE ACK, out-of-the-blue ABORT and SHUTDOWN COMPLETE. Calls from the\n
echo | API threads see inbound_datagram == nullptr and leave the source alone.\n
echo | Watch: ip inbound_datagram->local   ip deliverable.destination.sin_addr\n
end

tbreak SCTP_Socket::handle_send_packet if this == demo_multihomed
commands
echo \n[CHANGED] SCTP_Socket::handle_send_packet   (src/socket_event_loop.cpp) - multihomed\n
echo | Serialises and sendto()s one packet (unchanged). Now the socket comes from\n
echo | sending_socket(deliverable) instead of always being udp_socket, and the DF toggle\n
echo | for ip_fragment packets is applied to that same socket.\n
end

tbreak socket_event_loop.cpp:462 if this == demo_multihomed
commands
echo \n[NEW] SCTP_Socket::sending_socket   (src/socket_event_loop.cpp)\n
echo | Picks the socket a packet leaves from, which fixes its source address:\n
echo |   - only one address bound: udp_socket, without looking at anything (returned above);\n
echo |   - else deliverable.source if set (enqueue_packet stamped a reply);\n
echo |   - else the destination path's `source` (new Peer_Path field, set by record_arrival);\n
echo |   - else, or if neither matches another address, udp_socket: the first address bound.\n
echo | Watch: ip deliverable.source   ip source\n
end

# ---- the peer learns our second address (untouched code) -------------------

tbreak SCTP_Socket::handle_init_ack if this == demo_peer
commands
echo \n[CONTEXT] SCTP_Socket::handle_init_ack   (src/socket_handlers.cpp) - the peer, unchanged\n
echo | The other end of the change: the peer reads the INIT ACK multihomed just built.\n
echo | transport_addresses(src, params) collects the source address plus every IPv4\n
echo | Address parameter, so 127.0.0.2 now appears here; it did not before.\n
end

tbreak SCTP_Socket::add_peer_addresses if this == demo_peer
commands
echo \n[CONTEXT] SCTP_Socket::add_peer_addresses   (src/socket_api.cpp) - the peer, unchanged\n
echo | Adds 127.0.0.2 as an UNCONFIRMED Peer_Path. The existing heartbeat code then probes\n
echo | it (step 3), and multihomed answers on its second socket.\n
echo | Watch: p addresses   then finish, and p assoc.peer_address_list\n
end

# ---- steps 3/4: traffic reaches 127.0.0.2 ----------------------------------

tbreak socket_api.cpp:308 if this == demo_multihomed && local.s_addr == 0x0200007f
commands
echo \n[CHANGED] SCTP_Socket::record_arrival   (src/socket_api.cpp) - was record_encapsulation_port\n
echo | Called once a packet has passed the tag check. It already moved the path's UDP port\n
echo | to wherever the packet came from (RFC 6951 NAT rebinding); it now also stores the\n
echo | local address the packet reached in path->source. From here on, sending_socket\n
echo | sends everything for this destination (SACKs, DATA, heartbeats) from that address.\n
echo | This is the first packet multihomed has received on 127.0.0.2.\n
echo | Watch: ip local   then next, and ip path->source\n
end

tbreak socket_event_loop.cpp:473 if this == demo_multihomed
commands
echo \n[NEW] sending_socket choosing 127.0.0.2   (src/socket_event_loop.cpp)\n
echo | The first packet multihomed sends from its second address.\n
echo | Watch: ip other.address.sin_addr   up, then p deliverable.packet.chunks\n
end

# ---- step 5: multihomed initiates, INIT lists both -------------------------

tbreak SCTP_Socket::sctp_associate if this == demo_multihomed
commands
echo \n[CHANGED] SCTP_Socket::sctp_associate   (src/socket_api.cpp) - multihomed -> third\n
echo | Unchanged except the INIT: build_init now gets advertised_addresses() (the 0 before it\n
echo | is the Cookie Preservative argument, which was already defaulted to 0). The INIT\n
echo | leaves from the first address bound: it is not a reply and no path has a source yet.\n
end

tbreak build_init if addresses._M_impl._M_start != addresses._M_impl._M_finish
commands
echo \n[CHANGED] build_init   (src/builders.cpp)\n
echo | New last parameter `addresses` (default {}), written as IPv4 Address parameters\n
echo | before the optional Cookie Preservative. Also called with them by handle_error when\n
echo | a Stale Cookie error sends a fresh INIT.\n
end

tbreak SCTP_Socket::handle_init if this == demo_third
commands
echo \n[CONTEXT] SCTP_Socket::handle_init   (src/socket_handlers.cpp) - third, unchanged path\n
echo | third reads 127.0.0.1 and 127.0.0.2 from the INIT, as any responder would. They ride\n
echo | in its State Cookie and become Peer_Paths when the COOKIE ECHO arrives.\n
end

# ---- shutdown --------------------------------------------------------------

tbreak SCTP_Socket::sctp_close if this == demo_multihomed
commands
echo \n[CHANGED] SCTP_Socket::sctp_close   (src/socket_api.cpp) - multihomed\n
echo | Unchanged except that, after udp_socket, every socket in other_local_addresses is\n
echo | closed and the list cleared.\n
end

# Not reached here: run_icmp_errors(socket) [CHANGED] reads one socket's error queue
# (it used to read udp_socket's), and the Stale Cookie retry INIT in handle_error.

run
