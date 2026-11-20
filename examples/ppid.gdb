# Guided tour of the Payload Protocol Identifier change, over examples/ppid.
#
#   make BUILD=build/debug OPT="-O0 -g" build/debug/examples/ppid
#   gdb -x examples/ppid.gdb build/debug/examples/ppid
#
# Each stop happens once, prints what the code is for and what changed, then
# waits. `continue` goes to the next stop; `next`/`step`/`finish` walk the body.
# [CHANGED] existing code edited, [CONTEXT] untouched code the change feeds
# into. The step numbers match the demo's own output.
#
# The PPID (RFC 9260 3.3.1) is a 32-bit field in every DATA chunk header. SCTP
# never acts on it: the sending application picks it, and the receiving one gets
# it back with the message, to tell what kind of payload it is (51 is WebRTC
# text, 53 WebRTC binary). Before this change every chunk was sent with 0 and a
# received PPID was dropped.

set breakpoint pending on
set print pretty on
set pagination off
set confirm off

# ---- sending -----------------------------------------------------------------

tbreak socket_api.cpp:458
commands
echo \n[CHANGED] SCTP_Socket::sctp_send_data   (src/socket_api.cpp) - step 2, "hello" with PPID 51\n
echo | The ULP's SEND. New trailing parameter `ppid` (default 0), after `unordered` so no\n
echo | existing call changes meaning. It is stored on the queued Outbound_Message beside\n
echo | the stream, SSN and bytes (Outbound_Message gained `ppid`). Nothing is cut yet:\n
echo | the event loop turns queued messages into DATA chunks when a packet can carry them.\n
echo | Watch: p ppid   then `next` and p assoc.outbound.back()\n
end

tbreak socket_event_loop.cpp:149
commands
echo \n[CHANGED] cut_new_data   (src/socket_event_loop.cpp) - "hello" becomes a DATA chunk\n
echo | Each chunk cut from a message now copies message.ppid into payload_protocal,\n
echo | where the literal 0 used to be. One field, but every chunk passes through here.\n
echo | Watch: p message.ppid   then `advance 157` and p chunks.back()\n
end

tbreak serialize.cpp:558 if v.payload_protocal != 0
commands
echo \n[CONTEXT] DATA serialization   (src/serialize.cpp) - unchanged\n
echo | The field goes on the wire after TSN, stream and SSN, written big-endian by\n
echo | append32 like every other integer: an application passing 51 puts 00 00 00 33 on\n
echo | the wire, the same bytes a peer reading it as an integer expects.\n
echo | Watch: p/x v.payload_protocal   then `next` and p/x *(out._M_impl._M_finish - 4)@4\n
end

tbreak socket_event_loop.cpp:149 if message.bytes._M_impl._M_finish - message.bytes._M_impl._M_start > 1000 && message.offset != 0
commands
echo \n[CHANGED] cut_new_data - step 3, a middle fragment of the 4000-byte message\n
echo | 4000 bytes do not fit one packet, so the message is cut into four chunks with\n
echo | consecutive TSNs. 3.3.1: the PPID "MUST be sent even in fragmented DATA chunks",\n
echo | for boxes in the network that look at it, so every fragment carries the same value,\n
echo | not just the first (B) one.\n
echo | Watch: p message.offset   p message.ppid   then `advance 157` and p/x chunks.back().flags\n
echo |        (0 here: neither B nor E, a middle fragment)\n
end

# ---- receiving ---------------------------------------------------------------

tbreak serialize.cpp:403
commands
echo \n[CONTEXT] DATA deserialization   (src/serialize.cpp) - unchanged, receiver side\n
echo | The PPID was always parsed into data_chunk_value::payload_protocal. What was\n
echo | missing is everything after this: nothing carried it further.\n
echo | Watch: next, then p out\n
end

tbreak socket_handlers.cpp:152
commands
echo \n[CHANGED] reassemble   (src/socket_handlers.cpp) - "hello" arrives\n
echo | DATA is consumed in TSN order. A chunk with the B bit opens a Reassembly, which\n
echo | now records the chunk's PPID beside its stream and SSN (Reassembly gained `ppid`).\n
echo | When the E chunk closes the message, the PPID goes with it in a Delivery\n
echo | (Delivery gained `ppid`).\n
echo | Watch: p data.payload_protocal   then `next` and p message\n
end

tbreak order_message
commands
echo \n[CHANGED] order_message   (src/socket_handlers.cpp) - "hello" is complete\n
echo | Decides whether a whole message goes up now or waits for an earlier SSN on its\n
echo | stream. It takes a new `ppid` argument and builds the Delivery here, before the\n
echo | decision, because a message that waits is now kept whole: Inbound_Stream::early\n
echo | maps SSN -> Delivery where it used to map SSN -> bytes, so a message held for\n
echo | ordering keeps its PPID until advance_stream releases it.\n
echo | Watch: p ppid   p unordered   then `next` twice and p message\n
end

tbreak Receive_Queue::push if ppid != 0
commands
echo \n[CHANGED] Receive_Queue::push   (src/receive_queue.cpp) - receiver\n
echo | Delivered messages wait here for the application. push gained a trailing `ppid`,\n
echo | stored on the queued Message; handle_data_packet passes delivery.ppid.\n
echo | Watch: p ppid   p stream\n
end

tbreak receive_queue.cpp:42
commands
echo \n[CHANGED] Receive_Queue::read_locked   (src/receive_queue.cpp) - the application reads\n
echo | Copies as much of the front message as fits; the Read it returns now includes the\n
echo | message's ppid alongside key, byte count, partial flag and stream.\n
echo | Watch: next, then p read\n
end

tbreak socket_api.cpp:550 if this == demo_receiver
commands
echo \n[CHANGED] SCTP_Socket::sctp_recv_data_from   (src/socket_api.cpp) - back to the application\n
echo | New trailing out-parameter `out_ppid` (default nullptr), last, like\n
echo | the send side. sctp_recv_data has the same. Each read of a message part way\n
echo | through returns the same PPID.\n
echo | Watch: p read._M_payload._M_payload._M_value   then continue: the demo prints "ppid 51"\n
end

# ---- step 3: the fragmented message arrives ----------------------------------

tbreak socket_handlers.cpp:152 if data.payload_protocal == 53
commands
echo \n[CHANGED] reassemble - step 3, the first of the four fragments\n
echo | Only the B fragment's PPID is kept. The other three carry the same value but are\n
echo | not read for it: the RFC gives no rule for fragments that disagree, and the\n
echo | message's first chunk is where it began.\n
echo | Watch: p data.flags   (2: B)   p data.user_data.size()\n
end

# ---- step 4: unordered -------------------------------------------------------

tbreak order_message if unordered
commands
echo \n[CHANGED] order_message - step 4, an unordered message\n
echo | Unordered messages skip the SSN check and go straight up, with their PPID, through\n
echo | the same Delivery.\n
echo | Watch: p stream_id   p ppid\n
end

# Not reached over loopback, which never reorders or fills the window. All are in
# tests/test_ppid.cpp or the partial delivery tests:
#   - assemble_early (socket_handlers.cpp:217) takes the PPID from the B fragment of
#     a message completed above the Cumulative TSN Ack;
#   - advance_stream (socket_handlers.cpp:117) releases a held Delivery, PPID and all;
#   - partial delivery (socket_handlers.cpp:163, :1784) hands up pieces of a message
#     before its end, each with the PPID of its B fragment.

run
