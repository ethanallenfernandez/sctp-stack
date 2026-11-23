#ifndef SCTP_DELIVERABLE_HPP
#define SCTP_DELIVERABLE_HPP

// One outbound packet, the association it belongs to, and the transport address
// it goes to. Lives here because both the send queue and the expiration queue
// hold these.

#include <sctp/protocol/association.hpp>
#include <sctp/protocol/sctp.hpp>

struct Deliverable {
    Association_Key location{};
    sockaddr_in destination;
    SCTP_Packet packet;
    // Sent without DF: it holds a chunk cut before its path's PMTU fell, and
    // a DATA chunk is never re-fragmented (RFC 9260 6.9).
    bool ip_fragment{false};
    // Our address to send from. INADDR_ANY: wherever the destination's
    // packets last arrived.
    in_addr source{};
};

#endif
