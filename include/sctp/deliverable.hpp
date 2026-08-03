#ifndef SCTP_DELIVERABLE_HPP
#define SCTP_DELIVERABLE_HPP

// One outbound packet plus the association it is destined for. Shared by the
// send queue (which holds packets waiting for the wire) and the expiration
// queue (which holds a copy to retransmit when a timer fires), so it lives
// here rather than in either of them.

#include <sctp/association.hpp>
#include <sctp/sctp.hpp>

struct Deliverable {
    Association_Key location;
    SCTP_Packet packet;
};

#endif
