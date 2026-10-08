#ifndef SCTP_DELIVERABLE_HPP
#define SCTP_DELIVERABLE_HPP

// One outbound packet, the association it belongs to, and the transport address
// it goes to. Lives here because both the send queue and the expiration queue
// hold these.

#include <sctp/association.hpp>
#include <sctp/sctp.hpp>

struct Deliverable {
    Association_Key location;
    sockaddr_in destination;
    SCTP_Packet packet;
};

#endif
