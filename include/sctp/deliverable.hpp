#ifndef SCTP_DELIVERABLE_HPP
#define SCTP_DELIVERABLE_HPP

// One outbound packet plus its destination. Lives here because both the send
// queue and the expiration queue hold these.

#include <sctp/association.hpp>
#include <sctp/sctp.hpp>

struct Deliverable {
    Association_Key location;
    SCTP_Packet packet;
};

#endif
