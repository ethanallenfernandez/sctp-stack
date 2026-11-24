#ifndef SCTP_DELIVERABLE_HPP
#define SCTP_DELIVERABLE_HPP

#include <sctp/protocol/association.hpp>
#include <sctp/protocol/sctp.hpp>

// One outbound packet, the association it belongs to, and the peer's IPv4
// address and UDP encapsulation port it goes to. A source of INADDR_ANY sends
// from wherever the destination's packets last arrived. ip_fragment sends
// without DF, for a packet holding a DATA chunk cut before its path's PMTU fell.
struct Deliverable {
    Association_Key location{};
    sockaddr_in destination;
    SCTP_Packet packet;
    bool ip_fragment{false};
    in_addr source{};
};

#endif
