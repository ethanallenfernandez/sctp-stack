#ifndef SCTP_CHECKSUM_HPP
#define SCTP_CHECKSUM_HPP

#include <stdint.h>
#include <vector>

uint32_t calculate_sctp_checksum(const uint8_t* data, size_t len);

#endif