/**
 *  @file iotsec_ipv.h
 *
 *  @brief Include file for the IOTsec IP Version (IPv4/IPv6) abstraction layer
 */

#ifndef IOTSEC_IPV_H
#define IOTSEC_IPV_H

#include <netinet/in.h>

#ifdef IOTSEC_IP6

#define IOTSEC_IPV_AF_INET AF_INET6
#define IOTSEC_IPV_INET_ADDRSTRLEN INET6_ADDRSTRLEN
#define IOTSEC_IPV_SIN_ADDR sin6_addr
#define IOTSEC_IPV_SIN_PORT sin6_port

typedef struct sockaddr_in6 iotsec_ipv_sockaddr_in_t;

#else /* IOTSEC_IP4 */

#define IOTSEC_IPV_AF_INET AF_INET
#define IOTSEC_IPV_INET_ADDRSTRLEN INET_ADDRSTRLEN
#define IOTSEC_IPV_SIN_ADDR sin_addr
#define IOTSEC_IPV_SIN_PORT sin_port

typedef struct sockaddr_in iotsec_ipv_sockaddr_in_t;

#endif /* IOTSEC_IP6 */

#endif
