#ifndef _CONNTRACKER_H_
#define _CONNTRACKER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <gmodule.h>

#define SUCCESS 0
#define ERROR -1

#define LESS -1
#define EQUAL 0
#define MORE 1

/* base */

struct ipv4base {
	struct in_addr src;
	struct in_addr dst;
};

struct ipv6base {
	struct in6_addr src;
	struct in6_addr dst;
};

struct portbase {
	uint16_t src;
	uint16_t dst;
};

struct icmpbase {
	uint8_t type;
	uint8_t code;
};

/* flows */

struct tcpv4flow {
	struct ipv4base addrs;
	struct portbase base;
	uint8_t reply;
};

struct udpv4flow {
	struct ipv4base addrs;
	struct portbase base;
	uint8_t reply;
};

struct icmpv4flow {
	struct ipv4base addrs;
	struct icmpbase base;
	uint8_t reply;
};

/* IPv6 netfilter flows */

struct tcpv6flow {
	struct ipv6base addrs;
	struct portbase base;
	uint8_t reply;
};

struct udpv6flow {
	struct ipv6base addrs;
	struct portbase base;
	uint8_t reply;
};

struct icmpv6flow {
	struct ipv6base addrs;
	struct icmpbase base;
	uint8_t reply;
};

#endif

/* vi:syntax=on:noexpandtab:nosmarttab:tabstop=8:shiftwidth=8:softtabstop=8
 */
