/*
 *  T50 - Experimental Packet Injector
 *
 *  Copyright (C) 2010 - 2011 Nelson Brito <nbrito@sekure.org>
 *  Copyright (C) 2011 - Fernando Mercês <fernando@mentebinaria.com.br>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __COMMON_H
#define __COMMON_H

#define PACKAGE "T50"
#define SITE "http://t50.sf.net"

#if !(linux) || !(__linux__)
# error "Sorry! The t50 was only tested under Linux!"
#endif  /* __linux__ */

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/resource.h>

/* This code prefers to use Linux headers rather than BSD favored */
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/igmp.h>
#include <linux/dccp.h>
#include <linux/if_ether.h>

/* Purpose-built config library to be used by T50 modules */
#include <config.h>

/* Purpose-built protocol libraries to be used by T50 modules */
#include <protocol/egp.h>
#include <protocol/gre.h>
#include <protocol/rip.h>
#include <protocol/igmp.h>
#include <protocol/ospf.h>
#include <protocol/rsvp.h>
#include <protocol/eigrp.h>
#include <protocol/tcp_options.h>

/* NOTE: This will do nothing. Used only to prevent warnings. */
#define UNUSED_PARAM(x) { (x) = (x); }

/* Data types */
typedef uint32_t in_addr_t;
typedef int socket_t;

/* Limits */

/* #define RAND_MAX 2147483647 */ /* NOTE: Already defined @ stdlib.h */
#define CIDR_MINIMUM 8
#define CIDR_MAXIMUM 30
#define MAXIMUM_IP_ADDRESSES  16777215

/* #define INADDR_ANY ((in_addr_t) 0) */ /* NOTE: Already defined @ linux/in.h */
#define IPPORT_ANY ((uint16_t) 0)

extern char *mod_acronyms[];
extern char *mod_names[];

/* OBS: Used only in config.c.
        Isn't better to move this definitions?! */
enum t50_module
{
  MODULE_ICMP           = 0,
#define MODULE_ICMP     MODULE_ICMP
  MODULE_IGMPv1,
#define MODULE_IGMPv1   MODULE_IGMPv1
  MODULE_IGMPv3,
#define MODULE_IGMPv3   MODULE_IGMPv3
  MODULE_TCP,
#define MODULE_TCP      MODULE_TCP
  MODULE_EGP,
#define MODULE_EGP      MODULE_EGP
  MODULE_UDP,
#define MODULE_UDP      MODULE_UDP
  MODULE_RIPv1,
#define MODULE_RIPv1    MODULE_RIPv1
  MODULE_RIPv2,
#define MODULE_RIPv2    MODULE_RIPv2
  MODULE_DCCP,
#define MODULE_DCCP     MODULE_DCCP
  MODULE_RSVP,
#define MODULE_RSVP     MODULE_RSVP
  MODULE_IPSEC,
#define MODULE_IPSEC    MODULE_IPSEC
  MODULE_EIGRP,
#define MODULE_EIGRP    MODULE_EIGRP
  MODULE_OSPF,
#define MODULE_OSPF     MODULE_OSPF

  MODULE_T50,
# define MODULE_T50        MODULE_T50
# define T50_THRESHOLD_MIN MODULE_T50
};

/* Global common protocol definitions used by code */
#define AUTH_TYPE_HMACNUL 0x0000
#define AUTH_TYPE_HMACMD5 0x0002
#define AUTH_TLEN_HMACMD5 16
#define AUTH_TLEN_HMACMD5 16
#define auth_hmac_md5_len(foo) ((foo) ? AUTH_TLEN_HMACMD5 : 0)

#define IPVERSION 4
#define IP_MF 0x2000
#define IP_DF 0x4000

/* T50 DEFINITIONS. */
#define IPPROTO_T50 69
#define FIELD_MUST_BE_NULL NULL
#define FIELD_MUST_BE_ZERO 0

/* Common protocol structures used by code */
/*
 * User Datagram Protocol (RFC 768)
 *
 * Checksum is the 16-bit one's complement of the one's complement sum of a
 * pseudo header of information from the IP header, the UDP header, and the
 * data,  padded  with zero octets  at the end (if  necessary)  to  make  a
 * multiple of two octets.
 *
 * The pseudo  header  conceptually prefixed to the UDP header contains the
 * source  address,  the destination  address,  the protocol,  and the  UDP
 * length.   This information gives protection against misrouted datagrams.
 * This checksum procedure is the same as is used in TCP.
 *
 *                   0      7 8     15 16    23 24    31 
 *                  +--------+--------+--------+--------+
 *                  |          source address           |
 *                  +--------+--------+--------+--------+
 *                  |        destination address        |
 *                  +--------+--------+--------+--------+
 *                  |  zero  |protocol|   UDP length    |
 *                  +--------+--------+--------+--------+
 *
 * If the computed  checksum  is zero,  it is transmitted  as all ones (the
 * equivalent  in one's complement  arithmetic).   An all zero  transmitted
 * checksum  value means that the transmitter  generated  no checksum  (for
 * debugging or for higher level protocols that don't care). 
 */
struct psdhdr 
{
  in_addr_t saddr;                  /* source address              */
  in_addr_t daddr;                  /* destination address         */
  uint8_t   zero;                   /* must be zero                */
  uint8_t   protocol;               /* protocol                    */
  uint16_t  len;                    /* header length               */
};

/* Common macros used by code */
#define __32BIT_RND(foo) ((foo) == 0 ? (uint32_t)rand() : (uint32_t)(foo))
#define __24BIT_RND(foo) ((foo) == 0 ? rand() >> 8 : (foo))
#define __16BIT_RND(foo) ((foo) == 0 ? rand() >> 16 : (foo))
#define __8BIT_RND(foo)  ((foo) == 0 ? rand() >> 24 : (foo))
#define __7BIT_RND(foo)  ((foo) == 0 ? rand() >> 25 : (foo))
#define __6BIT_RND(foo)  ((foo) == 0 ? rand() >> 26 : (foo))
#define __5BIT_RND(foo)  ((foo) == 0 ? rand() >> 27 : (foo))
#define __4BIT_RND(foo)  ((foo) == 0 ? rand() >> 28 : (foo))
#define __3BIT_RND(foo)  ((foo) == 0 ? rand() >> 29 : (foo))
#define __2BIT_RND(foo)  ((foo) == 0 ? (uint32_t)(rand() >> 30) : (uint32_t)(foo))

#define INADDR_RND(foo) __32BIT_RND(foo)
#define IPPORT_RND(foo) __16BIT_RND(foo)

extern uint32_t NETMASK_RND(uint32_t);

#ifdef __HAVE_DEBUG__
#define ERROR(s) \
  fprintf(stderr, "%s: %s at %s, line %d\n", PACKAGE, s, __FILE__, \
    __LINE__); fflush(stderr);
#else
#define ERROR(s) fprintf(stderr, "%s: %s\n", PACKAGE, s); fflush(stderr);
#endif

/* Common routines used by code */
extern struct cidr *config_cidr(uint32_t, in_addr_t);
/* Command line interface options validation. */
extern int checkConfigOptions(const struct config_options *);
/* Checksum calculation. */
extern uint16_t cksum(uint16_t *, int32_t);
/* Command line interface options configuration. */
extern struct config_options *getConfigOptions(int, char **);
/* IP address and name resolve. */
extern in_addr_t resolv(char *);
/* Socket configuration. */
extern socket_t sock(void);
/* Help and usage message. */
extern void usage(void);

/* Common module routines used by code */
/* Function Name: ICMP packet header configuration. */
extern void icmp   (const socket_t, const struct config_options *);
/* Function Name: IGMPv1 packet header configuration. */
extern void igmpv1 (const socket_t, const struct config_options *);
/* Function Name: IGMPv3 packet header configuration. */
extern void igmpv3 (const socket_t, const struct config_options *);
/* Function Name: TCP packet header configuration. */
extern void tcp    (const socket_t, const struct config_options *);
/* Function Name: EGP packet header configuration. */
extern void egp    (const socket_t, const struct config_options *);
/* Function Name: UDP packet header configuration. */
extern void udp    (const socket_t, const struct config_options *);
/* Function Name: RIPv1 packet header configuration. */
extern void ripv1  (const socket_t, const struct config_options *);
/* Function Name: RIPv2 packet header configuration. */
extern void ripv2  (const socket_t, const struct config_options *);
/* Function Name: DCCP packet header configuration. */
extern void dccp   (const socket_t, const struct config_options *);
/* Function Name: RSVP packet header configuration. */
extern void rsvp   (const socket_t, const struct config_options *);
/* Function Name: IPSec packet header configuration. */
extern void ipsec  (const socket_t, const struct config_options *);
/* Function Name: EIGRP packet header configuration. */
extern void eigrp  (const socket_t, const struct config_options *);
/* Function Name: OSPF packet header configuration. */
extern void ospf   (const socket_t, const struct config_options *);

#endif /* __COMMON_H */
