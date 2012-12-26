/*
 *	T50 - Experimental Mixed Packet Injector
 *
 *	Copyright (C) 2010 - 2011 Nelson Brito <nbrito@sekure.org>
 *	Copyright (C) 2011 - Fernando Mercês <fernando@mentebinaria.com.br>
 *
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define RIPVERSION 2

#include <common.h>

/* Function Name: RIPv2 packet header configuration.

Description:   This function configures and sends the RIPv2 packet header.

Targets:       N/A */
void ripv2(const socket_t fd, const struct config_options *o)
{
  /* GRE options size. */
  size_t greoptlen = gre_opt_len(o->gre.options, o->encapsulated);

  /* Packet size. */
  const uint32_t packet_size = sizeof(struct iphdr)  + 
    greoptlen             + 
    sizeof(struct udphdr) + 
    rip_hdr_len(o->rip.auth);

  /* Checksum offset, GRE offset and Counter. */
  uint32_t offset, counter;

  /* Packet and Checksum. */
  uint8_t packet[packet_size], *checksum;

  /* Socket address, IP header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* GRE Encapsulated IP Header. */
  struct iphdr * gre_ip;

  /* UDP header and PSEUDO header. */
  struct udphdr * udp;
  struct psdhdr * pseudo;

  /* Setting SOCKADDR structure. */
  sin.sin_family      = AF_INET;
  sin.sin_port        = htons(IPPORT_RND(o->dest));
  sin.sin_addr.s_addr = o->ip.daddr;

  /* IP Header structure making a pointer to Packet. */
  ip           = (struct iphdr *)packet;
  ip->version  = IPVERSION;
  ip->ihl      = sizeof(struct iphdr)/4;
  ip->tos	     = o->ip.tos;
  ip->frag_off = htons(o->ip.frag_off ? 
      (o->ip.frag_off >> 3) | IP_MF : 
      o->ip.frag_off | IP_DF);
  ip->tot_len  = htons(packet_size);
  ip->id       = htons(__16BIT_RND(o->ip.id));
  ip->ttl      = o->ip.ttl;
  ip->protocol = o->encapsulated ? 
    IPPROTO_GRE : 
    o->ip.protocol;
  ip->saddr    = INADDR_RND(o->ip.saddr);
  ip->daddr    = o->ip.daddr;
  /* The code does not have to handle this, Kernel will do-> */
  ip->check    = 0;

  /* Computing the GRE Offset. */
  offset = sizeof(struct iphdr);

  /* GRE Encapsulation takes place. */
  gre_ip = gre_encapsulation(packet, o,
        sizeof(struct iphdr) + 
        sizeof(struct udphdr) + 
        rip_hdr_len(o->rip.auth));

  /* UDP Header structure making a pointer to  IP Header structure. */
  udp         = (struct udphdr *)((uint8_t *)ip + sizeof(struct iphdr) + greoptlen);
  udp->source = htons(IPPORT_RIP); 
  udp->dest   = htons(IPPORT_RIP);
  udp->len    = htons(sizeof(struct udphdr) + 
      rip_hdr_len(o->rip.auth));
  udp->check  = 0;
  /* Computing the Checksum offset. */
  offset = sizeof(struct udphdr);

  /* Storing both Checksum and Packet. */
  checksum = (uint8_t *)udp + offset;

  /*
   * RIP Version 2 -- Carrying Additional Information (RFC 1388)
   *
   * 3. Protocol Extensions
   *
   * The new RIP datagram format is:
   *
   *    0                   1                   2                   3 3
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   | Command (1)   | Version (1)   |       Routing Domain (2)      |
   *   +---------------+---------------+-------------------------------+
   *   | Address Family Identifier (2) |       Route Tag (2)           |
   *   +-------------------------------+-------------------------------+
   *   |                         IP Address (4)                        |
   *   +---------------------------------------------------------------+
   *   |                         Subnet Mask (4)                       |
   *   +---------------------------------------------------------------+
   *   |                         Next Hop (4)                          |
   *   +---------------------------------------------------------------+
   *   |                         Metric (4)                            |
   *   +---------------------------------------------------------------+
   *
   * XXX Playing with:
   *
   *    0                   1                   2                   3 3
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   | Command (1)   | Version (1)   |       Routing Domain (2)      |
   *   +---------------+---------------+-------------------------------+
   */
  *checksum++ = o->rip.command;
  *checksum++ = RIPVERSION;
  *((uint16_t *)checksum) = htons(__16BIT_RND(o->rip.domain));
  checksum += sizeof(uint16_t);
  /* Computing the Checksum offset. */
  offset += RIP_HEADER_LENGTH;	
  /*
   * RIP-2 MD5 Authentication (RFC 2082)
   *
   * 3.2.  Processing Algorithm
   *
   *    0                   1                   2                   3 3
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |             0xFFFF            |    Authentication Type (2)    |
   *   +-------------------------------+-------------------------------+
   *   |    RIP-2 Packet Length        |    Key ID    | Auth Data Len  |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |               Sequence Number (non-decreasing)                |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |               reserved must be zero                           |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |               reserved must be zero                           |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |                                                               |
   *   /    (RIP-2 Packet Length - 24) bytes of Data                   /
   *   |                                                               |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |             0xFFFF            |       0x01                    |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   /  Authentication Data (var. length; 16 bytes with Keyed MD5)   /
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *
   * XXX Playing with:
   *
   *    0                   1                   2                   3 3
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |             0xFFFF            |    Authentication Type (2)    |
   *   +-------------------------------+-------------------------------+
   *   |    RIP-2 Packet Length        |    Key ID    | Auth Data Len  |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |               Sequence Number (non-decreasing)                |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |               reserved must be zero                           |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |               reserved must be zero                           |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */
  if (o->rip.auth)
  {
    *((uint16_t *)checksum) = htons(0xffff);
    checksum += sizeof(uint16_t);
    *((uint16_t *)checksum) = htons(0x0003);
    checksum += sizeof(uint16_t);
    *((uint16_t *)checksum) = htons(RIP_HEADER_LENGTH + 
        RIP_AUTH_LENGTH         + 
        RIP_MESSAGE_LENGTH);
    checksum += sizeof(uint16_t);
    *checksum++ = o->rip.key_id;
    *checksum++ = RIP_AUTH_LENGTH;
    *((uint32_t *)checksum) = htonl(__32BIT_RND(o->rip.sequence));
    checksum += sizeof(uint32_t);
    *((uint32_t *)checksum) = FIELD_MUST_BE_ZERO;
    checksum += sizeof(uint32_t);
    *((uint32_t *)checksum) = FIELD_MUST_BE_ZERO;
    checksum += sizeof(uint32_t);
    /* Computing the Checksum offset. */
    offset += RIP_AUTH_LENGTH;
  }		
  /*
   * XXX Playing with:
   *
   * RIP Version 2 -- Carrying Additional Information (RFC 1388)
   *
   *    0                   1                   2                   3 3
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   | Address Family Identifier (2) |       Route Tag (2)           |
   *   +-------------------------------+-------------------------------+
   *   |                         IP Address (4)                        |
   *   +---------------------------------------------------------------+
   *   |                         Subnet Mask (4)                       |
   *   +---------------------------------------------------------------+
   *   |                         Next Hop (4)                          |
   *   +---------------------------------------------------------------+
   *   |                         Metric (4)                            |
   *   +---------------------------------------------------------------+
   *
   * RIP-2 MD5 Authentication (RFC 2082)
   *
   *    0                   1                   2                   3 3
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |                                                               |
   *   /    (RIP-2 Packet Length - 24) bytes of Data                   /
   *   |                                                               |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */
  *((uint16_t *)checksum) = htons(__16BIT_RND(o->rip.family));
  checksum += sizeof(uint16_t);
  *((uint16_t *)checksum) = htons(__16BIT_RND(o->rip.tag));
  checksum += sizeof(uint16_t);
  *((in_addr_t *)checksum) = INADDR_RND(o->rip.address);
  checksum += sizeof(in_addr_t);
  *((in_addr_t *)checksum) = NETMASK_RND(htonl(o->rip.netmask));
  checksum += sizeof(in_addr_t);
  *((in_addr_t *)checksum) = INADDR_RND(o->rip.next_hop);
  checksum += sizeof(in_addr_t);
  *((in_addr_t *)checksum) = htonl(__32BIT_RND(o->rip.metric));
  checksum += sizeof(in_addr_t);
  /* Computing the Checksum offset. */
  offset += RIP_MESSAGE_LENGTH;
  /*
   * XXX Playing with:
   *
   * RIP-2 MD5 Authentication (RFC 2082)
   *
   *    0                   1                   2                   3 3
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |             0xFFFF            |       0x01                    |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   /  Authentication Data (var. length; 16 bytes with Keyed MD5)   /
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */
  if (o->rip.auth)
  {
    *((uint16_t *)checksum) = htons(0xffff);
    checksum += sizeof(uint16_t);
    *((uint16_t *)checksum) = htons(0x0001);
    checksum += sizeof(uint16_t);
    /*
     * The Authentication key uses HMAC-MD5 or HMAC-SHA-1 digest.
     */
    for(counter = 0 ; counter < auth_hmac_md5_len(o->rip.auth) ; counter++)
      *checksum++ = __8BIT_RND(0);
    /* Computing the Checksum offset. */
    offset += RIP_TRAILER_LENGTH + 
      auth_hmac_md5_len(o->rip.auth);
  }

  /* PSEUDO Header structure making a pointer to Checksum. */
  pseudo           = (struct psdhdr *)(checksum);
  pseudo->saddr    = o->encapsulated ? 
    gre_ip->saddr : 
    ip->saddr;
  pseudo->daddr    = o->encapsulated ? 
    gre_ip->daddr : 
    ip->daddr;
  pseudo->zero     = 0;
  pseudo->protocol = o->ip.protocol;
  pseudo->len      = htons(offset);
  /* Computing the Checksum offset. */
  offset += sizeof(struct psdhdr);

  /* Computing the checksum. */
  udp->check  = o->bogus_csum ? 
    __16BIT_RND(0) : 
    cksum((uint16_t *)udp, offset);

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, o, packet_size);

  /* Sending packet. */
  if (sendto(fd, &packet, packet_size, 0|MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1 && errno != EPERM)
  {
    perror("sendto()");
    /* Closing the socket. */
    close(fd);
    /* Exiting. */
    exit(EXIT_FAILURE);
  }
}
