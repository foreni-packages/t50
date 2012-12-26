/*
 *  T50 - Experimental Mixed Packet Injector
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

#include <common.h>

/* Function Name: IGMPv1 packet header configuration.
Description:   This function configures and sends the IGMPv1 packet header. */
void igmpv1(const socket_t fd, const struct config_options *o)
{
  /* GRE options size. */
  size_t greoptlen = gre_opt_len(o->gre.options, o->encapsulated);

  /* Packet size. */
  const uint32_t packet_size = sizeof(struct iphdr) + 
    greoptlen            + 
    sizeof(struct igmphdr);

  /* Checksum offset and GRE offset. */
  uint32_t offset;

  /* Packet. */
  uint8_t packet[packet_size];

  /* Socket address, IP header and IGMPv1 header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* GRE Encapsulated IP Header. */
  struct iphdr * gre_ip __attribute__ ((unused));

  /* IGMPv1 header. */
  struct igmphdr * igmpv1;

  /* Setting SOCKADDR structure. */
  sin.sin_family      = AF_INET;
  sin.sin_port        = htons(IPPORT_RND(o->dest));
  sin.sin_addr.s_addr = o->ip.daddr;

  /* IP Header structure making a pointer to Packet. */
  ip           = (struct iphdr *)packet;
  ip->version  = IPVERSION;
  ip->ihl      = sizeof(struct iphdr)/4;
  ip->tos      = o->ip.tos;
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
        sizeof(struct igmphdr));

  /* IGMPv1 Header structure making a pointer to Packet. */
  igmpv1        = (struct igmphdr *)((uint8_t *)ip + sizeof(struct iphdr) + greoptlen);
  igmpv1->type  = o->igmp.type;
  igmpv1->code  = o->igmp.code;
  igmpv1->group = INADDR_RND(o->igmp.group);
  igmpv1->csum  = 0;
  /* Computing the Packet offset. */
  offset = sizeof(struct igmphdr);

  /* Computing the checksum. */
  igmpv1->csum  = o->bogus_csum ? 
    __16BIT_RND(0) : 
    cksum((uint16_t *)igmpv1, offset);

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
