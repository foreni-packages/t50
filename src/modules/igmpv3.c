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

/* Function Name: IGMPv3 packet header configuration.
Description:   This function configures and sends the IGMPv3 packet header. */
void igmpv3(const socket_t fd, const struct config_options *o)
{
  /* GRE options size. */
  size_t greoptlen = gre_opt_len(o->gre.options, o->encapsulated);

  /* Packet size. */
  const uint32_t packet_size = sizeof(struct iphdr) + 
    greoptlen            + 
    igmpv3_hdr_len(o->igmp.type, o->igmp.sources);

  /* Checksum offset, GRE offset and Counter. */
  uint32_t offset, counter;

  /* Packet and Checksum. */
  uint8_t packet[packet_size], *checksum;

  /* Socket address and IP header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* GRE Encapsulated IP Header. */
  struct iphdr * gre_ip __attribute__ ((unused));

  /* IGMPv3 Query header, IGMPv3 Report header and IGMPv3 GREC header. */
  struct igmpv3_query * igmpv3_query;
  struct igmpv3_report * igmpv3_report;
  struct igmpv3_grec * igmpv3_grec;

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
        igmpv3_hdr_len(o->igmp.type, o->igmp.sources));

  /* Identifying the IGMP Type and building it. */
  if (o->igmp.type == IGMPV3_HOST_MEMBERSHIP_REPORT)
  {
    /* IGMPv3 Report Header structure making a pointer to Packet. */
    igmpv3_report           = (struct igmpv3_report *)((uint8_t *)ip + sizeof(struct iphdr) + greoptlen);
    igmpv3_report->type     = o->igmp.type;
    igmpv3_report->resv1    = FIELD_MUST_BE_ZERO;
    igmpv3_report->resv2    = FIELD_MUST_BE_ZERO;
    igmpv3_report->ngrec    = htons(1);
    igmpv3_report->csum     = 0;
    /* Computing the Checksum offset. */
    offset  = sizeof(struct igmpv3_report);

    /* Storing both Checksum and Packet. */
    checksum = (uint8_t *)igmpv3_report + offset;

    /* IGMPv3 Group Record Header structure making a pointer to Checksum. */
    igmpv3_grec                = (struct igmpv3_grec *)(checksum + (offset - sizeof(struct igmpv3_report)));
    igmpv3_grec->grec_type     = __8BIT_RND(o->igmp.grec_type);
    igmpv3_grec->grec_auxwords = FIELD_MUST_BE_ZERO;
    igmpv3_grec->grec_nsrcs    = htons(o->igmp.sources);
    igmpv3_grec->grec_mca      = INADDR_RND(o->igmp.grec_mca);
    checksum += sizeof(struct igmpv3_grec);
    /* Computing the Checksum offset. */
    offset += sizeof(struct igmpv3_grec);
    /* Dealing with source address(es). */
    for(counter = 0 ; counter < o->igmp.sources ; counter++)
    {
      *((in_addr_t *)checksum) = INADDR_RND(o->igmp.address[counter]);
      checksum += sizeof(in_addr_t);
    }
    /* Computing the Checksum offset. */
    offset += IGMPV3_TLEN_NSRCS(o->igmp.sources);
    /* Computing the checksum. */
    igmpv3_report->csum     = o->bogus_csum ? 
      __16BIT_RND(0) : 
      cksum((uint16_t *)igmpv3_report, offset);
  }else{
    /* IGMPv3 Query Header structure making a pointer to Packet. */
    igmpv3_query           = (struct igmpv3_query *)((uint8_t *)ip + sizeof(struct iphdr) + greoptlen);
    igmpv3_query->type     = o->igmp.type;
    igmpv3_query->code     = o->igmp.code;
    igmpv3_query->group    = INADDR_RND(o->igmp.group);
    igmpv3_query->suppress = o->igmp.suppress;
    igmpv3_query->qrv      = __3BIT_RND(o->igmp.qrv);
    igmpv3_query->qqic     = __8BIT_RND(o->igmp.qqic);
    igmpv3_query->nsrcs    = htons(o->igmp.sources);
    igmpv3_query->csum     = 0;
    /* Computing the Checksum offset. */
    offset  = sizeof(struct igmpv3_query);

    /* Storing both Checksum and Packet. */
    checksum = (uint8_t *)igmpv3_query + offset;

    /* Dealing with source address(es). */
    for(counter = 0 ; counter < o->igmp.sources ; counter++)
    {
      *((in_addr_t *)checksum) = INADDR_RND(o->igmp.address[counter]);
      checksum += sizeof(in_addr_t);
    }
    /* Computing the Checksum offset. */
    offset += IGMPV3_TLEN_NSRCS(o->igmp.sources);
    /* Computing the checksum. */
    igmpv3_query->csum     = o->bogus_csum ? 
      __16BIT_RND(0) : 
      cksum((uint16_t *)igmpv3_query, offset);
  }

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, o, packet_size);

  /* Sending Packet. */
  if (sendto(fd, &packet, packet_size, 0|MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1 && errno != EPERM)
  {
    perror("sendto()");
    /* Closing the socket. */
    close(fd);
    /* Exiting. */
    exit(EXIT_FAILURE);
  }
}
