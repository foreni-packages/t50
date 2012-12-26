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

#include <common.h>

/* Function Name: DCCP packet header configuration.

Description:   This function configures and sends the DCCP packet header.

Targets:       N/A */
void dccp(const socket_t fd, const struct config_options *o)
{
  /* GRE options size. */
  size_t greoptlen = gre_opt_len(o->gre.options, o->encapsulated);

  /* DCCP Header length. */
  size_t dccp_length = dccp_packet_hdr_len(o->dccp.type);

  /* DCCP Extended Sequence NUmber length. */
  uint32_t dccp_ext_length = (o->dccp.ext ? 
      sizeof(struct dccp_hdr_ext) : 
      0);

  /* Packet size. */
  const uint32_t packet_size = sizeof(struct iphdr) + 
    greoptlen               + 
    sizeof(struct dccp_hdr) + 
    dccp_ext_length         + 
    dccp_length;

  /* Checksum offset and GRE offset. */
  uint32_t offset;

  /* Packet and Checksum. */
  uint8_t packet[packet_size], *checksum;

  /* Socket address and IP heade. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* GRE Encapsulated IP Header. */
  struct iphdr * gre_ip;

  /* DCCP header and PSEUDO header. */
  struct dccp_hdr * dccp;
  struct psdhdr * pseudo;

  /* DCCP Headers. */
  struct dccp_hdr_ext * dccp_ext;
  struct dccp_hdr_request * dccp_req;
  struct dccp_hdr_response * dccp_res;
  struct dccp_hdr_ack_bits * dccp_ack;
  struct dccp_hdr_reset * dccp_rst;

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

  gre_ip = gre_encapsulation(packet, o, 
        sizeof(struct iphdr) + 
        sizeof(struct dccp_hdr) + 
        dccp_ext_length         + 
        dccp_length);

  /* DCCP Header structure making a pointer to Packet. */
  dccp                 = (struct dccp_hdr *)((uint8_t *)ip + sizeof(struct iphdr) + greoptlen);
  dccp->dccph_sport    = htons(IPPORT_RND(o->source)); 
  dccp->dccph_dport    = htons(IPPORT_RND(o->dest));
  /*
   * Datagram Congestion Control Protocol (DCCP) (RFC 4340)
   *
   *   Data Offset: 8 bits
   *     The offset from the start of the packet's DCCP header to the start
   *     of its  application data area, in 32-bit words.  The receiver MUST
   *     ignore packets whose Data Offset is smaller than the minimum-sized
   *     header for the given Type or larger than the DCCP packet itself.
   */
  dccp->dccph_doff     = o->dccp.doff ? 
    o->dccp.doff : 
    (sizeof(struct dccp_hdr) + 
     dccp_length + 
     dccp_ext_length)/4;
  dccp->dccph_type     = o->dccp.type;
  dccp->dccph_ccval    = __4BIT_RND(o->dccp.ccval);
  /*
   * Datagram Congestion Control Protocol (DCCP) (RFC 4340)
   *
   * 9.2.  Header Checksum Coverage Field
   *
   *   The  Checksum Coverage field in the DCCP generic header (see Section
   *   5.1)  specifies what parts of the packet are covered by the Checksum
   *   field, as follows:
   *
   *   CsCov = 0      The  Checksum  field  covers  the  DCCP  header, DCCP
   *                  options,    network-layer   pseudoheader,   and   all
   *                  application  data  in the packet,  possibly padded on 
   *                  the right with zeros to an even number of bytes.
   *
   *   CsCov = 1-15   The  Checksum  field  covers  the  DCCP  header, DCCP
   *                  options,  network-layer pseudoheader, and the initial
   *                  (CsCov-1)*4 bytes of the packet's application data.
   */
  dccp->dccph_cscov    = o->dccp.cscov ? 
    (o->dccp.cscov-1)*4 : 
    (o->bogus_csum ? 
     __4BIT_RND(0) : 
     o->dccp.cscov);
  /*
   * Datagram Congestion Control Protocol (DCCP) (RFC 4340)
   *
   * 5.1.  Generic Header
   *
   *   The DCCP generic header takes different forms depending on the value
   *   of X,  the Extended Sequence Numbers bit.  If X is one, the Sequence
   *   Number field is 48 bits long, and the generic header takes 16 bytes,
   *   as follows.
   *
   *        0                   1                   2                   3
   *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *       |          Source Port          |           Dest Port           |
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *       |  Data Offset  | CCVal | CsCov |           Checksum            |
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *       |     |       |X|               |                               .
   *       | Res | Type  |=|   Reserved    |  Sequence Number (high bits)  .
   *       |     |       |1|               |                               .
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *       .                  Sequence Number (low bits)                   |
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *
   *   If  X  is  zero,  only the low 24 bits of the  Sequence  Number  are
   *   transmitted, and the generic header is 12 bytes long.
   *
   *        0                   1                   2                   3
   *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *       |          Source Port          |           Dest Port           |
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *       |  Data Offset  | CCVal | CsCov |           Checksum            |
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   *       |     |       |X|                                               |
   *       | Res | Type  |=|          Sequence Number (low bits)           |
   *       |     |       |0|                                               |
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */
  dccp->dccph_x        = o->dccp.ext;
  dccp->dccph_seq      = htons(__16BIT_RND(o->dccp.sequence_01));
  dccp->dccph_seq2     = o->dccp.ext ? 
    0 : 
    __8BIT_RND(o->dccp.sequence_02);
  dccp->dccph_checksum = 0;

  /* Computing the Checksum offset. */
  offset  = sizeof(struct dccp_hdr);

  /* Storing both Checksum and Packet. */
  checksum = (uint8_t *)dccp + offset;

  /* DCCP Extended Header structure making a pointer to Checksum. */
  if (o->dccp.ext)
  {
    dccp_ext                = (struct dccp_hdr_ext *)(checksum + (offset - sizeof(struct dccp_hdr)));
    dccp_ext->dccph_seq_low = htonl(__32BIT_RND(o->dccp.sequence_03));
    /* Computing the Checksum offset. */
    offset += sizeof(struct dccp_hdr_ext);
  }

  /* Identifying the DCCP Type and building it. */
  switch (o->dccp.type)
  {
    case DCCP_PKT_REQUEST:
      /* DCCP Request Header structure making a pointer to Checksum. */
      dccp_req                    = (struct dccp_hdr_request *)(checksum + (offset - sizeof(struct dccp_hdr)));
      dccp_req->dccph_req_service = htonl(__32BIT_RND(o->dccp.service));
      /* Computing the Checksum offset. */
      offset += sizeof(struct dccp_hdr_request);
      break;

    case DCCP_PKT_RESPONSE:
      /* DCCP Response Header structure making a pointer to Checksum. */
      dccp_res                                   = (struct dccp_hdr_response *)(checksum + (offset - sizeof(struct dccp_hdr)));
      dccp_res->dccph_resp_ack.dccph_reserved1   = FIELD_MUST_BE_ZERO;
      dccp_res->dccph_resp_ack.dccph_ack_nr_high = htons(__16BIT_RND(o->dccp.acknowledge_01));
      dccp_res->dccph_resp_ack.dccph_ack_nr_low  = htonl(__32BIT_RND(o->dccp.acknowledge_02));
      dccp_res->dccph_resp_service               = htonl(__32BIT_RND(o->dccp.service));
      /* Computing the Checksum offset. */
      offset += sizeof(struct dccp_hdr_response);

    case DCCP_PKT_DATA:
      break;

    case DCCP_PKT_DATAACK:
    case DCCP_PKT_ACK:
    case DCCP_PKT_SYNC:
    case DCCP_PKT_SYNCACK:
    case DCCP_PKT_CLOSE:
    case DCCP_PKT_CLOSEREQ:
      /* DCCP Acknowledgment Header structure making a pointer to Checksum. */
      dccp_ack                    = (struct dccp_hdr_ack_bits *)(checksum + (offset - sizeof(struct dccp_hdr)));
      dccp_ack->dccph_reserved1   = FIELD_MUST_BE_ZERO;
      dccp_ack->dccph_ack_nr_high = htons(__16BIT_RND(o->dccp.acknowledge_01));
      /* Until DCCP Options implementation. */
      if (o->dccp.type == DCCP_PKT_DATAACK ||
          o->dccp.type == DCCP_PKT_ACK)
        dccp_ack->dccph_ack_nr_low  = htonl(0x00000001);
      else
        dccp_ack->dccph_ack_nr_low  = htonl(__32BIT_RND(o->dccp.acknowledge_02));
      /* Computing the Checksum offset. */
      offset += sizeof(struct dccp_hdr_ack_bits);
      break;

    default:
      /* DCCP Reset Header structure making a pointer to Checksum. */
      dccp_rst                                    = (struct dccp_hdr_reset *)(checksum + (offset - sizeof(struct dccp_hdr)));
      dccp_rst->dccph_reset_ack.dccph_reserved1   = FIELD_MUST_BE_ZERO;
      dccp_rst->dccph_reset_ack.dccph_ack_nr_high = htons(__16BIT_RND(o->dccp.acknowledge_01));
      dccp_rst->dccph_reset_ack.dccph_ack_nr_low  = htonl(__32BIT_RND(o->dccp.acknowledge_02));
      dccp_rst->dccph_reset_code                  = __8BIT_RND(o->dccp.rst_code);
      /* Computing the Checksum offset. */
      offset += sizeof(struct dccp_hdr_reset);
      break;
  }

  /* Checksum making a pointer to PSEUDO Header structure. */
  pseudo           = (struct psdhdr *)(checksum + (offset - sizeof(struct dccp_hdr)));
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
  dccp->dccph_checksum = o->bogus_csum ? 
    __16BIT_RND(0) : 
    cksum((uint16_t *)dccp, offset);

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
