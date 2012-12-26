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

/*
 * prototypes.
 */
static  size_t eigrp_hdr_len(const uint16_t, const uint16_t, const uint8_t, const uint32_t);

/* Function Name: EIGRP packet header configuration.

Description:   This function configures and sends the EIGRP packet header.

Targets:       N/A */
void eigrp(const socket_t fd, const struct config_options *o)
{
  /* GRE options size. */
  size_t greoptlen = gre_opt_len(o->gre.options, o->encapsulated);

  /* EIGRP Destination Address and Prefix. */
  in_addr_t dest = INADDR_RND(o->eigrp.dest);

  /* Must compute the EIGRP Destination Prefix here. */
  uint32_t prefix = __5BIT_RND(o->eigrp.prefix);

  /* EIGRP TLV size. */
  size_t eigrp_tlv_len = eigrp_hdr_len(o->eigrp.opcode, o->eigrp.type, prefix, o->eigrp.auth);

  /* Packet size. */
  const uint32_t packet_size = sizeof(struct iphdr)     + 
    greoptlen                + 
    sizeof(struct eigrp_hdr) + 
    eigrp_tlv_len;

  /* Checksum offset, GRE offset and Counter. */
  uint32_t offset, counter;

  /* Packet and Checksum. */
  uint8_t packet[packet_size], *checksum;

  /* Socket address and IP header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* GRE Encapsulated IP Header. */
  struct iphdr * gre_ip __attribute__ ((unused));

  /* EIGRP header. */
  struct eigrp_hdr * eigrp;

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
        sizeof(struct eigrp_hdr) + 
        eigrp_tlv_len);

  /* 
   * Please,  be advised that there is no deep information about EIGRP,  no
   * other than EIGRP PCAP files public available.  Due to that I have done
   * a deep analysis using live EIGRP PCAP files to build the EIGRP Packet.
   *
   * There are some really good resources, such as:
   * http://www.protocolbase.net/protocols/protocol_EIGRP.php
   * http://packetlife.net/captures/category/cisco-proprietary/
   * http://oreilly.com/catalog/iprouting/chapter/ch04.html
   *
   * EIGRP Header structure making a pointer to IP Header structure.
   */
  eigrp              = (struct eigrp_hdr *)((uint8_t *)ip + sizeof(struct iphdr) + greoptlen);
  eigrp->version     = o->eigrp.ver_minor ? 
    o->eigrp.ver_minor : 
    EIGRPVERSION;
  eigrp->opcode      = __8BIT_RND(o->eigrp.opcode);
  eigrp->flags       = htonl(__32BIT_RND(o->eigrp.flags));
  eigrp->sequence    = htonl(__32BIT_RND(o->eigrp.sequence));
  eigrp->acknowledge = o->eigrp.type == EIGRP_TYPE_SEQUENCE ? 
    htonl(__32BIT_RND(o->eigrp.acknowledge)) : 
    0;
  eigrp->as          = htonl(__32BIT_RND(o->eigrp.as));
  eigrp->check       = 0;

  /* Computing the Checksum offset. */
  offset  = sizeof(struct eigrp_hdr);

  /* Storing both Checksum and Packet. */
  checksum = (uint8_t *)eigrp + offset;

  /*
   * Every live EIGRP PCAP file brings Authentication Data TLV first.
   *
   * The Authentication Data TVL must be used only in some cases:
   * 1. IP Internal or External Routes TLV for Update
   * 2. Software Version with Parameter TLVs for Hello
   * 3. Next Multicast Sequence TLV for Hello
   */
  if (o->eigrp.auth)
  {
    if (o->eigrp.opcode == EIGRP_OPCODE_UPDATE  ||
        (o->eigrp.opcode == EIGRP_OPCODE_HELLO   &&
         (o->eigrp.type   == EIGRP_TYPE_MULTICAST ||
          o->eigrp.type   == EIGRP_TYPE_SOFTWARE)))
    {
      /*
       * Enhanced Interior Gateway Routing Protocol (EIGRP)
       *
       * Authentication Data TLV  (EIGRP Type = 0x0002)
       *
       *    0                   1                   2                   3 3
       *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *   |             Type              |            Length             |
       *   +---------------------------------------------------------------+
       *   |     Authentication Method     |    Authentication Key Size    |
       *   +---------------------------------------------------------------+
       *   |                     Authentication Key ID                     |
       *   +---------------------------------------------------------------+
       *   |                                                               |
       *   +                                                               +
       *   |                          Padding (?)                          |
       *   +                                                               +
       *   |                                                               |
       *   +---------------------------------------------------------------+
       *   |                                                               |
       *   +                                                               +
       *   |                    Authentication Key Block                   |
       *   +                          (MD5 Digest)                         +
       *   |                                                               |
       *   +                                                               +
       *   |                                                               |
       *   +---------------------------------------------------------------+
       */
      *((uint16_t *)checksum) = htons(EIGRP_TYPE_AUTH);
      checksum += sizeof(uint16_t);
      *((uint16_t *)checksum) = htons(o->eigrp.length ? 
          o->eigrp.length : 
          EIGRP_TLEN_AUTH);
      checksum += sizeof(uint16_t);
      *((uint16_t *)checksum) = htons(AUTH_TYPE_HMACMD5);
      checksum += sizeof(uint16_t);
      *((uint16_t *)checksum) = htons(auth_hmac_md5_len(o->eigrp.auth));
      checksum += sizeof(uint16_t);
      *((uint32_t *)checksum) = htonl(__32BIT_RND(o->eigrp.key_id));
      checksum += sizeof(uint32_t);
      for(counter = 0 ; counter < EIGRP_PADDING_BLOCK ; counter++)
        *checksum++ = FIELD_MUST_BE_ZERO;
      /*
       * The Authentication key uses HMAC-MD5 or HMAC-SHA-1 digest.
       */
      for(counter = 0 ; counter < auth_hmac_md5_len(o->eigrp.auth) ; counter++)
        *checksum++ = __8BIT_RND(0);
      /* Computing the Checksum offset. */
      offset += EIGRP_TLEN_AUTH;
    }
  }

  /*
   * AFAIK,   there are differences when building the EIGRP packet for
   * Update, Request, Query and Reply.  Any EIGRP PCAP file I saw does
   * not carry Paremeter,  Software Version and/or Multicast Sequence,
   * instead, it carries Authentication Data, IP Internal and External
   * Routes or nothing (depends on the EIGRP Type).
   */
  if (o->eigrp.opcode == EIGRP_OPCODE_UPDATE   ||
      o->eigrp.opcode == EIGRP_OPCODE_REQUEST  ||
      o->eigrp.opcode == EIGRP_OPCODE_QUERY    ||
      o->eigrp.opcode == EIGRP_OPCODE_REPLY)
  {
    if (o->eigrp.type == EIGRP_TYPE_INTERNAL ||
        o->eigrp.type == EIGRP_TYPE_EXTERNAL)
    {
      /*
       * Enhanced Interior Gateway Routing Protocol (EIGRP)
       *
       * IP Internal Routes TLV  (EIGRP Type = 0x0102)
       *
       *    0                   1                   2                   3 3
       *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *   |             Type              |            Length             |
       *   +---------------------------------------------------------------+
       *   |                       Next Hop Address                        |
       *   +---------------------------------------------------------------+
       *   |                             Delay                             |
       *   +---------------------------------------------------------------+
       *   |                           Bandwidth                           |
       *   +---------------------------------------------------------------+
       *   |        Maximum Transmission Unit (MTU)        |   Hop Count   |
       *   +---------------------------------------------------------------+
       *   |  Reliability  |     Load      |           Reserved            |
       *   +---------------------------------------------------------------+
       *   |    Prefix     //
       *   +---------------+
       *
       *   +---------------------------------------------------------------+
       *   //           Destination IP Address(es) (1-4 octets)            |
       *   +---------------------------------------------------------------+
       *
       * IP External Routes TLV  (EIGRP Type = 0x0103)
       *
       *    0                   1                   2                   3 3
       *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *   |             Type              |            Length             |
       *   +---------------------------------------------------------------+
       *   |                       Next Hop Address                        |
       *   +---------------------------------------------------------------+
       *   |                      Originating Router                       |
       *   +---------------------------------------------------------------+
       *   |                Originating Autonomous System                  |
       *   +---------------------------------------------------------------+
       *   |                         Arbitrary TAG                         |
       *   +---------------------------------------------------------------+
       *   |                   External Protocol Metric                    |
       *   +---------------------------------------------------------------+
       *   |           Reserved1           | Ext. Proto ID |     Flags     |
       *   +---------------------------------------------------------------+
       *   |                             Delay                             |
       *   +---------------------------------------------------------------+
       *   |                           Bandwidth                           |
       *   +---------------------------------------------------------------+
       *   |        Maximum Transmission Unit (MTU)        |   Hop Count   |
       *   +---------------------------------------------------------------+
       *   |  Reliability  |     Load      |           Reserved2           |
       *   +---------------------------------------------------------------+
       *   |    Prefix     //
       *   +---------------+
       *
       *   +---------------------------------------------------------------+
       *   //           Destination IP Address(es) (1-4 octets)            |
       *   +---------------------------------------------------------------+
       *
       * The only difference between Internal and External Routes TLVs is 20
       * octets.
       */
      *((uint16_t *)checksum) = htons(o->eigrp.type == EIGRP_TYPE_INTERNAL ? 
          EIGRP_TYPE_INTERNAL : 
          EIGRP_TYPE_EXTERNAL);
      checksum += sizeof(uint16_t);
      /*
       * For both Internal and External Routes TLV the code must perform
       * an additional step to compute the EIGRP header length,  because 
       * it depends on the the EIGRP Prefix, and it can be 1-4 octets.
       */
      *((uint16_t *)checksum) = htons(o->eigrp.length ? 
          o->eigrp.length : 
          (o->eigrp.type == EIGRP_TYPE_INTERNAL ? 
           EIGRP_TLEN_INTERNAL : 
           EIGRP_TLEN_EXTERNAL) + 
          EIGRP_DADDR_LENGTH(prefix));
      checksum += sizeof(uint16_t);
      *((in_addr_t *)checksum) = INADDR_RND(o->eigrp.next_hop);
      checksum += sizeof(in_addr_t);
      /*
       * The only difference between Internal and External Routes TLVs is 20
       * octets. Building 20 extra octets for IP External Routes TLV.
       */
      if (o->eigrp.type == EIGRP_TYPE_EXTERNAL)
      {
        *((in_addr_t *)checksum) = INADDR_RND(o->eigrp.src_router);
        checksum += sizeof(in_addr_t);
        *((uint32_t *)checksum) = htonl(__32BIT_RND(o->eigrp.src_as));
        checksum += sizeof(uint32_t);
        *((uint32_t *)checksum) = htonl(__32BIT_RND(o->eigrp.tag));
        checksum += sizeof(uint32_t);
        *((uint32_t *)checksum) = htonl(__32BIT_RND(o->eigrp.proto_metric));
        checksum += sizeof(uint32_t);
        *((uint16_t *)checksum) = o->eigrp.opcode == EIGRP_OPCODE_UPDATE ? 
          FIELD_MUST_BE_ZERO : 
          htons(0x0004);
        checksum += sizeof(uint16_t);
        *checksum++ = __8BIT_RND(o->eigrp.proto_id);
        *checksum++ = __8BIT_RND(o->eigrp.ext_flags);
      }
      *((uint32_t *)checksum) = htonl(__32BIT_RND(o->eigrp.delay));
      checksum += sizeof(uint32_t);
      *((uint32_t *)checksum) = htonl(__32BIT_RND(o->eigrp.bandwidth));
      checksum += sizeof(uint32_t);
      *((uint32_t *)checksum) = htonl(__24BIT_RND(o->eigrp.mtu) << 8);
      checksum += sizeof(uint32_t) - 1;
      *checksum++ = __8BIT_RND(o->eigrp.hop_count);
      *checksum++ = __8BIT_RND(o->eigrp.reliability);
      *checksum++ = __8BIT_RND(o->eigrp.load);
      *((uint16_t *)checksum) = o->eigrp.opcode == EIGRP_OPCODE_UPDATE ? 
        FIELD_MUST_BE_ZERO : 
        htons(0x0004);
      checksum += sizeof(uint16_t);
      *checksum++ = prefix;
      *((in_addr_t *)checksum) = EIGRP_DADDR_BUILD(dest, prefix);
      checksum += EIGRP_DADDR_LENGTH(prefix);
      /* Computing the Checksum offset. */
      offset += (o->eigrp.type == EIGRP_TYPE_INTERNAL ? 
          EIGRP_TLEN_INTERNAL : 
          EIGRP_TLEN_EXTERNAL) + 
        EIGRP_DADDR_LENGTH(prefix);
    }
    /*
     * In the other hand,   EIGRP Packet for Hello can carry Paremeter, 
     * Software Version, Multicast Sequence or nothing (Acknowledge).
     */
  }else if (o->eigrp.opcode == EIGRP_OPCODE_HELLO)
  {
    /*
     * AFAIK,  EIGRP TLVs must follow a predefined sequence in order to
     * be built. I am not sure whether any TLV's precedence will impact
     * in the routers'  processing of  EIGRP Packet,  so I am following 
     * exactly what I saw on live  EIGRP PCAP files.  Read the code and
     * you will understand what I am talking about.
     */
    switch (o->eigrp.type)
    {
      case EIGRP_TYPE_PARAMETER:
        /*
         * Enhanced Interior Gateway Routing Protocol (EIGRP)
         *
         * General Parameter TLV (EIGRP Type = 0x0001)
         *
         *    0                   1                   2                   3 3
         *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *   |             Type              |            Length             |
         *   +---------------------------------------------------------------+
         *   |      K1       |      K2       |      K3       |      K4       |
         *   +---------------------------------------------------------------+
         *   |      K5       |    Reserved   |           Hold Time           |
         *   +---------------------------------------------------------------+
         */
eigrp_parameter:    
        *((uint16_t *)checksum) = htons(EIGRP_TYPE_PARAMETER);
        checksum += sizeof(uint16_t);
        *((uint16_t *)checksum) = htons(o->eigrp.length ? 
            o->eigrp.length : 
            EIGRP_TLEN_PARAMETER);
        checksum += sizeof(uint16_t);
        *checksum++ = (o->eigrp.values & EIGRP_KVALUE_K1) == EIGRP_KVALUE_K1 ? 
          __8BIT_RND(o->eigrp.k1) : 
          o->eigrp.k1;
        *checksum++ = (o->eigrp.values & EIGRP_KVALUE_K2) == EIGRP_KVALUE_K2 ? 
          __8BIT_RND(o->eigrp.k2) : 
          o->eigrp.k2;
        *checksum++ = (o->eigrp.values & EIGRP_KVALUE_K3) == EIGRP_KVALUE_K3 ? 
          __8BIT_RND(o->eigrp.k3) : 
          o->eigrp.k3;
        *checksum++ = (o->eigrp.values & EIGRP_KVALUE_K4) == EIGRP_KVALUE_K4 ? 
          __8BIT_RND(o->eigrp.k4) : 
          o->eigrp.k4;
        *checksum++ = (o->eigrp.values & EIGRP_KVALUE_K5) == EIGRP_KVALUE_K5 ? 
          __8BIT_RND(o->eigrp.k5) : 
          o->eigrp.k5;
        *checksum++ = FIELD_MUST_BE_ZERO;
        *((uint16_t *)checksum) = htons(o->eigrp.hold);
        checksum += sizeof(uint16_t);
        /* Computing the Checksum offset. */
        offset += EIGRP_TLEN_PARAMETER;
        /* Going to the next TLV, if it needs to do so-> */
        if (o->eigrp.type == EIGRP_TYPE_SOFTWARE ||
            o->eigrp.type == EIGRP_TYPE_MULTICAST)
          goto eigrp_software;
        break;

      case EIGRP_TYPE_SOFTWARE:
        /* Going to the next TLV. */
        goto eigrp_parameter;
        /*
         * Enhanced Interior Gateway Routing Protocol (EIGRP)
         *
         * Software Version TLV (EIGRP Type = 0x0004)
         *
         *    0                   1                   2                   3 3
         *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *   |             Type              |            Length             |
         *   +---------------------------------------------------------------+
         *   |   IOS Major   |   IOS Minor   |  EIGRP Major  |  EIGRP Minor  |
         *   +---------------------------------------------------------------+
         */
eigrp_software:     
        *((uint16_t *)checksum) = htons(EIGRP_TYPE_SOFTWARE);
        checksum += sizeof(uint16_t);
        *((uint16_t *)checksum) = htons(o->eigrp.length ? 
            o->eigrp.length : 
            EIGRP_TLEN_SOFTWARE);
        checksum += sizeof(uint16_t);
        *checksum++ = __8BIT_RND(o->eigrp.ios_major);
        *checksum++ = __8BIT_RND(o->eigrp.ios_minor);
        *checksum++ = __8BIT_RND(o->eigrp.ver_major);
        *checksum++ = __8BIT_RND(o->eigrp.ver_minor);
        /* Computing the Checksum offset. */
        offset += EIGRP_TLEN_SOFTWARE;
        /* Going to the next TLV, if it needs to do so-> */
        if (o->eigrp.type == EIGRP_TYPE_MULTICAST)
          goto eigrp_multicast;
        break;

      case EIGRP_TYPE_MULTICAST:
        /* Going to the next TLV. */
        goto eigrp_parameter;
        /*
         * Enhanced Interior Gateway Routing Protocol (EIGRP)
         *
         * Sequence TLV (EIGRP Type = 0x0003)
         *
         *    0                   1                   2                   3 3
         *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *   |             Type              |            Length             |
         *   +---------------------------------------------------------------+
         *   |  Addr Length  //
         *   +---------------+
         *
         *   +---------------------------------------------------------------+
         *   //                         IP Address                           |
         *   +---------------------------------------------------------------+
         */
eigrp_multicast:
        *((uint16_t *)checksum) = htons(EIGRP_TYPE_SEQUENCE);
        checksum += sizeof(uint16_t);
        *((uint16_t *)checksum) = htons(o->eigrp.length ? 
            o->eigrp.length : 
            EIGRP_TLEN_SEQUENCE);
        checksum += sizeof(uint16_t);
        *checksum++ = sizeof(o->eigrp.address);
        *((in_addr_t *)checksum) = INADDR_RND(o->eigrp.address);
        checksum += sizeof(in_addr_t);
        /*
         * Enhanced Interior Gateway Routing Protocol (EIGRP)
         *
         * Next Multicast Sequence TLV (EIGRP Type = 0x0005)
         *
         *    0                   1                   2                   3 3
         *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *   |             Type              |            Length             |
         *   +---------------------------------------------------------------+
         *   |                    Next Multicast Sequence                    |
         *   +---------------------------------------------------------------+
         */       
        *((uint16_t *)checksum) = htons(EIGRP_TYPE_MULTICAST);
        checksum += sizeof(uint16_t);
        *((uint16_t *)checksum) = htons(o->eigrp.length ? 
            o->eigrp.length : 
            EIGRP_TLEN_MULTICAST);
        checksum += sizeof(uint16_t);
        *((uint32_t *)checksum) = htonl(__32BIT_RND(o->eigrp.multicast));
        checksum += sizeof(uint32_t);
        /* Computing the Checksum offset. */
        offset += EIGRP_TLEN_MULTICAST + 
          EIGRP_TLEN_SEQUENCE;
        break;
      default:
        break;
    }
  }

  /* Computing the checksum. */
  eigrp->check    = o->bogus_csum ? 
    __16BIT_RND(0) : 
    cksum((uint16_t *)eigrp, offset);

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, o, packet_size);

  /* Sending packet. */
  if (sendto(fd, &packet, packet_size, 0|MSG_NOSIGNAL, (struct sockaddr *) &sin, sizeof(struct sockaddr)) == -1 && errno != EPERM)
  {
    perror("sendto()");
    /* Closing the socket. */
    close(fd);
    /* Exiting. */
    exit(EXIT_FAILURE);
  }
}

/* EIGRP header size calculation */
static size_t eigrp_hdr_len(const uint16_t foo,
    const uint16_t bar, const uint8_t baz, const uint32_t qux)
{
  /* The code starts with size '0' and it accumulates all the required
   * size if the conditionals match. Otherwise, it returns size '0'. */
  size_t size=0;

  /*
   * The Authentication Data TVL must be used only in some cases:
   * 1. IP Internal or External Routes TLV for Update
   * 2. Software Version with Parameter TLVs for Hello
   * 3. Next Multicast Sequence TLV for Hello
   */
  if (qux)
  {
    if (foo == EIGRP_OPCODE_UPDATE  ||
        (foo == EIGRP_OPCODE_HELLO   &&
         (bar == EIGRP_TYPE_MULTICAST ||
          bar == EIGRP_TYPE_SOFTWARE)))
      size += EIGRP_TLEN_AUTH;
  }
  /*
   * AFAIK,   there are differences when building the EIGRP packet for
   * Update, Request, Query and Reply.  Any EIGRP PCAP file I saw does
   * not carry Parameter,  Software Version and/or Multicast Sequence,
   * instead, it carries Authentication Data, IP Internal and External
   * Routes or nothing (depends on the EIGRP Type).
   */
  if (foo == EIGRP_OPCODE_UPDATE   ||
      foo == EIGRP_OPCODE_REQUEST  ||
      foo == EIGRP_OPCODE_QUERY    ||
      foo == EIGRP_OPCODE_REPLY)
  {
    /*
     * For both Internal and External Routes TLV the code must perform
     * an additional step to compute the EIGRP header length,  because 
     * it depends on the the EIGRP Prefix, and it can be 1-4 octets.
     */
    if (bar == EIGRP_TYPE_INTERNAL)
    {
      size += EIGRP_TLEN_INTERNAL;
      size += EIGRP_DADDR_LENGTH(baz);
    }else if (bar == EIGRP_TYPE_EXTERNAL)
    {
      size += EIGRP_TLEN_EXTERNAL;
      size += EIGRP_DADDR_LENGTH(baz);
    }
    /*
     * In the other hand, EIGRP Packet for Hello can carry Parameter, 
     * Software Version, Multicast Sequence or nothing (Acknowledge).
     */
  }
  else if (foo == EIGRP_OPCODE_HELLO)
  {
    /*
     * AFAIK,  EIGRP TLVs must follow a predefined sequence in order to
     * be built. I am not sure whether any TLV's precedence will impact
     * in the routers'  processing of  EIGRP Packet,  so I am following 
     * exactly what I saw on live  EIGRP PCAP files.  Read the code and
     * you will understand what I am talking about.
     */
    switch(bar)
    {
      case EIGRP_TYPE_MULTICAST:
        size += EIGRP_TLEN_MULTICAST;
        size += EIGRP_TLEN_SEQUENCE;
      case EIGRP_TYPE_SOFTWARE:
        size += EIGRP_TLEN_SOFTWARE;
      case EIGRP_TYPE_PARAMETER:
        size += EIGRP_TLEN_PARAMETER;
        break;
    }
  }

  return size;
}

