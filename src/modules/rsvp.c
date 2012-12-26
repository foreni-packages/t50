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
static  size_t rsvp_objects_len(const uint8_t, const uint8_t, const uint8_t, const uint8_t);

/* Function Name: RSVP packet header configuration.

Description:   This function configures and sends the RSVP packet header.

Targets:       N/A */
void rsvp(const socket_t fd, const struct config_options *o)
{
  /* GRE options size. */
  size_t greoptlen = gre_opt_len(o->gre.options, o->encapsulated);

  /* RSVP Objects Length. */
  size_t objects_length = rsvp_objects_len(o->rsvp.type, o->rsvp.scope, o->rsvp.adspec, o->rsvp.tspec);

  /* Packet size. */
  const uint32_t packet_size = sizeof(struct iphdr)           + 
    sizeof(struct rsvp_common_hdr) + 
    greoptlen                      + 
    objects_length;

  /* Checksum offset, GRE offset and Counter. */
  uint32_t offset, counter;

  /* Packet and Checksum. */
  uint8_t packet[packet_size], *checksum;

  /* Socket address and IP header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* GRE Encapsulated IP Header. */
  struct iphdr * gre_ip __attribute__ ((unused));

  /* RSVP Common header. */
  struct rsvp_common_hdr * rsvp;

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
        sizeof(struct iphdr)           + 
        sizeof(struct rsvp_common_hdr) +
        objects_length);

  /* RSVP Header structure making a pointer to IP Header structure. */
  rsvp           = (struct rsvp_common_hdr *)((uint8_t *)ip + sizeof(struct iphdr) + greoptlen);
  rsvp->flags    = __4BIT_RND(o->rsvp.flags);
  rsvp->version  = RSVPVERSION;
  rsvp->type     = o->rsvp.type;
  rsvp->ttl      = __8BIT_RND(o->rsvp.ttl);
  rsvp->length   = htons(sizeof(struct rsvp_common_hdr) + 
      objects_length);
  rsvp->reserved = FIELD_MUST_BE_ZERO;
  rsvp->check    = 0;
  /* Computing the Checksum offset. */
  offset  = sizeof(struct rsvp_common_hdr);

  /* Storing both Checksum and Packet. */
  checksum = (uint8_t *)rsvp + offset;

  /*
   * The SESSION Object Class is present for all RSVP Messages.
   *
   * Resource ReSerVation Protocol (RSVP) (RFC 2205)
   *
   * A.1 SESSION Class
   *
   * SESSION Class = 1.
   *
   * o    IPv4/UDP SESSION object: Class = 1, C-Type = 1
   *
   * +-------------+-------------+-------------+-------------+
   * |             IPv4 DestAddress (4 bytes)                |
   * +-------------+-------------+-------------+-------------+
   * | Protocol Id |    Flags    |          DstPort          |
   * +-------------+-------------+-------------+-------------+
   */
  *((uint16_t *)checksum) = htons(RSVP_LENGTH_SESSION);
  checksum += sizeof(uint16_t);
  *checksum++ = RSVP_OBJECT_SESSION;
  *checksum++ = 1;
  *((in_addr_t *)checksum) = INADDR_RND(o->rsvp.session_addr);
  checksum += sizeof(in_addr_t);
  *checksum++ = __8BIT_RND(o->rsvp.session_proto);
  *checksum++ = __8BIT_RND(o->rsvp.session_flags);
  *((uint16_t *)checksum) = htons(__16BIT_RND(o->rsvp.session_port));
  checksum += sizeof(uint16_t);
  /* Computing the Checksum offset. */
  offset += RSVP_LENGTH_SESSION;

  /* 
   * The RESV_HOP Object Class is present for the following:
   * 3.1.3 Path Messages
   * 3.1.4 Resv Messages
   * 3.1.5 Path Teardown Messages
   * 3.1.6 Resv Teardown Messages
   * 3.1.8 Resv Error Messages
   */
  if (o->rsvp.type == RSVP_MESSAGE_TYPE_PATH ||
      o->rsvp.type == RSVP_MESSAGE_TYPE_RESV ||
      o->rsvp.type == RSVP_MESSAGE_TYPE_PATHTEAR ||
      o->rsvp.type == RSVP_MESSAGE_TYPE_RESVTEAR ||
      o->rsvp.type == RSVP_MESSAGE_TYPE_RESVERR)
  {
    /*
     * Resource ReSerVation Protocol (RSVP) (RFC 2205)
     *
     * A.2 RSVP_HOP Class
     *
     * RSVP_HOP class = 3.
     *
     * o    IPv4 RSVP_HOP object: Class = 3, C-Type = 1
     *
     * +-------------+-------------+-------------+-------------+
     * |             IPv4 Next/Previous Hop Address            |
     * +-------------+-------------+-------------+-------------+
     * |                 Logical Interface Handle              |
     * +-------------+-------------+-------------+-------------+
     */
    *((uint16_t *)checksum) = htons(RSVP_LENGTH_RESV_HOP);
    checksum += sizeof(uint16_t);
    *checksum++ = RSVP_OBJECT_RESV_HOP;
    *checksum++ = 1;
    *((in_addr_t *)checksum) = INADDR_RND(o->rsvp.hop_addr);
    checksum += sizeof(in_addr_t);
    *((uint32_t *)checksum) = htonl(__32BIT_RND(o->rsvp.hop_iface));
    checksum += sizeof(uint32_t);
    /* Computing the Checksum offset. */
    offset += RSVP_LENGTH_RESV_HOP;
  }

  /* 
   * The TIME_VALUES Object Class is present for the following:
   * 3.1.3 Path Messages
   * 3.1.4 Resv Messages
   */
  if (o->rsvp.type == RSVP_MESSAGE_TYPE_PATH ||
      o->rsvp.type == RSVP_MESSAGE_TYPE_RESV)
  {
    /*
     * Resource ReSerVation Protocol (RSVP) (RFC 2205)
     *
     * A.4 TIME_VALUES Class
     *
     * TIME_VALUES class = 5.
     *
     * o    TIME_VALUES Object: Class = 5, C-Type = 1
     *
     * +-------------+-------------+-------------+-------------+
     * |                   Refresh Period R                    |
     * +-------------+-------------+-------------+-------------+
     */
    *((uint16_t *)checksum) = htons(RSVP_LENGTH_TIME_VALUES);
    checksum += sizeof(uint16_t);
    *checksum++ = RSVP_OBJECT_TIME_VALUES;
    *checksum++ = 1;
    *((uint32_t *)checksum) = htonl(__32BIT_RND(o->rsvp.time_refresh));
    checksum += sizeof(uint32_t);
    /* Computing the Checksum offset. */
    offset += RSVP_LENGTH_TIME_VALUES;
  }

  /* 
   * The ERROR_SPEC Object Class is present for the following:
   * 3.1.5 Path Teardown Messages
   * 3.1.8 Resv Error Messages
   * 3.1.9 Confirmation Messages
   */
  if (o->rsvp.type == RSVP_MESSAGE_TYPE_PATHERR ||
      o->rsvp.type == RSVP_MESSAGE_TYPE_RESVERR ||
      o->rsvp.type == RSVP_MESSAGE_TYPE_RESVCONF)
  {
    /*
     * Resource ReSerVation Protocol (RSVP) (RFC 2205)
     *
     * A.5 ERROR_SPEC Class
     *
     * ERROR_SPEC class = 6.
     *
     * o    IPv4 ERROR_SPEC object: Class = 6, C-Type = 1
     *
     * +-------------+-------------+-------------+-------------+
     * |            IPv4 Error Node Address (4 bytes)          |
     * +-------------+-------------+-------------+-------------+
     * |    Flags    |  Error Code |        Error Value        |
     * +-------------+-------------+-------------+-------------+
     */
    *((uint16_t *)checksum) = htons(RSVP_LENGTH_ERROR_SPEC);
    checksum += sizeof(uint16_t);
    *checksum++ = RSVP_OBJECT_ERROR_SPEC;
    *checksum++ = 1;
    *((in_addr_t *)checksum) = INADDR_RND(o->rsvp.error_addr);
    checksum += sizeof(in_addr_t);
    *checksum++ = __3BIT_RND(o->rsvp.error_flags);
    *checksum++ = __8BIT_RND(o->rsvp.error_code);
    *((uint16_t *)checksum) = htons(__16BIT_RND(o->rsvp.error_value));
    checksum += sizeof(uint16_t);
    /* Computing the Checksum offset. */
    offset += RSVP_LENGTH_ERROR_SPEC;
  }

  /* 
   * The SENDER_TEMPLATE,  SENDER_TSPEC and  ADSPEC Object Classes are
   * present for the following:
   * 3.1.3 Path Messages
   * 3.1.5 Path Teardown Messages
   * 3.1.7 Path Error Messages
   */
  if (o->rsvp.type == RSVP_MESSAGE_TYPE_PATH     ||
      o->rsvp.type == RSVP_MESSAGE_TYPE_PATHTEAR ||
      o->rsvp.type == RSVP_MESSAGE_TYPE_PATHERR)
  {
    /*
     * Resource ReSerVation Protocol (RSVP) (RFC 2205)
     *
     * A.10 SENDER_TEMPLATE Class
     *
     * SENDER_TEMPLATE class = 11.
     *
     * o    IPv4 SENDER_TEMPLATE object: Class = 11, C-Type = 1
     *
     * Definition same as IPv4/UDP FILTER_SPEC object.
     *
     * RSVP Extensions for IPSEC (RFC 2207)
     *
     * 3.3  SENDER_TEMPLATE Class
     *
     * SENDER_TEMPLATE class = 11.
     *
     * o    IPv4/GPI SENDER_TEMPLATE object: Class = 11, C-Type = 4
     *
     * Definition same as IPv4/GPI FILTER_SPEC object.
     */
    *((uint16_t *)checksum) = htons(RSVP_LENGTH_SENDER_TEMPLATE);
    checksum += sizeof(uint16_t);
    *checksum++ = RSVP_OBJECT_SENDER_TEMPLATE;
    *checksum++ = 1;
    *((in_addr_t *)checksum) = INADDR_RND(o->rsvp.sender_addr);
    checksum += sizeof(in_addr_t);
    *((uint16_t *)checksum) = FIELD_MUST_BE_ZERO;
    checksum += sizeof(uint16_t);
    *((uint16_t *)checksum) = htons(__16BIT_RND(o->rsvp.sender_port));
    checksum += sizeof(uint16_t);
    /* Computing the Checksum offset. */
    offset += RSVP_LENGTH_SENDER_TEMPLATE;
    /*
     * Resource ReSerVation Protocol (RSVP) (RFC 2205)
     *
     * A.11 SENDER_TSPEC Class
     *
     * SENDER_TSPEC class = 12.
     *
     * o    Intserv SENDER_TSPEC object: Class = 12, C-Type = 2
     *
     * The contents and encoding rules for this object are specified
     * in documents prepared by the int-serv working group.
     */
    *((uint16_t *)checksum) = htons(RSVP_LENGTH_SENDER_TSPEC + 
        TSPEC_SERVICES(o->rsvp.tspec));
    checksum += sizeof(uint16_t);
    *checksum++ = RSVP_OBJECT_SENDER_TSPEC;
    *checksum++ = 2;
    /*
     * The Use of RSVP with IETF Integrated Services (RFC 2210)
     *
     * 3.1. RSVP SENDER_TSPEC Object
     *
     *       31           24 23           16 15            8 7             0
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 1   | 0 (a) |    reserved           |             7 (b)             |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 2   |    1  (c)     |0| reserved    |             6 (d)             |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 3   |   127 (e)     |    0 (f)      |             5 (g)             |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 4   |  Token Bucket Rate [r] (32-bit IEEE floating point number)    |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 5   |  Token Bucket Size [b] (32-bit IEEE floating point number)    |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 6   |  Peak Data Rate [p] (32-bit IEEE floating point number)       |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 7   |  Minimum Policed Unit [m] (32-bit integer)                    |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 8   |  Maximum Packet Size [M]  (32-bit integer)                    |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    *((uint16_t *)checksum) = FIELD_MUST_BE_ZERO;
    checksum += sizeof(uint16_t);
    *((uint16_t *)checksum) = htons((TSPEC_SERVICES(o->rsvp.tspec) - 
          RSVP_LENGTH_SENDER_TSPEC)/4);
    checksum += sizeof(uint16_t);
    *checksum++ = o->rsvp.tspec;
    *checksum++ = FIELD_MUST_BE_ZERO;
    *((uint16_t *)checksum) = htons(TSPEC_SERVICES(o->rsvp.tspec)/4);
    checksum += sizeof(uint16_t);

    /* Identifying the RSVP TSPEC and building it. */
    switch (o->rsvp.tspec)
    {
      case TSPEC_TRAFFIC_SERVICE:
      case TSPEC_GUARANTEED_SERVICE:
        *checksum++ = TSPECT_TOKEN_BUCKET_SERVICE;
        *checksum++ = FIELD_MUST_BE_ZERO;
        *((uint16_t *)checksum) = htons((TSPEC_SERVICES(o->rsvp.tspec) - 
              TSPEC_MESSAGE_HEADER)/4);
        checksum += sizeof(uint16_t);
        *((uint32_t *)checksum) = htonl(__32BIT_RND(o->rsvp.tspec_r));
        checksum += sizeof(uint32_t);
        *((uint32_t *)checksum) = htonl(__32BIT_RND(o->rsvp.tspec_b));
        checksum += sizeof(uint32_t);
        *((uint32_t *)checksum) = htonl(__32BIT_RND(o->rsvp.tspec_p));
        checksum += sizeof(uint32_t);
        *((uint32_t *)checksum) = htonl(__32BIT_RND(o->rsvp.tspec_m));
        checksum += sizeof(uint32_t);
        *((uint32_t *)checksum) = htonl(__32BIT_RND(o->rsvp.tspec_M));
        checksum += sizeof(uint32_t);
        break;
      default:
        break;
    }
    /* Computing the Checksum offset. */
    offset += RSVP_LENGTH_SENDER_TSPEC;
    offset += TSPEC_SERVICES(o->rsvp.tspec);

    /*
     * Resource ReSerVation Protocol (RSVP) (RFC 2205)
     *
     * A.12 ADSPEC Class
     *
     * ADSPEC class = 13.
     *
     * o    Intserv ADSPEC object: Class = 13, C-Type = 2
     *
     * The contents and format for this object are specified in
     * documents prepared by the int-serv working group.
     */
    *((uint16_t *)checksum) = htons(RSVP_LENGTH_ADSPEC + 
        ADSPEC_SERVICES(o->rsvp.adspec));
    checksum += sizeof(uint16_t);
    *checksum++ = RSVP_OBJECT_ADSPEC;
    *checksum++ = 2;
    /*
     * The Use of RSVP with IETF Integrated Services (RFC 2210)
     *
     * 3.3.1. RSVP ADSPEC format
     *
     *      31           24 23            16 15            8 7             0
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     | 0 (a) |      reserved         |  Msg length - 1 (b)           |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     |                                                               |
     *     |    Default General Parameters fragment (Service 1)  (c)       |
     *     |    (Always Present)                                           |
     *     |                                                               |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     |                                                               |
     *     |    Guaranteed Service Fragment (Service 2)    (d)             |
     *     |    (Present if application might use Guaranteed Service)      |
     *     |                                                               |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     |                                                               |
     *     |    Controlled-Load Service Fragment (Service 5)  (e)          |
     *     |    (Present if application might use Controlled-Load Service) |
     *     |                                                               |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    *((uint16_t *)checksum) = FIELD_MUST_BE_ZERO;
    checksum += sizeof(uint16_t);

    *((uint16_t *)checksum) = htons((ADSPEC_SERVICES(o->rsvp.adspec) - 
          ADSPEC_MESSAGE_HEADER)/4);

    checksum += sizeof(uint16_t);
    /* Computing the Checksum offset. */
    offset += RSVP_LENGTH_ADSPEC;
    /*
     * The Use of RSVP with IETF Integrated Services (RFC 2210)
     *
     * 3.3.2. Default General Characterization Parameters ADSPEC data fragment
     *
     *      31            24 23           16 15            8 7             0
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 1   |    1  (c)     |x| reserved    |           8 (d)               |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 2   |    4 (e)      |    (f)        |           1 (g)               |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 3   |        IS hop cnt (32-bit unsigned integer)                   |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 4   |    6 (h)      |    (i)        |           1 (j)               |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 5   |  Path b/w estimate  (32-bit IEEE floating point number)       |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 6   |     8 (k)     |    (l)        |           1 (m)               |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 7   |        Minimum path latency (32-bit integer)                  |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 8   |     10 (n)    |      (o)      |           1 (p)               |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 9   |      Composed MTU (32-bit unsigned integer)                   |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    *checksum++ = ADSPEC_PARAMETER_SERVICE;
    *checksum++ = FIELD_MUST_BE_ZERO;
    *((uint16_t *)checksum) = htons((ADSPEC_PARAMETER_LENGTH - 
          ADSPEC_MESSAGE_HEADER)/4);
    checksum += sizeof(uint16_t);
    *checksum++ = ADSPEC_PARAMETER_ISHOPCNT;
    *checksum++ = FIELD_MUST_BE_ZERO;
    *((uint16_t *)checksum) = htons(ADSPEC_SERVDATA_HEADER/4);
    checksum += sizeof(uint16_t);
    *((uint32_t *)checksum) = htonl(__32BIT_RND(o->rsvp.adspec_hop));
    checksum += sizeof(uint32_t);
    *checksum++ = ADSPEC_PARAMETER_BANDWIDTH;
    *checksum++ = FIELD_MUST_BE_ZERO;
    *((uint16_t *)checksum) = htons(ADSPEC_SERVDATA_HEADER/4);
    checksum += sizeof(uint16_t);
    *((uint32_t *)checksum) = htonl(__32BIT_RND(o->rsvp.adspec_path));
    checksum += sizeof(uint32_t);
    *checksum++ = ADSPEC_PARAMETER_LATENCY;
    *checksum++ = FIELD_MUST_BE_ZERO;
    *((uint16_t *)checksum) = htons(ADSPEC_SERVDATA_HEADER/4);
    checksum += sizeof(uint16_t);
    *((uint32_t *)checksum) = htonl(__32BIT_RND(o->rsvp.adspec_minimum));
    checksum += sizeof(uint32_t);
    *checksum++ = ADSPEC_PARAMETER_COMPMTU;
    *checksum++ = FIELD_MUST_BE_ZERO;
    *((uint16_t *)checksum) = htons(ADSPEC_SERVDATA_HEADER/4);
    checksum += sizeof(uint16_t);
    *((uint32_t *)checksum) = htonl(__32BIT_RND(o->rsvp.adspec_mtu));
    checksum += sizeof(uint32_t);
    /* Computing the Checksum offset. */
    offset += ADSPEC_PARAMETER_LENGTH;

    /* Identifying the ADSPEC and building it. */
    switch (o->rsvp.adspec)
    {
      case ADSPEC_GUARANTEED_SERVICE:
        /*
         * The Use of RSVP with IETF Integrated Services (RFC 2210)
         *
         * 3.3.3. Guaranteed Service ADSPEC data fragment
         *
         *      31            24 23           16 15            8 7             0
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * 1   |     2 (a)     |x|  reserved   |             N-1 (b)           |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * 2   |    133 (c)    |     0 (d)     |             1 (e)             |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * 3   |   End-to-end composed value for C [Ctot] (32-bit integer)     |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * 4   |     134 (f)   |       (g)     |             1 (h)             |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * 5   |   End-to-end composed value for D [Dtot] (32-bit integer)     |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * 6   |     135 (i)   |       (j)     |             1 (k)             |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * 7   | Since-last-reshaping point composed C [Csum] (32-bit integer) |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * 8   |     136 (l)   |       (m)     |             1 (n)             |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * 9   | Since-last-reshaping point composed D [Dsum] (32-bit integer) |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * 10  | Service-specific general parameter headers/values, if present |
         *  .  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  .
         * N   |                                                               |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
adspec_guarantee:
        *checksum++ = ADSPEC_GUARANTEED_SERVICE;
        *checksum++ = FIELD_MUST_BE_ZERO;
        *((uint16_t *)checksum) = htons((ADSPEC_GUARANTEED_LENGTH - 
              ADSPEC_MESSAGE_HEADER)/4);
        checksum += sizeof(uint16_t);
        *checksum++ = 133;
        *checksum++ = FIELD_MUST_BE_ZERO;
        *((uint16_t *)checksum) = htons(ADSPEC_SERVDATA_HEADER/4);
        checksum += sizeof(uint16_t);
        *((uint32_t *)checksum) = htonl(__32BIT_RND(o->rsvp.adspec_Ctot));
        checksum += sizeof(uint32_t);
        *checksum++ = 134;
        *checksum++ = FIELD_MUST_BE_ZERO;
        *((uint16_t *)checksum) = htons(ADSPEC_SERVDATA_HEADER/4);
        checksum += sizeof(uint16_t);
        *((uint32_t *)checksum) = htonl(__32BIT_RND(o->rsvp.adspec_Dtot));
        checksum += sizeof(uint32_t);
        *checksum++ = 135;
        *checksum++ = FIELD_MUST_BE_ZERO;
        *((uint16_t *)checksum) = htons(ADSPEC_SERVDATA_HEADER/4);
        checksum += sizeof(uint16_t);
        *((uint32_t *)checksum) = htonl(__32BIT_RND(o->rsvp.adspec_Csum));
        checksum += sizeof(uint32_t);
        *checksum++ = 136;
        *checksum++ = FIELD_MUST_BE_ZERO;
        *((uint16_t *)checksum) = htons(ADSPEC_SERVDATA_HEADER/4);
        checksum += sizeof(uint16_t);
        *((uint32_t *)checksum) = htonl(__32BIT_RND(o->rsvp.adspec_Dsum));
        checksum += sizeof(uint32_t);
        /* Computing the Checksum offset. */
        offset += ADSPEC_GUARANTEED_LENGTH;
        /* Going to the next ADSPEC, if it needs to do so-> */
        if (o->rsvp.adspec == ADSPEC_CONTROLLED_SERVICE)
          goto adspec_controlled;
        break;

      case ADSPEC_CONTROLLED_SERVICE:
        /* Going to the next ADSPEC. */
        goto adspec_guarantee;
        /*
         * The Use of RSVP with IETF Integrated Services (RFC 2210)
         *
         * 3.3.4. Controlled-Load Service ADSPEC data fragment
         *
         *      31            24 23           16 15            8 7             0
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * 1   |     5 (a)     |x|  (b)        |            N-1 (c)            |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * 2   | Service-specific general parameter headers/values, if present |
         *  .  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  .
         * N   |                                                               |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
adspec_controlled:
        *checksum++ = ADSPEC_CONTROLLED_SERVICE;
        *checksum++ = FIELD_MUST_BE_ZERO;
        *((uint16_t *)checksum) = htons(ADSPEC_CONTROLLED_LENGTH - 
            ADSPEC_MESSAGE_HEADER);
        checksum += sizeof(uint16_t);
        /* Computing the Checksum offset. */
        offset += ADSPEC_CONTROLLED_LENGTH;
        break;
    }
  }

  /* 
   * The RESV_CONFIRM Object Class is present for the following:
   * 3.1.4 Resv Messages
   * 3.1.9 Confirmation Messages
   */
  if (o->rsvp.type == RSVP_MESSAGE_TYPE_RESV ||
      o->rsvp.type == RSVP_MESSAGE_TYPE_RESVCONF)
  {
    /*
     * Resource ReSerVation Protocol (RSVP) (RFC 2205)
     *
     * A.14 Resv_CONFIRM Class
     *
     * RESV_CONFIRM class = 15.
     *
     * o    IPv4 RESV_CONFIRM object: Class = 15, C-Type = 1
     *
     * +-------------+-------------+-------------+-------------+
     * |            IPv4 Receiver Address (4 bytes)            |
     * +-------------+-------------+-------------+-------------+
     */
    *((uint16_t *)checksum) = htons(RSVP_LENGTH_RESV_CONFIRM);
    checksum += sizeof(uint16_t);
    *checksum++ = RSVP_OBJECT_RESV_CONFIRM;
    *checksum++ = 1;
    *((in_addr_t *)checksum) = INADDR_RND(o->rsvp.confirm_addr);
    checksum += sizeof(in_addr_t);
    /* Computing the Checksum offset. */
    offset += RSVP_LENGTH_RESV_CONFIRM;
  }

  /* 
   * The STYLE Object Classes is present for the following:
   * 3.1.4 Resv Messages
   * 3.1.6 Resv Teardown Messages
   * 3.1.8 Resv Error Messages
   * 3.1.9 Confirmation Messages
   */
  if (o->rsvp.type == RSVP_MESSAGE_TYPE_RESV     ||
      o->rsvp.type == RSVP_MESSAGE_TYPE_RESVTEAR ||
      o->rsvp.type == RSVP_MESSAGE_TYPE_RESVERR  ||
      o->rsvp.type == RSVP_MESSAGE_TYPE_RESVCONF)
  {
    /* 
     * The SCOPE Object Classes is present for the following:
     * 3.1.4 Resv Messages
     * 3.1.6 Resv Teardown Messages
     * 3.1.8 Resv Error Messages
     */
    if (o->rsvp.type == RSVP_MESSAGE_TYPE_RESV     ||
        o->rsvp.type == RSVP_MESSAGE_TYPE_RESVTEAR ||
        o->rsvp.type == RSVP_MESSAGE_TYPE_RESVERR)
    {
      /*
       * Resource ReSerVation Protocol (RSVP) (RFC 2205)
       *
       * A.6 SCOPE Class
       *
       * SCOPE class = 7.
       *
       * o    IPv4 SCOPE List object: Class = 7, C-Type = 1
       *
       * +-------------+-------------+-------------+-------------+
       * |                IPv4 Src Address (4 bytes)             |
       * +-------------+-------------+-------------+-------------+
       * //                                                      //
       * +-------------+-------------+-------------+-------------+
       * |                IPv4 Src Address (4 bytes)             |
       * +-------------+-------------+-------------+-------------+
       */
      *((uint16_t *)checksum) = htons(RSVP_LENGTH_SCOPE(o->rsvp.scope));
      checksum += sizeof(uint16_t);
      *checksum++ = RSVP_OBJECT_SCOPE;
      *checksum++ = 1;

      /* Dealing with scope address(es). */
      for(counter = 0; counter < o->rsvp.scope ; counter ++)
      {
        *((in_addr_t *)checksum) = INADDR_RND(o->rsvp.address[counter]);
        checksum += sizeof(in_addr_t);
      }

      /* Computing the Checksum offset. */
      offset += RSVP_LENGTH_SCOPE(o->rsvp.scope);
    }
    /*
     * Resource ReSerVation Protocol (RSVP) (RFC 2205)
     *
     * A.7 STYLE Class
     *
     * STYLE class = 8.
     *
     * o    STYLE object: Class = 8, C-Type = 1
     *
     * +-------------+-------------+-------------+-------------+
     * |   Flags     |              Option Vector              |
     * +-------------+-------------+-------------+-------------+
     */
    *((uint16_t *)checksum) = htons(RSVP_LENGTH_STYLE);
    checksum += sizeof(uint16_t);
    *checksum++ = RSVP_OBJECT_STYLE;
    *checksum++ = 1;
    *checksum++ = FIELD_MUST_BE_ZERO;
    *((uint32_t *)checksum) = htonl(__24BIT_RND(o->rsvp.style_opt) << 8);
    checksum += sizeof(in_addr_t) - 1;
    /* Computing the Checksum offset. */
    offset += RSVP_LENGTH_STYLE;
  }

  /* Computing the checksum. */
  rsvp->check   = o->bogus_csum ? 
    __16BIT_RND(0) : 
    cksum((uint16_t *)rsvp, offset);

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

/* Function Name: RSVP objects size claculation.

Description:   This function calculates the size of RSVP objects.

Targets:       N/A */
static size_t rsvp_objects_len(const uint8_t foo, const uint8_t bar, const uint8_t baz, const uint8_t qux)
{
  size_t size;

  /*
   * The code starts with the size of SESSION Object Class  (according
   * to the RFC 2205, this is required in every RSVP message), and, if
   * the appropriate RSVP Message type matches,  size  accumulates the
   * corresponded Object Class(s)  size  to build the appropriate RSVP 
   * message.  Otherwise,   it just returns the size of SESSION Object
   * Class.
   */
  size = RSVP_LENGTH_SESSION;

  /* 
   * The RESV_HOP Object Class is present for the following:
   * 3.1.3 Path Messages
   * 3.1.4 Resv Messages
   * 3.1.5 Path Teardown Messages
   * 3.1.6 Resv Teardown Messages
   * 3.1.8 Resv Error Messages
   */
  if (foo == RSVP_MESSAGE_TYPE_PATH     ||
      foo == RSVP_MESSAGE_TYPE_RESV     ||
      foo == RSVP_MESSAGE_TYPE_PATHTEAR ||
      foo == RSVP_MESSAGE_TYPE_RESVTEAR ||
      foo == RSVP_MESSAGE_TYPE_RESVERR)
    size += RSVP_LENGTH_RESV_HOP;

  /* 
   * The TIME_VALUES Object Class is present for the following:
   * 3.1.3 Path Messages
   * 3.1.4 Resv Messages
   */
  if (foo == RSVP_MESSAGE_TYPE_PATH ||
      foo == RSVP_MESSAGE_TYPE_RESV)
    size += RSVP_LENGTH_TIME_VALUES;

  /* 
   * The ERROR_SPEC Object Class is present for the following:
   * 3.1.5 Path Teardown Messages
   * 3.1.8 Resv Error Messages
   * 3.1.9 Confirmation Messages
   */
  if (foo == RSVP_MESSAGE_TYPE_PATHERR ||
      foo == RSVP_MESSAGE_TYPE_RESVERR ||
      foo == RSVP_MESSAGE_TYPE_RESVCONF)
    size += RSVP_LENGTH_ERROR_SPEC;

  /* 
   * The SENDER_TEMPLATE,  SENDER_TSPEC and  ADSPEC Object Classes are
   * present for the following:
   * 3.1.3 Path Messages
   * 3.1.5 Path Teardown Messages
   * 3.1.7 Path Error Messages
   */
  if (foo == RSVP_MESSAGE_TYPE_PATH     ||
      foo == RSVP_MESSAGE_TYPE_PATHTEAR ||
      foo == RSVP_MESSAGE_TYPE_PATHERR)
  {
    size += RSVP_LENGTH_SENDER_TEMPLATE;
    size += RSVP_LENGTH_SENDER_TSPEC;
    size += TSPEC_SERVICES(qux);
    size += RSVP_LENGTH_ADSPEC;
    size += ADSPEC_SERVICES(baz);
  }

  /* 
   * The RESV_CONFIRM Object Class is present for the following:
   * 3.1.4 Resv Messages
   * 3.1.9 Confirmation Messages
   */
  if (foo == RSVP_MESSAGE_TYPE_RESV ||
      foo == RSVP_MESSAGE_TYPE_RESVCONF)
    size += RSVP_LENGTH_RESV_CONFIRM;

  /* 
   * The STYLE Object Classes is present for the following:
   * 3.1.4 Resv Messages
   * 3.1.6 Resv Teardown Messages
   * 3.1.8 Resv Error Messages
   * 3.1.9 Confirmation Messages
   */
  if (foo == RSVP_MESSAGE_TYPE_RESV     ||
      foo == RSVP_MESSAGE_TYPE_RESVTEAR ||
      foo == RSVP_MESSAGE_TYPE_RESVERR  ||
      foo == RSVP_MESSAGE_TYPE_RESVCONF)
  {
    /* 
     * The SCOPE Object Classes is present for the following:
     * 3.1.4 Resv Messages
     * 3.1.6 Resv Teardown Messages
     * 3.1.8 Resv Error Messages
     */
    if (foo == RSVP_MESSAGE_TYPE_RESV     ||
        foo == RSVP_MESSAGE_TYPE_RESVTEAR ||
        foo == RSVP_MESSAGE_TYPE_RESVERR)
      size += RSVP_LENGTH_SCOPE(bar);

    size += RSVP_LENGTH_STYLE;
  } 

  return size;
}
