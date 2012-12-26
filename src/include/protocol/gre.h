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
#ifndef __GRE_H
#define __GRE_H 1

#include <common.h>

#define GREVERSION             0

/* GRE Options */
enum gre_option{
	GRE_OPTION_STRICT           = 0x01,
#define GRE_OPTION_STRICT             GRE_OPTION_STRICT
	GRE_OPTION_SEQUENCE         = 0x02,
#define GRE_OPTION_SEQUENCE           GRE_OPTION_SEQUENCE
#define GRE_OPTLEN_SEQUENCE    sizeof (struct gre_seq_hdr)
	GRE_OPTION_KEY              = 0x04,
#define GRE_OPTION_KEY                GRE_OPTION_KEY
#define GRE_OPTLEN_KEY         sizeof(struct gre_key_hdr)
	GRE_OPTION_ROUTING          = 0x08,
#define GRE_OPTION_ROUTING            GRE_OPTION_ROUTING
	GRE_OPTION_CHECKSUM         = 0x10,
#define GRE_OPTION_CHECKSUM           GRE_OPTION_CHECKSUM
#define GRE_OPTLEN_CHECKSUM    sizeof(struct gre_sum_hdr)
};


/* GRE PROTOCOL STRUCTURES

   GRE protocol structures used by code.
   Any new GRE protocol structure should be added in this section. */
/*
 * Generic Routing Encapsulation (GRE) (RFC 1701)
 *
 *   The GRE packet header has form:
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |C|R|K|S|s|Recur|  Flags  | Ver |         Protocol Type         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |      Checksum (optional)      |       Offset (optional)       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Key (optional)                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Sequence Number (optional)                 |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Routing (optional)
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Key and Sequence Number Extensions to GRE (RFC 2890)
 *
 *   The proposed GRE header will have the following format:
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |C| |K|S| Reserved0       | Ver |         Protocol Type         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |      Checksum (optional)      |       Reserved1 (Optional)    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Key (optional)                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                 Sequence Number (Optional)                    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct gre_hdr{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint16_t recur:3,                /* recursion control           */
	          s:1,                    /* strict source route         */
	          S:1,                    /* sequence number present     */
	          K:1,                    /* key present                 */
	          R:1,                    /* routing present             */
	          C:1,                    /* checksum present            */
	          version:3,              /* version                     */
	          flags:5;                /* flags                       */
#elif defined(__BIG_ENDIAN_BITFIELD)
	uint16_t C:1,                    /* checksum present            */
	          R:1,                    /* routing present             */
	          K:1,                    /* key present                 */
	          S:1,                    /* sequence number present     */
	          s:1,                    /* strict source route         */
	          recur:3,                /* recursion control           */
	          flags:5,                /* flags                       */
	          version:3;              /* version                     */
#else
#	error	"Adjust your <asm/byteorder.h> defines"
#endif
	uint16_t proto;                  /* protocol                    */
	uint8_t  __optional[0];          /* optional                    */
};
/*
 * Generic Routing Encapsulation (GRE) (RFC 1701)
 *
 *    Offset (2 octets)
 *
 *    The  offset  field  indicates  the octet offset from the start of the
 *    Routing  field  to  the  first octet of the active Source Route Entry
 *    to be examined.  This  field  is  present  if  the Routing Present or
 *    the Checksum Present bit is set to 1, and contains valid  information
 *    only if the Routing Present bit is set to 1.
 *
 *    Checksum (2 octets)
 *
 *    The Checksum  field  contains the IP (one's complement)  checksum  of
 *    the GRE  header  and  the  payload  packet.  This field is present if
 *    the  Routing  Present  or  the  Checksum Present bit is set to 1, and
 *    contains  valid  information  only if the Checksum Present bit is set
 *    to 1.
 */
struct gre_sum_hdr{
	uint16_t check;                  /* checksum                    */
	uint16_t offset;                 /* offset                      */
};
/*
 * Generic Routing Encapsulation (GRE) (RFC 1701)
 *
 *    Key (4 octets)
 *
 *    The  Key  field  contains  a  four octet number which was inserted by
 *    the encapsulator.  It may be used by the receiver to authenticate the
 *    source of the packet. The techniques for determining authenticity are
 *    outside of the scope of this document.  The Key field is only present
 *    if the Key Present field is set to 1.
 */
struct gre_key_hdr{
	uint32_t key;                    /* key                         */
};
/*
 * Generic Routing Encapsulation (GRE) (RFC 1701)
 *
 *    Sequence Number (4 octets)
 *
 *    The Sequence Number  field  contains an unsigned 32 bit integer which
 *    is inserted by  the  encapsulator.  It may be used by the receiver to
 *    establish the  order  in which packets have been transmitted from the
 *    encapsulator to the receiver. The exact algorithms for the generation
 *    of  the  Sequence  Number  and  the  semantics  of their reception is 
 *    outside of the scope of this document.
 */
struct gre_seq_hdr{
	uint32_t sequence;          /* sequence number             */
};	

size_t gre_opt_len(const uint8_t foo, const uint8_t bar);
struct iphdr *gre_encapsulation(void *, const struct config_options *, uint32_t);
void gre_checksum(void *, const struct config_options *, uint32_t);

#endif  /* __GRE_H */
