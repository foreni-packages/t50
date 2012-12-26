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

#ifndef EIGRP_H
#define EIGRP_H

#define IPPROTO_EIGRP 88
#define EIGRPVERSION 2
#define EIGRP_FLAG_INIT 0x00000001
#define EIGRP_FLAG_COND 0x00000002

#include <common.h>

/* EIGRP Message Opcode */
enum eigrp_opcode {
	EIGRP_OPCODE_UPDATE         = 1,
#define EIGRP_OPCODE_UPDATE           EIGRP_OPCODE_UPDATE
	EIGRP_OPCODE_REQUEST,
#define EIGRP_OPCODE_REQUEST          EIGRP_OPCODE_REQUEST
	EIGRP_OPCODE_QUERY,
#define EIGRP_OPCODE_QUERY            EIGRP_OPCODE_QUERY
	EIGRP_OPCODE_REPLY,
#define EIGRP_OPCODE_REPLY            EIGRP_OPCODE_REPLY
	EIGRP_OPCODE_HELLO,
#define EIGRP_OPCODE_HELLO            EIGRP_OPCODE_HELLO
	EIGRP_OPCODE_IPX_SAP,
#define EIGRP_OPCODE_IPX_SAP          EIGRP_OPCODE_IPX_SAP
};

/* EIGRP Message Type/Length/Value */
enum eigrp_tlv {
	EIGRP_TYPE_PARAMETER        = 0x0001,
#define EIGRP_TYPE_PARAMETER          EIGRP_TYPE_PARAMETER
#define EIGRP_TLEN_PARAMETER   12
	EIGRP_TYPE_AUTH,
#define EIGRP_TYPE_AUTH               EIGRP_TYPE_AUTH
#define EIGRP_TLEN_AUTH        40
#define EIGRP_PADDING_BLOCK    12
#define EIGRP_MAXIMUM_KEYID    2147483647
	EIGRP_TYPE_SEQUENCE,
#define EIGRP_TYPE_SEQUENCE           EIGRP_TYPE_SEQUENCE
#define EIGRP_TLEN_SEQUENCE    9
	EIGRP_TYPE_SOFTWARE,
#define EIGRP_TYPE_SOFTWARE           EIGRP_TYPE_SOFTWARE
#define EIGRP_TLEN_SOFTWARE    8
	EIGRP_TYPE_MULTICAST,
#define EIGRP_TYPE_MULTICAST          EIGRP_TYPE_MULTICAST
#define EIGRP_TLEN_MULTICAST   8
	EIGRP_TYPE_INTERNAL         = 0x0102,
#define EIGRP_TYPE_INTERNAL           EIGRP_TYPE_INTERNAL
#define EIGRP_TLEN_INTERNAL    25
	EIGRP_TYPE_EXTERNAL         = 0x0103,
#define EIGRP_TYPE_EXTERNAL           EIGRP_TYPE_EXTERNAL
#define EIGRP_TLEN_EXTERNAL    45
#define EIGRP_DADDR_BUILD(foo, bar) \
			(foo &= htonl(~(0xffffffff >> ((bar >> 3) * 8))))

#define EIGRP_DADDR_LENGTH(foo) \
			(((foo >> 3) & 3) + (foo % 8 ? 1 : 0))
};

/* EIGRP K Values bitmask */
enum eigrp_kvalue_bitmask{
	EIGRP_KVALUE_K1             = 0x01,
#define EIGRP_KVALUE_K1               EIGRP_KVALUE_K1
	EIGRP_KVALUE_K2             = 0x02,
#define EIGRP_KVALUE_K2               EIGRP_KVALUE_K2
	EIGRP_KVALUE_K3             = 0x04,
#define EIGRP_KVALUE_K3               EIGRP_KVALUE_K3
	EIGRP_KVALUE_K4             = 0x08,
#define EIGRP_KVALUE_K4               EIGRP_KVALUE_K4
	EIGRP_KVALUE_K5             = 0x10,
#define EIGRP_KVALUE_K5               EIGRP_KVALUE_K5
};

/*
 * Enhanced Interior Gateway Routing Protocol (EIGRP)
 *
 *    0                   1                   2                   3 3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Version    |    Opcode     |           Checksum            |
 *   +---------------+---------------+-------------------------------+
 *   |                             Flags                             |
 *   +-------------------------------+-------------------------------+
 *   |                        Sequence Number                        |
 *   +---------------------------------------------------------------+
 *   |                     Acknowledgment Number                     |
 *   +---------------------------------------------------------------+
 *   |                   Autonomous System Number                    |
 *   +---------------------------------------------------------------+
 *   |                                                               |
 *   //                  TLV (Type/Length/Value)                    //
 *   |                                                               |
 *   +---------------------------------------------------------------+
 *
 * Please,  be advised that there is no deep information about EIGRP,  no
 * other than EIGRP PCAP files public available.  Due to that I have done
 * a deep analysis using live EIGRP PCAP files to build the EIGRP Packet.
 *
 * There are some really good resources, such as:
 * http://www.protocolbase.net/protocols/protocol_EIGRP.php
 * http://packetlife.net/captures/category/cisco-proprietary/
 * http://oreilly.com/catalog/iprouting/chapter/ch04.html
 */
 
/* EIGRP PROTOCOL STRUCTURES */
struct eigrp_hdr {
	uint16_t version:8,              /* version                     */
	          opcode:8;               /* opcode                      */
	uint16_t check;                  /* checksum                    */
	uint32_t flags;                  /* flags                       */
	uint32_t sequence;               /* sequence number             */
	uint32_t acknowledge;            /* acknowledgment sequence #   */
	uint32_t as;                     /* autonomous system           */
	uint8_t  __tlv[0];               /* TLV (Type/Length/Value)     */
};

#endif  /* __EIGRP_H */
