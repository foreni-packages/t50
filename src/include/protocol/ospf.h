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

#ifndef __OSPF_H
#define __OSPF_H 1

#include <common.h>

#define IPPROTO_OSPF           89
#define OSPFVERSION            2
/* OSPF Message Type */
enum ospf_type{
	OSPF_TYPE_HELLO             = 1,
#define OSPF_TLEN_HELLO        20
#define OSPF_TLEN_NEIGHBOR(foo) \
			(foo * sizeof(in_addr_t))
	OSPF_TYPE_DD,
#define OSPF_TLEN_DD           8
	OSPF_TYPE_LSREQUEST,
#define OSPF_TLEN_LSREQUEST    12
	OSPF_TYPE_LSUPDATE,
#define OSPF_TLEN_LSUPDATE     4
	OSPF_TYPE_LSACK,
#define OSPF_TYPE_LSACK               OSPF_TYPE_LSACK
};
/* OSPF HELLO, DD and LSA Option */
enum ospf_option{
	OSPF_OPTION_TOS             = 0x01,
#define OSPF_OPTION_TOS               OSPF_OPTION_TOS
	OSPF_OPTION_EXTERNAL        = 0x02,
#define OSPF_OPTION_EXTERNAL          OSPF_OPTION_EXTERNAL
	OSPF_OPTION_MULTICAST       = 0x04,
#define OSPF_OPTION_MULTICAST         OSPF_OPTION_MULTICAST
	OSPF_OPTION_NSSA            = 0x08,
#define OSPF_OPTION_NSSA              OSPF_OPTION_NSSA
	OSPF_OPTION_LLS             = 0x10,
#define OSPF_OPTION_LLS               OSPF_OPTION_LLS
	OSPF_OPTION_DEMAND          = 0x20,
#define OSPF_OPTION_DEMAND            OSPF_OPTION_DEMAND
	OSPF_OPTION_OPAQUE          = 0x40,
#define OSPF_OPTION_OPAQUE            OSPF_OPTION_OPAQUE
	OSPF_OPTION_DOWN            = 0x80,
#define OSPF_OPTION_DOWN              OSPF_OPTION_DOWN
};
/* OSPF DD DB Description */
enum dd_dbdesc{
	DD_DBDESC_MSLAVE            = 0x01,
#define DD_DBDESC_MSLAVE              DD_DBDESC_MSLAVE
	DD_DBDESC_MORE              = 0x02,
#define DD_DBDESC_MORE                DD_DBDESC_MORE
	DD_DBDESC_INIT              = 0x04,
#define DD_DBDESC_INIT                DD_DBDESC_INIT
	DD_DBDESC_OOBRESYNC         = 0x08,
#define DD_DBDESC_OOBRESYNC           DD_DBDESC_OOBRESYNC
};
/* OSPF LSA LS Type */
enum lsa_type{
#define LSA_TLEN_GENERIC(foo) \
			(sizeof(struct ospf_lsa_hdr) + \
			(foo * sizeof(uint32_t)))
	LSA_TYPE_ROUTER             = 1,
#define LSA_TLEN_ROUTER        LSA_TLEN_GENERIC(4)
	LSA_TYPE_NETWORK,
#define LSA_TLEN_NETWORK       LSA_TLEN_GENERIC(2)
	LSA_TYPE_SUMMARY_IP,
#define LSA_TYPE_SUMMARY_IP           LSA_TYPE_SUMMARY_IP
	LSA_TYPE_SUMMARY_AS,
#define LSA_TLEN_SUMMARY       LSA_TLEN_GENERIC(2)
	LSA_TYPE_ASBR,
#define LSA_TYPE_ASBR                 LSA_TYPE_ASBR
#define LSA_TLEN_ASBR          LSA_TLEN_GENERIC(4)
	LSA_TYPE_MULTICAST,
#define LSA_TLEN_MULTICAST     LSA_TLEN_GENERIC(2)
	LSA_TYPE_NSSA,
#define LSA_TLEN_NSSA          LSA_TLEN_ASBR
	LSA_TYPE_OPAQUE_LINK        = 9,
#define LSA_TYPE_OPAQUE_LINK          LSA_TYPE_OPAQUE_LINK
	LSA_TYPE_OPAQUE_AREA,
#define LSA_TYPE_OPAQUE_AREA          LSA_TYPE_OPAQUE_AREA
	LSA_TYPE_OPAQUE_FLOOD,
#define LSA_TYPE_OPAQUE_FLOOD         LSA_TYPE_OPAQUE_FLOOD
};
/* OSPF Router-LSA Flag */
enum router_flag{
	ROUTER_FLAG_BORDER          = 0x01,
#define ROUTER_FLAG_BORDER            ROUTER_FLAG_BORDER
	ROUTER_FLAG_EXTERNAL        = 0x02,
#define ROUTER_FLAG_EXTERNAL          ROUTER_FLAG_EXTERNAL
	ROUTER_FLAG_VIRTUAL         = 0x04,
#define ROUTER_FLAG_VIRTUAL           ROUTER_FLAG_VIRTUAL
	ROUTER_FLAG_WILD            = 0x08,
#define ROUTER_FLAG_WILD              ROUTER_FLAG_WILD
	ROUTER_FLAG_NSSA_TR         = 0x10,
#define ROUTER_FLAG_NSSA_TR           ROUTER_FLAG_NSSA_TR
};
/* OSPF Router-LSA Link type */
enum link_type{
	LINK_TYPE_PTP               = 1,
#define LINK_TYPE_PTP                 LINK_TYPE_PTP
	LINK_TYPE_TRANSIT,
#define LINK_TYPE_TRANSIT             LINK_TYPE_TRANSIT
	LINK_TYPE_STUB,
#define LINK_TYPE_STUB                LINK_TYPE_STUB
	LINK_TYPE_VIRTUAL,
#define LINK_TYPE_VIRTUAL             LINK_TYPE_VIRTUAL
};
/* OSPF Group-LSA Type */
enum vertex_type{
	VERTEX_TYPE_ROUTER          = 0x00000001,
#define VERTEX_TYPE_ROUTER            VERTEX_TYPE_ROUTER
	VERTEX_TYPE_NETWORK,
#define VERTEX_TYPE_NETWORK           VERTEX_TYPE_NETWORK
};
#define OSPF_TLV_HEADER        sizeof(struct ospf_lls_hdr)
/* OSPF LLS Type/Length/Value */
enum ospf_tlv{
	OSPF_TLV_RESERVED           = 0,
#define OSPF_TLV_RESERVED             OSPF_TLV_RESERVED
	OSPF_TLV_EXTENDED,
#define OSPF_TLV_EXTENDED             OSPF_TLV_EXTENDED
#define OSPF_LEN_EXTENDED      OSPF_TLV_HEADER
#define EXTENDED_OPTIONS_LR    0x00000001
#define EXTENDED_OPTIONS_RS    0x00000002
	OSPF_TLV_CRYPTO,
#define OSPF_LEN_CRYPTO \
		OSPF_TLV_HEADER + \
		AUTH_TLEN_HMACMD5
};
/* Calculating OSPF LLS Type/Length/Value length */
#	define ospf_tlv_len(foo, bar, baz) \
			(foo == OSPF_TYPE_HELLO || \
			 foo == OSPF_TYPE_DD ? \
				(bar ? \
					OSPF_TLV_HEADER * 2 + \
					OSPF_LEN_EXTENDED   + \
					(baz ? \
						OSPF_TLV_HEADER + \
						OSPF_LEN_CRYPTO : \
					0) : \
				0) : \
			0)

/* OSPF PROTOCOL STRUCTURES

   OSPF protocol structures used by code.
   Any new OSPF protocol structure should be added in this section. */
/*
 * OSPF Version 2 (RFC 2328)
 *
 * A.3.1 The OSPF packet header
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Version #   |     Type      |         Packet length         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |	                       Router ID                            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                           Area ID                             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           Checksum            |             AuType            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ospf_hdr{
	uint16_t version:8,              /* version                     */
	          type:8;                 /* type                        */
	uint16_t length;                 /* length                      */
	in_addr_t rid;                    /* router ID                   */
	in_addr_t aid;                    /* area ID                     */
	uint16_t check;                  /* checksum                    */
	uint16_t autype;                 /* authentication type         */
	uint8_t  __ospf_auth[0];         /* authentication header       */
	uint8_t  __ospf_type_hdr[0];     /* type header                 */
};
/*
 * OSPF Version 2 (RFC 2328)
 *
 * A.3.1 The OSPF packet header
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Authentication                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Authentication                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * D.3 Cryptographic authentication
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              0                |    Key ID     | Auth Data Len |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                 Cryptographic sequence number                 |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ospf_auth_hdr{
	uint16_t reserved;               /* reserved must be zero       */
	uint16_t key_id:8,               /* authentication key ID       */
	          length:8;               /* authentication length       */
	uint32_t sequence;               /* authentication sequence #   */
};
/*
 * OSPF Version 2 (RFC 2328)
 *
 * A.4.1 The Link State Advertisement (LSA) header
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |            LS age             |    Options    |    LS type    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                        Link State ID                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                     Advertising Router                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                     LS sequence number                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         LS checksum           |             length            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ospf_lsa_hdr{
	uint16_t age;                    /* LSA age                     */
	uint8_t  options;                /* LSA options                 */
	uint8_t  type;                   /* LSA type                    */
	in_addr_t lsid;                   /* LSA link state ID           */
	in_addr_t router;                 /* LSA advertising router      */
	uint32_t sequence;               /* LSA sequence number         */
	uint16_t check;                  /* LSA checksum                */
	uint16_t length;                 /* LSA length                  */
};
/*
 * OSPF Link-Local Signaling (RFC 5613)
 *
 * 2.2.  LLS Data Block
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |            Checksum           |       LLS Data Length         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  |                           LLS TLVs                            |
 *  .                                                               .
 *  .                                                               .
 *  .                                                               .
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ospf_lls_hdr{
	uint16_t check;                  /* LLS checksum                */
	uint16_t length;                 /* LLS length                  */
};

#endif  /* __OSPF_H */
