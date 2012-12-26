/*
 *	T50 - Experimental Packet Injector
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

#ifndef CONFIG_H
#define CONFIG_H

#include <common.h>

/* Command line interface options which do not have short options */
enum {
	/* XXX COMMON OPTIONS                            */
	OPTION_THRESHOLD = 128,
	OPTION_FLOOD,
	OPTION_ENCAPSULATED,
#ifdef  __HAVE_TURBO__
	OPTION_TURBO,
#endif  /* __HAVE_TURBO__ */
	OPTION_LIST_PROTOCOL,
	/* XXX DCCP, TCP & UDP HEADER OPTIONS            */
	OPTION_SOURCE,
	OPTION_DESTINATION,
	/* XXX IP HEADER OPTIONS  (IPPROTO_IP = 0)       */
	OPTION_IP_TOS,
	OPTION_IP_ID,
	OPTION_IP_OFFSET,
	OPTION_IP_TTL,
	OPTION_IP_PROTOCOL,
	/* XXX GRE HEADER OPTIONS (IPPROTO_GRE = 47)     */
	OPTION_GRE_SEQUENCE_PRESENT,
	OPTION_GRE_KEY_PRESENT,
	OPTION_GRE_CHECKSUM_PRESENT,
	OPTION_GRE_KEY,
	OPTION_GRE_SEQUENCE,
	OPTION_GRE_SADDR,
	OPTION_GRE_DADDR,
	/* XXX ICMP HEADER OPTIONS (IPPROTO_ICMP = 1)    */
	OPTION_ICMP_TYPE,
	OPTION_ICMP_CODE,
	OPTION_ICMP_GATEWAY,
	OPTION_ICMP_ID,
	OPTION_ICMP_SEQUENCE,
	/* XXX IGMP HEADER OPTIONS (IPPROTO_IGMP = 2)    */
	OPTION_IGMP_TYPE,
	OPTION_IGMP_CODE,
	OPTION_IGMP_GROUP,
	OPTION_IGMP_QRV,
	OPTION_IGMP_SUPPRESS,
	OPTION_IGMP_QQIC,
	OPTION_IGMP_GREC_TYPE,
	OPTION_IGMP_SOURCES,
	OPTION_IGMP_GREC_MULTICAST,
	OPTION_IGMP_ADDRESS,
	/* XXX TCP HEADER OPTIONS (IPPROTO_TCP = 6)      */
	OPTION_TCP_ACKNOWLEDGE,
	OPTION_TCP_SEQUENCE,
	OPTION_TCP_OFFSET,
	OPTION_TCP_URGENT_POINTER,
	OPTION_TCP_MSS,
	OPTION_TCP_WSOPT,
	OPTION_TCP_TSOPT,
	OPTION_TCP_SACK_OK,
	OPTION_TCP_CC,
	OPTION_TCP_CC_NEW,
	OPTION_TCP_CC_ECHO,
	OPTION_TCP_SACK_EDGE,
	OPTION_TCP_MD5_SIGNATURE,
	OPTION_TCP_AUTHENTICATION,
	OPTION_TCP_AUTH_KEY_ID,
	OPTION_TCP_AUTH_NEXT_KEY,
	OPTION_TCP_NOP,
	/* XXX EGP HEADER OPTIONS (IPPROTO_EGP = 8)      */
	OPTION_EGP_TYPE,
	OPTION_EGP_CODE,
	OPTION_EGP_STATUS,
	OPTION_EGP_AS,
	OPTION_EGP_SEQUENCE,
	OPTION_EGP_HELLO,
	OPTION_EGP_POLL,
	/* XXX RIP HEADER OPTIONS (IPPROTO_UDP = 17)     */
	OPTION_RIP_COMMAND,
	OPTION_RIP_FAMILY,
	OPTION_RIP_ADDRESS,
	OPTION_RIP_METRIC,
	OPTION_RIP_DOMAIN,
	OPTION_RIP_TAG,
	OPTION_RIP_NETMASK,
	OPTION_RIP_NEXTHOP,
	OPTION_RIP_AUTHENTICATION,
	OPTION_RIP_AUTH_KEY_ID,
	OPTION_RIP_AUTH_SEQUENCE,
	/* XXX DCCP HEADER OPTIONS (IPPROTO_DCCP = 33)   */
	OPTION_DCCP_OFFSET,
	OPTION_DCCP_CSCOV,
	OPTION_DCCP_CCVAL,
	OPTION_DCCP_TYPE,
	OPTION_DCCP_EXTEND,
	OPTION_DCCP_SEQUENCE_01,
	OPTION_DCCP_SEQUENCE_02,
	OPTION_DCCP_SEQUENCE_03,
	OPTION_DCCP_SERVICE,
	OPTION_DCCP_ACKNOWLEDGE_01,
	OPTION_DCCP_ACKNOWLEDGE_02,
	OPTION_DCCP_RESET_CODE,
	/* XXX RSVP HEADER OPTIONS (IPPROTO_RSVP = 46)   */
	OPTION_RSVP_FLAGS,
	OPTION_RSVP_TYPE,
	OPTION_RSVP_TTL,
	OPTION_RSVP_SESSION_ADDRESS,
	OPTION_RSVP_SESSION_PROTOCOL,
	OPTION_RSVP_SESSION_FLAGS,
	OPTION_RSVP_SESSION_PORT,
	OPTION_RSVP_HOP_ADDRESS,
	OPTION_RSVP_HOP_IFACE,
	OPTION_RSVP_TIME_REFRESH,
	OPTION_RSVP_ERROR_ADDRESS,
	OPTION_RSVP_ERROR_FLAGS,
	OPTION_RSVP_ERROR_CODE,
	OPTION_RSVP_ERROR_VALUE,
	OPTION_RSVP_SCOPE,
	OPTION_RSVP_SCOPE_ADDRESS,
	OPTION_RSVP_STYLE_OPTION,
	OPTION_RSVP_SENDER_ADDRESS,
	OPTION_RSVP_SENDER_PORT,
	OPTION_RSVP_TSPEC_TRAFFIC,
	OPTION_RSVP_TSPEC_GUARANTEED,
	OPTION_RSVP_TSPEC_TOKEN_R,
	OPTION_RSVP_TSPEC_TOKEN_B,
	OPTION_RSVP_TSPEC_DATA_P,
	OPTION_RSVP_TSPEC_MINIMUM,
	OPTION_RSVP_TSPEC_MAXIMUM,
	OPTION_RSVP_ADSPEC_ISHOP,
	OPTION_RSVP_ADSPEC_PATH,
	OPTION_RSVP_ADSPEC_MINIMUM,
	OPTION_RSVP_ADSPEC_MTU,
	OPTION_RSVP_ADSPEC_GUARANTEED,
	OPTION_RSVP_ADSPEC_CONTROLLED,
	OPTION_RSVP_ADSPEC_CTOT,
	OPTION_RSVP_ADSPEC_DTOT,
	OPTION_RSVP_ADSPEC_CSUM,
	OPTION_RSVP_ADSPEC_DSUM,
	OPTION_RSVP_CONFIRM_ADDR,
	/* XXX IPSEC HEADER OPTIONS (IPPROTO_AH = 51 & IPPROTO_ESP = 50) */
	OPTION_IPSEC_AH_LENGTH,
	OPTION_IPSEC_AH_SPI,
	OPTION_IPSEC_AH_SEQUENCE,
	OPTION_IPSEC_ESP_SPI,
	OPTION_IPSEC_ESP_SEQUENCE,
	/* XXX EIGRP HEADER OPTIONS (IPPROTO_EIGRP = 88) */
	OPTION_EIGRP_OPCODE,
	OPTION_EIGRP_FLAGS,
	OPTION_EIGRP_SEQUENCE,
	OPTION_EIGRP_ACKNOWLEDGE,
	OPTION_EIGRP_AS,
	OPTION_EIGRP_TYPE,
	OPTION_EIGRP_LENGTH,
	OPTION_EIGRP_K1,
	OPTION_EIGRP_K2,
	OPTION_EIGRP_K3,
	OPTION_EIGRP_K4,
	OPTION_EIGRP_K5,
	OPTION_EIGRP_HOLD,
	OPTION_EIGRP_IOS_VERSION,
	OPTION_EIGRP_PROTO_VERSION,
	OPTION_EIGRP_NEXTHOP,
	OPTION_EIGRP_DELAY,
	OPTION_EIGRP_BANDWIDTH,
	OPTION_EIGRP_MTU,
	OPTION_EIGRP_HOP_COUNT,
	OPTION_EIGRP_LOAD,
	OPTION_EIGRP_RELIABILITY,
	OPTION_EIGRP_DESINATION,
	OPTION_EIGRP_SOURCE_ROUTER,
	OPTION_EIGRP_SOURCE_AS,
	OPTION_EIGRP_TAG,
	OPTION_EIGRP_METRIC,
	OPTION_EIGRP_ID,
	OPTION_EIGRP_EXTERNAL_FLAGS,
	OPTION_EIGRP_ADDRESS,
	OPTION_EIGRP_MULTICAST,
	OPTION_EIGRP_AUTHENTICATION,
	OPTION_EIGRP_AUTH_KEY_ID,
	/* XXX OSPF HEADER OPTIONS (IPPROTO_OSPF = 89)   */
	OPTION_OSPF_TYPE,
	OPTION_OSPF_LENGTH,
	OPTION_OSPF_ROUTER_ID,
	OPTION_OSPF_AREA_ID,
	OPTION_OSPF_NETMASK,
	OPTION_OSPF_HELLO_INTERVAL,
	OPTION_OSPF_HELLO_PRIORITY,
	OPTION_OSPF_HELLO_DEAD,
	OPTION_OSPF_HELLO_DESIGN,
	OPTION_OSPF_HELLO_BACKUP,
	OPTION_OSPF_HELLO_NEIGHBOR,
	OPTION_OSPF_HELLO_ADDRESS,
	OPTION_OSPF_DD_MTU,
	OPTION_OSPF_DD_MASTER_SLAVE,
	OPTION_OSPF_DD_MORE,
	OPTION_OSPF_DD_INIT,
	OPTION_OSPF_DD_OOBRESYNC,
	OPTION_OSPF_DD_SEQUENCE,
	OPTION_OSPF_DD_INCLUDE_LSA,
	OPTION_OSPF_LSA_AGE,
	OPTION_OSPF_LSA_DO_NOT_AGE,
	OPTION_OSPF_LSA_TYPE,
	OPTION_OSPF_LSA_LSID,
	OPTION_OSPF_LSA_ROUTER,
	OPTION_OSPF_LSA_SEQUENCE,
	OPTION_OSPF_LSA_METRIC,
	OPTION_OSPF_LSA_FLAG_BORDER,
	OPTION_OSPF_LSA_FLAG_EXTERNAL,
	OPTION_OSPF_LSA_FLAG_VIRTUAL,
	OPTION_OSPF_LSA_FLAG_WILD,
	OPTION_OSPF_LSA_FLAG_NSSA_TR,
	OPTION_OSPF_LSA_LINK_ID,
	OPTION_OSPF_LSA_LINK_DATA,
	OPTION_OSPF_LSA_LINK_TYPE,
	OPTION_OSPF_LSA_ATTACHED,
	OPTION_OSPF_LSA_LARGER,
	OPTION_OSPF_LSA_FORWARD,
	OPTION_OSPF_LSA_EXTERNAL,
	OPTION_OSPF_VERTEX_ROUTER,
	OPTION_OSPF_VERTEX_NETWORK,
	OPTION_OSPF_VERTEX_ID,
	OPTIONS_OSPF_LLS_OPTION_LR,
	OPTIONS_OSPF_LLS_OPTION_RS,
	OPTION_OSPF_AUTHENTICATION,
	OPTION_OSPF_AUTH_KEY_ID,
	OPTION_OSPF_AUTH_SEQUENCE,
};


/* Config structures */
struct cidr{
	uint32_t  hostid;                 /* hosts identifiers           */
	in_addr_t __1st_addr;             /* first IP address            */
};

struct config_options {
	/* XXX COMMON OPTIONS                                            */
	uint32_t  threshold;              /* amount of packets           */
	uint32_t  flood;                  /* flood                       */
	uint8_t   encapsulated:1;         /* GRE encapsulated            */
	uint32_t  bogus_csum;             /* bogus packet checksum       */
#ifdef  __HAVE_TURBO__
	uint32_t  turbo;                  /* duplicate the attack        */
#endif  /* __HAVE_TURBO__ */
	/* XXX DCCP, TCP & UDP HEADER OPTIONS                            */
	uint16_t  source;                 /* general source port         */
	uint16_t  dest;                   /* general destination port    */

	uint32_t  bits:5;                 /* CIDR bits                   */

	/* XXX IP HEADER OPTIONS  (IPPROTO_IP = 0)                       */
	struct{
		uint8_t   tos;            /* type of service             */
		uint16_t  id;             /* identification              */
		uint16_t  frag_off;       /* fragmentation offset        */
		uint8_t   ttl;            /* time to live                */
		uint8_t   protocol;       /* packet protocol             */
		uint32_t  protoname;      /* protocol name               */
		in_addr_t saddr;          /* source address              */
		in_addr_t daddr;          /* destination address         */
	} ip;
	/* XXX GRE HEADER OPTIONS (IPPROTO_GRE = 47)                     */
	struct{
		uint8_t   options;        /* GRE options bitmask         */
		uint8_t   S:1;            /* sequence number present     */
		uint8_t   K:1;            /* key present                 */
		uint8_t   C:1;            /* checksum present            */
		uint32_t  key;            /* key                         */
		uint32_t  sequence;       /* sequence number             */
		in_addr_t saddr;          /* GRE source address          */
		in_addr_t daddr;          /* GRE destination address     */
	} gre;
	/* XXX ICMP HEADER OPTIONS (IPPROTO_ICMP = 1)                    */
	struct{
		uint8_t   type;           /* type                        */
		uint8_t   code;           /* code                        */
		uint16_t  id;             /* identification              */
		uint16_t  sequence;       /* sequence number             */
		in_addr_t gateway;        /* gateway address             */
	} icmp;
	/* XXX IGMP HEADER OPTIONS (IPPROTO_IGMP = 2)                    */
	struct{
		uint8_t   type;           /* type                        */
		uint8_t   code;           /* code                        */
		in_addr_t group;          /* group address               */
		uint8_t   qrv:3,          /* querier robustness variable */
		          suppress:1;     /* suppress router-side        */
		uint8_t   qqic;           /* querier query interv. code  */
		uint8_t   grec_type;      /* group record type           */
		uint8_t   sources;        /* number of sources           */
		in_addr_t grec_mca;       /* group record multicast addr */
		in_addr_t address[255];   /* source address(es)          */
	} igmp;
	/* XXX TCP HEADER OPTIONS (IPPROTO_TCP = 6)                      */
	struct{
		uint32_t  sequence;       /* initial sequence number     */
		uint32_t  acknowledge;    /* acknowledgment sequence     */
		uint8_t   doff:4;         /* data offset                 */
		uint8_t   fin:1;          /* end of data flag            */
		uint8_t   syn:1;          /* synchronize ISN flag        */
		uint8_t   rst:1;          /* reset connection flag       */
		uint8_t   psh:1;          /* push flag                   */
		uint8_t   ack:1;          /* acknowledgment # valid flag */
		uint8_t   urg:1;          /* urgent pointer valid flag   */
		uint8_t   ece:1;          /* ecn-echo                    */
		uint8_t   cwr:1;          /* congestion windows reduced  */
		uint16_t  window;         /* window size                 */
		uint16_t  urg_ptr;        /* urgent pointer data         */
		uint8_t   options;        /* TCP options bitmask         */
		uint16_t  mss;            /* MSS option        (RFC793)  */
		uint8_t   wsopt;          /* WSOPT option      (RFC1323) */
		uint32_t  tsval;          /* TSval option      (RFC1323) */
		uint32_t  tsecr;          /* TSecr option      (RFC1323) */
		uint32_t  cc;             /* T/TCP CC          (RFC1644) */
		uint32_t  cc_new;         /* T/TCP CC.NEW      (RFC1644) */
		uint32_t  cc_echo;        /* T/TCP CC.ECHO     (RFC1644) */
		uint32_t  sack_left;      /* SACK-Left option  (RFC2018) */
		uint32_t  sack_right;     /* SACK-Right option (RFC2018) */
		uint8_t   md5:1;          /* MD5 Option        (RFC2385) */
		uint8_t   auth:1;         /* AO Option         (RFC5925) */
		uint8_t   key_id;         /* AO key ID         (RFC5925) */
		uint8_t   next_key;       /* AO next key ID    (RFC5925) */
		uint8_t   nop;            /* NOP option        (RFC793)  */
	} tcp;
	/* XXX EGP HEADER OPTIONS (IPPROTO_EGP = 8)                      */
	struct{
		uint8_t   type;           /* type                        */
		uint8_t   code;           /* code                        */
		uint8_t   status;         /* status                      */
		uint16_t  as;             /* autonomous system           */
		uint16_t  sequence;       /* sequence number             */
		uint16_t  hello;          /* hello interval              */
		uint16_t  poll;           /* poll interval               */
	} egp;
	/* XXX RIP HEADER OPTIONS (IPPROTO_UDP = 17)                     */
	struct{
		uint8_t   command;        /* command                     */
		uint16_t  family;         /* address family identifier   */
		in_addr_t address;        /* IP address                  */
		uint32_t  metric;         /* metric                      */
		uint16_t  domain;         /* router domain               */
		uint16_t  tag;            /* router tag                  */
		in_addr_t netmask;        /* subnet mask                 */
		in_addr_t next_hop;       /* next hop                    */
		uint8_t   auth:1;         /* authentication              */
		uint8_t   key_id;         /* authentication key ID       */
		uint32_t  sequence;       /* authentication sequence     */
	} rip;
	/* XXX DCCP HEADER OPTIONS (IPPROTO_DCCP = 33)                   */
	struct{
		uint8_t   doff;           /* data offset                 */
		uint8_t   cscov:4;        /* checksum coverage           */
		uint8_t   ccval:4;        /* HC-sender CCID              */
		uint8_t   type:4;         /* DCCP type                   */
		uint8_t   ext:1;          /* extend the sequence number  */
		uint16_t  sequence_01;    /* sequence number             */
		uint8_t   sequence_02;    /* extended sequence number    */
		uint32_t  sequence_03;    /* low sequence number         */
		uint32_t  service;        /* service code                */
		uint16_t  acknowledge_01; /* acknowledgment # high       */
		uint32_t  acknowledge_02; /* acknowledgment # low        */
		uint8_t   rst_code;       /* reset code                  */
	} dccp;
	/* XXX RSVP HEADER OPTIONS (IPPROTO_RSVP = 46)                   */
	struct{
		uint8_t   flags:4;        /* flags                       */
		uint8_t   type;           /* message type                */
		uint8_t   ttl;            /* time to live                */
		in_addr_t session_addr;   /* SESSION destination address */
		uint8_t   session_proto;  /* SESSION protocol ID         */
		uint8_t   session_flags;  /* SESSION flags               */
		uint16_t  session_port;   /* SESSION destination port    */
		in_addr_t hop_addr;       /* RESV_HOP neighbor address   */
		uint32_t  hop_iface;      /* RESV_HOP logical interface  */
		uint32_t  time_refresh;   /* TIME refresh interval       */
		in_addr_t error_addr;     /* ERROR node address          */
		uint8_t   error_flags:3;  /* ERROR flags                 */
		uint8_t   error_code;     /* ERROR code                  */
		uint16_t  error_value;    /* ERROR value                 */
		uint8_t   scope;          /* number of SCOPE(s)          */
		in_addr_t address[255];   /* SCOPE address(es)           */
		uint32_t  style_opt:24;   /* STYLE option vector         */
		in_addr_t sender_addr;    /* SENDER TEMPLATE address     */
		uint16_t  sender_port;    /* SENDER TEMPLATE port        */
		uint8_t   tspec;          /* TSPEC services              */
		uint32_t  tspec_r;        /* TSPEC Token Bucket Rate     */
		uint32_t  tspec_b;        /* TSPEC Token Bucket Size     */
		uint32_t  tspec_p;        /* TSPEC Peak Data Rate        */
		uint32_t  tspec_m;        /* TSEPC Minimum Policed Unit  */
		uint32_t  tspec_M;        /* TSPEC Maximum Packet Size   */
		uint32_t  adspec_hop;     /* ADSPEC IS HOP cnt           */
		uint32_t  adspec_path;    /* ADSPEC Path b/w estimate    */
		uint32_t  adspec_minimum; /* ADSPEC Minimum Path Latency */
		uint32_t  adspec_mtu;     /* ADSPEC Composed MTU         */
		uint8_t   adspec;         /* ADSPEC services             */
		uint32_t  adspec_Ctot;    /* ADSPEC ETE composed value C */
		uint32_t  adspec_Dtot;    /* ADSPEC ETE composed value D */
		uint32_t  adspec_Csum;    /* ADSPEC SLR point composed C */
		uint32_t  adspec_Dsum;    /* ADSPEC SLR point composed C */
		in_addr_t confirm_addr;   /* CONFIRM receiver address    */
	} rsvp;
	/* XXX IPSEC HEADER OPTIONS (IPPROTO_AH = 51 & IPPROTO_ESP = 50) */
	struct{
		uint8_t   ah_length;      /* AH header length            */
		uint32_t  ah_spi;         /* AH SPI                      */
		uint32_t  ah_sequence;    /* AH sequence number          */
		uint32_t  esp_spi;        /* ESP SPI                     */
		uint32_t  esp_sequence;   /* ESP sequence number         */
	} ipsec;
	/* XXX EIGRP HEADER OPTIONS (IPPROTO_EIGRP = 88)                 */
	struct{
		uint8_t   opcode;         /* opcode                      */
		uint32_t  flags;          /* flags                       */
		uint32_t  sequence;       /* sequence number             */
		uint32_t  acknowledge;    /* acknowledgment sequence #   */
		uint32_t  as;             /* autonomous system           */
		uint16_t  type;           /* type                        */
		uint16_t  length;         /* length                      */
		uint8_t   values;         /* EIGRP K values bitmask      */
		uint8_t   k1;             /* K1 value                    */
		uint8_t   k2;             /* K2 value                    */
		uint8_t   k3;             /* K3 value                    */
		uint8_t   k4;             /* K4 value                    */
		uint8_t   k5;             /* K5 value                    */
		uint16_t  hold;           /* hold time                   */
		uint8_t   ios_major;      /* IOS Major Version           */
		uint8_t   ios_minor;      /* IOS Minor Version           */
		uint8_t   ver_major;      /* EIGRP Major Version         */
		uint8_t   ver_minor;      /* EIGRP Minor Version         */
		in_addr_t next_hop;       /* next hop address            */
		uint32_t  delay;          /* delay                       */
		uint32_t  bandwidth;      /* bandwidth                   */
		uint32_t  mtu:24;         /* maximum transmission unit   */
		uint8_t   hop_count;      /* hop count                   */
		uint8_t   load;           /* load                        */
		uint8_t   reliability;    /* reliability                 */
		uint8_t   prefix:5;       /* subnet prefix - aka CIDR    */
		in_addr_t dest;           /* destination address         */
		in_addr_t src_router;     /* originating router          */
		uint32_t  src_as;         /* originating autonomous sys  */
		uint32_t  tag;            /* arbitrary tag               */
		uint32_t  proto_metric;   /* external protocol metric    */
		uint8_t   proto_id;       /* external protocol ID        */
		uint8_t   ext_flags;      /* external flags              */
		in_addr_t address;        /* IP address sequence         */
		uint32_t  multicast;      /* multicast sequence          */
		uint8_t   auth:1;         /* authentication              */
		uint32_t  key_id;         /* authentication key ID       */
	}eigrp;
	/* XXX OSPF HEADER OPTIONS (IPPROTO_OSPF = 89)                   */
	struct{
		uint8_t   type;           /* type                        */
		uint16_t  length;         /* length                      */
		in_addr_t rid;            /* router ID                   */
		in_addr_t aid;            /* area ID                     */
		uint8_t   AID:1;          /* area ID present             */
		uint8_t   options;        /* options                     */
		in_addr_t netmask;        /* subnet mask                 */
		uint16_t  hello_interval; /* HELLO interval              */
		uint8_t   hello_priority; /* HELLO router priority       */
		uint32_t  hello_dead;     /* HELLO router dead interval  */
		in_addr_t hello_design;   /* HELLO designated router     */
		in_addr_t hello_backup;   /* HELLO backup designated     */
		uint8_t   neighbor;       /* HELLO number of neighbors   */
		in_addr_t address[255];   /* HELLO neighbor address(es)  */
		uint16_t  dd_mtu;         /* DD MTU                      */ 
		uint8_t   dd_dbdesc;      /* DD DB description           */
		uint32_t  dd_sequence;    /* DD sequence number          */
		uint8_t   dd_include_lsa; /* DD LSA Header               */
		uint16_t  lsa_age;        /* LSA age                     */
		uint8_t   lsa_dage:1;     /* LSA do not age              */
		uint8_t   lsa_type;       /* LSA header type             */
		in_addr_t lsa_lsid;       /* LSA ID                      */
		in_addr_t lsa_router;     /* LSA advertising router      */
		uint32_t  lsa_sequence;   /* LSA sequence number         */
		uint32_t  lsa_metric:24;  /* LSA metric                  */
		uint8_t   lsa_flags;      /* Router-LSA flags            */
		in_addr_t lsa_link_id;    /* Router-LSA link ID          */
		in_addr_t lsa_link_data;  /* Router-LSA link data        */
		uint8_t   lsa_link_type;  /* Router-LSA link type        */
		in_addr_t lsa_attached;   /* Network-LSA attached router */
		uint8_t   lsa_larger:1;   /* ASBR/NSSA-LSA ext. larger   */
		in_addr_t lsa_forward;    /* ASBR/NSSA-LSA forward       */
		in_addr_t lsa_external;   /* ASBR/NSSA-LSA external      */
		uint32_t  vertex_type;    /* Group-LSA vertex type       */
		in_addr_t vertex_id;      /* Group-LSA vertex ID         */
		uint32_t  lls_options;    /* LSS Extended TLV options    */
		uint8_t   auth:1;         /* authentication              */
		uint8_t   key_id;         /* authentication key ID       */
		uint32_t  sequence;       /* authentication sequence     */
	} ospf;
};
#endif /* CONFIG_H */
