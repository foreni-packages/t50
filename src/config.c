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

/* Default command line interface options. */
static struct config_options o = {
  /* XXX COMMON OPTIONS                                                         */
  1000,                               /* default threshold                      */
  0,                                  /* do not flood                           */
  0,                                  /* no GRE encapsulation by default        */
  0,                                  /* do not use bogus checksum              */
#ifdef  __HAVE_TURBO__
  0,                                  /* do not duplicate the attack            */
#endif  /* __HAVE_TURBO__ */
  /* XXX DCCP, TCP & UDP HEADER OPTIONS                                         */
  IPPORT_ANY,                         /* no default source port                 */
  IPPORT_ANY,                         /* no default destination port            */
  /* Classless Interdomain Routing (CIDR)                                       */
  0,                                  /* no default CIDR bits                   */
  /* XXX IP HEADER OPTIONS  (IPPROTO_IP = 0)                                    */
  { IPTOS_PREC_IMMEDIATE,       /* default type of service                */
    0,                          /* default identification                 */
    0,                          /* default fragmentation offset           */
    255,                        /* default time to live                   */
    IPPROTO_TCP,                /* default packet protocol                */
    MODULE_TCP,                 /* default protocol name                  */
    INADDR_ANY,                 /* source address                         */
    INADDR_ANY },               /* destination address                    */
  /* XXX GRE HEADER OPTIONS (IPPROTO_GRE = 47)                                  */
  { 0,                          /* no GRE options by default              */
    0,                          /* default sequence number present        */
    0,                          /* default key present                    */
    0,                          /* default checksum present               */
    0,                          /* default key                            */
    0,                          /* default sequence number                */
    INADDR_ANY,                 /* GRE source address                     */
    INADDR_ANY },               /* GRE destination address                */
  /* XXX ICMP HEADER OPTIONS (IPPROTO_ICMP = 1)                                 */
  { ICMP_ECHO,                  /* default type                           */
    0,                          /* default code                           */
    0,                          /* default identification                 */
    0,                          /* default sequence                       */
    INADDR_ANY },               /* destination gateway address            */
  /* XXX IGMP HEADER OPTIONS (IPPROTO_IGMP = 2)                                 */
  { IGMP_HOST_MEMBERSHIP_QUERY, /* default type                           */
    0,                          /* default code                           */
    INADDR_ANY,                 /* default address                        */
    0,                          /* default querier robustness variable    */
    0,                          /* default suppress router-side process   */
    0,                          /* default querier query interv. code     */
    1,                          /* default group record type              */
    2,                          /* default number of sources              */
    INADDR_ANY,                 /* default group record multicast address */
    { INADDR_ANY } },           /* default source address(es)             */
  /* XXX TCP HEADER OPTIONS (IPPROTO_TCP = 6)                                   */
  { 0,                          /* default sequence number                */
    0,                          /* default acknowledgment sequence        */
    0,                          /* default data offset                    */
    0,                          /* default end of data flag               */
    0,                          /* default synchronize ISN flag           */
    0,                          /* default reset connection flag          */
    0,                          /* default push flag                      */
    0,                          /* default acknowledgment # valid flag    */
    0,                          /* default urgent pointer valid flag      */
    0,                          /* default ecn-echo                       */
    0,                          /* default congestion windows reduced     */
    0,                          /* default window size                    */
    0,                          /* default urgent pointer data            */
    0,                          /* no TCP options by default              */
    0,                          /* default MSS option        (RFC793)     */
    0,                          /* default WSOPT option      (RFC1323)    */
    0,                          /* default TSval option      (RFC1323)    */
    0,                          /* default TSecr option      (RFC1323)    */
    0,                          /* default T/TCP CC          (RFC1644)    */
    0,                          /* default T/TCP CC.NEW      (RFC1644)    */
    0,                          /* default T/TCP CC.ECHO     (RFC1644)    */
    0,                          /* default SACK-Left option  (RFC2018)    */
    0,                          /* default SACK-Right option (RFC2018)    */
    0,                          /* do not use MD5 option by default       */
    0,                          /* do not use AO option by default        */
    1,                          /* default AO key ID         (RFC5925)    */
    1,                          /* default AO next key ID    (RFC5925)    */
    TCPOPT_EOL },               /* default NOP option        (RFC793)     */
  /* XXX EGP HEADER OPTIONS (IPPROTO_EGP = 8)                                   */
  { EGP_NEIGHBOR_ACQUISITION,   /* default type                           */
    EGP_ACQ_CODE_CEASE_CMD,     /* default code                           */
    EGP_ACQ_STAT_ACTIVE_MODE,   /* default status                         */
    0,                          /* default autonomous system              */
    0,                          /* default sequence number                */
    0,                          /* default hello interval                 */
    0 },                        /* default poll interval                  */
  /* XXX RIP HEADER OPTIONS (IPPROTO_UDP = 17)                                  */
  {       2,                          /* default command                        */
    AF_INET,                    /* default address family identifier      */
    INADDR_ANY,                 /* default IP address                     */
    0,                          /* default metric                         */
    0,                          /* default router domain                  */
    0,                          /* default router tag                     */
    INADDR_ANY,                 /* default subnet mask                    */
    0,                          /* default next hop                       */
    0,                          /* do not use authentication by default   */
    1,                          /* default authentication key ID          */
    0 },                        /* default authentication sequence        */
  /* XXX DCCP HEADER OPTIONS (IPPROTO_DCCP = 33)                                */
  { 0,                          /* default data offset                    */
    0,                          /* default checksum coverage              */
    0,                          /* default HC-sender CCID                 */
    DCCP_PKT_REQUEST,           /* default type                           */
    0,                          /* default extend sequence number         */
    0,                          /* default sequence number                */
    0,                          /* default extended sequence number       */
    0,                          /* default sequence low number            */
    0,                          /* default service code                   */
    0,                          /* default acknowledgment # high          */
    0,                          /* default acknowledgment # low           */
    0 },                        /* default reset code                     */
  /* XXX RSVP HEADER OPTIONS (IPPROTO_RSVP = 46)                                */
  { 1,                          /* default flags                          */
    RSVP_MESSAGE_TYPE_PATH,     /* default message type                   */
    254,                        /* default time to live                   */
    INADDR_ANY,                 /* default SESSION destination address    */
    1,                          /* default SESSION protocol ID            */
    1,                          /* default SESSION flags                  */
    IPPORT_ANY,                 /* default SESSION destination port       */
    INADDR_ANY,                 /* default HOP neighbor address           */
    0,                          /* default HOP logical interface          */
    360,                        /* default TIME refresh interval          */
    INADDR_ANY,                 /* default ERROR node address             */
    2,                          /* default ERROR flags                    */
    2,                          /* default ERROR code                     */
    8,                          /* default ERROR value                    */
    1,                          /* default number of SCOPE(s)             */
    { INADDR_ANY },             /* default SCOPE address(es)              */
    18,                         /* default STYLE option vector            */
    INADDR_ANY,                 /* default SENDER TEMPLATE address        */
    IPPORT_ANY,                 /* default SENDER TEMPLATE port           */
    6,                          /* default TSPEC service                  */
    0,                          /* default TSPEC Token Bucket Rate        */
    0,                          /* default TSPEC Token Bucket Size        */
    0,                          /* default TSPEC Peak Data Rate           */
    0,                          /* default TSEPC Minimum Policed Unit     */
    0,                          /* default TSPEC Maximum Packet Size      */
    0,                          /* default ADSPEC IS HOP cnt              */
    0,                          /* default ADSPEC Path b/w estimate       */
    0,                          /* default ADSPEC Minimum Path Latency    */
    0,                          /* default ADSPEC Composed MTU            */
    0,                          /* no default ADSPEC service              */
    0,                          /* default ADSPEC ETE composed value C    */
    0,                          /* default ADSPEC ETE composed value D    */
    0,                          /* default ADSPEC SLR point composed C    */
    0,                          /* default ADSPEC SLR point composed D    */
    INADDR_ANY },               /* default CONFIRM receiver address       */
  /* XXX IPSEC HEADER OPTIONS (IPPROTO_AH = 51 & IPPROTO_ESP = 50)              */
  { 0,                          /* default AH header length               */
    0,                          /* default AH SPI                         */
    0,                          /* default AH sequence number             */
    0,                          /* default ESP SPI                        */
    0 },                        /* default ESP sequence number            */
  /* XXX EIGRP HEADER OPTIONS (IPPROTO_EIGRP = 88)                              */
  { EIGRP_OPCODE_UPDATE,        /* default opcode                         */
    0,                          /* default flags                          */
    0,                          /* default sequence number                */
    0,                          /* default acknowledgment sequence #      */
    0,                          /* default autonomous system              */
    EIGRP_TYPE_INTERNAL,        /* default type                           */
    0,                          /* default length                         */
    0,                          /* no EIGRP K Values by default           */
    1,                          /* default K1 value                       */
    0,                          /* default K2 value                       */
    1,                          /* default K3 value                       */
    0,                          /* default K4 value                       */
    0,                          /* default K5 value                       */
    360,                        /* default hold time                      */
    12,                         /* default IOS Major Version              */
    4,                          /* default IOS Minor Version              */
    1,                          /* default EIGRP Major Version            */
    2,                          /* default EIGRP Minor Version            */
    INADDR_ANY,                 /* default next hop address               */
    0,                          /* default delay                          */
    0,                          /* default bandwidth                      */
    1500,                       /* default maximum transmission unit      */
    0,                          /* default hop count                      */
    0,                          /* default load                           */
    0,                          /* default reliability                    */
    0,                          /* default subnet prefix - aka CIDR       */
    INADDR_ANY,                 /* default destination address            */
    INADDR_ANY,                 /* default originating router             */
    0,                          /* default originating autonomous system  */
    0,                          /* default arbitrary tag                  */
    0,                          /* default external protocol metric       */
    2,                          /* default external protocol ID           */
    0,                          /* default external flags                 */
    INADDR_ANY,                 /* default IP address sequence            */
    0,                          /* default multicast sequence             */
    0,                          /* do not use authentication by default   */
    1 },                        /* default authentication key ID          */
  /* XXX OSPF HEADER OPTIONS (IPPROTO_OSPF = 89)                                */
  { OSPF_TYPE_HELLO,            /* default type                           */
    0,                          /* default length                         */
    INADDR_ANY,                 /* default router ID                      */
    INADDR_ANY,                 /* default area ID                        */
    0,                          /* no default area ID is set              */
    0,                          /* no default option is set               */
    INADDR_ANY,                 /* default subnet mask                    */
    0,                          /* default HELLO interval                 */
    1,                          /* default HELLO router priority          */
    360,                        /* default HELLO router dead interval     */
    INADDR_ANY,                 /* default HELLO designated router        */
    INADDR_ANY,                 /* default HELLO backup designated        */
    0,                          /* default HELLO number of neighbors      */
    { INADDR_ANY },             /* default HELLO neighbor address(es)     */
    1500,                       /* default DD MTU                         */
    0,                          /* no default DD option is set            */
    0,                          /* default DD sequence number             */
    0,                          /* do not use DD LSA Header by default    */
    360,                        /* default LSA age                        */
    0,                          /* age LSA by default                     */
    LSA_TYPE_ROUTER,            /* default LSA header type                */
    INADDR_ANY,                 /* default LSA ID                         */
    INADDR_ANY,                 /* default LSA advertising router         */
    0,                          /* default LSA sequence number            */
    0,                          /* default LSA metric                     */
    0,                          /* no default Router-LSA flag is set      */
    INADDR_ANY,                 /* default Router-LSA link ID             */
    INADDR_ANY,                 /* default Router-LSA link data           */
    LINK_TYPE_PTP,              /* default Router-LSA link type           */
    INADDR_ANY,                 /* default Network-LSA attached router    */
    0,                          /* default ASBR/NSSA-LSA ext, larger      */
    INADDR_ANY,                 /* default ASBR/NSSA-LSA forward          */
    INADDR_ANY,                 /* default ASBR/NSSA-LSA external         */
    0,                          /* default Group-LSA vertex type          */
    INADDR_ANY,                 /* default Group-LSA vertex ID            */
    0,                          /* default LSS Extended TLV options       */
    0,                          /* do not use authentication by default   */
    1,                          /* default authentication key ID          */
    0 },                        /* default authentication sequence        */
};

/* NOTE: Declare long_opt[] here as static makes sense! */
static const struct option long_opt[] = {
  /* XXX COMMON OPTIONS                                                             */
  { "threshold",              required_argument, NULL, OPTION_THRESHOLD              },
  { "flood",                  no_argument,       NULL, OPTION_FLOOD                  },
  { "encapsulated",           no_argument,       NULL, OPTION_ENCAPSULATED           },
  { "bogus-csum",             no_argument,       NULL, 'B'                           },
#ifdef  __HAVE_TURBO__
  { "turbo",                  no_argument,       NULL, OPTION_TURBO                  },
#endif  /* __HAVE_TURBO__ */
  { "help",                   no_argument,       NULL, 'h'                           },
  /* XXX GRE HEADER OPTIONS (IPPROTO_GRE = 47)                                       */
  { "gre-seq-present",        no_argument,       NULL, OPTION_GRE_SEQUENCE_PRESENT   },
  { "gre-key-present",        no_argument,       NULL, OPTION_GRE_KEY_PRESENT        },
  { "gre-sum-present",        no_argument,       NULL, OPTION_GRE_CHECKSUM_PRESENT   },
  { "gre-key",                required_argument, NULL, OPTION_GRE_KEY                },
  { "gre-sequence",           required_argument, NULL, OPTION_GRE_SEQUENCE           },
  { "gre-saddr",              required_argument, NULL, OPTION_GRE_SADDR              },
  { "gre-daddr",              required_argument, NULL, OPTION_GRE_DADDR              },
  /* XXX DCCP, TCP & UDP HEADER OPTIONS                                              */
  { "sport",                  required_argument, NULL, OPTION_SOURCE                 },
  { "dport",                  required_argument, NULL, OPTION_DESTINATION            },
  /* XXX IP HEADER OPTIONS  (IPPROTO_IP = 0)                                         */
  { "saddr",                  required_argument, NULL, 's'                           },
  { "tos",                    required_argument, NULL, OPTION_IP_TOS                 },
  { "id",                     required_argument, NULL, OPTION_IP_ID                  },
  { "frag-offset",            required_argument, NULL, OPTION_IP_OFFSET              },
  { "ttl",                    required_argument, NULL, OPTION_IP_TTL                 },
  { "protocol",               required_argument, NULL, OPTION_IP_PROTOCOL            },
  /* XXX ICMP HEADER OPTIONS (IPPROTO_ICMP = 1)                                      */
  { "icmp-type",              required_argument, NULL, OPTION_ICMP_TYPE              },
  { "icmp-code",              required_argument, NULL, OPTION_ICMP_CODE              },
  { "icmp-gateway",           required_argument, NULL, OPTION_ICMP_GATEWAY           },
  { "icmp-id",                required_argument, NULL, OPTION_ICMP_ID                },
  { "icmp-sequence",          required_argument, NULL, OPTION_ICMP_SEQUENCE          },
  /* XXX IGMP HEADER OPTIONS (IPPROTO_IGMP = 2)                                      */
  { "igmp-type",              required_argument, NULL, OPTION_IGMP_TYPE              },
  { "igmp-code",              required_argument, NULL, OPTION_IGMP_CODE              },
  { "igmp-group",             required_argument, NULL, OPTION_IGMP_GROUP             },
  { "igmp-qrv",               required_argument, NULL, OPTION_IGMP_QRV               },
  { "igmp-suppress",          no_argument,       NULL, OPTION_IGMP_SUPPRESS          },
  { "igmp-qqic",              required_argument, NULL, OPTION_IGMP_QQIC              },
  { "igmp-grec-type",         required_argument, NULL, OPTION_IGMP_GREC_TYPE         }, 
  { "igmp-sources",           required_argument, NULL, OPTION_IGMP_SOURCES           },
  { "igmp-multicast",         required_argument, NULL, OPTION_IGMP_GREC_MULTICAST    }, 
  { "igmp-address",           required_argument, NULL, OPTION_IGMP_ADDRESS           },
  /* XXX TCP HEADER OPTIONS (IPPROTO_TCP = 6)                                        */
  { "acknowledge",            required_argument, NULL, OPTION_TCP_ACKNOWLEDGE        },
  { "sequence",               required_argument, NULL, OPTION_TCP_SEQUENCE           },
  { "data-offset",            required_argument, NULL, OPTION_TCP_OFFSET             },
  { "fin",                    no_argument,       NULL, 'F'                           },
  { "syn",                    no_argument,       NULL, 'S'                           },
  { "rst",                    no_argument,       NULL, 'R'                           },
  { "psh",                    no_argument,       NULL, 'P'                           },
  { "ack",                    no_argument,       NULL, 'A'                           },
  { "urg",                    no_argument,       NULL, 'U'                           },
  { "ece",                    no_argument,       NULL, 'E'                           },
  { "cwr",                    no_argument,       NULL, 'C'                           },
  { "window",                 required_argument, NULL, 'W'                           },
  { "urg-pointer",            required_argument, NULL, OPTION_TCP_URGENT_POINTER     },
  { "mss",                    required_argument, NULL, OPTION_TCP_MSS                },
  { "wscale",                 required_argument, NULL, OPTION_TCP_WSOPT              },
  { "tstamp",                 required_argument, NULL, OPTION_TCP_TSOPT              },
  { "sack-ok",                no_argument,       NULL, OPTION_TCP_SACK_OK            },
  { "cc",                     required_argument, NULL, OPTION_TCP_CC                 },
  { "ccnew",                  required_argument, NULL, OPTION_TCP_CC_NEW             },
  { "ccecho",                 required_argument, NULL, OPTION_TCP_CC_ECHO            },
  { "sack",                   required_argument, NULL, OPTION_TCP_SACK_EDGE          },
  { "md5-signature",          no_argument,       NULL, OPTION_TCP_MD5_SIGNATURE      },
  { "authentication",         no_argument,       NULL, OPTION_TCP_AUTHENTICATION     },
  { "auth-key-id",            required_argument, NULL, OPTION_TCP_AUTH_KEY_ID        },
  { "auth-next-key",          required_argument, NULL, OPTION_TCP_AUTH_NEXT_KEY      },
  { "nop",                    no_argument,       NULL, OPTION_TCP_NOP                },
  /* XXX EGP HEADER OPTIONS (IPPROTO_EGP = 8)                                        */
  { "egp-type",               required_argument, NULL, OPTION_EGP_TYPE               },
  { "egp-code",               required_argument, NULL, OPTION_EGP_CODE               },
  { "egp-status",             required_argument, NULL, OPTION_EGP_STATUS             },
  { "egp-as",                 required_argument, NULL, OPTION_EGP_AS                 },
  { "egp-sequence",           required_argument, NULL, OPTION_EGP_SEQUENCE           },
  { "egp-hello",              required_argument, NULL, OPTION_EGP_HELLO              },
  { "egp-poll",               required_argument, NULL, OPTION_EGP_POLL               },
  /* XXX RIP HEADER OPTIONS (IPPROTO_UDP = 17)                                       */
  { "rip-command",            required_argument, NULL, OPTION_RIP_COMMAND            },
  { "rip-family",             required_argument, NULL, OPTION_RIP_FAMILY             },
  { "rip-address",            required_argument, NULL, OPTION_RIP_ADDRESS            },
  { "rip-metric",             required_argument, NULL, OPTION_RIP_METRIC             },
  { "rip-domain",             required_argument, NULL, OPTION_RIP_DOMAIN             },
  { "rip-tag",                required_argument, NULL, OPTION_RIP_TAG                },
  { "rip-netmask",            required_argument, NULL, OPTION_RIP_NETMASK            },
  { "rip-next-hop",           required_argument, NULL, OPTION_RIP_NEXTHOP            },
  { "rip-authentication",     no_argument,       NULL, OPTION_RIP_AUTHENTICATION     },
  { "rip-auth-key-id",        required_argument, NULL, OPTION_RIP_AUTH_KEY_ID        },
  { "rip-auth-sequence",      required_argument, NULL, OPTION_RIP_AUTH_SEQUENCE      },
  /* XXX DCCP HEADER OPTIONS (IPPROTO_DCCP = 33)                                     */
  { "dccp-data-offset",       required_argument, NULL, OPTION_DCCP_OFFSET            },
  { "dccp-cscov",             required_argument, NULL, OPTION_DCCP_CSCOV             },
  { "dccp-ccval",             required_argument, NULL, OPTION_DCCP_CCVAL             },
  { "dccp-type",              required_argument, NULL, OPTION_DCCP_TYPE              },
  { "dccp-extended",          no_argument,       NULL, OPTION_DCCP_EXTEND            },
  { "dccp-sequence-1",        required_argument, NULL, OPTION_DCCP_SEQUENCE_01       },
  { "dccp-sequence-2",        required_argument, NULL, OPTION_DCCP_SEQUENCE_02       },
  { "dccp-sequence-3",        required_argument, NULL, OPTION_DCCP_SEQUENCE_03       },
  { "dccp-service",           required_argument, NULL, OPTION_DCCP_SERVICE           },
  { "dccp-acknowledge-1",     required_argument, NULL, OPTION_DCCP_ACKNOWLEDGE_01    },
  { "dccp-acknowledge-2",     required_argument, NULL, OPTION_DCCP_ACKNOWLEDGE_02    },
  { "dccp-reset-code",        required_argument, NULL, OPTION_DCCP_RESET_CODE        },
  /* XXX RSVP HEADER OPTIONS (IPPROTO_RSVP = 46)                                     */
  { "rsvp-flags",             required_argument, NULL, OPTION_RSVP_FLAGS             },
  { "rsvp-type",              required_argument, NULL, OPTION_RSVP_TYPE              },
  { "rsvp-ttl",               required_argument, NULL, OPTION_RSVP_TTL               },
  { "rsvp-session-addr",      required_argument, NULL, OPTION_RSVP_SESSION_ADDRESS   },
  { "rsvp-session-proto",     required_argument, NULL, OPTION_RSVP_SESSION_PROTOCOL  },
  { "rsvp-session-flags",     required_argument, NULL, OPTION_RSVP_SESSION_FLAGS     },
  { "rsvp-session-port",      required_argument, NULL, OPTION_RSVP_SESSION_PORT      },
  { "rsvp-hop-addr",          required_argument, NULL, OPTION_RSVP_HOP_ADDRESS       },
  { "rsvp-hop-iface",         required_argument, NULL, OPTION_RSVP_HOP_IFACE         },
  { "rsvp-time-refresh",      required_argument, NULL, OPTION_RSVP_TIME_REFRESH      },
  { "rsvp-error-addr",        required_argument, NULL, OPTION_RSVP_ERROR_ADDRESS     },
  { "rsvp-error-flags",       required_argument, NULL, OPTION_RSVP_ERROR_FLAGS       },
  { "rsvp-error-code",        required_argument, NULL, OPTION_RSVP_ERROR_CODE        },
  { "rsvp-error-value",       required_argument, NULL, OPTION_RSVP_ERROR_VALUE       },
  { "rsvp-scope",             required_argument, NULL, OPTION_RSVP_SCOPE             },
  { "rsvp-address",           required_argument, NULL, OPTION_RSVP_SCOPE_ADDRESS     },
  { "rsvp-style-option",      required_argument, NULL, OPTION_RSVP_STYLE_OPTION      },
  { "rsvp-sender-addr",       required_argument, NULL, OPTION_RSVP_SENDER_ADDRESS    },
  { "rsvp-sender-port",       required_argument, NULL, OPTION_RSVP_SENDER_PORT       },
  { "rsvp-tspec-traffic",     no_argument,       NULL, OPTION_RSVP_TSPEC_TRAFFIC     },
  { "rsvp-tspec-guaranteed",  no_argument,       NULL, OPTION_RSVP_TSPEC_GUARANTEED  },
  { "rsvp-tspec-r",           required_argument, NULL, OPTION_RSVP_TSPEC_TOKEN_R     },
  { "rsvp-tspec-b",           required_argument, NULL, OPTION_RSVP_TSPEC_TOKEN_B     },
  { "rsvp-tspec-p",           required_argument, NULL, OPTION_RSVP_TSPEC_DATA_P      },
  { "rsvp-tspec-m",           required_argument, NULL, OPTION_RSVP_TSPEC_MINIMUM     },
  { "rsvp-tspec-M",           required_argument, NULL, OPTION_RSVP_TSPEC_MAXIMUM     },
  { "rsvp-adspec-ishop",      required_argument, NULL, OPTION_RSVP_ADSPEC_ISHOP      },
  { "rsvp-adspec-path",       required_argument, NULL, OPTION_RSVP_ADSPEC_PATH       },
  { "rsvp-adspec-m",          required_argument, NULL, OPTION_RSVP_ADSPEC_MINIMUM    },
  { "rsvp-adspec-mtu",        required_argument, NULL, OPTION_RSVP_ADSPEC_MTU        },
  { "rsvp-adspec-guaranteed", no_argument,       NULL, OPTION_RSVP_ADSPEC_GUARANTEED },
  { "rsvp-adspec-Ctot",       required_argument, NULL, OPTION_RSVP_ADSPEC_CTOT       },
  { "rsvp-adspec-Dtot",       required_argument, NULL, OPTION_RSVP_ADSPEC_DTOT       },
  { "rsvp-adspec-Csum",       required_argument, NULL, OPTION_RSVP_ADSPEC_CSUM       },
  { "rsvp-adspec-Dsum",       required_argument, NULL, OPTION_RSVP_ADSPEC_DSUM       },
  { "rsvp-adspec-controlled", no_argument,       NULL, OPTION_RSVP_ADSPEC_CONTROLLED },
  { "rsvp-confirm-addr",      required_argument, NULL, OPTION_RSVP_CONFIRM_ADDR      },
  /* XXX IPSEC HEADER OPTIONS (IPPROTO_AH = 51 & IPPROTO_ESP = 50)                   */
  { "ipsec-ah-length",        required_argument, NULL, OPTION_IPSEC_AH_LENGTH        },
  { "ipsec-ah-spi",           required_argument, NULL, OPTION_IPSEC_AH_SPI           },
  { "ipsec-ah-sequence",      required_argument, NULL, OPTION_IPSEC_AH_SEQUENCE      },
  { "ipsec-esp-spi",          required_argument, NULL, OPTION_IPSEC_ESP_SPI          },
  { "ipsec-esp-sequence",     required_argument, NULL, OPTION_IPSEC_ESP_SEQUENCE     },
  /* XXX EIGRP HEADER OPTIONS (IPPROTO_EIGRP = 88)                                   */
  { "eigrp-opcode",           required_argument, NULL, OPTION_EIGRP_OPCODE           },
  { "eigrp-flags",            required_argument, NULL, OPTION_EIGRP_FLAGS            },
  { "eigrp-sequence",         required_argument, NULL, OPTION_EIGRP_SEQUENCE         },
  { "eigrp-acknowledge",      required_argument, NULL, OPTION_EIGRP_ACKNOWLEDGE      },
  { "eigrp-as",               required_argument, NULL, OPTION_EIGRP_AS               },
  { "eigrp-type",             required_argument, NULL, OPTION_EIGRP_TYPE             },
  { "eigrp-length",           required_argument, NULL, OPTION_EIGRP_LENGTH           },
  { "eigrp-k1",               required_argument, NULL, OPTION_EIGRP_K1               },
  { "eigrp-k2",               required_argument, NULL, OPTION_EIGRP_K2               },
  { "eigrp-k3",               required_argument, NULL, OPTION_EIGRP_K3               },
  { "eigrp-k4",               required_argument, NULL, OPTION_EIGRP_K4               },
  { "eigrp-k5",               required_argument, NULL, OPTION_EIGRP_K5               },
  { "eigrp-hold",             required_argument, NULL, OPTION_EIGRP_HOLD             },
  { "eigrp-ios-ver",          required_argument, NULL, OPTION_EIGRP_IOS_VERSION      },
  { "eigrp-rel-ver",          required_argument, NULL, OPTION_EIGRP_PROTO_VERSION    },
  { "eigrp-next-hop",         required_argument, NULL, OPTION_EIGRP_NEXTHOP          },
  { "eigrp-delay",            required_argument, NULL, OPTION_EIGRP_DELAY            },
  { "eigrp-bandwidth",        required_argument, NULL, OPTION_EIGRP_BANDWIDTH        },
  { "eigrp-mtu",              required_argument, NULL, OPTION_EIGRP_MTU              },
  { "eigrp-hop-count",        required_argument, NULL, OPTION_EIGRP_HOP_COUNT        },
  { "eigrp-load",             required_argument, NULL, OPTION_EIGRP_LOAD             },
  { "eigrp-reliability",      required_argument, NULL, OPTION_EIGRP_RELIABILITY      },
  { "eigrp-daddr",            required_argument, NULL, OPTION_EIGRP_DESINATION       },
  { "eigrp-src-router",       required_argument, NULL, OPTION_EIGRP_SOURCE_ROUTER    },
  { "eigrp-src-as",           required_argument, NULL, OPTION_EIGRP_SOURCE_AS        },
  { "eigrp-tag",              required_argument, NULL, OPTION_EIGRP_TAG              },
  { "eigrp-proto-metric",     required_argument, NULL, OPTION_EIGRP_METRIC           },
  { "eigrp-proto-id",         required_argument, NULL, OPTION_EIGRP_ID               },
  { "eigrp-ext-flags",        required_argument, NULL, OPTION_EIGRP_EXTERNAL_FLAGS   },
  { "eigrp-address",          required_argument, NULL, OPTION_EIGRP_ADDRESS          },
  { "eigrp-multicast",        required_argument, NULL, OPTION_EIGRP_MULTICAST        },
  { "eigrp-authentication",   no_argument,       NULL, OPTION_EIGRP_AUTHENTICATION   },
  { "eigrp-auth-key-id",      required_argument, NULL, OPTION_EIGRP_AUTH_KEY_ID      },
  /* XXX OSPF HEADER OPTIONS (IPPROTO_OSPF = 89)                                     */
  { "ospf-type",              required_argument, NULL, OPTION_OSPF_TYPE              },
  { "ospf-length",            required_argument, NULL, OPTION_OSPF_LENGTH            },
  { "ospf-router-id",         required_argument, NULL, OPTION_OSPF_ROUTER_ID         },
  { "ospf-area-id",           required_argument, NULL, OPTION_OSPF_AREA_ID           },
  { "ospf-option-MT",         no_argument,       NULL, '1'                           },
  { "ospf-option-E",          no_argument,       NULL, '2'                           },
  { "ospf-option-MC",         no_argument,       NULL, '3'                           },
  { "ospf-option-NP",         no_argument,       NULL, '4'                           },
  { "ospf-option-L",          no_argument,       NULL, '5'                           },
  { "ospf-option-DC",         no_argument,       NULL, '6'                           },
  { "ospf-option-O",          no_argument,       NULL, '7'                           },
  { "ospf-option-DN",         no_argument,       NULL, '8'                           },
  { "ospf-netmask",           required_argument, NULL, OPTION_OSPF_NETMASK           },
  { "ospf-hello-interval",    required_argument, NULL, OPTION_OSPF_HELLO_INTERVAL    },
  { "ospf-hello-priority",    required_argument, NULL, OPTION_OSPF_HELLO_PRIORITY    },
  { "ospf-hello-dead",        required_argument, NULL, OPTION_OSPF_HELLO_DEAD        },
  { "ospf-hello-design",      required_argument, NULL, OPTION_OSPF_HELLO_DESIGN      },
  { "ospf-hello-backup",      required_argument, NULL, OPTION_OSPF_HELLO_BACKUP      },
  { "ospf-neighbor",          required_argument, NULL, OPTION_OSPF_HELLO_NEIGHBOR    },
  { "ospf-address",           required_argument, NULL, OPTION_OSPF_HELLO_ADDRESS     },
  { "ospf-dd-mtu",            required_argument, NULL, OPTION_OSPF_DD_MTU            },
  { "ospf-dd-dbdesc-MS",      no_argument,       NULL, OPTION_OSPF_DD_MASTER_SLAVE   },
  { "ospf-dd-dbdesc-M",       no_argument,       NULL, OPTION_OSPF_DD_MORE           },
  { "ospf-dd-dbdesc-I",       no_argument,       NULL, OPTION_OSPF_DD_INIT           },
  { "ospf-dd-dbdesc-R",       no_argument,       NULL, OPTION_OSPF_DD_OOBRESYNC      },
  { "ospf-dd-sequence",       required_argument, NULL, OPTION_OSPF_DD_SEQUENCE       },
  { "ospf-dd-include-lsa",    no_argument,       NULL, OPTION_OSPF_DD_INCLUDE_LSA    },
  { "ospf-lsa-age",           required_argument, NULL, OPTION_OSPF_LSA_AGE           },
  { "ospf-lsa-do-not-age",    no_argument,       NULL, OPTION_OSPF_LSA_DO_NOT_AGE    },
  { "ospf-lsa-type",          required_argument, NULL, OPTION_OSPF_LSA_TYPE          },
  { "ospf-lsa-id",            required_argument, NULL, OPTION_OSPF_LSA_LSID          },
  { "ospf-lsa-router",        required_argument, NULL, OPTION_OSPF_LSA_ROUTER        },
  { "ospf-lsa-sequence",      required_argument, NULL, OPTION_OSPF_LSA_SEQUENCE      },
  { "ospf-lsa-metric",        required_argument, NULL, OPTION_OSPF_LSA_METRIC        },
  { "ospf-lsa-flag-B",        no_argument,       NULL, OPTION_OSPF_LSA_FLAG_BORDER   },
  { "ospf-lsa-flag-E",        no_argument,       NULL, OPTION_OSPF_LSA_FLAG_EXTERNAL },
  { "ospf-lsa-flag-V",        no_argument,       NULL, OPTION_OSPF_LSA_FLAG_VIRTUAL  },
  { "ospf-lsa-flag-W",        no_argument,       NULL, OPTION_OSPF_LSA_FLAG_WILD     },
  { "ospf-lsa-flag-NT",       no_argument,       NULL, OPTION_OSPF_LSA_FLAG_NSSA_TR  },
  { "ospf-lsa-link-id",       required_argument, NULL, OPTION_OSPF_LSA_LINK_ID       },
  { "ospf-lsa-link-data",     required_argument, NULL, OPTION_OSPF_LSA_LINK_DATA     },
  { "ospf-lsa-link-type",     required_argument, NULL, OPTION_OSPF_LSA_LINK_TYPE     },
  { "ospf-lsa-attached",      required_argument, NULL, OPTION_OSPF_LSA_ATTACHED      },
  { "ospf-lsa-larger",        no_argument,       NULL, OPTION_OSPF_LSA_LARGER        },
  { "ospf-lsa-forward",       required_argument, NULL, OPTION_OSPF_LSA_FORWARD       },
  { "ospf-lsa-external",      required_argument, NULL, OPTION_OSPF_LSA_EXTERNAL      },
  { "ospf-vertex-router",     no_argument,       NULL, OPTION_OSPF_VERTEX_ROUTER     },
  { "ospf-vertex-network",    no_argument,       NULL, OPTION_OSPF_VERTEX_NETWORK    },
  { "ospf-vertex-id",         required_argument, NULL, OPTION_OSPF_VERTEX_ID         },
  { "ospf-lls-extended-LR",   no_argument,       NULL, OPTIONS_OSPF_LLS_OPTION_LR    },
  { "ospf-lls-extended-RS",   no_argument,       NULL, OPTIONS_OSPF_LLS_OPTION_RS    },
  { "ospf-authentication",    no_argument,       NULL, OPTION_OSPF_AUTHENTICATION    },
  { "ospf-auth-key-id",       required_argument, NULL, OPTION_OSPF_AUTH_KEY_ID       },
  { "ospf-auth-sequence",     required_argument, NULL, OPTION_OSPF_AUTH_SEQUENCE     },
  { 0,                        0,                 NULL, 0                             },
};

/* CLI options configuration */
struct config_options *getConfigOptions(int argc, char ** argv) 
{
  int cli_opts;
  int counter;

  /* The following variables will be used by 'getsubopt()'. */
  char  *optionp, *valuep, *tmp_ptr;
  int opt_ind;

  /* Checking command line interface options. */
  for (;;)
  {
    opt_ind = 0;

    if ( (cli_opts = getopt_long(argc, argv, "s:12345678FSRPAUECW:Bh?", long_opt, &opt_ind)) == -1 )
      break;

    switch (cli_opts)
    {
      /* XXX COMMON OPTIONS */
      case OPTION_THRESHOLD:
        o.threshold = atol(optarg);
        break;
      case OPTION_FLOOD:
        o.flood = 1;
        break;
      case OPTION_ENCAPSULATED:
        o.encapsulated = 1;
        break;
      case 'B':
        o.bogus_csum = 1;
        break;

#ifdef  __HAVE_TURBO__
      case OPTION_TURBO:
        o.turbo = 1;
        break;
#endif  /* __HAVE_TURBO__ */

      case OPTION_LIST_PROTOCOL:
        fprintf(stdout,
            "List of supported protocols:\n");
        for (counter = 0; mod_acronyms[counter] != NULL ; counter++)
          fprintf(stdout,
              "\t%2d PROTO = %-6s (%s)\n",
              counter+1,
              mod_acronyms[counter],
              mod_names[counter]);
        exit(EXIT_SUCCESS);
        break;

      /* XXX GRE HEADER OPTIONS (IPPROTO_GRE = 47) */
      case OPTION_GRE_SEQUENCE_PRESENT:
        o.gre.options |= GRE_OPTION_SEQUENCE;
        o.gre.S = 1;
        break;
      case OPTION_GRE_KEY_PRESENT:
        o.gre.options |= GRE_OPTION_KEY;
        o.gre.K = 1;
        break;
      case OPTION_GRE_CHECKSUM_PRESENT:
        o.gre.options |= GRE_OPTION_CHECKSUM;
        o.gre.C = 1;
        break;
      case OPTION_GRE_KEY:
        o.gre.key = atol(optarg);
        break;
      case OPTION_GRE_SEQUENCE:
        o.gre.sequence = atoi(optarg);
        break;
      case OPTION_GRE_SADDR:
        o.gre.saddr = resolv(optarg);
        break;
      case OPTION_GRE_DADDR:
        o.gre.daddr = resolv(optarg);
        break;

      /* XXX DCCP, TCP & UDP HEADER OPTIONS */
      case OPTION_SOURCE:
        o.source = atoi(optarg);
        break;
      case OPTION_DESTINATION:
        o.dest = atoi(optarg);
        break;

      /* XXX IP HEADER OPTIONS  (IPPROTO_IP = 0) */
      case OPTION_IP_TOS:
        o.ip.tos = atoi(optarg);
        break;
      case OPTION_IP_ID:
        o.ip.id = atoi(optarg);
        break;
      case OPTION_IP_OFFSET:
        o.ip.frag_off = atoi(optarg);
        break;
      case OPTION_IP_TTL:
        o.ip.ttl = atoi(optarg);
        break;
      case 's':
        o.ip.saddr = resolv(optarg);
        break;
      case OPTION_IP_PROTOCOL:
        optionp = optarg;

        while (*optionp != '\0')
        {
          switch (counter = getsubopt(&optionp, mod_acronyms, &valuep))
          {
            case MODULE_ICMP:
              o.ip.protocol  = IPPROTO_ICMP;
              o.ip.protoname = counter; break;
            case MODULE_IGMPv1:
              o.ip.protocol  = IPPROTO_IGMP;
              o.ip.protoname = counter; break;
            case MODULE_IGMPv3:
              o.ip.protocol  = IPPROTO_IGMP;
              o.ip.protoname = counter; break;
            case MODULE_TCP:
              o.ip.protocol  = IPPROTO_TCP;
              o.ip.protoname = counter; break;
            case MODULE_EGP:
              o.ip.protocol  = IPPROTO_EGP;
              o.ip.protoname = counter; break;
            case MODULE_UDP:
              o.ip.protocol  = IPPROTO_UDP;
              o.ip.protoname = counter; break;
            case MODULE_RIPv1:
              o.ip.protocol  = IPPROTO_UDP;
              o.ip.protoname = counter; break;
            case MODULE_RIPv2:
              o.ip.protocol  = IPPROTO_UDP;
              o.ip.protoname = counter; break;
            case MODULE_DCCP:
              o.ip.protocol  = IPPROTO_DCCP;
              o.ip.protoname = counter; break;
            case MODULE_RSVP:
              o.ip.protocol  = IPPROTO_RSVP;
              o.ip.protoname = counter; break;
            case MODULE_IPSEC:
              o.ip.protocol  = IPPROTO_AH;
              o.ip.protoname = counter; break;
            case MODULE_EIGRP:
              o.ip.protocol  = IPPROTO_EIGRP;
              o.ip.protoname = counter; break;
            case MODULE_OSPF:
              o.ip.protocol  = IPPROTO_OSPF;
              o.ip.protoname = counter; break;
            case MODULE_T50:
              o.ip.protocol  = IPPROTO_T50;
              o.ip.protoname = counter; break;
            default:
              fprintf(stderr,
                  "%s(): Protocol %s is not implemented\n",
                  __FUNCTION__,
                  optarg);
              fflush(stderr);
              exit(EXIT_FAILURE);
          }
        } 
        break;

      /* XXX ICMP HEADER OPTIONS (IPPROTO_ICMP = 1) */
      case OPTION_ICMP_TYPE:
        o.icmp.type = atoi(optarg); break;
      case OPTION_ICMP_CODE:
        o.icmp.code = atoi(optarg); break;
      case OPTION_ICMP_ID:
        o.icmp.id = atoi(optarg); break;
      case OPTION_ICMP_SEQUENCE:
        o.icmp.sequence = atoi(optarg); break;
      case OPTION_ICMP_GATEWAY:
        o.icmp.gateway = resolv(optarg); break;

      /* XXX IGMP HEADER OPTIONS (IPPROTO_IGMP = 2) */
      case OPTION_IGMP_TYPE:
        o.igmp.type = atoi(optarg); break;
      case OPTION_IGMP_CODE:
        o.igmp.code = atoi(optarg); break;
      case OPTION_IGMP_GROUP:
        o.igmp.group = resolv(optarg); break;
      case OPTION_IGMP_QRV:
        o.igmp.qrv = atoi(optarg); break;
      case OPTION_IGMP_SUPPRESS:
        o.igmp.suppress = 1;  break;
      case OPTION_IGMP_QQIC:
        o.igmp.qqic = atoi(optarg); break;
      case OPTION_IGMP_GREC_TYPE:
        o.igmp.grec_type = atoi(optarg); break;
      case OPTION_IGMP_SOURCES:
        o.igmp.sources = atoi(optarg); break;
      case OPTION_IGMP_GREC_MULTICAST:
        o.igmp.grec_mca = resolv(optarg); break;
      case OPTION_IGMP_ADDRESS:
        tmp_ptr = strtok(optarg, ",");

        for (counter = 0;
            counter < (int)(sizeof(o.igmp.address)/sizeof(in_addr_t));
            counter++)
        {
          if (tmp_ptr == NULL) 
            break;

          o.igmp.address[counter] = resolv(tmp_ptr);
          tmp_ptr = strtok(NULL, ",");
        }

        o.igmp.sources = counter; 
        break;

      /* XXX TCP HEADER OPTIONS (IPPROTO_TCP = 6) */
      case OPTION_TCP_SEQUENCE:
        o.tcp.sequence = atol(optarg); break;
      case OPTION_TCP_ACKNOWLEDGE:
        o.tcp.acknowledge = atol(optarg); break;
      case OPTION_TCP_OFFSET:
        o.tcp.doff = atoi(optarg);  break;
      case 'F':
        o.tcp.fin = 1;  break;
      case 'S':
        o.tcp.syn = 1;  break;
      case 'R':
        o.tcp.rst = 1;  break;
      case 'P':
        o.tcp.psh = 1;  break;
      case 'A':
        o.tcp.ack = 1;  break;
      case 'U':
        o.tcp.urg = 1;  break;
      case 'E':
        o.tcp.ece = 1;  break;
      case 'C':
        o.tcp.cwr = 1;  break;
      case 'W':
        o.tcp.window = atoi(optarg); break;
      case OPTION_TCP_URGENT_POINTER:
        o.tcp.urg_ptr = atoi(optarg); break;
      case OPTION_TCP_MSS:
        o.tcp.options |= TCP_OPTION_MSS;
        o.tcp.mss = atoi(optarg); break;
      case OPTION_TCP_WSOPT:
        o.tcp.options |= TCP_OPTION_WSOPT;
        o.tcp.wsopt = atoi(optarg); break;
      case OPTION_TCP_TSOPT:
        o.tcp.options |= TCP_OPTION_TSOPT;
        if ( (tmp_ptr = (char *) strchr(optarg, 0x3a)) != NULL )
        {
          uint32_t t;

          if ((t = atol(tmp_ptr + 1)) != 0)
            o.tcp.tsecr = t;

          tmp_ptr     = strtok(optarg, ":");

          if (tmp_ptr != NULL)
            o.tcp.tsval = atol(tmp_ptr);
        } 
        break;
      case OPTION_TCP_SACK_OK:
        o.tcp.options |= TCP_OPTION_SACK_OK; break;
      case OPTION_TCP_CC:
        o.tcp.options |= TCP_OPTION_CC;
        o.tcp.cc = atol(optarg); break;
      case OPTION_TCP_CC_NEW:
        o.tcp.options |= TCP_OPTION_CC_NEXT;
        o.tcp.cc_new = atol(optarg); break;
      case OPTION_TCP_CC_ECHO:
        o.tcp.options |= TCP_OPTION_CC_NEXT;
        o.tcp.cc_echo = atol(optarg); break;
      case OPTION_TCP_SACK_EDGE:
        o.tcp.options |= TCP_OPTION_SACK_EDGE;

        if ( (tmp_ptr = (char *) strchr(optarg, 0x3a)) != NULL )
        {
          uint32_t t;

          if ((t = atol(tmp_ptr + 1)) != 0)
            o.tcp.sack_right = t;
          tmp_ptr          = strtok(optarg, ":");
          if (tmp_ptr != NULL)
            o.tcp.sack_left = atol(tmp_ptr);
        } 
        break;

      case OPTION_TCP_MD5_SIGNATURE:
        o.tcp.md5  = 1;
        o.tcp.auth = 0; break;
      case OPTION_TCP_AUTHENTICATION:
        o.tcp.md5  = 0;
        o.tcp.auth = 1; break;
      case OPTION_TCP_AUTH_KEY_ID:
        o.tcp.key_id = atoi(optarg); break;
      case OPTION_TCP_AUTH_NEXT_KEY:
        o.tcp.next_key = atoi(optarg); break;
      case OPTION_TCP_NOP:
        o.tcp.nop = TCPOPT_NOP; break;

      /* XXX EGP HEADER OPTIONS (IPPROTO_EGP = 8) */
      case OPTION_EGP_TYPE:
        o.egp.type = atoi(optarg);  break;
      case OPTION_EGP_CODE:
        o.egp.code = atoi(optarg);  break;
      case OPTION_EGP_STATUS:
        o.egp.status = atoi(optarg); break;
      case OPTION_EGP_AS:
        o.egp.as = atoi(optarg); break;
      case OPTION_EGP_SEQUENCE:
        o.egp.sequence = atoi(optarg); break;
      case OPTION_EGP_HELLO:
        o.egp.hello = atoi(optarg); break;
      case OPTION_EGP_POLL:
        o.egp.poll = atoi(optarg);  break;

      /* XXX RIP HEADER OPTIONS (IPPROTO_UDP = 17) */
      case OPTION_RIP_COMMAND:
        o.rip.command = atoi(optarg); break;
      case OPTION_RIP_FAMILY:
        o.rip.family = atoi(optarg); break;
      case OPTION_RIP_ADDRESS:
        o.rip.address = resolv(optarg); break;
      case OPTION_RIP_METRIC:
        o.rip.metric = atol(optarg); break;
      case OPTION_RIP_DOMAIN:
        o.rip.domain = atoi(optarg); break;
      case OPTION_RIP_TAG:
        o.rip.tag = atoi(optarg); break;
      case OPTION_RIP_NETMASK:
        o.rip.netmask = resolv(optarg); break;
      case OPTION_RIP_NEXTHOP:
        o.rip.next_hop = resolv(optarg); break;
      case OPTION_RIP_AUTHENTICATION:
        o.rip.auth = 1;
        break;
      case OPTION_RIP_AUTH_KEY_ID:
        o.rip.key_id = atoi(optarg); break;
      case OPTION_RIP_AUTH_SEQUENCE:
        o.rip.sequence = atol(optarg); break;

      /* XXX DCCP HEADER OPTIONS (IPPROTO_DCCP = 33) */
      case OPTION_DCCP_OFFSET:
        o.dccp.doff = atoi(optarg); break;
      case OPTION_DCCP_CSCOV:
        o.dccp.cscov = atoi(optarg); break;
      case OPTION_DCCP_CCVAL:
        o.dccp.ccval = atoi(optarg); break;
      case OPTION_DCCP_TYPE:
        o.dccp.type = atoi(optarg); break;
      case OPTION_DCCP_EXTEND:
        o.dccp.ext = 1; break;
      case OPTION_DCCP_SEQUENCE_01:
        o.dccp.sequence_01 = atoi(optarg); break;
      case OPTION_DCCP_SEQUENCE_02:
        o.dccp.sequence_02 = atoi(optarg); break;
      case OPTION_DCCP_SEQUENCE_03:
        o.dccp.sequence_03 = atol(optarg); break;
      case OPTION_DCCP_SERVICE:
        o.dccp.service = atol(optarg); break;
      case OPTION_DCCP_ACKNOWLEDGE_01:
        o.dccp.acknowledge_01 = atoi(optarg); break;
      case OPTION_DCCP_ACKNOWLEDGE_02:
        o.dccp.acknowledge_02 = atol(optarg); break;
      case OPTION_DCCP_RESET_CODE:
        o.dccp.rst_code = atoi(optarg); break;

      /* XXX RSVP HEADER OPTIONS (IPPROTO_RSVP = 46) */
      case OPTION_RSVP_FLAGS:
        o.rsvp.flags = atoi(optarg); break;
      case OPTION_RSVP_TYPE:
        o.rsvp.type = atoi(optarg); break;
      case OPTION_RSVP_TTL:
        o.rsvp.ttl = atoi(optarg);  break;
      case OPTION_RSVP_SESSION_ADDRESS:
        o.rsvp.session_addr = resolv(optarg); break;
      case OPTION_RSVP_SESSION_PROTOCOL:
        o.rsvp.session_proto = atoi(optarg); break;
      case OPTION_RSVP_SESSION_FLAGS:
        o.rsvp.session_flags = atoi(optarg); break;
      case OPTION_RSVP_SESSION_PORT:
        o.rsvp.session_port = atoi(optarg); break;
      case OPTION_RSVP_HOP_ADDRESS:
        o.rsvp.hop_addr = resolv(optarg); break;
      case OPTION_RSVP_HOP_IFACE:
        o.rsvp.hop_iface = atol(optarg); break;
      case OPTION_RSVP_TIME_REFRESH:
        o.rsvp.time_refresh = atol(optarg); break;
      case OPTION_RSVP_ERROR_ADDRESS:
        o.rsvp.error_addr = resolv(optarg); break;
      case OPTION_RSVP_ERROR_FLAGS:
        o.rsvp.error_flags = atoi(optarg); break;
      case OPTION_RSVP_ERROR_CODE:
        o.rsvp.error_code = atoi(optarg); break;
      case OPTION_RSVP_ERROR_VALUE:
        o.rsvp.error_value = atoi(optarg); break;
      case OPTION_RSVP_SCOPE:
        o.rsvp.scope = atoi(optarg); break;
      case OPTION_RSVP_SCOPE_ADDRESS:
        tmp_ptr = strtok(optarg, ",");
        for (counter=0; counter < (int)(sizeof(o.rsvp.address)/sizeof(in_addr_t)); counter++)
        {
          if (tmp_ptr == NULL) break;
          o.rsvp.address[counter] = resolv(tmp_ptr);
          tmp_ptr = strtok(NULL, ",");
        }
        o.rsvp.scope = counter; 
        break;
      case OPTION_RSVP_STYLE_OPTION:
        o.rsvp.style_opt = atol(optarg);
        break;
      case OPTION_RSVP_SENDER_ADDRESS:
        o.rsvp.sender_addr = resolv(optarg); break;
      case OPTION_RSVP_SENDER_PORT:
        o.rsvp.sender_port = atoi(optarg); break;
      case OPTION_RSVP_TSPEC_TRAFFIC:
        o.rsvp.tspec = TSPEC_TRAFFIC_SERVICE; break;
      case OPTION_RSVP_TSPEC_GUARANTEED:
        o.rsvp.tspec = TSPEC_GUARANTEED_SERVICE; break;
      case OPTION_RSVP_TSPEC_TOKEN_R:
        o.rsvp.tspec = TSPEC_TRAFFIC_SERVICE;
        o.rsvp.tspec_r = atol(optarg); break;
      case OPTION_RSVP_TSPEC_TOKEN_B:
        o.rsvp.tspec = TSPEC_TRAFFIC_SERVICE;
        o.rsvp.tspec_b = atol(optarg); break;
      case OPTION_RSVP_TSPEC_DATA_P:
        o.rsvp.tspec = TSPEC_TRAFFIC_SERVICE;
        o.rsvp.tspec_p = atol(optarg); break;
      case OPTION_RSVP_TSPEC_MINIMUM:
        o.rsvp.tspec = TSPEC_TRAFFIC_SERVICE;
        o.rsvp.tspec_m = atol(optarg); break;
      case OPTION_RSVP_TSPEC_MAXIMUM:
        o.rsvp.tspec = TSPEC_TRAFFIC_SERVICE;
        o.rsvp.tspec_M = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_ISHOP:
        o.rsvp.adspec_hop = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_PATH:
        o.rsvp.adspec_path = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_MINIMUM:
        o.rsvp.adspec_minimum = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_MTU:
        o.rsvp.adspec_mtu = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_GUARANTEED:
        o.rsvp.adspec = ADSPEC_GUARANTEED_SERVICE; break;
      case OPTION_RSVP_ADSPEC_CTOT:
        o.rsvp.adspec = ADSPEC_GUARANTEED_SERVICE;
        o.rsvp.adspec_Ctot = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_DTOT:
        o.rsvp.adspec = ADSPEC_GUARANTEED_SERVICE;
        o.rsvp.adspec_Dtot = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_CSUM:
        o.rsvp.adspec = ADSPEC_GUARANTEED_SERVICE;
        o.rsvp.adspec_Csum = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_DSUM:
        o.rsvp.adspec = ADSPEC_GUARANTEED_SERVICE;
        o.rsvp.adspec_Dsum = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_CONTROLLED:
        o.rsvp.adspec = ADSPEC_CONTROLLED_SERVICE; break;
      case OPTION_RSVP_CONFIRM_ADDR:
        o.rsvp.confirm_addr = resolv(optarg); break;

      /* XXX IPSEC HEADER OPTIONS (IPPROTO_AH = 51 & IPPROTO_ESP = 50) */
      case OPTION_IPSEC_AH_LENGTH:
        o.ipsec.ah_length = atoi(optarg); break;
      case OPTION_IPSEC_AH_SPI:
        o.ipsec.ah_spi = atol(optarg); break;
      case OPTION_IPSEC_AH_SEQUENCE:
        o.ipsec.ah_sequence = atol(optarg); break;
      case OPTION_IPSEC_ESP_SPI:
        o.ipsec.esp_spi = atol(optarg); break;
      case OPTION_IPSEC_ESP_SEQUENCE:
        o.ipsec.esp_sequence = atol(optarg); break;

      /* XXX EIGRP HEADER OPTIONS (IPPROTO_EIGRP = 88) */
      case OPTION_EIGRP_OPCODE:
        o.eigrp.opcode = atoi(optarg); break;
      case OPTION_EIGRP_FLAGS:
        o.eigrp.flags = atol(optarg); break;
      case OPTION_EIGRP_SEQUENCE:
        o.eigrp.sequence = atol(optarg); break;
      case OPTION_EIGRP_ACKNOWLEDGE:
        o.eigrp.acknowledge = atol(optarg); break;
      case OPTION_EIGRP_AS:
        o.eigrp.as = atol(optarg); break;
      case OPTION_EIGRP_TYPE:
        o.eigrp.type = atoi(optarg); break;
      case OPTION_EIGRP_LENGTH:
        o.eigrp.length = atoi(optarg); break;
      case OPTION_EIGRP_K1:
        o.eigrp.values |= EIGRP_KVALUE_K1;
        o.eigrp.k1 = atoi(optarg); break;
      case OPTION_EIGRP_K2:
        o.eigrp.values |= EIGRP_KVALUE_K2;
        o.eigrp.k2 = atoi(optarg); break;
      case OPTION_EIGRP_K3:
        o.eigrp.values |= EIGRP_KVALUE_K3;
        o.eigrp.k3 = atoi(optarg); break;
      case OPTION_EIGRP_K4:
        o.eigrp.values |= EIGRP_KVALUE_K4;
        o.eigrp.k4 = atoi(optarg); break;
      case OPTION_EIGRP_K5:
        o.eigrp.values |= EIGRP_KVALUE_K5;
        o.eigrp.k5 = atoi(optarg); break;
      case OPTION_EIGRP_HOLD:
        o.eigrp.hold = atoi(optarg); break;
      case OPTION_EIGRP_IOS_VERSION:
        if ( (tmp_ptr = (char *) strchr(optarg, '.')) != NULL )
        {
          int t;

          if ((t = atoi(tmp_ptr + 1)) != 0)
            o.eigrp.ios_minor = t;
          tmp_ptr           = strtok(optarg, ".");
          if (tmp_ptr != NULL)
            o.eigrp.ios_major = atoi(tmp_ptr);
        } 
        break;
      case OPTION_EIGRP_PROTO_VERSION:
        if ( (tmp_ptr = (char *) strchr(optarg, '.')) != NULL )
        {
          int t;

          if ((t = atoi(tmp_ptr + 1)) != 0)
            o.eigrp.ver_minor = t;
          tmp_ptr           = strtok(optarg, ".");
          if (tmp_ptr != NULL)
            o.eigrp.ver_major = atoi(tmp_ptr);
        } 
        break;
      case OPTION_EIGRP_NEXTHOP:
        o.eigrp.next_hop = resolv(optarg); break;
      case OPTION_EIGRP_DELAY:
        o.eigrp.delay = atol(optarg); break;
      case OPTION_EIGRP_BANDWIDTH:
        o.eigrp.bandwidth = atol(optarg); break;
      case OPTION_EIGRP_MTU:
        o.eigrp.mtu = atol(optarg); break;
      case OPTION_EIGRP_HOP_COUNT:
        o.eigrp.hop_count = atoi(optarg); break;
      case OPTION_EIGRP_LOAD:
        o.eigrp.load = atoi(optarg); break;
      case OPTION_EIGRP_RELIABILITY:
        o.eigrp.reliability = atoi(optarg); break;
      case OPTION_EIGRP_DESINATION:
        if ( (tmp_ptr = (char *) strchr(optarg, '/')) == NULL )
          o.eigrp.dest   = resolv(optarg);
        else
        {
          o.eigrp.prefix = atoi(tmp_ptr + 1);
          tmp_ptr        = strtok(optarg, "/");
          if (tmp_ptr != NULL)
            o.eigrp.dest = resolv(tmp_ptr);
        } 
        break;
      case OPTION_EIGRP_SOURCE_ROUTER:
        o.eigrp.src_router = resolv(optarg); break;
      case OPTION_EIGRP_SOURCE_AS:
        o.eigrp.src_as = atol(optarg); break;
      case OPTION_EIGRP_TAG:
        o.eigrp.tag = atol(optarg); break;
      case OPTION_EIGRP_METRIC:
        o.eigrp.proto_metric = atol(optarg); break;
      case OPTION_EIGRP_ID:
        o.eigrp.proto_id = atoi(optarg); break;
      case OPTION_EIGRP_EXTERNAL_FLAGS:
        o.eigrp.ext_flags = atoi(optarg); break;
      case OPTION_EIGRP_ADDRESS:
        o.eigrp.address = resolv(optarg); break;
      case OPTION_EIGRP_MULTICAST:
        o.eigrp.multicast = atol(optarg); break;
      case OPTION_EIGRP_AUTHENTICATION:
        o.eigrp.auth = 1; break;
      case OPTION_EIGRP_AUTH_KEY_ID:
        o.eigrp.key_id = atol(optarg); break;

      /* XXX OSPF HEADER OPTIONS (IPPROTO_OSPF = 89) */
      case OPTION_OSPF_TYPE:
        o.ospf.type = atoi(optarg); break;
      case OPTION_OSPF_LENGTH:
        o.ospf.length = atoi(optarg); break;
      case OPTION_OSPF_ROUTER_ID:
        o.ospf.rid = resolv(optarg); break;
      case OPTION_OSPF_AREA_ID:
        o.ospf.AID = 1;
        o.ospf.aid = resolv(optarg); break;
      case '1':
        o.ospf.options |= OSPF_OPTION_TOS; break;
      case '2':
        o.ospf.options |= OSPF_OPTION_EXTERNAL; break;
      case '3':
        o.ospf.options |= OSPF_OPTION_MULTICAST; break;
      case '4':
        o.ospf.options |= OSPF_OPTION_NSSA; break;
      case '5':
        o.ospf.options |= OSPF_OPTION_LLS; break;
      case '6':
        o.ospf.options |= OSPF_OPTION_DEMAND; break;
      case '7':
        o.ospf.options |= OSPF_OPTION_OPAQUE; break;
      case '8':
        o.ospf.options |= OSPF_OPTION_DOWN; break;
      case OPTION_OSPF_NETMASK:
        o.ospf.netmask = resolv(optarg); break;
      case OPTION_OSPF_HELLO_INTERVAL:
        o.ospf.hello_interval = atoi(optarg); break;
      case OPTION_OSPF_HELLO_PRIORITY:
        o.ospf.hello_priority = atoi(optarg); break;
      case OPTION_OSPF_HELLO_DEAD:
        o.ospf.hello_dead = atol(optarg); break;
      case OPTION_OSPF_HELLO_DESIGN:
        o.ospf.hello_design = resolv(optarg); break;
      case OPTION_OSPF_HELLO_BACKUP:
        o.ospf.hello_backup = resolv(optarg); break;
      case OPTION_OSPF_HELLO_NEIGHBOR:
        o.ospf.neighbor = atoi(optarg); break;
      case OPTION_OSPF_HELLO_ADDRESS:
        tmp_ptr = strtok(optarg, ",");
        for (counter=0; counter < (int)(sizeof(o.ospf.address)/sizeof(in_addr_t)); counter++)
        {
          if (tmp_ptr == NULL)
            break;

          o.ospf.address[counter] = resolv(tmp_ptr);
          tmp_ptr = strtok(NULL, ",");
        }
        o.ospf.neighbor = counter;  
        break;
      case OPTION_OSPF_DD_MTU:
        o.ospf.dd_mtu = atoi(optarg); break;
      case OPTION_OSPF_DD_MASTER_SLAVE:
        o.ospf.dd_dbdesc |= DD_DBDESC_MSLAVE; break;
      case OPTION_OSPF_DD_MORE:
        o.ospf.dd_dbdesc |= DD_DBDESC_MORE; break;
      case OPTION_OSPF_DD_INIT:
        o.ospf.dd_dbdesc |= DD_DBDESC_INIT; break;
      case OPTION_OSPF_DD_OOBRESYNC:
        o.ospf.dd_dbdesc |= DD_DBDESC_OOBRESYNC; break;
      case OPTION_OSPF_DD_SEQUENCE:
        o.ospf.dd_sequence = atol(optarg); break;
      case OPTION_OSPF_DD_INCLUDE_LSA:
        o.ospf.dd_include_lsa = 1; break;
      case OPTION_OSPF_LSA_AGE:
        o.ospf.lsa_age = atoi(optarg); break;
      case OPTION_OSPF_LSA_DO_NOT_AGE:
        o.ospf.lsa_dage = 1; break;
      case OPTION_OSPF_LSA_TYPE:
        o.ospf.lsa_type = atoi(optarg); break;
      case OPTION_OSPF_LSA_LSID:
        o.ospf.lsa_lsid = resolv(optarg); break;
      case OPTION_OSPF_LSA_ROUTER:
        o.ospf.lsa_router = resolv(optarg); break;
      case OPTION_OSPF_LSA_SEQUENCE:
        o.ospf.lsa_sequence = atol(optarg); break;
      case OPTION_OSPF_LSA_METRIC:
        o.ospf.lsa_metric = atol(optarg); break;
      case OPTION_OSPF_LSA_FLAG_BORDER:
        o.ospf.lsa_flags |= ROUTER_FLAG_BORDER; break;
      case OPTION_OSPF_LSA_FLAG_EXTERNAL:
        o.ospf.lsa_flags |= ROUTER_FLAG_EXTERNAL; break;
      case OPTION_OSPF_LSA_FLAG_VIRTUAL:
        o.ospf.lsa_flags |= ROUTER_FLAG_VIRTUAL; break;
      case OPTION_OSPF_LSA_FLAG_WILD:
        o.ospf.lsa_flags |= ROUTER_FLAG_WILD; break;
      case OPTION_OSPF_LSA_FLAG_NSSA_TR:
        o.ospf.lsa_flags |= ROUTER_FLAG_NSSA_TR; break;
      case OPTION_OSPF_LSA_LINK_ID:
        o.ospf.lsa_link_id = resolv(optarg); break;
      case OPTION_OSPF_LSA_LINK_DATA:
        o.ospf.lsa_link_data = resolv(optarg); break;
      case OPTION_OSPF_LSA_LINK_TYPE:
        o.ospf.lsa_link_type = atoi(optarg); break;
      case OPTION_OSPF_LSA_ATTACHED:
        o.ospf.lsa_attached = resolv(optarg); break;
      case OPTION_OSPF_LSA_LARGER:
        o.ospf.lsa_larger = 1; break;
      case OPTION_OSPF_LSA_FORWARD:
        o.ospf.lsa_forward = resolv(optarg); break;
      case OPTION_OSPF_LSA_EXTERNAL:
        o.ospf.lsa_external = resolv(optarg); break;
      case OPTION_OSPF_VERTEX_ROUTER:
        o.ospf.vertex_type = VERTEX_TYPE_ROUTER; break;
      case OPTION_OSPF_VERTEX_NETWORK:
        o.ospf.vertex_type = VERTEX_TYPE_NETWORK; break;
      case OPTION_OSPF_VERTEX_ID:
        o.ospf.vertex_id = resolv(optarg); break;
      case OPTIONS_OSPF_LLS_OPTION_LR:
        o.ospf.lls_options = EXTENDED_OPTIONS_LR; break;
      case OPTIONS_OSPF_LLS_OPTION_RS:
        o.ospf.lls_options = EXTENDED_OPTIONS_RS; break;
      case OPTION_OSPF_AUTHENTICATION:
        o.ospf.auth = 1; break;
      case OPTION_OSPF_AUTH_KEY_ID:
        o.ospf.key_id = atoi(optarg); break;
      case OPTION_OSPF_AUTH_SEQUENCE:
        o.ospf.sequence = atol(optarg); break;

      /* XXX HELP/USAGE MESSAGE */
      case 'h':
      case '?':
      default:
        usage();
        exit(EXIT_FAILURE);
    }
  }

  /* Checking the command line interface options. */
  if (optind >= argc)
  {
    ERROR("too many arguments. Try --help for usage and help");
    exit(EXIT_FAILURE);
  }

  if ((tmp_ptr = (char *) strchr(argv[optind], 0x2f)) == NULL)
    o.ip.daddr = resolv(argv[optind]);
  else
  {
    o.bits     = atoi(tmp_ptr + 1);
    tmp_ptr   = strtok(argv[optind], "/");
    if (tmp_ptr != NULL)
      o.ip.daddr = resolv(tmp_ptr);
  }

  return &o;
}
