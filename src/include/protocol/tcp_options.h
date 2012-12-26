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

#ifndef __TCP_OPTIONS_H
#define __TCP_OPTIONS_H 1

#include <common.h>

enum tcp_option{
	TCPOPT_EOL                  = 0,
#define TCPOPT_EOL                    TCPOPT_EOL
	TCPOPT_NOP,
#define TCPOPT_NOP                    TCPOPT_NOP
	TCPOPT_MSS,
#define TCPOPT_MSS                    TCPOPT_MSS
#define TCPOLEN_MSS            4
	TCPOPT_WSOPT,
#define TCPOPT_WSOPT                  TCPOPT_WSOPT
#define TCPOLEN_WSOPT          3
	TCPOPT_SACK_OK,
#define TCPOPT_SACK_OK                TCPOPT_SACK_OK
#define TCPOLEN_SACK_OK        2
	TCPOPT_SACK_EDGE,
#define TCPOPT_SACK_EDGE              TCPOPT_SACK_EDGE
/*
 * TCP Selective Acknowledgement Options (SACK) (RFC 2018)
 *
 * A SACK option that specifies n blocks will  have a length of 8*n+2
 * bytes,  so  the  40 bytes  available for TCP options can specify a
 * maximum of 4 blocks.   It is expected that SACK will often be used 
 * in conjunction with the Timestamp option used for RTTM,which takes
 * an additional 10 bytes (plus two bytes of padding); thus a maximum
 * of 3 SACK blocks will be allowed in this case.
 */
#define TCPOLEN_SACK_EDGE(foo) \
			((foo * (sizeof(uint32_t) * 2)) + \
			TCPOLEN_SACK_OK)
	TCPOPT_TSOPT                = 8,
#define TCPOPT_TSOPT                  TCPOPT_TSOPT
#define TCPOLEN_TSOPT          10
	TCPOPT_CC                   = 11,
#define TCPOPT_CC                     TCPOPT_CC
	TCPOPT_CC_NEW,
#define TCPOPT_CC_NEW                 TCPOPT_CC_NEW
	TCPOPT_CC_ECHO,
#define TCPOPT_CC_ECHO                TCPOPT_CC_ECHO
#define TCPOLEN_CC             6
	TCPOPT_MD5                  = 19,
#define TCPOPT_MD5                    TCPOPT_MD5
#define TCPOLEN_MD5            18
	TCPOPT_AO                   = 29,
#define TCPOPT_AO                     TCPOPT_AO
#define TCPOLEN_AO             20

/*
 * Transmission Control Protocol (TCP) (RFC 793)
 *
 * Padding:  variable
 *
 *  The TCP header padding is used to ensure that the TCP header ends
 *  and data begins on a 32 bit boundary.  The padding is composed of
 *  zeros.
 */
#define TCPOLEN_PADDING(foo) \
			((foo & 3) ? \
				sizeof(uint32_t) - (foo & 3) : \
			0)
};
/* TCP Options bitmask. */
enum tcp_option_bitmask{
	TCP_OPTION_MSS              = 0x01,
#define TCP_OPTION_MSS                TCP_OPTION_MSS
	TCP_OPTION_WSOPT            = 0x02,
#define TCP_OPTION_WSOPT              TCP_OPTION_WSOPT
	TCP_OPTION_TSOPT            = 0x04,
#define TCP_OPTION_TSOPT              TCP_OPTION_TSOPT
	TCP_OPTION_SACK_OK          = 0x08,
#define TCP_OPTION_SACK_OK            TCP_OPTION_SACK_OK
	TCP_OPTION_CC               = 0x10,
#define TCP_OPTION_CC                 TCP_OPTION_CC
	TCP_OPTION_CC_NEXT          = 0x20,
#define TCP_OPTION_CC_NEXT            TCP_OPTION_CC_NEXT
	TCP_OPTION_SACK_EDGE        = 0x40,
#define TCP_OPTION_SACK_EDGE          TCP_OPTION_SACK_EDGE
};

#endif  /* __TCP_OPTIONS_H */
