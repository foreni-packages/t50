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

#ifndef __RSVP_H
#define __RSVP_H 1

#include <common.h>

#define RSVPVERSION 1

/* RSVP Message Type */
enum rsvp_type{
	RSVP_MESSAGE_TYPE_PATH      = 1,
#define RSVP_MESSAGE_TYPE_PATH        RSVP_MESSAGE_TYPE_PATH
	RSVP_MESSAGE_TYPE_RESV,
#define RSVP_MESSAGE_TYPE_RESV        RSVP_MESSAGE_TYPE_RESV
	RSVP_MESSAGE_TYPE_PATHERR,
#define RSVP_MESSAGE_TYPE_PATHERR     RSVP_MESSAGE_TYPE_PATHERR
	RSVP_MESSAGE_TYPE_RESVERR,
#define RSVP_MESSAGE_TYPE_RESVERR     RSVP_MESSAGE_TYPE_RESVERR
	RSVP_MESSAGE_TYPE_PATHTEAR,
#define RSVP_MESSAGE_TYPE_PATHTEAR    RSVP_MESSAGE_TYPE_PATHTEAR
	RSVP_MESSAGE_TYPE_RESVTEAR,
#define RSVP_MESSAGE_TYPE_RESVTEAR    RSVP_MESSAGE_TYPE_RESVTEAR
	RSVP_MESSAGE_TYPE_RESVCONF,
#define RSVP_MESSAGE_TYPE_RESVCONF    RSVP_MESSAGE_TYPE_RESVCONF
	RSVP_MESSAGE_TYPE_BUNDLE    = 12,
#define RSVP_MESSAGE_TYPE_BUNDLE      RSVP_MESSAGE_TYPE_BUNDLE
	RSVP_MESSAGE_TYPE_ACK,
#define RSVP_MESSAGE_TYPE_ACK         RSVP_MESSAGE_TYPE_ACK
	RSVP_MESSAGE_TYPE_SREFRESH  = 15,
#define RSVP_MESSAGE_TYPE_SREFRESH    RSVP_MESSAGE_TYPE_SREFRESH
	RSVP_MESSAGE_TYPE_HELLO     = 20,
#define RSVP_MESSAGE_TYPE_HELLO       RSVP_MESSAGE_TYPE_HELLO
	RSVP_MESSAGE_TYPE_NOTIFY,
#define RSVP_MESSAGE_TYPE_NOTIFY      RSVP_MESSAGE_TYPE_NOTIFY
};
/*
 * Resource ReSerVation Protocol (RSVP) (RFC 2205)
 *
 * 3.1.2 Object Formats
 *
 *       Every  object  consists of  one or more 32-bit words with a one-
 *       word header, with the following format:
 *
 *          0             1              2             3
 *   +-------------+-------------+-------------+-------------+
 *   |       Length (bytes)      |  Class-Num  |   C-Type    |
 *   +-------------+-------------+-------------+-------------+
 *   |                                                       |
 *   //                  (Object contents)                   //
 *   |                                                       |
 *   +-------------+-------------+-------------+-------------+
 */
#define RSVP_OBJECT_HEADER_LENGTH \
			(sizeof(uint16_t) + \
			(sizeof(uint8_t) * 2))
/* RSVP Object Class */
enum rsvp_object_class{
	RSVP_OBJECT_SESSION         = 1,
#define RSVP_OBJECT_SESSION           RSVP_OBJECT_SESSION
#define RSVP_LENGTH_SESSION   RSVP_OBJECT_HEADER_LENGTH + 8
	RSVP_OBJECT_RESV_HOP        = 3,
#define RSVP_LENGTH_RESV_HOP   RSVP_OBJECT_HEADER_LENGTH + 8
	RSVP_OBJECT_INTEGRITY,
#define RSVP_LENGTH_INTEGRITY  RSVP_OBJECT_HEADER_LENGTH + 20
	RSVP_OBJECT_TIME_VALUES,
#define RSVP_LENGTH_TIME_VALUES     RSVP_OBJECT_HEADER_LENGTH + 4
	RSVP_OBJECT_ERROR_SPEC,
#define RSVP_LENGTH_ERROR_SPEC      RSVP_OBJECT_HEADER_LENGTH + 8
	RSVP_OBJECT_SCOPE,
#define RSVP_LENGTH_SCOPE(foo) \
			(RSVP_OBJECT_HEADER_LENGTH + \
			(foo * sizeof(in_addr_t)))
	RSVP_OBJECT_STYLE,
#define RSVP_LENGTH_STYLE      RSVP_OBJECT_HEADER_LENGTH + 4
	RSVP_OBJECT_FLOWSPEC,
#define RSVP_LENGTH_FLOWSPEC   RSVP_OBJECT_HEADER_LENGTH + 32
	RSVP_OBJECT_FILTER_SPEC,
#define RSVP_LENGTH_FILTER_SPEC    RSVP_OBJECT_HEADER_LENGTH + 8
	RSVP_OBJECT_SENDER_TEMPLATE,
#define RSVP_LENGTH_SENDER_TEMPLATE RSVP_OBJECT_HEADER_LENGTH + 8
	RSVP_OBJECT_SENDER_TSPEC,
#define RSVP_LENGTH_SENDER_TSPEC    RSVP_OBJECT_HEADER_LENGTH + 8
	RSVP_OBJECT_ADSPEC,
#define RSVP_OBJECT_ADSPEC            RSVP_OBJECT_ADSPEC
#define RSVP_LENGTH_ADSPEC     RSVP_OBJECT_HEADER_LENGTH + ADSPEC_MESSAGE_HEADER
	RSVP_OBJECT_POLICY_DATA,
#define RSVP_OBJECT_POLICY_DATA       RSVP_OBJECT_POLICY_DATA
	RSVP_OBJECT_RESV_CONFIRM,
#define RSVP_OBJECT_RESV_CONFIRM      RSVP_OBJECT_RESV_CONFIRM
#define RSVP_LENGTH_RESV_CONFIRM    RSVP_OBJECT_HEADER_LENGTH + 4
	RSVP_OBJECT_MESSAGE_ID      = 23,
#define RSVP_OBJECT_MESSAGE_ID        RSVP_OBJECT_MESSAGE_ID
	RSVP_OBJECT_MESSAGE_ID_ACK,
#define RSVP_OBJECT_MESSAGE_ID_ACK    RSVP_OBJECT_MESSAGE_ID_ACK
	RSVP_OBJECT_MESSAGE_ID_NACK = RSVP_OBJECT_MESSAGE_ID_ACK,
#define RSVP_OBJECT_MESSAGE_ID_NACK   RSVP_OBJECT_MESSAGE_ID_NACK
};
/* RSVP TSPEC Class Service */
enum tspec_service{
#define TSPEC_MESSAGE_HEADER   4
	TSPEC_TRAFFIC_SERVICE       = 1,
#define TSPEC_TRAFFIC_SERVICE         TSPEC_TRAFFIC_SERVICE
	TSPEC_GUARANTEED_SERVICE,
#define TSPEC_GUARANTEED_SERVICE      TSPEC_GUARANTEED_SERVICE
#define TSPECT_TOKEN_BUCKET_SERVICE   127
#define TSPEC_TOKEN_BUCKET_LENGTH   24
#define TSPEC_SERVICES(foo) \
		(foo == TSPEC_TRAFFIC_SERVICE   || \
		 foo == TSPEC_GUARANTEED_SERVICE ? \
			TSPEC_TOKEN_BUCKET_LENGTH : \
		0)
};
/* RSVP ADSPEC Class Service */
enum adspec_service{
#define ADSPEC_MESSAGE_HEADER  4
#define ADSPEC_SERVDATA_HEADER 4
#define ADSPEC_PARAMETER_DATA  4
	ADSPEC_PARAMETER_SERVICE    = 1,
#define ADSPEC_PARAMETER_SERVICE      ADSPEC_PARAMETER_SERVICE
#define ADSPEC_PARAMETER_LENGTH \
			(ADSPEC_MESSAGE_HEADER   + \
			((ADSPEC_SERVDATA_HEADER + \
			ADSPEC_PARAMETER_DATA) * 4))
#define ADSPEC_PARAMETER_ISHOPCNT   4
#define ADSPEC_PARAMETER_BANDWIDTH  6
#define ADSPEC_PARAMETER_LATENCY    8
#define ADSPEC_PARAMETER_COMPMTU    10
	ADSPEC_GUARANTEED_SERVICE,
#define ADSPEC_GUARANTEED_SERVICE     ADSPEC_GUARANTEED_SERVICE
#define ADSPEC_GUARANTEED_LENGTH \
			(ADSPEC_MESSAGE_HEADER   + \
			((ADSPEC_SERVDATA_HEADER + \
			ADSPEC_PARAMETER_DATA) * 4))
	ADSPEC_CONTROLLED_SERVICE   = 5,
#define ADSPEC_CONTROLLED_SERVICE     ADSPEC_CONTROLLED_SERVICE
#define ADSPEC_CONTROLLED_LENGTH      ADSPEC_MESSAGE_HEADER
#define ADSPEC_SERVICES(foo) \
			(ADSPEC_PARAMETER_LENGTH + \
			(foo == ADSPEC_CONTROLLED_SERVICE || \
			 foo == ADSPEC_GUARANTEED_SERVICE  ? \
				ADSPEC_GUARANTEED_LENGTH : \
			0) + \
			(foo == ADSPEC_CONTROLLED_SERVICE ? \
				ADSPEC_CONTROLLED_LENGTH : \
			0))
};


/* RSVP PROTOCOL STRUCTURES

   RSVP protocol structures used by code.
   Any new RSVP protocol structure should be added in this section. */
/*
 * Resource ReSerVation Protocol (RSVP) (RFC 2205)
 *
 * 3.1.1 Common Header
 *
 *          0             1              2             3
 *   +-------------+-------------+-------------+-------------+
 *   | Vers | Flags|  Msg Type   |       RSVP Checksum       |
 *   +-------------+-------------+-------------+-------------+
 *   |  Send_TTL   | (Reserved)  |        RSVP Length        |
 *   +-------------+-------------+-------------+-------------+
 */
struct rsvp_common_hdr{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint16_t flags:4,                /* flags                       */
	          version:4,              /* version                     */
	          type:8;                 /* message type                */
#elif defined(__BIG_ENDIAN_BITFIELD)
	uint16_t version:4,              /* version                     */
	          flags:4,                /* flags                       */
	          type:8;                 /* message type                */
#else
#	error	"Adjust your <asm/byteorder.h> defines"
#endif
	uint16_t check;                  /* checksum                    */
	uint8_t  ttl;                    /* time to live                */
	uint8_t  reserved;               /* reserved                    */
	uint16_t length;                 /* message length              */
};

#endif  /* __RSVP_H */
