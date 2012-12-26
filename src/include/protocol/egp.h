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

#ifndef __EGP_H
#define __EGP_H

#define EGPVERSION 2

#include <common.h>

/* EGP Message Types */
enum egp_type {
	EGP_NEIGHBOR_UPDATE_RESP    = 1,
#define EGP_NEIGHBOR_UPDATE_RESP      EGP_NEIGHBOR_UPDATE_RESP
	EGP_NEIGHBOR_POLL_COMMAND,
#define EGP_NEIGHBOR_POLL_COMMAND     EGP_NEIGHBOR_POLL_COMMAND
	EGP_NEIGHBOR_ACQUISITION,
#define EGP_NEIGHBOR_ACQUISITION      EGP_NEIGHBOR_ACQUISITION
	EGP_NEIGHBOR_REACHABILITY   = 5,
#define EGP_NEIGHBOR_REACHABILITY     EGP_NEIGHBOR_REACHABILITY
	EGP_NEIGHBOR_ERROR_RESP     = 8
#define EGP_NEIGHBOR_ERROR_RESP       EGP_NEIGHBOR_ERROR_RESP
};

/* EGP Message Neighbor Acquisition Codes */
enum acquisition_code {
	EGP_ACQ_CODE_REQUEST_CMD    = 0,
#define EGP_ACQ_CODE_REQUEST_CMD      EGP_ACQ_CODE_REQUEST_CMD
	EGP_ACQ_CODE_CONFIRM_RESP,
#define EGP_ACQ_CODE_CONFIRM_RESP     EGP_ACQ_CODE_CONFIRM_RESP
	EGP_ACQ_CODE_REFUSE_RESP,
#define EGP_ACQ_CODE_REFUSE_RESP      EGP_ACQ_CODE_REFUSE_RESP
	EGP_ACQ_CODE_CEASE_CMD,
#define EGP_ACQ_CODE_CEASE_CMD        EGP_ACQ_CODE_CEASE_CMD
	EGP_ACQ_CODE_CEASE_ACKCMD,
#define EGP_ACQ_CODE_CEASE_ACKCMD     EGP_ACQ_CODE_CEASE_ACKCMD

};

/* EGP Message Neighbor Acquisition Type */
enum egp_acq_status {
	EGP_ACQ_STAT_UNSPECIFIED    = 0,
#define EGP_ACQ_STAT_UNSPECIFIED      EGP_ACQ_STAT_UNSPECIFIED
	EGP_ACQ_STAT_ACTIVE_MODE,
#define EGP_ACQ_STAT_ACTIVE_MODE      EGP_ACQ_STAT_ACTIVE_MODE
	EGP_ACQ_STAT_PASSIVE_MODE,
#define EGP_ACQ_STAT_PASSIVE_MODE     EGP_ACQ_STAT_PASSIVE_MODE
	EGP_ACQ_STAT_INSUFFICIENT,
#define EGP_ACQ_STAT_INSUFFICIENT     EGP_ACQ_STAT_INSUFFICIENT
	EGP_ACQ_STAT_ADM_PROHIBIT,
#define EGP_ACQ_STAT_ADM_PROHIBIT     EGP_ACQ_STAT_ADM_PROHIBIT
	EGP_ACQ_STAT_GOING_DOWN,
#define EGP_ACQ_STAT_GOING_DOWN       EGP_ACQ_STAT_GOING_DOWN
	EGP_ACQ_STAT_PARAMETER,
#define EGP_ACQ_STAT_PARAMETER        EGP_ACQ_STAT_PARAMETER
	EGP_ACQ_STAT_VIOLATION,
#define EGP_ACQ_STAT_VIOLATION        EGP_ACQ_STAT_VIOLATION
};

/* EGP PROTOCOL STRUCTURES

   EGP protocol structures used by code.
   Any new EGP protocol structure should be added in this section. */
/*
 * Exterior Gateway Protocol (EGP) Formal Specification (RFC 904)
 *
 * Appendix A.  EGP Message Formats
 *
 *      The  formats  for  the  various  EGP messages are described in this
 * section.  All  EGP  messages  include  a ten-octet header of six fields,
 * which may  be followed  by  additional fields depending on message type.
 * The format of the  header is shown below along with a description of its
 * fields.
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | EGP Version # |     Type      |     Code      |    Status     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Checksum               |       Autonomous System #     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Sequence #             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * EGP Version #           assigned number identifying the EGP version
 *                         (currently 2)
 *
 * Type                    identifies the message type
 *
 * Code                    identifies the message code (subtype)
 *
 * Status                  contains message-dependent status information
 *
 * Checksum                The EGP checksum  is the 16-bit one's complement
 *                         of the one's  complement sum  of the EGP message
 *                         starting with the EGP version number field. When
 *                         computing the checksum the checksum field itself
 *                         should be zero.
 *
 * Autonomous System #     assigned   number   identifying  the  particular
 *                         autonomous system
 * 
 * Sequence #              send state variable (commands) or  receive state
 *                         variable (responses and indications)
 */
 
struct egp_hdr {
	uint8_t  version;                /* version                     */
	uint8_t  type;                   /* type                        */
	uint8_t  code;                   /* code                        */
	uint8_t  status;                 /* status                      */
	uint16_t check;                  /* checksum                    */
	uint16_t as;                     /* autonomous system           */
	uint16_t sequence;               /* sequence number             */
	uint8_t  __data[0];              /* data                        */
};

/*
 * Exterior Gateway Protocol (EGP) Formal Specification (RFC 904)
 *
 * A.1.  Neighbor Acquisition Messages
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | EGP Version # |     Type      |     Code      |    Status     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Checksum               |       Autonomous System #     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Sequence #             |          Hello Interval       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Poll Interval          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Note:  the Hello Interval and Poll Interval fields are present  only  in
 * Request and Confirm messages.
 *
 * Type                    3
 *
 * Code                    0       Request command
 *                         1       Confirm response
 *                         2       Refuse response
 *                         3       Cease command
 *                         4       Cease-ack response
 *
 * Status (see below)      0       unspecified
 *                         1       active mode
 *                         2       passive mode
 *                         3       insufficient resources
 *                         4       administratively prohibited
 *                         5       going down
 *                         6       parameter problem
 *                         7       protocol violation
 *
 * Hello Interval          minimum Hello command polling interval (seconds)
 *
 * Poll Interval           minimum Poll command polling interval (seconds)
 */
 
struct egp_acq_hdr {
	__be16	  hello;                  /* hello interval              */
	__be16	  poll;                   /* poll interval               */
};

#endif  /* __EGP_H */
