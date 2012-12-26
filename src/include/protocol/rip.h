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

#ifndef __RIP_H
#define __RIP_H 1

#include <common.h>

#define IPPORT_RIP             520
#define RIP_HEADER_LENGTH      4
#define RIP_MESSAGE_LENGTH     20
#define RIP_AUTH_LENGTH        20
#define RIP_TRAILER_LENGTH     4

/* Calculating RIP Header length */
#	define rip_hdr_len(foo) \
			(RIP_HEADER_LENGTH + \
			RIP_MESSAGE_LENGTH + \
			(foo ? \
				RIP_AUTH_LENGTH + \
				RIP_TRAILER_LENGTH + \
				AUTH_TLEN_HMACMD5 : \
			0))

#endif  /* __RIP_H */
