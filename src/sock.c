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

#include <common.h>

/* Socket configuration */
socket_t sock(void)
{
	socket_t fd;
	uint32_t len;
	uint32_t n = 1, *nptr = &n;

	/* Setting SOCKET RAW. */
	if( (fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
	{
		ERROR("error opening raw socket");
		exit(EXIT_FAILURE);
	}

	/* Setting IP_HDRINCL. */
	if( setsockopt(fd, IPPROTO_IP, IP_HDRINCL, nptr, sizeof(n)) < 0 )
	{
		ERROR("error setting socket options");
		exit(EXIT_FAILURE);
	}

/* Taken from libdnet by Dug Song. */
#ifdef SO_SNDBUF
	len = sizeof(n);
	/* Getting SO_SNDBUF. */
	if( getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &n, &len) < 0 )
	{
		ERROR("error getting socket buffer");
		exit(EXIT_FAILURE);
	}

	/* Setting the maximum SO_SNDBUF in bytes.
	 * 128      =  1 kilobit
	 * 10485760 = 10 megabytes */
	for(n+=128; n<10485760; n+=128)
	{
		/* Setting SO_SNDBUF. */
		if( setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &n, len) < 0 )
		{
			if(errno == ENOBUFS)	break;
			ERROR("error setting socket buffer");
			exit(EXIT_FAILURE);
		}
	}
#endif /* SO_SNDBUF */

#ifdef SO_BROADCAST
	/* Setting SO_BROADCAST. */
	if( setsockopt(fd, SOL_SOCKET, SO_BROADCAST, nptr, sizeof(n)) < 0 )
	{
		ERROR("error setting socket broadcast");
		exit(EXIT_FAILURE);
	}
#endif /* SO_BROADCAST */

#ifdef SO_PRIORITY
	if( setsockopt(fd, SOL_SOCKET, SO_PRIORITY, nptr, sizeof(n)) < 0 )
	{
		perror("error setting socket priority");
		exit(EXIT_FAILURE);
	}
#endif /* SO_PRIORITY */

	return fd;
}
