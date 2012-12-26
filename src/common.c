/*
* T50 - Experimental Mixed Packet Injector
*
* Copyright (C) 2010 - 2011 Nelson Brito <nbrito@sekure.org>
* Copyright (C) 2011 - Fernando Mercês <fernando@mentebinaria.com.br>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <common.h>

char *mod_acronyms[]   = {
				"ICMP",
				"IGMPv1",
				"IGMPv3",
				"TCP",
				"EGP",
				"UDP",
				"RIPv1",
				"RIPv2",
				"DCCP",
				"RSVP",
				"IPSEC",
				"EIGRP",
				"OSPF",
				"T50",
				NULL
};

char *mod_names[] = {
				"Internet Control Message Protocol",
				"Internet Group Message Protocol v1",
				"Internet Group Message Protocol v3",
				"Transmission Control Protocol",
				"Exterior Gateway Protocol",
				"User Datagram Protocol",
				"Routing Information Protocol v1",
				"Routing Information Protocol v2",
				"Datagram Congestion Control Protocol",
				"Resource ReSerVation Protocol",
				"Internet Protocol Security (AH/ESP)",
				"Enhanced Interior Gateway Routing Protocol",
				"Open Shortest Path First",
				NULL
};

/* NOTE: This routine cannot be inlined due to its compliexity. */
uint32_t NETMASK_RND(uint32_t foo)
{
  uint32_t t;

  if (foo != INADDR_ANY)
    t = foo;
  else
    t = ~(0xffffffffUL >> (8 + ((rand() >> 27) % 23)));

  return htonl(t);
}
