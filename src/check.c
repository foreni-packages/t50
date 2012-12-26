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

/* Validate options */
int checkConfigOptions(const struct config_options *o)
{
  /* Warning missed privileges. */
  if ( getuid() )
  {
    ERROR("you must have privileges to run me");    
    return 0;
  }

  /* Warning missed target. */
  if (o->ip.daddr == INADDR_ANY)
  {
    ERROR("try --help for usage and help");
    return 0;
  }

  /* Sanitizing the CIDR. */
  if ( (o->bits < CIDR_MINIMUM  || o->bits > CIDR_MAXIMUM) && o->bits != 0)
  {
    char errstr[48];

    sprintf(errstr, "CIDR must be beewten %d and %d",
        CIDR_MINIMUM, CIDR_MAXIMUM);
    ERROR(errstr);
    return 0;
  }

  /* Sanitizing the TCP Options SACK_Permitted and SACK Edges. */
  if ( (o->tcp.options & TCP_OPTION_SACK_OK) == TCP_OPTION_SACK_OK &&
      (o->tcp.options & TCP_OPTION_SACK_EDGE) == TCP_OPTION_SACK_EDGE )
  {
    ERROR("TCP options SACK-Permitted and SACK Edges are not allowed");
    return 0;
  }

  /* Sanitizing the TCP Options T/TCP CC and T/TCP CC.ECHO. */
  if ((o->tcp.options & TCP_OPTION_CC) == TCP_OPTION_CC && (o->tcp.cc_echo) )
  {
    ERROR("TCP options T/TCP CC and T/TCP CC.ECHO are not allowed");
    return 0;
  }

  /* Testing IANA IP address allocation for private internets (RFC 1700, 1918 and 3330). */
  switch(ntohl(o->ip.daddr) & 0xff000000)
  {
    /* Allowing 10/8 (RFC 1918). */
    case 0x0a000000: break;

                     /* Allowing 127/8 (RFC 1700). */
    case 0x7f000000: break;

                     /* Allowing 169.254/16 (RFC 3330). */
    case 0xa9000000:
                     if ((ntohl(o->ip.daddr) & 0xffff0000) != 0xa9fe0000)
                     {
                       fprintf(stderr, "T50 is RFC 1700, RFC 1918 and RFC 3330 compliance\n");
                       fflush(stderr);
                       return 0;
                     }
                     break;

                     /* Allowing 172.16/12 (RFC 1918). */
    case 0xac000000:
                     if ((ntohl(o->ip.daddr) & 0xffff0000) < 0xac100000 || \
                         (ntohl(o->ip.daddr) & 0xffff0000) > 0xac1f0000)
                     {
                       fprintf(stderr, "T50 is RFC 1700, RFC 1918 and RFC 3330 compliance\n");
                       fflush(stderr);
                       return 0;
                     }
                     break;

                     /* Allowing 192.168/16 (RFC 1918). */
    case 0xc0000000:
                     if ((ntohl(o->ip.daddr) & 0xffff0000) != 0xc0a80000)
                     {
                       fprintf(stderr, "T50 is RFC 1700, RFC 1918 and RFC 3330 compliance\n");
                       fflush(stderr);
                       return 0;
                     }
                     break;

                     /* Blocking all other IP addresses. */
    default:
                     fprintf(stderr, "T50 is RFC 1700, RFC 1918 and RFC 3330 compliance\n");
                     fflush(stderr);
                     return 0;
                     break;
  }

#ifdef  __HAVE_TURBO__
  /* Sanitizing TURBO mode. */
  if (o->turbo && o->flood == 0)
  {
    ERROR("turbo mode is only available in flood mode");
    return 0;
  }
#endif  /* __HAVE_TURBO__ */

  /* Sanitizing the threshold. */
  if (o->ip.protocol == IPPROTO_T50 && o->threshold < T50_THRESHOLD_MIN
      && o->flood == 0)
  {
    fprintf(stderr,
        "%s: protocol %s cannot have threshold smaller than %d\n",
        PACKAGE,
        mod_acronyms[o->ip.protoname],
        T50_THRESHOLD_MIN);
    fflush(stderr);
    return 0;
  }


  /* Warning FLOOD mode. */
  if (o->flood)
  {
    printf("entering in flood mode...\n");

#ifdef  __HAVE_TURBO__
    if (o->turbo) printf("activating turbo...\n");
#endif  /* __HAVE_TURBO__ */

    /* Warning CIDR mode. */
    if (o->bits) printf("performing DDoS...\n");

    printf("hit CTRL+C to break.\n");
  }

  /* Returning. */
  return 1;
}
