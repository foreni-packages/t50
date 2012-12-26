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

/* Function Name: IPSec packet header configuration.

Description:   This function configures and sends the IPSec packet header.

Targets:       N/A */
void ipsec(const socket_t fd, const struct config_options *o)
{
  /* GRE options size. */
  size_t greoptlen = gre_opt_len(o->gre.options, o->encapsulated);

  /* IPSec AH Integrity Check Value (ICV) */
  size_t ip_ah_icv = sizeof(uint32_t) * 3;

  /* IPSec ESP Data Encrypted (RANDOM). */
  size_t esp_data  = auth_hmac_md5_len(1);

  /* Packet size. */
  const uint32_t packet_size = sizeof(struct iphdr)       + 
    greoptlen             + 
    sizeof(struct ip_auth_hdr) + 
    ip_ah_icv                  +
    sizeof(struct ip_esp_hdr)  + 
    esp_data;

  /* Checksum offset, GRE offset and Counter. */
  uint32_t offset, counter;

  /* Packet. */
  uint8_t packet[packet_size], *checksum;

  /* Socket address, IP header and IPSec AH header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* GRE Encapsulated IP Header. */
  struct iphdr * gre_ip __attribute__ ((unused));

  /* IPSec AH header and IPSec ESP Header. */
  struct ip_auth_hdr * ip_auth;
  struct ip_esp_hdr * ip_esp;

  /* Setting SOCKADDR structure. */
  sin.sin_family      = AF_INET;
  sin.sin_port        = htons(IPPORT_RND(o->dest));
  sin.sin_addr.s_addr = o->ip.daddr;

  ip           = (struct iphdr *)packet;
  ip->version  = IPVERSION;
  ip->ihl      = sizeof(struct iphdr)/4;
  ip->tos      = o->ip.tos;
  ip->frag_off = htons(o->ip.frag_off ? 
      (o->ip.frag_off >> 3) | IP_MF : 
      o->ip.frag_off | IP_DF);
  ip->tot_len  = htons(packet_size);
  ip->id       = htons(__16BIT_RND(o->ip.id));
  ip->ttl      = o->ip.ttl;
  ip->protocol = o->encapsulated ? 
    IPPROTO_GRE : 
    o->ip.protocol;
  ip->saddr    = INADDR_RND(o->ip.saddr);
  ip->daddr    = o->ip.daddr;
  /* The code does not have to handle this, Kernel will do-> */
  ip->check    = 0;

  /* Computing the GRE Offset. */
  offset = sizeof(struct iphdr);

  /* GRE Encapsulation takes place. */
  gre_ip = gre_encapsulation(packet, o,
        sizeof(struct iphdr) + 
        sizeof(struct ip_auth_hdr) + 
        ip_ah_icv                  +
        sizeof(struct ip_esp_hdr)  + 
        esp_data);

  /* IPSec AH Header structure making a pointer to IP Header structure. */
  ip_auth          = (struct ip_auth_hdr *)((uint8_t *)ip + sizeof(struct iphdr) + greoptlen);
  ip_auth->nexthdr = IPPROTO_ESP;
  ip_auth->hdrlen  = o->ipsec.ah_length ? 
    o->ipsec.ah_length : 
    (sizeof(struct ip_auth_hdr)/4) + (ip_ah_icv/ip_ah_icv);
  ip_auth->spi     = htonl(__32BIT_RND(o->ipsec.ah_spi));
  ip_auth->seq_no  = htonl(__32BIT_RND(o->ipsec.ah_sequence));

  /* Computing the Checksum offset. */
  offset = sizeof(struct ip_auth_hdr);

  /* Storing both Checksum and Packet. */
  checksum = (uint8_t *)ip_auth + offset;

  /*
   * IP Authentication Header (RFC 2402)
   *
   * 2.  Authentication Header Format
   *
   *  0                   1                   2                   3
   *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * | Next Header   |  Payload Len  |          RESERVED             |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                 Security Parameters Index (SPI)               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                    Sequence Number Field                      |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                                                               |
   * +                Authentication Data (variable)                 |
   * |                                                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */
  /* Setting a fake encrypted content. */
  for(counter = 0 ; counter < ip_ah_icv ; counter++)
    *checksum++ = __8BIT_RND(0);

  /* IPSec ESP Header structure making a pointer to Checksum. */
  ip_esp         = (struct ip_esp_hdr *)(checksum + (offset - sizeof(struct ip_auth_hdr)));
  ip_esp->spi    = htonl(__32BIT_RND(o->ipsec.esp_spi));
  ip_esp->seq_no = htonl(__32BIT_RND(o->ipsec.esp_sequence));
  /* Computing the Checksum offset. */
  offset += sizeof(struct ip_esp_hdr);
  /* Carrying forward the Checksum. */
  checksum += sizeof(struct ip_esp_hdr);

  /* Setting a fake encrypted content. */
  for(counter = 0 ; counter < esp_data ; counter++)
    *checksum++ = __8BIT_RND(0);

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, o, packet_size);

  /* Sending packet. */
  if (sendto(fd, &packet, packet_size, 0|MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1 && errno != EPERM)
  {
    perror("sendto()");
    /* Closing the socket. */
    close(fd);
    /* Exiting. */
    exit(EXIT_FAILURE);
  }
}
