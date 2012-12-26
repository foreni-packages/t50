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

struct iphdr *gre_encapsulation(void *buffer, const struct config_options *o, uint32_t total_len)
{
  struct iphdr *ip, *gre_ip __attribute__ ((unused));
  struct gre_hdr *gre;
  struct gre_sum_hdr *gre_sum;
  int offset;

  /* GRE Encapsulation takes place. */
  if (o->encapsulated)
  {
    ip = (struct iphdr *)buffer;
    offset = sizeof(struct iphdr);

    /* GRE Header structure making a pointer to IP Header structure. */
    gre          = (struct gre_hdr *)((uint8_t *)ip + offset);
    gre->C       = o->gre.C;
    gre->K       = o->gre.K;
    gre->R       = FIELD_MUST_BE_ZERO;
    gre->S       = o->gre.S;
    gre->s       = FIELD_MUST_BE_ZERO;
    gre->recur   = FIELD_MUST_BE_ZERO;
    gre->version = GREVERSION;
    gre->flags   = FIELD_MUST_BE_ZERO;
    gre->proto   = htons(ETH_P_IP);

    /* Computing the GRE offset. */
    offset  += sizeof(struct gre_hdr);

    /* GRE CHECKSUM? */
    if (o->gre.options & GRE_OPTION_CHECKSUM)
    {
      /* GRE CHECKSUM Header structure making a pointer to IP Header structure. */
      gre_sum         = (struct gre_sum_hdr *)((uint8_t *)ip + offset);
      gre_sum->offset = FIELD_MUST_BE_ZERO;
      gre_sum->check  = 0;
      /* Computing the GRE offset. */
      offset += GRE_OPTLEN_CHECKSUM;
    }

    /* GRE KEY? */
    if (o->gre.options & GRE_OPTION_KEY)
    {
      /* GRE KEY Header structure making a pointer to IP Header structure. */
      struct gre_key_hdr *gre_key;

      gre_key      = (struct gre_key_hdr *)((uint8_t *)ip + offset);
      gre_key->key = htonl(__32BIT_RND(o->gre.key));
      /* Computing the GRE offset. */
      offset += GRE_OPTLEN_KEY;
    }

    /* GRE SEQUENCE? */
    if (o->gre.options & GRE_OPTION_SEQUENCE)
    {
      /* GRE SEQUENCE Header structure making a pointer to IP Header structure. */
      struct gre_seq_hdr *gre_seq;

      gre_seq          = (struct gre_seq_hdr *)((uint8_t *)ip + offset);
      gre_seq->sequence = htonl(__32BIT_RND(o->gre.sequence));
      /* Computing the GRE offset. */
      offset += GRE_OPTLEN_SEQUENCE;
    }

    /*
     * Generic Routing Encapsulation over IPv4 networks (RFC 1702)
     *
     * IP as both delivery and payload protocol
     *
     * When IP is encapsulated in IP,  the TTL, TOS,  and IP security options
     * MAY  be  copied from the payload packet into the same  fields  in  the
     * delivery packet. The payload packet's TTL MUST be decremented when the
     * packet is decapsulated to insure that no packet lives forever.
     */
    /* GRE Encapsulated IP Header structure making a pointer to to IP Header structure. */
    gre_ip           = (struct iphdr *)((uint8_t *)ip + offset);
    gre_ip->version  = ip->version;
    gre_ip->ihl      = ip->ihl;
    gre_ip->tos      = ip->tos;
    gre_ip->frag_off = ip->frag_off;
    gre_ip->tot_len  = htons(total_len);
    gre_ip->id       = ip->id;
    gre_ip->ttl      = ip->ttl;
    gre_ip->protocol = o->ip.protocol;
    gre_ip->saddr    = o->gre.saddr ? o->gre.saddr : ip->saddr;
    gre_ip->daddr    = o->gre.daddr ? o->gre.daddr : ip->daddr;
    /* Computing the checksum. */
    //gre_ip->check    = 0;
    gre_ip->check    = o->bogus_csum ? 
      __16BIT_RND(0) : 
      cksum((uint16_t *)gre_ip, sizeof(struct iphdr));

    return gre_ip;
  }

  return NULL;
}

void gre_checksum(void *buffer, const struct config_options *o, uint32_t packet_size)
{
  struct iphdr *ip __attribute__ ((unused));
  struct gre_hdr *gre;
  struct gre_sum_hdr *gre_sum;

  /* GRE Encapsulation takes place. */
  if (o->encapsulated)
  {
    ip = (struct iphdr *)buffer;
    gre = (struct gre_hdr *)((uint8_t *)buffer + sizeof(struct iphdr));
    gre_sum = (struct gre_sum_hdr *)((uint8_t *)gre + sizeof(struct gre_hdr));

    /* Computing the checksum. */
    if (o->gre.options & GRE_OPTION_CHECKSUM)
      gre_sum->check  = o->bogus_csum ? 
        __16BIT_RND(0) : 
        cksum((uint16_t *)gre, packet_size - sizeof(struct iphdr));
  }
}

/* Function Name: GRE header size calculation.

   Description:   This function calculates the size of GRE header.

   Targets:       N/A */
size_t gre_opt_len(const uint8_t foo, const uint8_t bar)
{
	size_t size;

	/*
	 * The code starts with size '0' and it accumulates all the required
	 * size if the conditionals match. Otherwise, it returns size '0'.
	 */
	size = 0;

	/*
	 * Returns the size of the entire  GRE  packet  only in the case  of
	 * encapsulation has been defined ('--encapsulated').
	 */
	if(bar){
		/*
		 * First thing is to accumulate GRE Header size.
		 */
		size += sizeof(struct gre_hdr);

		/*
		 * Checking whether add OPTIONAL header size.
		 *
		 * CHECKSUM HEADER?
		 */
		if((foo & GRE_OPTION_CHECKSUM) == GRE_OPTION_CHECKSUM)
			size += GRE_OPTLEN_CHECKSUM;
		/* KEY HEADER? */
		if((foo & GRE_OPTION_KEY) == GRE_OPTION_KEY)
			size += GRE_OPTLEN_KEY;
		/* SEQUENCE HEADER? */
		if((foo & GRE_OPTION_SEQUENCE) == GRE_OPTION_SEQUENCE)
			size += GRE_OPTLEN_SEQUENCE;

		/*
		 * Accumulating an extra IP Header size.
		 */
		size += sizeof(struct iphdr);
	}

	return(size);
}


