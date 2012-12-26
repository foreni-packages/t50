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

/* Global variables */
static pid_t pid = 1;
static socket_t fd;

/* Months */
static const char *const months[] = 
  { "Jan", "Feb", "Mar", "Apr", "May",  "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov",  "Dec" };

static struct launch_t50_modules 
{
  int32_t proto;
  void (* raw) (socket_t, struct config_options *);
} t50[] = 
  {
    { IPPROTO_ICMP,  (void *)icmp   },
    { IPPROTO_IGMP,  (void *)igmpv1 },
    { IPPROTO_IGMP,  (void *)igmpv3 },
    { IPPROTO_TCP,   (void *)tcp    },
    { IPPROTO_EGP,   (void *)egp    },
    { IPPROTO_UDP,   (void *)udp    },
    { IPPROTO_UDP,   (void *)ripv1  },
    { IPPROTO_UDP,   (void *)ripv2  },
    { IPPROTO_DCCP,  (void *)dccp   },
    { IPPROTO_RSVP,  (void *)rsvp   },
    { IPPROTO_AH,    (void *)ipsec  },
    { IPPROTO_EIGRP, (void *)eigrp  },
    { IPPROTO_OSPF,  (void *)ospf   },
    { 0, NULL }
  };
#define NUM_MODULES ((sizeof(t50) / sizeof(t50[0])) - 1)

/* This function handles Control-C (^C) */
static void ctrlc(int32_t signal)
{
  UNUSED_PARAM(signal);

  close(fd);

  /* NOTE: SIGSEGV is a fatal signal. I think handle it doesn't make sense! */
#if 0
  if (signal == SIGSEGV)
  {
      perror("Internal error: buffer overflow. SIGSEGV received.\n");
      exit(EXIT_FAILURE);
  }
#endif

  exit(EXIT_SUCCESS);
}

static void initializeSignalHandlers(void)
{
  /* NOTE: See 'man 2 signal' */
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_IGN;

  /* Ignoring signals. */
  sigaction(SIGHUP,  &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);

  sa.sa_handler = ctrlc;
  /* Handling signals. */
  sigaction(SIGINT,  &sa, NULL);
  //sigaction(SIGILL, &sa, NULL); /* not necessary */
  sigaction(SIGQUIT, &sa, NULL);
  sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGTRAP, &sa, NULL);
  //sigaction(SIGKILL, &sa, NULL); /* SIGKILL & SIGSTOP cannot be caught or ignored */
  //sigaction(SIGSTOP, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGTSTP, &sa, NULL);
  //sigaction(SIGSEGV, &sa, NULL); /* segmentation fault is a severe error. */
                                   /* Don't need to be caught here! */
#ifdef  __HAVE_TURBO__
  sigaction(SIGCHLD, &sa, NULL);
#endif

}

/* Main function launches all T50 modules */
int main(int argc, char *argv[])
{
  time_t lt;
  struct tm *tm;

  /* Ordinal day complement */
  char *d;
  
  /* Command line interface options. */
  struct config_options *o;

  /* Seed to use with 'srand()'. */
  struct timeval seed;

  /* Counter and random destination address. */
  uint32_t rand_daddr;

  /* CIDR host identifier and first IP address. */
  struct cidr *cidr;

  initializeSignalHandlers();

  /* Configuring command line interface options. */
  o = getConfigOptions(argc, argv);

  /* NOTE: checkConfigOptions now returns TRUE or FALSE, instead of
           EXIT_FAILURE or EXIT_SUCCESS. Makes more sense! */  
  /* Validating command line interface options. */
  if (!checkConfigOptions(o))
    exit(EXIT_FAILURE);

  /* Sanitizing the threshold. */
  if (o->ip.protocol == IPPROTO_T50)
    o->threshold -= (o->threshold % NUM_MODULES);

  /* Setting socket file descriptor. */
  fd = sock();

  /* Starting time counting. */
  gettimeofday(&seed, NULL);

  /* Using microseconds as seed. */
  srand((unsigned) seed.tv_usec);

#ifdef  __HAVE_TURBO__
  /* Entering in TURBO. */
  if (o->turbo)
  {
    if ((pid = fork()) == -1)
    {
      perror("Error creating child process. Exiting...");
      exit(EXIT_FAILURE);
    }

    /* Setting the priority to lowest (?) one. */
    if (setpriority(PRIO_PROCESS, PRIO_PROCESS, -15)  == -1)
    {
      perror("Error setting process priority. Exiting...");
      exit(EXIT_FAILURE);
    }
  }
#endif  /* __HAVE_TURBO__ */

  /* Calculating CIDR for destination address. */
  cidr = config_cidr(o->bits, o->ip.daddr);

  /* Getting the local time. */
  lt = time(NULL); tm = localtime(&lt);
  
  if (pid)
  {
    /* Setting ordinal day complement */
	 switch(tm->tm_mday)
	 {
		  case 1: case 21: case 31: d = "st"; break;
		  case 2: case 22: d = "nd"; break;
		  case 3: case 23: d = "rd"; break;
		  default: d = "th"; break;
	 }
  
    printf("\b\r%s %s successfully launched on %s %2d%s %d %.02d:%.02d:%.02d\n",
      PACKAGE,  VERSION, months[tm->tm_mon], tm->tm_mday, d,
      (tm->tm_year + 1900), tm->tm_hour, tm->tm_min, tm->tm_sec);
  }
  
  /* Execute if flood or while threshold greater than 0. */
  while(o->flood || o->threshold--)
  {
    /* Setting the destination IP address to RANDOM IP address. */
    if (cidr->hostid)
    {
      /* Generation RANDOM position for computed IP addresses. */
      /* FIX: No floating point! >-| */
      rand_daddr = rand() % cidr->hostid;

		/* FIX: No addresses array needed */
		o->ip.daddr = htonl(cidr->__1st_addr + rand_daddr);
    }   
    /* Sending ICMP/IGMP/TCP/UDP packets. */
    if (o->ip.protocol != IPPROTO_T50)
    {
      /* Getting the correct protocol. */
      o->ip.protocol = t50[o->ip.protoname].proto;
      /* Launching t50 module. */
      t50[o->ip.protoname].raw(fd, o);
    }
    else
    {
      /* NOTE: Using single pointer instead of calculating
               the pointers in every iteration. */               
      struct launch_t50_modules *p;

      /* Sending T50 packets. */ 
      for (p = t50; p->raw != NULL; p++)
      {
        /* Getting the correct protocol. */
        o->ip.protocol = p->proto;

        /* Launching t50 module. */
        p->raw(fd, o);
      }

      /* Sanitizing the threshold. */
      o->threshold -= NUM_MODULES - 1;
      /* Reseting protocol. */
      o->ip.protocol = IPPROTO_T50;
    }
  }

  /* Closing the socket. */
  close(fd);

  /* Getting the local time. */
  lt = time(NULL); tm = localtime(&lt);
  
  if (pid)
  {
    /* Setting ordinal day complement */
	switch(tm->tm_mday)
	{   
		case 1: case 21: case 31: d = "st"; break;
		case 2: case 22: d = "nd"; break;
		case 3: case 23: d = "rd"; break;
		default: d = "th"; break;
	}
    
    printf("\b\r%s %s successfully finished on %s %2d%s %d %.02d:%.02d:%.02d\n",
      PACKAGE,  VERSION, months[tm->tm_mon], tm->tm_mday, d,
      (tm->tm_year + 1900), tm->tm_hour, tm->tm_min, tm->tm_sec);
  }
  
  return(EXIT_SUCCESS);
}
