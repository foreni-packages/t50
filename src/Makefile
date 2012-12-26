# T50 Makefile
#
# Written by Fernando Mercês <fernando@mentebinaria.com.br>
#
# __HAVE_TURBO__ - turbo mode enable --turbo option. This makes
# T50 create a child process to improve performance.
#
# __HAVE_DEBUG__ - debug mode makes T50 print the source filename
# and line when an error occurs. This is a good idea if you're
# experiencing problems.
	
PREFIX=/usr
MANDIR=/usr/share/man/man8
SRCDIR=.
CC=gcc
USE_SSE=-msse -mfpmath=sse
STRIP=-s
CFLAGS=-W -Wall -Wextra -O3 $(USE_SSE) -ffast-math $(STRIP)
INCLUDES=-I$(SRCDIR)/include
DFLAGS=-D__HAVE_TURBO__ -DVERSION=\"$(shell cat ../VERSION)\"
#DFLAGS+=-D__HAVE_DEBUG__
SRC=$(shell find $(SRCDIR) -type f -name '*.c')
	
all:
	$(CC) $(CFLAGS) $(INCLUDES) $(DFLAGS) $(SRC) -o t50
	
clean:
	rm -f t50
	
install: 
	install t50 $(PREFIX)/sbin
	gzip -c -9 ../t50.1 > $(MANDIR)/t50.8.gz
	
uninstall:
	rm -f $(PREFIX)/sbin/t50
