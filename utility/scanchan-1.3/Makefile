# Simple makefile to build the prismdump utility
#
CC=gcc
LD=gcc
# To do: Use GNU autoconf
#
#
# Path to GLIB
#
GLIB_INCLUDE=-I/usr/include/glib-1.2/ -I/usr/lib/glib/include
#
# CFLAGS
CFLAGS=-ggdb0 -O2 -c $(GLIB_INCLUDE)
#
#
# Libraries to link against
LIBS= -lglib -lz
#
#

all: scanchan

scanchan.o:	scanchan.c
	$(CC) $(CFLAGS) -o $@ scanchan.c

scanchan: scanchan.o
	$(LD) -o scanchan scanchan.o $(LIBS)

clean:	
	rm -f scanchan.o scanchan *~
