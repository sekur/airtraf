##################################################
# Makefile
# airtraf library tree
#
# by Peter K. Lee <saint@elixar.net>
# February 2002

SHELL = /bin/sh

TOP = ..

LIBRARY = libairtraf.a

include $(TOP)/Makefile.rules

##################################################
# files to clean

CLEAN_FILES = *.o *~ core $(LIBRARY)

DIST_CLEAN_FILES = $(CLEAN_FILES)

##################################################
# files

OBJS =  utility.o         \
	db_utils.o        \
	logger.o          \
	packet_card.o     \
	ipcsum.o	  \
	$(LIBOBJS)

XOBJS = utility.o         \
	logger.o          \
	ipcsum.o	  \
	packet_card.o

INCS=-I/usr/include/mysql
LIBS=-L/usr/lib/mysql -lmysqlclient -lpthread -lm

##################################################
# targets
#
# all       -- compile library
# clean     -- remove object files
# depend    -- create dependency files
# depnodb   -- create dependency files w/o database
# distclean -- remove object files

all: $(LIBRARY)

sniff: just_sniff

clean:
	-rm -f $(CLEAN_FILES)

depend:
	$(CC) -MM $(INCS) $(CFLAGS) *.c > Makefile.depends

depnodb:
	$(CC) -MM $(CFLAGS) logger.c packet_card.c utility.c > Makefile.depends

distclean:
	-rm -f $(DIST_CLEAN_FILES)

.PHONY: all clean depend distclean

##################################################
# build specific files

$(LIBRARY): $(OBJS)
	$(AR) $(ARFLAGS) $(LIBRARY) $(OBJS)
	$(RANLIB) $(LIBRARY)

just_sniff: $(XOBJS)
	$(AR) $(ARFLAGS) $(LIBRARY) $(XOBJS)
	$(RANLIB) $(LIBRARY)

include Makefile.depends
