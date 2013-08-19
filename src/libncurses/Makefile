##################################################
# Makefile
# airtraf GUI library tree
#
# by Peter K. Lee <saint@elixar.net>
# February 2002

SHELL = /bin/sh

TOP = ..

include $(TOP)/Makefile.rules

##################################################
# files to clean

CLEAN_FILES = *.o *~ core $(GUI_LIBRARY)

DIST_CLEAN_FILES = $(CLEAN_FILES)

##################################################
# files

OBJS =  deskman.o	\
	input.o		\
	error.o		\
	menurt.o	\
	stdwinset.o	\
	$(LIBOBJS)

INCS=
LIBS=-lpanel -lncurses

##################################################
# targets
#
# all       -- compile library
# clean     -- remove object files
# depend    -- create dependency files
# distclean -- remove object files

all: $(GUI_LIBRARY)

clean:
	-rm -f $(CLEAN_FILES)

depend:
	$(CC) -MM $(INCS) $(CFLAGS) *.c > Makefile.depends

distclean:
	-rm -f $(DIST_CLEAN_FILES)

.PHONY: all clean depend distclean

##################################################
# build specific files

$(GUI_LIBRARY): $(OBJS)
	$(AR) $(ARFLAGS) $(GUI_LIBRARY) $(OBJS)
	$(RANLIB) $(GUI_LIBRARY)

include Makefile.depends
