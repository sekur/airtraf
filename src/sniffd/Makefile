##################################################
# Makefile
# airtraf sniffd source tree
#
# by Peter K. Lee <saint@elixar.net>
# March 2002

SHELL = /bin/sh

TOP = ..

include $(TOP)/Makefile.rules

##################################################
# files to clean

CLEAN_FILES      = *.o *~ core $(MAIN_PROG)

DIST_CLEAN_FILES = $(CLEAN_FILES)

##################################################
# files

MAIN_PROG = $(SNIFF_PROG)
MAIN_OBJS = airtraf.o			\
	    autoconfig.o		\
	    capture_engine.o		\
	    channel_scan.o		\
	    detailed_analysis.o 	\
	    detailed_scan.o		\
	    gui_main.o			\
	    gui_capture_utils.o		\
	    gui_channel_scan.o		\
	    gui_detailed_scan.o 	\
	    gui_gen_protocol_scan.o 	\
	    gui_tcp_analysis_scan.o   	\
	    mon_ids.o			\
	    packet_abstraction.o	\
	    p802_11b_parser.o		\
	    runtime.o			\
	    server.o			\
	    sniffer_engine.o

INCS =  -I$(COMMONLIBDIR) -I$(NCURSESLIBDIR)
LIBS =  -L$(COMMONLIBDIR) -lairtraf		\
	-L$(NCURSESLIBDIR) -lairgui	\
        -lpanel -lncurses -lpthread -lm

##################################################
# targets
#
# all       -- compile the iperf program
# clean     -- remove object files
# depend    -- reate dependency files
# distclean -- remove object files
# install   -- compile and install the airtraf program
#              call from top level 'make install'
#

all: $(MAIN_PROG)

clean:
	-rm -f $(CLEAN_FILES)

depend:
	$(CC) -MM $(INCS) $(CFLAGS) *.c > Makefile.depends

distclean:
	-rm -f $(DIST_CLEAN_FILES)

install: $(MAIN_PROG)
	$(INSTALL) -d $(INSTALL_DIR)
	$(INSTALL) $(MAIN_PROG) $(INSTALL_DIR)

.PHONY: all clean depend distclean install

##################################################
# build specific files

$(MAIN_PROG): $(LIBRARY) $(GUI_LIBRARY) $(MAIN_OBJS)
	$(CC) -o $(MAIN_PROG) $(LDFLAGS) $(MAIN_OBJS) $(LIBS)

include Makefile.depends

