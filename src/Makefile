##################################################
# Makefile
# airtraf MAIN INSTALLATION makefile
#
# by Peter K. Lee <saint@elixar.net>
# March 2002

SHELL = /bin/sh

VERSION = 1.1

TOP = .

include Makefile.rules
####################################
# files

PROGS   = airtraf

##################################################
# targets
#
# all       -- create dependency, compile library, and all airtraf programs
# clean     -- remove all compiled object files
# depend    -- create dependency files
# depnodb   -- create dependency files (w/o database)
# distclean -- remove most files that can be generated
# install   -- compile and install library and headers
# nodb      -- compiles library w/o database, just makes sniffer


#all: library gui_library programs success

all: depnodb gui_library just_sniff success

clean:
	@echo
	@echo "#####  cleaning out objects  #####"
	@echo ; (cd libcommon  ; make clean)
	@echo ; (cd libncurses ; make clean)
#	@echo ; (cd polld   ; make clean)
	@echo ; (cd sniffd  ; make clean)
	@echo
	@echo "#####  clean completed  #####"

depend:
	@echo
	@echo "#####  Making dependency Files  #####"
	@echo ; (cd libcommon  ; make depend)
	@echo ; (cd libncurses ; make depend)
	@echo ; (cd polld   ; make depend)
	@echo ; (cd sniffd  ; make depend)

depnodb:
	@echo
	@echo "#####  Making dependency Files  #####"
	@echo ; (cd libcommon  ; make depnodb)
	@echo ; (cd libncurses ; make depend)
	@echo ; (cd sniffd  ; make depend)

distclean:
	@echo ; (cd lib     ; make distclean)
	@echo ; (cd ncurses ; make distclean)
	@echo ; (cd polld   ; make distclean)
	@echo ; (cd sniffd  ; make distclean)

install: $(PROGS)
	@echo
	@echo "#####  Installing airtraf-$(VERSION)  #####"
	@echo
	@echo "Where should the airtraf binary be installed? [/usr/local/bin] :"
	@read  INSTALL_DIR;                                                 \
	export INSTALL_DIR;                                                 \
	INSTALL_DIR=`echo $$INSTALL_DIR | perl -p -e 's/~/$$ENV{"HOME"}/'`; \
	if test -z "$$INSTALL_DIR"; then                                    \
	  INSTALL_DIR=/usr/local/bin;                                       \
	fi;                                                                 \
	echo ; (cd sniffd ; make install)                                  
	@echo
	@echo "#####  Installation complete!  ####"
#	echo ; (cd polld  ; make install);                                  \

release:
	@echo
	@echo "#####  Making release airtraf-$(VERSION)  #####"
	@echo ; (cd ../.. ; rm -rf airtraf-$(VERSION); mkdir airtraf-$(VERSION); \
		cp -R airtraf-main/* airtraf-$(VERSION);                         \
		cd airtraf-$(VERSION) ;                                          \
		find . | grep CVS | xargs rm -rf)
	@echo ; (cd ../.. ; tar czvf airtraf-$(VERSION).tar.gz airtraf-$(VERSION))
	@echo 
	@echo "#####  Release successfully exported  #####"

success:
	@echo
	@echo "##########################################################"
	@echo "#         ALL BUILD COMPLETED SUCCESSFULLY!!!            #"
	@echo "##########################################################"
	@echo "# please refer to 'docs' directory for instructions on   #"
	@echo "# how to utilize the functions of AirTraf                #"
	@echo "#                                                        #"
	@echo "# Your AirTraf version is: $(VERSION)                           #"
	@echo "# -----------------------------------                    #"
	@echo "# Special Thanks to:                                     #"
	@echo "#   Robert D. Currier, Helen K. Sul,                     #"
	@echo "#   and the amazing Elixar Team!                         #"
	@echo "#                                                        #"
	@echo "##########################################################"
	@echo "# for more info: http://www.elixar.com                   #"
	@echo "# questions:  <support@elixar.com>                       #"
	@echo "##########################################################"
	@echo
	@echo "Now run 'make install'"

.PHONY: all clean depend distclean install release sniffer success

##################################################
# build specific files

library:
	@echo
	@echo "#####  Compiling Common Library  #####"
	-rm -f $(LIBRARY)
	@echo ; (cd libcommon ; make all)

gui_library:
	@echo
	@echo "#####  Compiling GUI Library  #####"
	-rm -f $(GUI_LIBRARY)
	@echo ; (cd libncurses ; make all)

programs:
	@echo
	@echo "#####  Compiling Polling Server  #####"
	-rm -f $(POLL_PROG) $(INIT_PROG)
	@echo ; (cd polld ; make all)
	@echo
	@echo "#####  Compiling Sniffing Server  #####"
	-rm -f $(SNIFF_PROG)
	@echo ; (cd sniffd ; make all)

just_sniff:
	@echo
	@echo "#####  Building AirTraf sniffer with needed parts  #####"
	-rm -f $(SNIFF_PROG)
	@echo ; (cd libcommon ; make sniff)
	@echo ; (cd sniffd ; make all)

