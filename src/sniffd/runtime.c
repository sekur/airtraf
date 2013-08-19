/****************************************************************************
    This file is part of AirTraf (Elixar, Inc.)

    AirTraf is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    AirTraf is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with AirTraf; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
******************************************************************************/
/****************************************************************
 **
 **  AIRTRAF:
 **     a wireless (802.11) traffic/performance analyzer
 **
 **  runtime.c
 **
 ****************************************************************
 **
 **   Copyright (c) 2001 all rights reserved.
 **
 **   Author: Peter K. Lee <pkl@duke.edu>
 **
 ***************************************************************/

/*=============================================================*/
/* System Includes */

#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/types.h>
#include <sys/time.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <errno.h>
#include <pthread.h>

#include "definition.h"
#include "sniff_include.h"

/*=============================================================*/
/* Local Global Variables */

/* time start/end information */
struct timeval t_start, t_end;
int hour, min, sec = 0;

/* thread stuff for server mode */
pthread_t thread;
pthread_cond_t start_cond;
pthread_mutex_t start_lock;

/*=============================================================*/
/* Function Prototypes */

/*=============================================================*/
/* Function Definitions */

///////////////////////////////////////////////////////////////////
//  MAIN AIRTRAF FUNCTIONS
///////////////////////////////////////////////////////////////////

/**
 * airtraf_init()
 * --------------
 * main airtraf initializer function, deals with setting up services
 * that have been specified in the command_line, opening up interface,
 * as well as calling the bss_list initializer function.
 **/
void airtraf_init(struct SETTINGS *mySettings)
{
  /* setup logging facilities */
  if (mySettings->logging_mode == ENABLED){
    init_log(CONNECT_LOG,mySettings->logfile);
    fprintf(stderr, "airtraf_init: [success] logging enabled\n");
  }

  /* setup listening server */
  if (mySettings->conn_mode == SERVER_MODE){
    pthread_cond_init(&start_cond, NULL);
    pthread_mutex_init(&start_lock, NULL);
    pthread_mutex_lock(&start_lock);
    
    /* start up the server */
    pthread_create(&thread, NULL, server, (void *)mySettings);
    pthread_cond_wait(&start_cond, &start_lock);
    fprintf(stderr, "airtraf_init: [success] server started\n");
  }

  if (mySettings->capture_mode == CAPTURE_MODE_RECORD){
    fprintf(stderr, "airtraf_init: [info] starting capture mode\n");
    if (!init_capture(mySettings)){
      fprintf(stderr, "airtraf_init: [error] initializing capture mode failed\n");
    }
  }

  /** open sniffing interface! **/
  (mySettings->sniff_socket) = pkt_card_sock_open(mySettings);

  /** keep the interface up!  if it fails here, bail-out... **/
  if (!pkt_card_ifup(mySettings)){
    fprintf(stderr, "airtraf_init: [error] (%s) failed to bring the interface's configuration status up!\n", mySettings->interface);
    exit(-1);
  }
  else
    fprintf(stderr, "airtraf_init: [success] (%s) flags updated to reflect UP & RUNNING.\n", mySettings->interface);
  
  /** see packet_abstraction.c for initialize_packet_abstraction() **/
  initialize_packet_abstraction();
  fprintf(stderr, "airtraf_init: [success] initialized packet_abstraction engine.\n");

  /** see p802_11b_parser.c for initialize_p802_11b_parser() **/
  initialize_p802_11b_parser();
  fprintf(stderr, "airtraf_init: [success] initialized 802.11b parser.\n");
   
  fprintf(stderr, "airtraf_init: [success] AirTraf initialization complete\n\n");
  gettimeofday(&t_start,NULL);
}

/**
 * airtraf_start()
 * ---------------
 * main function for getting the program rolling...  creates the GUI
 * if in INTRACTIVE MODE, and just runs in the background if in
 * DAEMONIZED MODE.
 **/
void airtraf_start(struct SETTINGS *mySettings)
{
  fprintf(stderr, "Entering AirTraf Execution...\n");

  /* if mode is INTERACTIVE, then start up the ncurses GUI */
  if (mySettings->runtime_mode == INTERACTIVE){
    initscr();

    if ((LINES < 45) || (COLS < 120)) {
      endwin();
      fprintf(stderr,
	      "\nThis program requires a screen size of at least 120 columns by 45 lines\n");
      fprintf(stderr, "Please resize your window\n\n");
      exit(1);
    }
    start_color();
    standardcolors(1);
    noecho();
    nonl();
    cbreak();
    
    program_interface(mySettings);

    endwin();
  }
  /* if mode is DAEMONIZED, then do not output to screen */
  else if (mySettings->runtime_mode == DAEMONIZED){
    /** just start the engine **/
    mySettings->scan_mode = DETAILED_SCAN;
    initialize_detailed_scan();
    init_potential_structs();
    start_sniffer_engine(mySettings); 
    while (get_engine_status() == ENABLED){
      if (mySettings->capture_mode == CAPTURE_MODE_RECORD){
	
      }
      // keep the interface up...
      pkt_card_ifup(mySettings);
      sleep(1);
    }
    free_potential_structs();
    free_detailed_scan();
  }
  fprintf(stderr, "Leaving AirTraf Execution...\n\n");
}

/**
 * airtraf_end()
 * ------------
 * The clean-up routines, flushing logs, closing sockets, removing
 * temproary data structures, etc.
 **/
void airtraf_end(struct SETTINGS *mySettings)
{
  unsigned char logmsg[MAX_MSG_SIZE];  

  /** CLEAN-UP Routine **/    
  if (mySettings->logging_mode == ENABLED){
    bzero(logmsg,sizeof(logmsg));  
    sprintf(logmsg,"** AirTraf Server Shutting Down **\n\n");
    write_log(CONNECT_LOG,logmsg);
    close_log(CONNECT_LOG);
  }

  if (mySettings->capture_mode == CAPTURE_MODE_RECORD){
    free_capture();
  }
  
  /** close sniffer socket **/
  pkt_card_sock_close(mySettings);
  
  if (DUMP_TO_SCREEN == ENABLED) {
    //    fprintf(stderr, "STATUS: AirTraf dumping data \n");
    //    dump_bsss(bss_list);
    //    fprintf(stderr,"\n%d packets analyzed ",counter);
    //    fprintf(stderr,"\t%d packets could not be analyzed\n",other);
    gettimeofday(&t_end,NULL);
    hour = ((t_end.tv_sec - t_start.tv_sec) / 3600);
    min  = (((t_end.tv_sec - t_start.tv_sec) / 60)-(hour * 60));
    sec  = ((t_end.tv_sec - t_start.tv_sec) - (hour *3600) - (min * 60));
    
    fprintf(stderr,"airtraf_end: [info] Elapsed Time: %02d:%02d:%02d\n",hour,min,sec);
    fprintf(stderr,"airtraf_end: [info] Exiting gracefully...\n\n");
  }
  else if (DUMP_TO_SCREEN == DISABLED) {
    fprintf(stderr,"airtraf_end: [info] Exiting gracefully...\n");
  }
}

