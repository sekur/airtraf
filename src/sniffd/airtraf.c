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
/*********************************************************************
 **
 ** AirTraf - Utility to measure traffic in the wireless segment of
 **           802.11b network.  Discovers connected nodes, then tracks
 **           incoming/outgoing traffic for each node.  Shows the
 **           current bandwidth usage, as well as total packet count,
 **           inc/outgoing for each node, and tracks specific
 **           management frames sent from the AP.
 **
 *********************************************************************
 *
 * There are many programs currently out there that does performance
 * monitoring, however, this program is unique in that it isolates the
 * traffic to nodes within the wireless segment, regardless of the
 * fact that the wireless segment is connected to the rest of the
 * network or not.
 *
 * It will currently be used to analyze packet information upto layer
 * 2 of the OSI model, however, it can be extended beyond if proven
 * desirable.
 *
 * This utility is written for use with IEEE 802.11 adapters based
 * on Intersil's PRISM II chipset (PCMCIA).  However currently, the
 * limitation of Prism2 drivers limit the sniffing of channel to
 * single channels.  It will also be equipped to work with Cisco
 * Aironet chipset, which offers an advantage of sniffing on all
 * channels at once (will be added later).
 *
 * The linux driver for these cards can be found on www.linux-wlan.com
 * It has been verified with a LinkSys WPC11 IEEE 802.11 adapter. 
 * 
 * Copyright (c)2001,2002 by Elixar.net  Durham, NC., all rights reserved.
 *
 * Comments/Bug reports should be sent to: Peter K. Lee (saint@elixar.net)
 * 
 *********************************************************************/

/*=============================================================*/
/* System Includes */

#include <ncurses.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <asm/types.h>
#include <sys/types.h>
#include <errno.h>
#include <features.h>
#include <pthread.h>
#include "getopt.h"

#include "definition.h"
#include "sniff_include.h"

// autoconfig stuff - *new* 11/15/02 (saint)
#include "autoconfig.h"

/*=============================================================*/
/* Local Static Definitions */

#define def_card          AIRONET
#define def_interface     NULL
#define def_mode          INTERACTIVE
#define def_conn_mode     ADHOC_MODE
#define def_logfile       "log.connection"
#define def_signal_support DISABLED
#define def_logging_mode  DISABLED

#define def_capture_version 1
#define def_capture_mode CAPTURE_MODE_OFF
#define def_capture_file     "airtraf.capture"
#define def_capture_status CAPTURE_STATUS_INACTIVE
#define def_capture_interval 1
#define def_capture_overwrite DISABLED

/*=============================================================*/
/* Local Global Variables */

int sysexit = 0;
struct SETTINGS *myset_ptr;

/*=============================================================*/
/* Local Structs */

struct option long_options[] =
  {
    {"card",           required_argument, NULL, 'C'},
    {"interface",      required_argument, NULL, 'I'},
    {"daemonized",     no_argument,       NULL, 'D'},
    {"server_mode",    no_argument,       NULL, 'S'},
    {"logfile",        optional_argument, NULL, 'L'},
    {"list",           no_argument,       NULL, 'l'},
    {"force",          no_argument,       NULL, 'f'},
    {"signal",         no_argument,       NULL, 'x'},
    {"help",           no_argument,       NULL, 'h'},
    {"debug",          no_argument,       NULL, 'z'},
    {"capture",        optional_argument, NULL, 'A'},
    { 0, 0, 0, 0}
  };

/*=============================================================*/
/* Function Prototypes */


/*=============================================================*/
/* Function Definitions */

static void usage (const char *pname)
{
  fprintf(stderr, "--------------------------------------------------------------------------\n");
  fprintf(stderr, "AirTraf: a wireless (802.11) network performance analyzer. by Peter K. Lee (Elixar, Inc.)\n");
  fprintf(stderr, "\nUsage:\n\t%s [-l -f] [-C <cardtype>] [-I <interface>] [-D] [-x] [-A <capture>] [-L <logfile>]\n", pname);
  fprintf(stderr, "\n-l : list available wireless devices in the system (& exits)\n");
  fprintf(stderr, "-f : force monitor mode, manual override, etc. (w/o prompting for sanity check)\n");
  fprintf(stderr, "-C : card type, either prism2, hermes or aironet (manual override)\n");
  fprintf(stderr, "-I : interface to listen on eth0. eth1, wlan0, etc. (manual override)\n");
  fprintf(stderr, "-D : runs the program in daemonized background *default:OFF* \n");
  //  fprintf(stderr, "-S : runs the program in server mode (allows connection from polling server) *default:OFF* \n");
  fprintf(stderr, "-A : runs the program in capture mode (filename arg allowed) \n");
  fprintf(stderr, "-L : enable logging mode *default:OFF (argument allows specification of log file name) \n");
  fprintf(stderr, "-x : enable signal strength *default:OFF (using patched aironet driver) \n");
  fprintf(stderr, "-h : view this usage message\n\n");
  exit(1);
}

/**
 * dump_trace()
 * --------------
 * dumps out potentially relevant data as to why this crash may have
 * occurred...
 **/
void dump_trace()
{
  potential_node_t * pnt = (potential_node_t *)get_p_nodes();
  potential_ap_t * pat = (potential_ap_t *)get_p_aps();
  struct channel_overview *cov = get_channel_snapshot();
  detailed_overview_t *ov = get_detailed_snapshot();
  bss_t *bsst = NULL;
  bss_node_t *bsnt = NULL;
  tcptable_t *tent = NULL;
  tcpconn_t *tcon = NULL;
  
  fprintf(stderr, "\n---------------  TRACE DUMP  --------------------\n");
  fprintf(stderr, "SETTINGS:\n");
  fprintf(stderr, "card_type=%d \tinterface=%s \truntime_mode=%d \tconn_mode=%d\n",
	  myset_ptr->card_type, myset_ptr->interface, myset_ptr->runtime_mode, myset_ptr->conn_mode);
  fprintf(stderr, "signal_support=%d \tsniff_socket=%d \tscan_mode=%d ",
	 myset_ptr->signal_support, myset_ptr->sniff_socket, myset_ptr->scan_mode);
  if (myset_ptr->chosen_ap != NULL)
    fprintf(stderr, "\tchosen_ap= OK\n\n");
  else
    fprintf(stderr, "\tchosen_ap= NULL\n\n");

  fprintf(stderr, "DATA STRUCTURES:\n");
  if (pnt == NULL)
    fprintf(stderr, "potential_nodes= NULL\n");
  else{
    fprintf(stderr, "potential_nodes= OK \tnum=%d\n", pnt->num);
  }
  if (pat == NULL)
    fprintf(stderr, "potential_aps= NULL\n");
  else{
    fprintf(stderr, "potential_aps= OK \tnum=%d\n", pat->num);
  }
  if (cov == NULL)
    fprintf(stderr, "channel_overview= NULL\n");
  else{
    fprintf(stderr, "channel_overview= OK \tnum_det_aps=%d\n", cov->num_det_aps);
  }
  if (ov == NULL)
    fprintf(stderr, "detailed_overview_t= NULL\n");
  else{
    fprintf(stderr, "detailed_overview_t= OK \ttot_ap=%d \ttot_nodes=%d\n",
	    ov->tot_num_ap, ov->tot_num_nodes);
    if (NULL == (bsst = ov->bss_list_top))
      fprintf(stderr, "bss_t= NULL\n");
    else{
      while (bsst != NULL){
	fprintf(stderr, "bss_t= OK \tnum nodes=%d\n", bsst->num);
	if (NULL== (bsnt = bsst->addr_list_head))
	  fprintf(stderr, "bss_node_t= NULL\n");
	else{
	  while (bsnt != NULL){
	    fprintf(stderr, "bss_node_t= OK \tstatus=%d \ttot_packet=%d \ttcp_conns=%d\n",
		    bsnt->status, bsnt->tot_packet, bsnt->tcp_connections);
	    if (NULL == (tent = bsnt->tcpinfo_head))
	      fprintf(stderr, "tcptable_t= NULL\n");
	    else{
	      while (tent != NULL){
		fprintf(stderr, "tcptable_t= OK \tnum_connected=%d\n", tent->num_connected);
		if (NULL == (tcon = tent->tcpconn_head))
		  fprintf(stderr, "tcpconn_t= NULL\n");
		else{
		  while (tcon != NULL){
		    fprintf(stderr, "tcpconn_t= OK \ttotal_count=%d\n", tcon->total_count);
		    tcon = tcon->next;
		  }
		}
		
		tent = tent->next;
	      }
	    }
	    bsnt = bsnt->next;
	  }
	}
	bsst = bsst->next;
      }
      
    }
  }
  
  fprintf(stderr, "\n-----------------------------------------------------------------\n\n");
}

/**
 * term_signal_handler()
 * ------------------------
 * Handler for the TERM signal and HUP signals.  Try to safely exit,
 * cleaning up after itself
 **/
void term_signal_handler(int signo)
{
 /*    erase(); */
/*     refresh(); */
/*     endwin(); */

    if (signo != SIGHUP)
	fprintf(stderr, "AirTraf process %u exiting on signal %d\n\n",
		getpid(), signo);

/*     if (active_facility_lockfile[0] != '\0') { */
/* 	unlink(active_facility_lockfile); */
/* 	adjust_instance_count(PROCCOUNTFILE, -1); */
/* 	if (active_facility_countfile[0] != '\0') */
/* 	    adjust_instance_count(active_facility_countfile, -1); */
/*     } */

/*     if (is_first_instance) */
/* 	unlink(IPTIDFILE); */

    exit(1);
}

/**
 * segvhandler()
 * ----------------
 * Handler for the SIGSEGV, Segmentation Fault.  Tries to clear the screen
 * and issue a better message than "Segmentation fault".  May not always
 * clean up properly.
 **/
void segvhandler()
{
  dump_trace();
  
  fprintf(stderr, "Fatal: memory allocation error\n\n");
  fprintf(stderr, "If you suspect a bug, please report the exact circumstances under which this\n");
  fprintf(stderr, "error was generated.  If possible, include gdb or strace data which may point\n");
  fprintf(stderr, "out where the error occured.  Bug reports may be sent in to saint@elixar.net.\n\n");
  fprintf(stderr, "AirTraf process %u aborting on signal 11.\n\n", getpid());
  
  /*    if (active_facility_lockfile[0] != '\0') */
  /* 	unlink(active_facility_lockfile); */
  
  /*     if (is_first_instance) */
  /* 	unlink(IPTIDFILE); */
  
  /*     if (active_facility_lockfile[0] != '\0') { */
  /* 	unlink(active_facility_lockfile); */
  /* 	adjust_instance_count(PROCCOUNTFILE, -1); */
  /* 	if (active_facility_countfile[0] != '\0') */
  /* 	    adjust_instance_count(active_facility_countfile, -1); */
  /*     } */
  
  exit(2);
}

/**
 * stop_signal()
 * --------------
 * soft kill...  generally just kill the sniffing engine.
 **/
void stop_signal ()
{
  if (!sysexit){
    sysexit = 1;
    ask_stop_sniffer_engine();
  }
}

/*=============================================================*/
/* Main Program */

int main(int argc, char **argv)
{
  // autoconfig vars
  int num_dev = 0;
  int force = 0, override = 0; 
  wireless_devices iwlist;
  wireless_devices *select = NULL;
  void *blah = compat_drivers; // shut up compiler

  // rest of program vars
  static struct SETTINGS mySettings;

  /* program name */
  char *pname = argv[0];
  char lognamebuf[100];
  char capturebuf[100];
  
  int c, option_index = 0;

  myset_ptr = &mySettings;
  blah = blah; // shut up compiler

  /* command line stuff */
  mySettings.card_type      = 0;
  mySettings.interface      = def_interface;
  mySettings.runtime_mode   = def_mode;
  mySettings.conn_mode      = def_conn_mode;
  mySettings.logfile        = def_logfile;
  mySettings.logging_mode   = def_logging_mode;
  mySettings.signal_support = def_signal_support;
  mySettings.sniff_socket   = 0;

  bzero(capturebuf, sizeof(capturebuf));
  mySettings.capture_file = capturebuf;
  strcpy(mySettings.capture_file, def_capture_file);
  mySettings.capture_version = def_capture_version;
  mySettings.capture_mode = def_capture_mode;
  mySettings.capture_size = 0;
  mySettings.capture_timestamp = NULL;
  mySettings.capture_duration = 0;
  mySettings.capture_interval = def_capture_interval;
  mySettings.capture_overwrite = def_capture_overwrite;
  mySettings.capture_status = def_capture_status;
  
  //  if(argc < 2){
  //    usage(pname);
  //  }
  
  if (getenv("TERM") == NULL) {
    fprintf(stderr, "Your TERM variable is not set.\n");
    fprintf(stderr, "Please set it to an appropriate value.\n");
    exit(1);
  }

  /** initialize autoconfig info **/
  init_autoconfig(&iwlist, &num_dev);
  
  /** load options from configuration file **/
  //  loadoptions(&options);

  /* parse command-line arguments */
  while ((c = getopt_long (argc, argv, "C:I:DSA::L::hlfzx", long_options,
			   &option_index)) != EOF)
    {
      switch(c)
	{
	case 'l':
	  print_autoconfig(&iwlist, &num_dev);
	  exit(1);
	  break;
	case 'f':
	  force = 1;
	  break;
	case 'C':
	  fprintf(stderr,"-C (cardtype) is now deprecated by default autoconfig feature (use only if you desire manual override)\n");
	  override = 1;
	  if(!strcasecmp("prism2", optarg)) {
	    mySettings.card_type = PRISMII;
	  } else if(!strcasecmp("aironet", optarg)) {
	    mySettings.card_type = AIRONET;
	  } else if(!strcasecmp("hermes", optarg)) {
	    mySettings.card_type = HERMES;
	  } else if(!strcasecmp("hostap", optarg)) {
	    mySettings.card_type = HOSTAP;
	  } else if(!strcasecmp("wlanng", optarg)) {
	    mySettings.card_type = WLANNG;
	  } else {
	    fprintf(stderr,"Invalid card type chosen!  Valid types: 'prism2' or 'aironet' (default)\n\n");
	    exit(1);
	  }
	  break;
	case 'I':
	  fprintf(stderr,"-I (interface) is now deprecated by default autoconfig feature (use only if you desire manual override)\n");
	  override = 1;
	  mySettings.interface = optarg;
	  break;
	case 'D':
	  printf("set to daemonized mode...\n");
	  mySettings.runtime_mode = DAEMONIZED;
	  break;
	case 'S':
	  mySettings.conn_mode = SERVER_MODE;
	  break;
	case 'A':
	  mySettings.capture_mode = CAPTURE_MODE_RECORD;
	  /** if there's optional argument */
	  if (optarg){
	    strncpy(capturebuf, optarg, sizeof(capturebuf) -1);
	    capturebuf[sizeof(capturebuf)-1] = '\0';
	    mySettings.capture_file = capturebuf;
	    while (*optarg){
	      *optarg++ = ' ';
	    }
	  }
	  break;
	case 'L':
	  mySettings.logging_mode = ENABLED;
	  /* if there's optional argument */
	  if (optarg){    
	    strncpy(lognamebuf, optarg, sizeof(lognamebuf) -1);
	    lognamebuf[sizeof(lognamebuf)-1] = '\0';
	    mySettings.logfile = lognamebuf;
	    while (*optarg){
	      *optarg++ = ' ';
	    }
	  }
	  break;
	case 'x':
	  mySettings.signal_support = ENABLED;
	  break;
	case 'h':
	  usage(pname);
	  break;
	case 'z':
	  break;
	case '?':
	  fprintf(stderr,"\nInvalid option or missing parameter, use airtraf -h for help\n\n");
	  exit(1);
	}
    }
  /* print a splash message */
  fprintf(stderr,"-----------------------------------------\n");
  fprintf(stderr,"Airtraf %s %c 2001,2002 Elixar, Inc.\n", VERSION_INFO,(int)169);
  fprintf(stderr,"Mode: sniffing server\n");
  fprintf(stderr,"Author: Peter K. Lee  All Rights Reserved\n");
  fprintf(stderr,"-----------------------------------------\n");

  /* if the user is overriding as manual settings, just go on... */
  if (override){
    if (mySettings.card_type == 0){
      fprintf(stderr,"\nYou need to specify card type, see below:\n\n");
      usage(pname);
    }
    
    /* if interface was not specified alert user */
    if (mySettings.interface == NULL){
      fprintf(stderr,"\nYou need to specify which interface to listen on, see below:\n\n");
      usage(pname);
    }
  }
  /* else proceed through autoconfig */
  else{
    /* print the result of autoconfig */
    print_autoconfig(&iwlist, &num_dev);
    
    if (num_dev == 1)
      select = &iwlist;
    else if (num_dev > 1)
      select = prompt_device(&iwlist, &num_dev);
    else // shouldn't get here
      exit(1);
    
    /** now put the card into monitor mode **/
    if (!enable_monitor(select, force)) exit(1);

    /** now update the internal SETTINGS **/
    mySettings.interface = select->ifname;
    switch(select->compat_id){
    case DRV_AIRO_CS:
    case DRV_AIRO:
      mySettings.card_type = AIRONET;
      break;
    case DRV_PRISM2_CS:
      mySettings.card_type = WLANNG;
      break;
    case DRV_PRISM2:
      mySettings.card_type = PRISMII;
      break;
    case DRV_HOSTAP_CS:
    case DRV_HOSTAP:
      mySettings.card_type = HOSTAP;
      break;
    case DRV_ORINOCO_CS:
    case DRV_ORINOCO:
      mySettings.card_type = HERMES;
      break;
    default:
      fprintf(stderr,"Unknown card type?  Why are we here?  PANIC!\n");
      exit(1);
      break;
    }
  }
  
  //  setpriority (PRIO_PROCESS, 0 , -10);
  signal(SIGSEGV, (void *) segvhandler);
  signal(SIGTERM, (void *) term_signal_handler);
  signal(SIGHUP, (void *) term_signal_handler);
  signal (SIGINT, (void *) stop_signal);  
    
  /** initialize airtraf as defined in runtime.c **/
  airtraf_init(&mySettings);

  /** begin airtraf as defined in runtime.c **/
  airtraf_start(&mySettings);
  
  /** now put the card out of monitor mode **/
  disable_monitor(select);

  /** stop airtraf as defined in runtime.c **/
  airtraf_end(&mySettings);

  return(0);
}
