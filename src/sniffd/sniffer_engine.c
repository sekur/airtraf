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
 **  sniffer_engine.c
 **
 ****************************************************************
 **
 **   Copyright (c) 2001,2002 all rights reserved.
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
#include <sys/socket.h>
#include <sys/resource.h>
#include <errno.h>
#include <pthread.h>

#include "definition.h"
#include "sniff_include.h"

/*=============================================================*/
/* Local Global Variables */

/* thread stuff for the engine */
pthread_t engine;
pthread_cond_t  engine_ready;
pthread_cond_t  engine_dead;
pthread_mutex_t engine_lock;

static int stop_scanning;
static int engine_status;
int channel_change;

/*=============================================================*/
/* Function Definitions */

////////////////////////////////////////////////////////////
// PRIVATE: helper functions
////////////////////////////////////////////////////////////

/**
 * sniff_packet()
 * --------------
 * the function to be called to read packet, do analysis, and update
 * the internal structure.
 * reads in p802.11 hdr, as well as ip hdr.
 * highest level call used by sniffer_engine...
 **/
void sniff_packet(struct SETTINGS *mySettings)
{
  struct packet_info *packet;
  
  /**
   * read the packet, and handle the type of packet returned.
   **/
  if (DEBUG) printf("reading socket\n");

  if (NULL == (packet = get_packet(mySettings)))
    return;
  if (DEBUG) printf("socket read ok\n");

  if (mySettings->scan_mode == CHANNEL_SCAN){
    process_channel_scan(packet);
  }
  else if (mySettings->scan_mode == DETAILED_SCAN){
    if (mySettings->runtime_mode == DAEMONIZED)
      mySettings->chosen_ap = NULL;
    if (mySettings->chosen_ap != NULL)
      process_detailed_scan(packet,
	     (struct access_point *)mySettings->chosen_ap);
    else
      process_detailed_scan(packet, NULL);
  } 
}

/**
 * sniffer_engine() <thread>
 * ----------------------
 * the main engine that loops forever(until stopped) reading packets,
 * organizing, adding, updating to the bss_list data structure.
 **/
void * sniffer_engine(void *var)
{
  struct SETTINGS *mySettings;
  struct timeval tv_pot_reset;
  struct timeval tv_old;
  struct timeval tv_new;
  float t_diff;

  pthread_mutex_lock(&engine_lock);

  mySettings = (struct SETTINGS*)var;
  gettimeofday(&tv_pot_reset, NULL);
  tv_old = tv_pot_reset;

  engine_status = ENABLED;
  channel_change = 0;
  
  pthread_cond_broadcast(&engine_ready);
  pthread_mutex_unlock(&engine_lock);

  while (!stop_scanning){
    
    gettimeofday(&tv_new, NULL);
    t_diff = get_time_diff(&tv_new, &tv_old);

    /** do deep scan & analysis **/
    if (mySettings->scan_mode == DETAILED_SCAN){
      if (t_diff > 1){
	pthread_mutex_lock(&engine_lock);
	update_all_bandwidth();
	tv_old = tv_new;
	pthread_mutex_unlock(&engine_lock);
      }
      
      if (mySettings->runtime_mode == INTERACTIVE){
	/** reset the potential structures every 30 secs. **/
	t_diff = get_time_diff(&tv_new, &tv_pot_reset);
	if (t_diff > 30){
	  /** get lock before resetting structures **/
	  pthread_mutex_lock(&engine_lock);
	  track_bad_data();
	  clean_up_bss_nodes();
	  clear_potential_structs();
	  pthread_mutex_unlock(&engine_lock);
	  tv_pot_reset = tv_new;
	}          
      }     
    }
    if (mySettings->scan_mode == CHANNEL_SCAN){
      /** update existing ap status every 30 secs... i.e. mark
	  inactive, eventually removing them... **/
      if (t_diff > 30){
	update_all_ap_status();
	tv_old = tv_new;
      }
      if (channel_change)
	continue;
    }
    pthread_mutex_lock(&engine_lock);
    /** read the packet **/
    if (DEBUG) fprintf(stderr,"calling sniff_packet()\n");
    sniff_packet(mySettings);
    if (DEBUG) fprintf(stderr,"returned from sniff_packet()\n");
    pthread_mutex_unlock(&engine_lock);
  }
  if (DEBUG) fprintf(stderr,"sniffer_engine(): trying to exit...\n");
  pthread_mutex_lock(&engine_lock);
  engine_status = DISABLED;  
  pthread_cond_broadcast(&engine_dead);
  pthread_mutex_unlock(&engine_lock);

  pthread_exit(&engine);
}

////////////////////////////////////////////////////////////
// PUBLIC: interface calls
////////////////////////////////////////////////////////////

void start_sniffer_engine(struct SETTINGS *mySettings)
{
  stop_scanning = DISABLED;
  
  /** lock stuff for the engine **/
  pthread_cond_init(&engine_ready, NULL);
  pthread_cond_init(&engine_dead, NULL);
  pthread_mutex_init(&engine_lock, NULL);
  pthread_mutex_lock(&engine_lock);
  
  /** launch the engine in a separate thread! **/
  pthread_create(&engine, NULL, sniffer_engine, (void *)mySettings);
  pthread_cond_wait(&engine_ready, &engine_lock);
  pthread_mutex_unlock(&engine_lock);
}

/**
 * ask_stop_sniffer_engine()
 * --------------------
 * a handy function call to stop the sniffer engine from collecting
 * data...
 **/
void ask_stop_sniffer_engine()
{
  stop_scanning = ENABLED;
}

/**
 * stop_sniffer_engine()
 * ----------------------
 * function to FORCE sniffer engine to stop, or better yet, to WAIT
 * until the thing's dead.
 **/
void stop_sniffer_engine(struct SETTINGS *mySettings)
{
  pthread_mutex_lock(&engine_lock);
  stop_scanning = ENABLED;
  pthread_cond_wait(&engine_dead, &engine_lock);
  pthread_mutex_unlock(&engine_lock);
}


/**
 * get_engine_status()
 * -------------------
 * simple function that returns the runtime status of the engine.
 **/
int get_engine_status()
{
  return (engine_status);
}
