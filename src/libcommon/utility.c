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
 **  utility.c
 **
 ****************************************************************
 **
 **   Copyright (c) 2001, 2002 all rights reserved.
 **
 **   Author: Peter K. Lee <saint@elixar.net>
 **
 ***************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "definition.h"
#include "utility.h"
#include "ipcsum.h"

/*=============================================================*/
/* Local Global Variables */

__u8 dummybuf[32];
int ssid_sort = 0;

/*=============================================================*/
/* Function Definitions */

/**
 * hexdump()
 * ---------
 * properly output buffer as hex
 **/
char *hexdump (__u8 * x, int y)
{
  int i = -1;
  while (++i < y)
    sprintf(&dummybuf[(i * 2)], "%02x", x[i]);
  return (dummybuf);
}

/**
 * genatime()
 * ----------
 * a simple utility to generate the current time
 **/
void genatime(time_t now, char *atime)
{
    bzero(atime, TIME_TARGET_MAX);
    strncpy(atime, ctime(&now), 26);
    atime[strlen(atime) - 1] = '\0';
}

/**
 * get_time_diff()
 * ---------------
 * A handy utility function that given two time values, finds the
 * difference between them, returning the result
 **/
float get_time_diff(struct timeval *t_new, struct timeval *t_old)
{
  float t_diff;
  double new_time;
  double old_time;
 
  new_time = (double)t_new->tv_sec + ((double)t_new->tv_usec/1000000);
  old_time = (double)t_old->tv_sec + ((double)t_old->tv_usec/1000000);
  t_diff = (double)new_time - (double)old_time;

  return (t_diff);
}

/**
 * get_elapsed_time()
 * ------------------
 * A handy routine that returns elapsed time between two time values
 * in h:m:s format.
 **/
void get_elapsed_time(struct timeval *t_end, struct timeval *t_start, char * buf)
{
  int hour, min, sec = 0;
  
  hour = ((t_end->tv_sec - t_start->tv_sec) / 3600);
  min  = (((t_end->tv_sec - t_start->tv_sec) / 60)-(hour * 60));
  sec  = ((t_end->tv_sec - t_start->tv_sec) - (hour *3600) - (min * 60));
    
  snprintf(buf,10,"%02d:%02d:%02d",hour,min,sec);      
}


/**
 * verify_chksum()
 * ---------------
 * if you have ip packet, then lets verify the chksum, and return the
 * result of the calculation
 * returns: 1 if good, 0 if bad
 **/
int verify_chksum(struct iphdr *ip)
{
  int ip_len = 0;
  int hdrcsum;
  int hdrchk;

  ip_len = ip->ihl * 4;
  hdrcsum = ip->check;
  ip->check = 0;
  hdrchk = in_cksum((u_short *) ip, ip_len);
  
  if (hdrcsum != hdrchk)
    return 0;
  else
    return 1;
}


///////////////////////////////////////////////////////////////////
//  OTHER: dumper
///////////////////////////////////////////////////////////////////

/**
 * This function dumps current values stored in the bss_list structure
 * to the screen.  It is primarily used for debugging purposes.  If
 * interested in seeing this output, enable DUMP_TO_SCREEN variable in
 * the definition.h file
 */
void dump_bsss (bss_t * info)
{
/*   __u8 bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; */
/*   bss_t *curr_bss=info; */
/*   int c; */

/*   while (curr_bss) */
/*     { */
/*       printf("*------------------------------*\n"); */
/*       printf("*    -AirTraf Results-         *\n"); */
/*       printf("*------------------------------*\n"); */
/*       printf("BSSID: %s    SSID: %s    CHANNEL: %d\n", hexdump((__u8 *)&curr_bss->bssid,6), curr_bss->ssid, curr_bss->channel); */
/*       printf("\nManagement Frames:\n"); */
/*       printf("\tBeacon:             %d\n",curr_bss->mgmt_data.beacon); */
/*       printf("\tDisassoc:           %d\n",curr_bss->mgmt_data.disassoc); */
/*       printf("\tOther:              %d\n",curr_bss->mgmt_data.other); */
/*       printf("\tTotal Packets:      %d\n",curr_bss->mgmt_data.mgmt_count); */
/*       printf("\tTotal Bytes:        %d\n",curr_bss->mgmt_data.mgmt_byte); */
/*       printf("\tAvg  Bandwidth:     %-8.4f Kbps\n",curr_bss->mgmt_data.bndwth.avg); */
/*       printf("\tHigh Bandwidth:     %-8.4f Kbps\n",curr_bss->mgmt_data.bndwth.high); */
/*       printf("\tLow  Bandwidth:     %-8.4f Kbps\n",curr_bss->mgmt_data.bndwth.low); */
/*       printf("\tCurr Bandwidth:     %-8.4f Kbps\n",curr_bss->mgmt_data.bndwth.curr); */
/*       printf("\nControl Frames: \n"); */
/*       printf("\tAcknowledgement:    %d\n",curr_bss->ctrl_data.ack); */
/*       printf("\tOther:              %d\n",curr_bss->ctrl_data.other); */
/*       printf("\tTotal Packets:      %d\n",curr_bss->ctrl_data.control_count); */
/*       printf("\tTotal Bytes:        %d\n",curr_bss->ctrl_data.control_byte); */
/*       printf("\tAvg  Bandwidth:     %-8.4f Kbps\n",curr_bss->ctrl_data.bndwth.avg); */
/*       printf("\tHigh Bandwidth:     %-8.4f Kbps\n",curr_bss->ctrl_data.bndwth.high); */
/*       printf("\tLow  Bandwidth:     %-8.4f Kbps\n",curr_bss->ctrl_data.bndwth.low); */
/*       printf("\tCurr Bandwidth:     %-8.4f Kbps\n",curr_bss->ctrl_data.bndwth.curr); */
/*       printf("\nData Frames:\n"); */
/*       printf("\tExternal Packets:   %d\n",curr_bss->normal_data.external_count); */
/*       printf("\tExternal Bytes:     %d\n",curr_bss->normal_data.external_byte); */
/*       printf("\tInternal Packets:   %d\n",curr_bss->normal_data.internal_count); */
/*       printf("\tInternal Bytes:     %d\n",curr_bss->normal_data.internal_byte); */
/*       printf("\tTotal Packets:      %d\n",curr_bss->normal_data.data_count); */
/*       printf("\tTotal Bytes:        %d\n",curr_bss->normal_data.data_byte); */
/*       printf("\tAvg  Bandwidth:     %-8.4f Mbps\n",curr_bss->normal_data.bndwth.avg); */
/*       printf("\tHigh Bandwidth:     %-8.4f Mbps\n",curr_bss->normal_data.bndwth.high); */
/*       printf("\tLow  Bandwidth:     %-8.4f Mbps\n",curr_bss->normal_data.bndwth.low); */
/*       printf("\tCurr Bandwidth:     %-8.4f Mbps\n",curr_bss->normal_data.bndwth.curr); */
/*       printf("\nCorrupt Frames:\n"); */
/* //      printf("\tFCS error:          %d\n",fcs_error); */
/* //      printf("\tTotal:              %d\n",curr_bss->corrupt_count); */
/* //      printf("\tBad Mac:            %d\n",p_nodes->num + 1 - curr_bss->num); */
/*       printf("\n*------------------------------------------------------*\n"); */
/*       printf("\nOVERALL ACTIVITY:\n"); */
/*       printf("\tTotal Packets:      %d\n",curr_bss->overall_count); */
/*       printf("\tTotal Bytes:        %d\n",curr_bss->overall_byte); */
/*       printf("\tAvg  Bandwidth:     %-8.4f Mbps\n",curr_bss->bndwth.avg); */
/*       printf("\tHigh Bandwidth:     %-8.4f Mbps\n",curr_bss->bndwth.high); */
/*       printf("\tLow  Bandwidth:     %-8.4f Mbps\n",curr_bss->bndwth.low); */
/*       printf("\tCurr Bandwidth:     %-8.4f Mbps\n",curr_bss->bndwth.curr); */
/*       printf("\n*------------------------------------------------------*\n"); */
/*       printf("\nConnected Nodes:\n"); */
/*       c = 0; */
/*       while (0 != memcmp (&curr_bss->addr_list[c].mac_addr,bcast,6)) */
/* 	{ */
/* 	  printf ("\tMAC address %d: %s ", c, hexdump((__u8 *)&curr_bss->addr_list[c].mac_addr,6)); */
	  
/* 	  if (0 == memcmp(&curr_bss->addr_list[c].mac_addr, */
/* 			  &curr_bss->bssid, 6)) */
/* 	    printf ("AP\n"); */
/* 	  else */
/* 	    printf ("STA\n"); */

/* 	  printf("\tActivity:   incoming packets:     %d   \toutgoing packets:    %d\n", */
/* 		 curr_bss->addr_list[c].inc_packet, */
/* 		 curr_bss->addr_list[c].out_packet); */
/* 	  printf("\t            incoming bytes:       %d   \toutgoing bytes:      %d\n", */
/* 		 curr_bss->addr_list[c].inc_byte, */
/* 		 curr_bss->addr_list[c].out_byte); */
/* 	  printf("\t            avg.signal strength:  %-10.2f\n", curr_bss->addr_list[c].avg_signal_str); */
/* 	  printf("\t            Avg  Bandwidth:       %-8.4f Mbps\n", curr_bss->addr_list[c].bndwth.avg); */
/* 	  printf("\t            High Bandwidth:       %-8.4f Mbps\n", curr_bss->addr_list[c].bndwth.high); */
/* 	  printf("\t            Low  Bandwidth:       %-8.4f Mbps\n", curr_bss->addr_list[c].bndwth.low); */
/* 	  printf("\t            Curr Bandwidth:       %-8.4f Mbps\n", curr_bss->addr_list[c].bndwth.curr); */
	  
/* 	  c++; */
/* 	} */
/*       curr_bss=curr_bss->next; */
/*     } */
} 
