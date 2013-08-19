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
 **  channel_scan.c
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
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <asm/types.h>

#include "definition.h"
#include "sniff_include.h"
/*===========================================================*/
/* Global Variables */

static struct channel_overview *overview;
static potential_ap_t *ap_filter;

/*=============================================================*/
/* Function Definitions */

////////////////////////////////////////////////////////////////
// INITIALIZATION ROUTINE
////////////////////////////////////////////////////////////////

/**
 * initialize_channel_scan()
 * -------------------------
 * initialize the data structure responsible for holding the channel
 * scan results.
 **/
void initialize_channel_scan()
{
  /* initialize the channel_scan structure */
  if (NULL == (overview = malloc(sizeof(struct channel_overview)))){
    perror("malloc");
    exit(-1);
  }   
  memset(overview,0,sizeof(struct channel_overview));
  if (NULL == (ap_filter = malloc(sizeof(potential_ap_t)))){
    perror("malloc");
    exit(-1);
  }
  memset(ap_filter,0,sizeof(potential_ap_t));
}

/**
 * reset_ap_list()
 * ---------------
 * reset access_point structs recursively
 **/
void reset_ap_list(struct access_point *ap)
{
  struct access_point * temp = ap;

  if (temp != NULL){
    reset_ap_list((struct access_point *)ap->next);
    free(temp);
    return;
  }
  else{
    return;
  }
}

/**
 * free_channel_scan()
 * -------------------
 * free up memory used in channel scan
 **/
void free_channel_scan()
{
  int i;
  for (i = 0; i < 15; i++){
    reset_ap_list(overview->all_chan[i]);
  }
  free(overview);
  free(ap_filter);
  overview = NULL;
  ap_filter = NULL;
}

///////////////////////////////////////////////////////////
// CHANNEL scanning routines
///////////////////////////////////////////////////////////

/**
 * new_access_point()
 * ------------------
 * simply dynamically allocates space, then initially fills the
 * corresponding information fields.
 * returns the new structure.
 **/
struct access_point *new_access_point(struct p802_11b_info *info, float signal)
{
  struct access_point *temp;

  if (NULL == (temp = malloc(sizeof(struct access_point)))){
    perror("malloc");
    return NULL;
  }

  memset(temp, 0, sizeof(struct access_point));
  
  if (!strlen(info->ssid)){
    snprintf(info->ssid,8,"Unknown");
  }
  memcpy(&temp->bssid, info->bssid, 6);
  strncpy(temp->ssid, info->ssid, 32);
  temp->channel = info->channel;
  temp->signal_str = signal;

  gettimeofday(&temp->timestamp, NULL);
  temp->status = AP_STATUS_NEW;
  
  return (temp);
}

/**
 * filter_ap()
 * -----------
 * filter out corrupt information...  or at least try...
 **/
int filter_ap(struct p802_11b_info *info)
{
  int i;
  for (i = 0; i < ap_filter->num; i++){
    if ((0 == memcmp(&ap_filter->ap_list[i].bssid,info->bssid,6))&&
	(0 == memcmp(&ap_filter->ap_list[i].ssid, info->ssid, 32))&&
	(ap_filter->ap_list[i].channel == info->channel)){
      if (ap_filter->ap_list[i].packet_count > 5){
	return (1);
      }
      else{
	ap_filter->ap_list[i].packet_count++;
	return (0);
      }
    }
  }
  if (ap_filter->num < MAX_MAC){
    memcpy(&ap_filter->ap_list[ap_filter->num].bssid, info->bssid, 6);
    strncpy(ap_filter->ap_list[ap_filter->num].ssid, info->ssid, 32);
    ap_filter->ap_list[ap_filter->num].channel = info->channel;
    ap_filter->ap_list[ap_filter->num].packet_count = 0;
    ap_filter->num++;
  }
  return (0);
}

/**
 * clean_filter()
 * --------------
 * simple routine to clear the filter
 **/
void clean_filter()
{
  memset(ap_filter, 0, sizeof(potential_ap_t));
}

/**
 * update_ap_info()
 * ----------------------
 * the routine that filters out invalid bssid's looks through internal
 * list to see if there's already same access point detected, if so,
 * update the signal strength & packet_count, if not, then make a new
 * access point structure.
 **/
void update_ap_info(struct p802_11b_info *info, float signal)
{
  __u8 bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  __u8 null_addr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  //  int limit = 0;
  struct access_point *temp;
  struct access_point *last;
  
  /* we don't care about b-cast addresses */
  if (0 == memcmp(bcast, info->bssid, 6))		
    return;

  /* we don't care about null bssid addresses */
  if (0 == memcmp (null_addr, info->bssid, 6))
    return;
  
  /* we don't care about invalid channels */
  if ((info->channel < 1)||(info->channel > 14))
    return;

  if (overview->all_chan[info->channel] == NULL){
    /* first put into potential list, then add if occurs again */
    if (!filter_ap(info))
      return;
    overview->all_chan[info->channel] = new_access_point(info, signal);
    overview->num_det_aps++;
    overview->num_active_aps++;
  }
  else{
    temp = overview->all_chan[info->channel];
    while (temp != NULL){
      if (0 == memcmp(&temp->bssid, info->bssid, 6)){
	temp->mgmt_count++;
	temp->packet_count++;
	temp->signal_str = signal;

	if (!strncmp(temp->ssid," ",32)&&strncmp(info->ssid," ",32)){
	  strncpy(temp->ssid, info->ssid, 32);
	}
	
	gettimeofday(&temp->timestamp, NULL);
	if (temp->status == AP_STATUS_INACTIVE){
	  temp->status = AP_STATUS_RENEW;
	  overview->num_active_aps++;
	}
	return;
      }
      last = temp;
      temp = (struct access_point*)temp->next;
    }
    /* first put into potential list, then add if occurs again */
    if (!filter_ap(info))
      return;
    last->next = new_access_point(info, signal);
    overview->num_det_aps++;
    overview->num_active_aps++;
  }
}

/**
 * find_access_point()
 * -------------------
 * goes through current access point and pick out the access point
 * with the same bssid. (not optimal)
 **/
struct access_point *find_access_point(__u8 *bssid)
{
  int i;
  struct access_point *temp;
  
  for (i = 1; i < 15; i++){
    temp = overview->all_chan[i];
    while (temp != NULL){
      if (0 == memcmp(&temp->bssid, bssid, 6)){
	return (temp);
      }
      temp = (struct access_point*)temp->next;
    }
  }
  return (NULL);
}

/**
 * check_activity()
 * ----------------
 * looks through data packets (if available) to see if the associated
 * network is encrypted or not.
 **/
void check_activity(struct p802_11b_info *info)
{
  __u8 bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  __u8 null_addr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  struct access_point *temp;
  
  /* we don't care about b-cast addresses */
  if (0 == memcmp(bcast, info->bssid, 6))		
    return;

  /* we don't care about null bssid addresses */
  if (0 == memcmp (null_addr, info->bssid, 6))
    return;

  if ((temp = find_access_point(info->bssid)) != NULL){
    switch(info->type)
      {
      case FT_MGMT:
	temp->mgmt_count++;
	break;
      case FT_CTRL:
	temp->ctrl_count++;
	break;
      case FT_DATA:
	temp->data_count++;
	temp->traffic_type = info->datatype;
	temp->wep_status = info->wep;
	break;
      }
    if (info->wep){
      temp->encrypt_count++;
    }
    temp->packet_count++;
    gettimeofday(&temp->timestamp,NULL);
    if (temp->status == AP_STATUS_INACTIVE){
      temp->status = AP_STATUS_RENEW;
    }
  }
}

/**
 * update_channel()
 * ----------------
 * simply differentiate whether to update current ap list info, or to
 * update existing ap's wep status.
 **/
void update_channel(struct p802_11b_info *info, float signal)
{
  struct access_point *temp;
  
  if (info->channel)
    update_ap_info(info, signal);
  else{
    if (info->bssid != NULL){
      check_activity(info); // check encryption status
    }
    else if (info->type == FT_CTRL){
      if ((temp = find_access_point(info->da)) != NULL)
	temp->ctrl_count++;
    }
  }
}

/////////////////////////////////////////////////////////////////
//  Public interface routines
/////////////////////////////////////////////////////////////////

/**
 * process_channel_scan()
 * ----------------------
 * run through channel scan, acquiring information about available
 * access points to monitor
 **/
void process_channel_scan(struct packet_info *packet)
{
  struct p802_11b_info *info = NULL;
  float signal_str = 0;
  
  if (packet->error_status)
    return;

  if (packet->driver_proto == AIRONET_MOD){
    signal_str = packet->driver_pkt->signal;
  }

  if (packet->mac_proto == p802_11){
    info = parse_p802_11b_hdr((wlan_hdr_t *)packet->mac_pkt);
  }
  else if (packet->mac_proto == hfa384x){
    signal_str = ((prism2_hdr_t *)packet->mac_pkt)->frame_descriptor.signal;
    info = parse_hfa384x_hdr((prism2_hdr_t *)packet->mac_pkt);
  }
  else if (packet->mac_proto == wlanngp2){
    signal_str = ((wlan_ng_hdr_t *)packet->mac_pkt)->signal.data;
    info = parse_wlanngp2_hdr((wlan_ng_hdr_t *)packet->mac_pkt);
  }
  else{
    return;
  }

  if (!info->status){
    return;
  }
  update_channel(info, signal_str);
}

/**
 * get_channel_snapshot()
 * ----------------------
 * returns the results of current structure holding the channel scan
 * related data.
 **/
struct channel_overview *get_channel_snapshot()
{
  return (overview);
}

/**
 * update_all_ap_status()
 * ----------------------
 * perform update of current status of access points, making sure that
 * we don't keep around inactive, unresponsive access points.
 **/
void update_all_ap_status()
{
  int i;
  struct timeval now;
  struct access_point *curr_ap = NULL;
  struct access_point *prev_ap = NULL;

  gettimeofday(&now, NULL);
  
  for (i = 1; i < 15; i++){
    curr_ap = overview->all_chan[i];
    while (curr_ap != NULL){
      /** if no traffic for about 1 min, lets mark it INACTIVE **/
      if (get_time_diff(&now, &curr_ap->timestamp) > 60){
	if (curr_ap->status != AP_STATUS_INACTIVE){
	  curr_ap->status = AP_STATUS_MARK_INACTIVE;
	  overview->num_active_aps--;
	}
      }
      /** if no traffic for about 5 min, lets get rid of it **/
      if (get_time_diff(&now, &curr_ap->timestamp) > 300){
	if (curr_ap == overview->all_chan[i]){
	  overview->all_chan[i] = curr_ap->next;
	  free(curr_ap);
	  curr_ap = overview->all_chan[i];
	  overview->num_det_aps--;
	  continue;
	}
	else{
	  prev_ap->next = curr_ap->next;
	  free(curr_ap);
	  curr_ap = prev_ap;
	  overview->num_det_aps--;
	}
      }
      prev_ap = curr_ap;
      curr_ap = (struct access_point*)curr_ap->next;
    }
  }
}

/**
 * channel_range()
 * ---------------
 * a wrapper function for gui_channel_scan to interface with the lower
 * level card to get allowed channel range...
 **/
int channel_range(struct SETTINGS*myset)
{
  return pkt_card_channel_range(myset);
}

/**
 * select_channel()
 * ----------------
 * a wrapper function for gui_channel_scan to interface with the lower
 * level card to set channel...
 **/
int select_channel(struct SETTINGS*myset, int channel)
{
  return pkt_card_chan_set(myset, channel);
}
