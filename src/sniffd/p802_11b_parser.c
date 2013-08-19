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
 **  p802_11b_parser.c
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
#include <asm/types.h>

#include "definition.h"
#include "sniff_include.h"

struct p802_11b_info *info = NULL; // structure holding parsed p802_11b information

/*=============================================================*/
/* Function Definitions */

////////////////////////////////////////////////////////////////
// INITIALIZATION ROUTINES
////////////////////////////////////////////////////////////////

/**
 * initialize_p802_11b_parser()
 * -----------
 * a simple routine for dynamically allocating the initial data
 * structures for p802_11b parsing
 **/
void initialize_p802_11b_parser()
{
  /* initialize the frame_info structure */

  if (NULL == (info = malloc(sizeof(struct p802_11b_info)))){
    perror("malloc: initialize_p802_11b_parser()");
    exit(-1);
  }
  memset(info, 0, sizeof(struct p802_11b_info));  
}
///////////////////////////////////////////////////////////////////
//  MAIN PACKET HANDLER PUBLIC FUNCTIONS
///////////////////////////////////////////////////////////////////

/**
 * parse_ap_info()
 * ---------------
 * go through ap capability info and grab data out
 **/
void parse_ap_info(wlan_hdr_t *hdr, int offset)
{
  __u8 temp_num;
  __u8 *packet;
  int info_ptr, tag_number, tag_length, loop_count;

  tag_number = 0;
  tag_length = 0;
  loop_count = 0;
  info_ptr = offset;

  packet = (__u8*)hdr;
  
  if (DEBUG) printf("parse_ap_info(): processing access point data\n");
  /* parse through the tags */
  while(tag_number != 3){

    /* !@# - in the case that this loop goes out of control... */
    loop_count++;
    if (loop_count > 6){
      return;
    }
    
    /** read tag number & get the tag length **/
    tag_number = packet[info_ptr];
    info_ptr++;                    
    tag_length = packet[info_ptr]; 
    info_ptr++;                  
    
    /* !@# - need to fix this!  Damn you corrupt packets!!!!! */
    if(tag_length > 32){
      return;
    }
    if (DEBUG) printf("tag_number = %d, tag_length = %d\n",tag_number,tag_length);
    if(tag_number == 0){
      temp_num = (tag_length & 0xff)+1;
      snprintf(info->ssid,temp_num,"%s",&packet[info_ptr]);
    }
    if(tag_number == 3){
	  info->channel = packet[info_ptr];		      
    }
    // move info_ptr to next tag number
    info_ptr += tag_length;
  }
  if (DEBUG) printf("parse_ap_info(): channel=%d\n",info->channel);
}

/**
 * parse_mgmt()
 * ------------------
 * main public interface function to be called by main functions to
 * manage mangement packet
 **/
void parse_mgmt(wlan_hdr_t *packet)
{
  if (DEBUG) printf("parse_mgmt(): processing mgmt frame\n");
		    
  info->da=(__u8 *)&packet->mac1;
  info->sa=(__u8 *)&packet->mac2;
  info->bssid=(__u8 *)&packet->mac3;
  
  if (DEBUG) printf("da: %s   sa: %s   bssid: %s\n",
		    hexdump((__u8*)info->da, 6),
		    hexdump((__u8*)info->sa, 6),
		    hexdump((__u8*)info->bssid, 6));

  info->status = 1;
  if (DEBUG) printf("parse_mgmt(): exiting...\n");
  return;
}

/**
 * parse_ctrl()
 * ---------------
 * main public interface function to be called by main functions to
 * manage control packet
 **/
void parse_ctrl(wlan_hdr_t *packet)
{
  if (DEBUG) printf("parse_ctrl(): processing control frame\n");

  info->da=(__u8 *)&packet->mac1;
  info->status = 1;
  if (DEBUG) printf("handlecontrol: exiting...\n");
  return;
}

/**
 * parse_data()
 * ------------
 * main public interface function to be called by main functions to
 * manage data packet
 **/
void parse_data(wlan_hdr_t *hdr)
{
  frame_control_t *fc;

  __u8 tofrom;
  
  if (DEBUG) printf("parse_data(): processing data packet\n");
  fc = (frame_control_t *) &hdr->frame_control;
  tofrom = (fc->toDS << 1) | fc->fromDS;
  switch (tofrom) 
    {
    case 0:			       // ad hoc
      info->datatype = p802_11b_ADHOC;
      info->da=(__u8 *)&hdr->mac1;
      info->sa=(__u8 *)&hdr->mac2;
      info->bssid=(__u8 *)&hdr->mac3;
      break;
    case 1:			       // AP to STA
      info->datatype = p802_11b_AP2STA;
      info->da=(__u8 *)&hdr->mac1;
      info->sa=(__u8 *)&hdr->mac3;
      info->bssid=(__u8 *)&hdr->mac2;
      break;
    case 2:			       // STA to AP
      info->datatype = p802_11b_STA2AP;
      info->da=(__u8 *)&hdr->mac3;
      info->sa=(__u8 *)&hdr->mac2;
      info->bssid=(__u8 *)&hdr->mac1;
      break;
    case 3:	                       // AP to AP
      info->datatype = p802_11b_AP2AP;
#if 0
      printf ("essid ");
      printf ("ra: %s ",hexdump((__u8 *)&p80211_hdr->mac1,6));
      printf ("ta: %s ",hexdump((__u8 *)&p80211_hdr->mac2,6));
      printf ("da: %s ",hexdump((__u8 *)&p80211_hdr->mac3,6));
      printf ("sa: %s\n",hexdump((__u8 *)&p80211_hdr->mac4,6));
#endif
      break;
    }
  info->status = 1;
  if (DEBUG) printf("parse_data(): exiting...\n");
  return;
}

/**
 * handleother()
 * ------------
 * main public interface function to be called by main functions to
 * manage unknown packet
 **/
void parse_other(wlan_hdr_t *packet)
{
  info->status = 0;
}


struct p802_11b_info *parse_p802_11b_hdr(wlan_hdr_t *hdr)
{
  frame_control_t *fc;
  
  memset(info, 0, sizeof(struct p802_11b_info));
  fc = (frame_control_t *)&hdr->frame_control;

  if (DEBUG) printf("parse_p802_11b_hdr():entering\n");
  info->type    = fc->type;
  info->subtype = fc->subtype;
  info->wep     = fc->wep;
  
  switch(fc->type)
    {
    case FT_MGMT:
      switch(fc->subtype)
	{
	case BEACON:
	case PROBE_RES:
	  parse_ap_info(hdr, sizeof(wlan_hdr_t) + 6);
	  break;
	}
      parse_mgmt(hdr);
      break;
    case FT_CTRL:
      parse_ctrl(hdr);
      break;
    case FT_DATA:
      parse_data(hdr);
      break;
    default:
      parse_other(hdr);
      break;
    }
  return (info);
}

struct p802_11b_info *parse_hfa384x_hdr(prism2_hdr_t *hdr)
{
  frame_control_t *fc;
  int descript_size = sizeof(hfa384x_descript_t);
  void *wlan_hdr;

  wlan_hdr = (void *)((char *)hdr + descript_size);

  if (DEBUG) printf("parse_hfa384x_hdr(): entering...\n");
  
  memset(info, 0, sizeof(struct p802_11b_info));
  fc = (frame_control_t *)&hdr->frame_control;

  info->type    = fc->type;
  info->subtype = fc->subtype;
  info->wep     = fc->wep;
  
  switch(fc->type)
    {
    case FT_MGMT:
      switch(fc->subtype)
	{
	case BEACON:
	case PROBE_RES:
	  parse_ap_info(wlan_hdr, sizeof(prism2_hdr_t) - descript_size + 6);
	  break;
	}
      parse_mgmt((wlan_hdr_t *)wlan_hdr);
      break;
    case FT_CTRL:
      parse_ctrl((wlan_hdr_t *)wlan_hdr);
      break;
    case FT_DATA:
      parse_data((wlan_hdr_t *)wlan_hdr);
      break;
    default:
      parse_other((wlan_hdr_t *)wlan_hdr);
      break;
    }
  return (info);
}

struct p802_11b_info *parse_wlanngp2_hdr(wlan_ng_hdr_t *hdr)
{
  frame_control_t *fc;
  wlan_hdr_t *whdr;
  int descript_size = sizeof(wlan_ng_hdr_t);
  void *wlan_hdr;

  wlan_hdr = (void *)((char *)hdr + descript_size);
  whdr = (wlan_hdr_t *)wlan_hdr;

  if (DEBUG) printf("parse_wlanngp2_hdr(): entering...\n");
  
  memset(info, 0, sizeof(struct p802_11b_info));
  fc = (frame_control_t *)&whdr->frame_control;

  info->type    = fc->type;
  info->subtype = fc->subtype;
  info->wep     = fc->wep;
  
  switch(fc->type)
    {
    case FT_MGMT:
      switch(fc->subtype)
	{
	case BEACON:
	case PROBE_RES:
	  parse_ap_info(wlan_hdr, sizeof(wlan_hdr_t) + 6);
	  break;
	}
      parse_mgmt((wlan_hdr_t *)wlan_hdr);
      break;
    case FT_CTRL:
      parse_ctrl((wlan_hdr_t *)wlan_hdr);
      break;
    case FT_DATA:
      parse_data((wlan_hdr_t *)wlan_hdr);
      break;
    default:
      parse_other((wlan_hdr_t *)wlan_hdr);
      break;
    }
  return (info);
}
