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
 **  packet_abstraction.c
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
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <netinet/ip.h>  // for struct iphdr
#include <netinet/tcp.h> // for struct tcphdr

#include "definition.h"
#include "sniff_include.h"

/*===========================================================*/
/* Global Variables */

static unsigned char msgbuf[MAX_BUFFER_SIZE];  // holds the packet

static struct packet_info *packet = NULL; // structure holding packet information

/*=============================================================*/
/* Function Definitions */

////////////////////////////////////////////////////////////////
// INITIALIZATION ROUTINES
////////////////////////////////////////////////////////////////

/**
 * initialize_packet_abstraction()
 * -----------
 * a simple routine for dynamically allocating the initial data
 * structures such as potential structs and intrusion detection
 * structs.
 **/
void initialize_packet_abstraction()
{
  /* initialize the frame_info structure */

  if (NULL == (packet = malloc(sizeof(struct packet_info)))){
    perror("malloc: initialize_packet_abstraction()");
    exit(-1);
  }
  memset(packet, 0, sizeof(struct packet_info));
}

///////////////////////////////////////////////////////////////
// Main abstraction routines
///////////////////////////////////////////////////////////////

/**
 * get_packet()
 * ------------
 * a wrapper function for the pkt_card_* interface, returning the
 * packet information about packet size, mac, network, transport layer
 * info, as well as error status.
 * returns: struct packet_info *
 **/
struct packet_info *get_packet (struct SETTINGS *mySettings)
{
  struct sockaddr_ll ifinfo; // interface info
  int wlan_ng_hdr_len = sizeof(wlan_ng_hdr_t);
  int pream_size = sizeof(struct airids_frame_info);
  int wlan_hdr_len = sizeof(wlan_hdr_t);
  int prism2_hdr_len = sizeof(prism2_hdr_t);
  int recvlen = 0;
  int ip_len = 0;
  int tcp_len = 0;
  int offset = 0;

  int total_hlen = 0;
  
  char proto[2];
  
  memset(msgbuf, 0, MAX_BUFFER_SIZE);
  memset(packet, 0, sizeof(struct packet_info));
	 
  recvlen = pkt_card_sock_read(mySettings->sniff_socket, msgbuf, MAX_BUFFER_SIZE, &ifinfo);
  if (DEBUG) fprintf(stderr,"total packet size: %d\n",recvlen);

  if (recvlen < 1){
    return (NULL);
  }

  if(mySettings->signal_support){
    packet->driver_proto = AIRONET_MOD;
    packet->packet_size = recvlen - pream_size;
    /* cast into airids_frame_info  */
    packet->driver_pkt = (struct airids_frame_info *)msgbuf; 
    
    if(packet->driver_pkt->fcs_error){
      packet->error_status = FCS_ERR;
      return (packet);
    }
    offset = pream_size;
  }
  else{
    packet->packet_size = recvlen;
    offset = 0;
  }

  if(mySettings->card_type == AIRONET){  
    packet->mac_proto = p802_11;
    packet->mac_pkt = (void *) (msgbuf + offset);
    /** simple test to make sure there are more higher protos **/
    if (packet->packet_size < (wlan_hdr_len + 3)){
      return (packet);
    }
    proto[0] = msgbuf[offset+wlan_hdr_len];
    proto[1] = msgbuf[offset+wlan_hdr_len+1];
  }  
  else if(mySettings->card_type == PRISMII){
    packet->mac_proto = hfa384x;
    packet->mac_pkt = (void *) (msgbuf + offset);
    /** simple test to make sure there are more higher protos **/
    if (packet->packet_size < (prism2_hdr_len + 3)){
      return (packet);
    }
    /** don't include driver crap in size byte analysis later **/
    packet->packet_size -= (sizeof(hfa384x_descript_t)+(sizeof(__u8)*7)); 
    proto[0] = msgbuf[offset+prism2_hdr_len];
    proto[1] = msgbuf[offset+prism2_hdr_len+1];
  }
  else if((mySettings->card_type==HERMES)||(mySettings->card_type==HOSTAP)||(mySettings->card_type==WLANNG)){
    packet->mac_proto = wlanngp2;
    packet->mac_pkt = (void *) (msgbuf + offset);
    /** simple test to make sure there are more higher protos **/
    if (packet->packet_size < (wlan_ng_hdr_len + 3)){
      return (packet);
    }
    /** don't include driver crap in size byte analysis later **/
    packet->packet_size -= wlan_ng_hdr_len;
    proto[0] = msgbuf[offset+wlan_ng_hdr_len+wlan_hdr_len];
    proto[1] = msgbuf[offset+wlan_ng_hdr_len+wlan_hdr_len+1];
  }    
  else{
    /** shouldn't ever get here... **/
    fprintf(stderr,"card type unsupported!\n");
    exit(1);
  }
  /** this doesn't work...  **/
  //  ifinfo.sll_protocol = htons(ifinfo.sll_protocol);

  /**
   * lets see if its IP...  sockaddr_ll only for 802.3! :(
   * +2 at the end because of protocol identifier between 802.11
   * protocol and ip header...
   **/

  /** see if its IP packet (there should be a better method...)**/
  if ((proto[0] == 8) && (proto[1] == 0)){
    if (mySettings->card_type == AIRONET){
      packet->net_pkt = (void *) (msgbuf + offset + wlan_hdr_len + 2);
      total_hlen += offset + wlan_hdr_len + 2;
    }
    else if (mySettings->card_type == PRISMII){
      packet->net_pkt = (void *) (msgbuf + offset + prism2_hdr_len + 2);
      total_hlen += offset + prism2_hdr_len + 2;
    }
    else if ((mySettings->card_type == HERMES)||(mySettings->card_type == HOSTAP)||(mySettings->card_type == WLANNG)){
      packet->net_pkt = (void *) (msgbuf + offset + wlan_ng_hdr_len + wlan_hdr_len + 2);
      total_hlen += offset + wlan_ng_hdr_len + wlan_hdr_len + 2;
    }
    else{
      fprintf(stderr, "major internal error!");
      exit(1);
    }
       
    /** if its version 4, then we're okay **/
    if ( ((struct iphdr *)packet->net_pkt)->version == 4){
      packet->net_proto = IPv4;
      /** if iphdr is invalid, then lets just ignore the entire packet **/
      if (!verify_chksum((struct iphdr *)packet->net_pkt)){
	packet->error_status = IPCHKSUM_ERR;
	return (packet);    
      }

      /** grab the higer level protocols **/
      ip_len = ((struct iphdr *)packet->net_pkt)->ihl * 4;
      packet->trans_pkt = (void *) (packet->net_pkt + ip_len);
      total_hlen += ip_len;
      if ((total_hlen > MAX_BUFFER_SIZE)||(total_hlen > recvlen)){
	packet->error_status = IPHDRLEN_ERR;
	return (packet);
      }
      
      /** parse higher protocols here... **/
      if (((struct iphdr *)packet->net_pkt)->protocol == IPPROTO_TCP){
	packet->trans_proto = TCP;
	tcp_len = ((struct tcphdr *)packet->trans_pkt)->doff * 4;
	packet->data = (void *) (packet->trans_pkt + tcp_len);
	total_hlen += tcp_len;
	packet->data_size = recvlen - total_hlen;
      }
      else if (((struct iphdr *)packet->net_pkt)->protocol == IPPROTO_UDP){
	packet->trans_proto = UDP;	
      }
      else if (((struct iphdr *)packet->net_pkt)->protocol == IPPROTO_ICMP){
	packet->trans_proto = ICMP;
      }
      else{
	packet->trans_proto = OTHER;
      }
    }
    else if ( ((struct iphdr *)packet->net_pkt)->version == 6){
      packet->net_proto = IPv6;
    }
    else{
      packet->net_proto = OTHER;
    }
  }
  else{
    packet->net_proto = OTHER;
  }
  return(packet);
}
