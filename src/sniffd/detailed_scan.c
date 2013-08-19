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
 **  detailed_scan.c
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
#include <linux/if_ether.h> // for ETH_P_IP
#include <netinet/in.h>
#include <netinet/ip.h>  // for struct iphdr
#include <netinet/tcp.h> // for struct tcphdr

#include "definition.h"
#include "sniff_include.h"

/*===========================================================*/
/* Global Variables */

/** structure heirarchy **/
static detailed_overview_t * overview;

static potential_node_t *p_nodes;
static potential_ap_t *p_aps;

int calc_bandwidth = 0;

/*=============================================================*/
/* Function Prototypes */

/*=============================================================*/
/* Function Definitions */

////////////////////////////////////////////////////////////////
// INITIALIZATION ROUTINES
////////////////////////////////////////////////////////////////

/**
 * initialize_detailed_scan()
 * -----------
 * a simple routine for dynamically allocating the initial data
 * structures such as potential structs and intrusion detection
 * structs.
 **/
void initialize_detailed_scan()
{
  /* initialize the MAIN AIRTRAF STRUCTURE */
  if (NULL == (overview = malloc(sizeof(detailed_overview_t)))){
    perror("malloc");
    exit(-1);
  }
  memset(overview,0,sizeof(detailed_overview_t));
}

/**
 * reset_tcp_conns()
 * --------------------
 * a recursive function to free up all the memory allocated to storing
 * tcpconn entries...
 **/
void reset_tcp_conns(tcpconn_t *conn)
{
  tcpconn_t * temp = conn;

  if (temp != NULL){
    reset_tcp_conns((tcpconn_t *)temp->next);
    free(temp);
    return;
  }
  else{
    return;
  }
}

/**
 * reset_tcp_entries()
 * --------------------
 * a recursive function to free up all the memory allocated to storing
 * tcpinfo entries...
 **/
void reset_tcp_entries(tcptable_t *tcp_entry)
{
  tcptable_t * temp = tcp_entry;

  if (temp != NULL){
    reset_tcp_entries((tcptable_t *)temp->next);
    reset_tcp_conns((tcpconn_t *)temp->tcpconn_head);
    free(temp);
    return;
  }
  else{
    return;
  }
}

/**
 * reset_addr_list()
 * ---------------
 * a recursive function to free up all the memory allocated to storing
 * addr_list structures...  
 **/
void reset_addr_list(bss_node_t *node)
{
  bss_node_t * temp = node;
  
  if (temp != NULL){
    reset_addr_list((bss_node_t *)temp->next);
    reset_tcp_entries((tcptable_t *)temp->tcpinfo_head);
    free(temp);
    return;
  }
  else{
    return;
  }
}

/**
 * reset_bss_list()
 * ---------------
 * a recursive function to free up all the memory allocated to storing
 * bss_list structures...  
 **/
void reset_bss_list(bss_t *info)
{
  bss_t * temp = info;
  
  if (temp != NULL){
    reset_bss_list((bss_t *)temp->next);
    reset_addr_list((bss_node_t *)temp->addr_list_head);
    free(temp);
    return;
  }
  else{
    return;
  }
}

/**
 * free_detailed_snapshot()
 * -------------------------
 * free up detailed_overview structure's memory space.
 **/
void free_detailed_scan()
{
  reset_bss_list(overview->bss_list_top);
  free(overview);
  overview = NULL;
}

/**
 * init_potential_structs()
 * ------------------------
 * function that creates the potential structs for storing node & ap
 * data.  It dynamically creates the structs, and sets the pointer to
 * the global data pointer.
 **/
void init_potential_structs()
{
  /* initialize potential AP structure */
  if (NULL == (p_aps = malloc(sizeof(potential_ap_t)))){
    perror("malloc");
    exit(-1);
  }
  memset(p_aps, 0, sizeof(potential_ap_t));

  /* initialize potential node structure */
  if (NULL == (p_nodes = malloc(sizeof(potential_node_t)))){
    perror("malloc");
    exit(-1);
  }
  memset(p_nodes, 0, sizeof(potential_node_t));
}

/**
 * clear_potential_structs()
 * --------------------------
 * just 0 out the memory space...
 **/
void clear_potential_structs()
{
  memset(p_aps, 0, sizeof(potential_ap_t));
  memset(p_nodes, 0, sizeof(potential_node_t));
}

/**
 * free_potential_structs()
 * ------------------------
 * free up memory space used by the potential structures.
 **/
void free_potential_structs()
{
  free(p_nodes);
  free(p_aps);
}

void * get_p_nodes()
{
  return (void *)p_nodes;
}

void * get_p_aps()
{
  return (void *)p_aps;
}

/**
 * reset_potential_structs()
 * -------------------------
 * Since potential node info, as well as potential ap info never
 * really gets reset, we'll reset the structure holding this info from
 * time to time to keep the elements from growing too big and
 * segfaulting after many hours...
 **/
void reset_potential_structs()
{
  free_potential_structs();
  init_potential_structs();
}

///////////////////////////////////////////////////////////////////
//  POTENTIAL DATA FUNCTIONS
///////////////////////////////////////////////////////////////////

/**
 * track_bad_data()
 * ----------------
 * since there's bad data caught in the filter of potential
 * structures, periodically call this to grab the bad stuff within the
 * potential structs, so that we get better measure of corruptness in
 * the air.
 * should be called prior to resetting potential structures.
 **/
void track_bad_data()
{
  int c = 0;
  while(c < p_nodes->num){
    if(!p_nodes->nodes[c].status){
      overview->filtered_data++;
      overview->filtered_data_byte += p_nodes->nodes[c].bytes_seen;
    }
    c++;
  }
}

/* find whether the given addr is already in the potential node list */
int pot_find_node(__u8 *addr)
{
  int c = 0;
  while (c < p_nodes->num){
    if (0 == memcmp(&p_nodes->nodes[c].mac_addr,addr,6)){
      if (DEBUG) printf("pot_find_node: pot loc %d\n",c);
      return (c);
    }
    c++;
  }
  return (-1);
}

/* add the given addr into the potential node list */
void add_potential_node(__u8 *addr, __u32 pkt_size)
{
  struct timeval tv;
  __u32 entry_usecs;
  int loc;

  if(p_nodes->num >= MAX_MAC){
    return;
  }
  
  gettimeofday(&tv,NULL);
  entry_usecs = (tv.tv_sec * 1000000) + tv.tv_usec;
  
  if ((loc = pot_find_node(addr)) == -1){
    if (DEBUG) printf("add_potential_node: adding new node into pot. list\n");
    memcpy(&p_nodes->nodes[p_nodes->num].mac_addr,addr,6);
    p_nodes->nodes[p_nodes->num].bytes_seen = pkt_size;
    p_nodes->nodes[p_nodes->num].time_of_entry = entry_usecs;
    p_nodes->nodes[p_nodes->num].status = 0;
    p_nodes->num++;
  }
  else{
    if (!p_nodes->nodes[loc].status){
      p_nodes->nodes[loc].bytes_seen += pkt_size; 
    }
  }
  return;
}

/**
 * pot_find_ap()
 * --------------
 * coincidentally, this is the same filtering routine as in channel
 * scan...  code reusability?  ack, will get to it later...
 **/
int pot_find_ap(struct p802_11b_info *info)
{
  int i;
  for (i = 0; i < p_aps->num; i++){
    if ((0 == memcmp(&p_aps->ap_list[i].bssid,info->bssid,6))&&
	(0 == memcmp(&p_aps->ap_list[i].ssid, info->ssid, 32))&&
	(p_aps->ap_list[i].channel == info->channel)){
      if (p_aps->ap_list[i].packet_count > 5){
	return (1);
      }
      else{
	p_aps->ap_list[i].packet_count++;
	return (0);
      }
    }
  }
  /** it's not on the potential list... lets add it **/
  if (p_aps->num < MAX_MAC){
    memcpy(&p_aps->ap_list[p_aps->num].bssid, info->bssid, 6);
    strncpy(p_aps->ap_list[p_aps->num].ssid, info->ssid, 32);
    p_aps->ap_list[p_aps->num].channel = info->channel;
    p_aps->ap_list[p_aps->num].packet_count = 0;
    p_aps->num++;
  }
  return (0);  
}

/* add the given bssid into the potential ap list */
/* void add_potential_ap(__u8 *bssid) */
/* { */
/*   if (pot_find_ap(bssid) == -1){ */
/*     if (DEBUG) printf("add_potential_node: adding new node into pot. list\n"); */
/*     memcpy(&p_aps->mac_addr_list[(p_aps->num) * 6],bssid,6); */
/*     p_aps->num++; */
/*   } */
/*   return; */
/* } */


///////////////////////////////////////////////////////////////////
//  BSS DATA STRUCTURE FUNCTIONS
///////////////////////////////////////////////////////////////////

/**
 * clean_up_bss_nodes()
 * --------------------
 * in the case that there are some packets that make it through the 4
 * levels of packet filtering, FCS, IP Chksum, Timed Filtering, AND IP
 * match filtering, let us clean up those nodes that have only seen
 * less than 3 packets total in a period of say, 10 secs.
 **/
void clean_up_bss_nodes()
{
  bss_t * temp = overview->bss_list_top;
  bss_node_t *temp_node = temp->addr_list_head;

  while (temp != NULL){
    while (temp_node != NULL){
      if(temp_node-> tot_packet < 3){
	temp_node->status = 0;
      }
      else{
	temp_node->status = 1;
      }
      temp_node = temp_node->next;
    }
    temp = (bss_t*)temp->next;
  }
}

/**
 * bss_find_node()
 * ---------------
 * search whether the given node with the address exists in the
 * current structure holding node->ap associations
 **/
bss_node_t * bss_find_node (bss_t *curr, __u8 *addr)
{
  bss_node_t * temp = curr->addr_list_head;

  while (temp != NULL){
    if (0 == memcmp(&temp->mac_addr, addr, 6)){
      if (DEBUG) fprintf(stderr, "bss_find_node: found one!\n");
      return (temp);      
    }
    temp = temp->next;
  }
  if (DEBUG) fprintf(stderr, "bss_find_node: doesn't exist!\n");
  return (NULL);
}

/**
 * bss_verify_ip()
 * ---------------
 * we have high confidence that the IP address we captured is correct,
 * therefore, we want to go through the entire addr_list to see if
 * there's already the ip address in there although the mac address
 * we're looking at is not in the list.
 * @returns TRUE if no ip already exists,
 * @returns FALSE otherwise
 **/
int bss_verify_ip(bss_t *curr, struct iphdr* ip_pkt)
{
  bss_node_t * temp = curr->addr_list_head;

  if (ip_pkt == NULL) return (0);
  
  while (temp != NULL){
    if (temp->ip_addr.s_addr != 0){
      if (0 == memcmp(&temp->ip_addr.s_addr, &ip_pkt->saddr, 4))
	return (0);
    }
    temp = temp->next;
  }
  /** if we get here, then there's no ip in the list **/
  return (1);
}

/**
 * bss_get_node()
 * -----------------
 * scroll through the list & returns the node with the requested
 * position
 * parem: pos >= 0
 **/
bss_node_t * bss_get_node(bss_t *curr, int pos)
{
  int c = 0;
  bss_node_t * temp;
  
  if (curr == NULL) return (NULL);
  if (curr->num == 0) return (NULL);
  if (pos >= curr->num) return (NULL);
  
  temp = curr->addr_list_head;
  while ((temp != NULL) && (c < pos)){
    temp = temp->next;
    c++;
  }
  if (c != pos)
    return (NULL);
  else
    return (temp);
}

/**
 * bss_add_node()
 * --------------
 * attempt to add the given mac address into the current structure
 * holding node information.  First check if the address is indeed a
 * valid one to be associated into the structure.
 **/

void bss_add_node (bss_t *curr, __u8 *addr, __u8 datatype,
		   struct packet_info *packet)
{
  __u8 bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

  bss_node_t * temp = NULL;
  int entry_num;
  struct timeval tv;
  __u32 usecs;
  
  if (DEBUG) fprintf(stderr, "bss_add_node: adding node\n");

  /** we don't care about b-cast addresses **/
  if (0 == memcmp(bcast, addr, 6)){
    return;
  }

  /** these are special cases that should by default be added **/
  if (packet == NULL){
      if ((bss_find_node(curr,addr) == NULL) && (curr->num < MAX_MAC)){
	if (NULL == (temp = malloc(sizeof(bss_node_t)))) return;
	bzero(temp, sizeof(bss_node_t));
	memcpy(temp->mac_addr, &curr->bssid, 6);
	temp->status = 1;
	temp->next = NULL;
	if (curr->addr_list_head == NULL){
	  curr->addr_list_head = temp;
	  curr->addr_list_tail = temp;
	}
	else{
	  curr->addr_list_tail->next = temp;
	  curr->addr_list_tail = temp;
	}
	if (DEBUG) fprintf(stderr, "bss_add_node: special added\n");
	curr->num++;
	overview->tot_num_nodes++;
      }
      return;
  }

  /**
   * we only want addresses in the wireless segment!
   * meaning, only those on the potential list (acknowledgement
   * receivers, or those that pass the timed filter & ip match)
   */
  if ((bss_find_node(curr,addr) == NULL)){
    if ((entry_num = pot_find_node(addr)) != -1){
      gettimeofday(&tv,NULL);
      usecs = tv.tv_sec * 1000000 + tv.tv_usec;
      /**
       * if time diff of last entry & this packet is > 50000 usecs we
       * simply reset the time to be the current one, hope for future...
       */
      if((usecs - p_nodes->nodes[entry_num].time_of_entry) > 50000){
	p_nodes->nodes[entry_num].time_of_entry = usecs;
	return;
      }
      if (packet->net_proto != IPv4) return;
      if(bss_verify_ip(curr, (struct iphdr *)packet->net_pkt)){
	if (NULL == (temp = malloc(sizeof(bss_node_t)))) return;
	bzero(temp, sizeof(bss_node_t));
	memcpy(temp->mac_addr, addr, 6);
	temp->status = 1;
	temp->next = NULL;
	if (curr->addr_list_head == NULL){
	  curr->addr_list_head = temp;
	  curr->addr_list_tail = temp;
	}
	else{
	  curr->addr_list_tail->next = temp;
	  curr->addr_list_tail = temp;
	}
	p_nodes->nodes[entry_num].status = 1; // don't track bytes anymore.
	curr->num++;
	overview->tot_num_nodes++;
	return;
      }
      else{
	overview->bad_mac++;
	overview->bad_mac_byte += packet->packet_size;
	return;
      }
      if (DEBUG) printf("bss_add_node: Node ADDED!\n");
    }
    else{
      if (datatype == p802_11b_STA2AP)
	add_potential_node(addr, packet->packet_size);
    }
  }
  else{
    if ((entry_num = pot_find_node(addr)) != -1){
      p_nodes->nodes[entry_num].status = 1;
    }
  }
  
  if (DEBUG) printf("bss_add_node: exiting...\n");
  return;
}

/**
 * new_bss()
 * ---------
 * attempt to add a new bss (new base station) into memory,
 * dynamically creating a new structure set for holding all the
 * necessary data associated with the new station.
 * First check to see if the mac address of discoverd base station is
 * valid.
 **/
bss_t *new_bss(struct p802_11b_info *info)
{
  bss_t *temp;

  if (DEBUG) printf("new_bss: adding new bss into database\n");

  /* we first put into potential list, if it is valid, then it should
   * pop up again... 
   */
  if (!pot_find_ap(info)){
    return NULL;
  }
  else{
    if (NULL == (temp = malloc(sizeof(bss_t)))){
      perror("malloc: new_bss()");
      return NULL;
    }
    if (DEBUG) printf("new_bss: malloc okay\n");

    memset(temp, 0, sizeof(bss_t));
  
    bzero(&temp->ssid,32);
    if (strlen(info->ssid))
      strncpy(temp->ssid,info->ssid,32);
    memcpy(&temp->bssid,info->bssid,6);
    temp->channel = info->channel;
    bss_add_node(temp, info->sa, 0, NULL);
    
    if (DEBUG) printf("new_bss: exiting...\n");
    return(temp);
  }
  return NULL;
}



///////////////////////////////////////////////////////////////////
//  DATA MANIPULATION FUNTIONS: time/bandwidth
///////////////////////////////////////////////////////////////////

/**
 * update_bandwidth()
 * ------------------
 * A subroutine of update_all_bandwidth() that basically does the
 * bandwidth calculation given the bandwidth_t struct holding
 * bandwidth data.
 **/
void update_bandwidth(bandwidth_t *bw, int type, struct timeval *t_now)
{
  float t_diff;
  __u32 byte_diff;

  t_diff = get_time_diff(t_now,&bw->old_time);
  
  bw->num++;
  
  /** get current bandwidth **/
  byte_diff = bw->tot_byte - bw->old_byte_tot;
  bw->curr = ((float)(byte_diff*8)/(float)t_diff)/type;
  bw->old_time = *t_now;
  bw->old_byte_tot = bw->tot_byte;
    
  /** get high bandwidth **/
  if (bw->curr > bw->high){
    bw->high = bw->curr;
  }
  
  /** get low bandwidth (but not 0.00)**/
  /** since its initially 0, if so, then change! **/
  if (bw->low == 0){
    bw->low = bw->curr;
  }
  if ((bw->curr > 0) && (bw->curr < bw->low)){
    bw->low = bw->curr;
  }
  
  /** get avg bandwidth **/
  bw->avg = ((bw->avg * (bw->num - 1)) + bw->curr) / bw->num;
}

/**
 * update_all_bandwidth()
 * ------------------
 * A function called periodically to update the bandwidth of the
 * entire bss_list data structure, going through the entire data
 * bandwidth for mgmt, ctrl, data, and associated nodes
 **/
void update_all_bandwidth()
{
  struct timeval t_now;
  bss_t	*temp;
  bss_node_t *temp_node;
  tcptable_t * tcp_entry;

  gettimeofday(&t_now,NULL);

  for (temp = overview->bss_list_top; temp; temp=(bss_t*)temp->next){
    update_bandwidth(&temp->bndwth,1000000,&t_now);
    update_bandwidth(&temp->mgmt_data.bndwth,1000,&t_now);
    update_bandwidth(&temp->ctrl_data.bndwth,1000,&t_now);
    update_bandwidth(&temp->normal_data.bndwth,1000000,&t_now);
    update_bandwidth(&temp->normal_data.extband,1000000,&t_now);
    /** do protocol bandwidth update **/
    update_bandwidth(&temp->network_data.ip.band, 1000,&t_now);
    update_bandwidth(&temp->network_data.ipv6.band, 1000,&t_now);
    update_bandwidth(&temp->network_data.other.band, 1000,&t_now);
    update_bandwidth(&temp->transport_data.tcp.band, 1000,&t_now);
    update_bandwidth(&temp->transport_data.udp.band, 1000,&t_now);
    update_bandwidth(&temp->transport_data.icmp.band, 1000,&t_now);
    update_bandwidth(&temp->transport_data.other.band, 1000,&t_now);
    /** do background traffic bandwidth update **/
    update_bandwidth(&temp->network_data.ip.extband, 1000,&t_now);
    update_bandwidth(&temp->network_data.ipv6.extband, 1000,&t_now);
    update_bandwidth(&temp->network_data.other.extband, 1000,&t_now);
    update_bandwidth(&temp->transport_data.tcp.extband, 1000,&t_now);
    update_bandwidth(&temp->transport_data.udp.extband, 1000,&t_now);
    update_bandwidth(&temp->transport_data.icmp.extband, 1000,&t_now);
    update_bandwidth(&temp->transport_data.other.extband, 1000,&t_now);    

    for (temp_node = temp->addr_list_head; temp_node; temp_node = temp_node->next){
      update_bandwidth(&temp_node->bndwth, 1000000, &t_now);
      /** also do the protocol bandwidth update... **/
      for (tcp_entry = temp_node->tcpinfo_head; tcp_entry; tcp_entry = tcp_entry->next){
	update_bandwidth(&tcp_entry->incoming_rate, 1000, &t_now);
	update_bandwidth(&tcp_entry->outgoing_rate, 1000, &t_now);
	update_bandwidth(&tcp_entry->total_rate, 1000, &t_now);
	tcp_entry->avg_rtt_latency = get_curr_rtt_time(tcp_entry); // we'll sneak this one in here...
      }
    }

    /** keep track of all lost data... **/
    overview->corrupt_tot = (overview->bad_mac + overview->bad_ip_chksum
			     + overview->fcs_error + overview->filtered_data);
    overview->corrupt_tot_byte = (overview->bad_mac_byte
				  + overview->bad_ip_chksum_byte
				  + overview->fcs_error_byte
				  + overview->filtered_data_byte);

    /* do some other stuff here for now... */
    temp->link_utilization = temp->bndwth.curr/11*100;
    temp->background_noise = (float)temp->normal_data.extband.curr/temp->bndwth.curr*100;
    temp->packet_loss = (float)overview->corrupt_tot_byte/temp->overall_byte*100;
  }
}

///////////////////////////////////////////////////////////////////
//  DATA organizing, adding/filtering routines
///////////////////////////////////////////////////////////////////

/**
 * update_node_stats()
 * ---------------
 * Function that gets called every time a new packet arrives to update
 * the data structure holding all wireless traffic related
 * information.
 **/
void update_node_stats(struct p802_11b_info *info, struct packet_info *packet)
{
  int special_pass = 0;
  bss_t	*temp;

  if ((info->type == FT_MGMT) &&
      (info->subtype == PROBE_RES))
    special_pass = 1;
  
  /** special case if its CTRL ACK Frame **/
  if (info->type == FT_CTRL){
    if (info->subtype == ACK){
      if(DEBUG) printf("update_node_stats: adding potential node\n");
      add_potential_node(info->da, packet->packet_size);
    }
    temp = overview->bss_list_top;
    if (temp != NULL)
      analyze_packet(temp, info, packet, ENABLED);
    return;
  }

  if (info->bssid == NULL)
    return;
  
  if (NULL == overview->bss_list_top){
    return;
  }
  else { // go through current bss_list
    for (temp = overview->bss_list_top; temp; temp=(bss_t *)temp->next ){
      // sorting by bss mac addresses	    
      if (DEBUG) fprintf(stderr,"update_node_stats: sorting by bss mac\n");
      if (0 == memcmp (&temp->bssid, info->bssid, 6)){
	if (DEBUG) fprintf(stderr,"update_node_stats: found relevant traffic\n");
	if (packet->net_proto == IPv4){
	  if (info->datatype == p802_11b_STA2AP){
	    bss_add_node(temp, info->sa, info->datatype, packet);
	  }
	  else{
	    bss_add_node(temp, info->sa, info->datatype, packet);
	    bss_add_node(temp, info->da, info->datatype, packet);	    
	  }
	}
	else if (special_pass)	  
	  bss_add_node(temp, info->da, 0, packet);
	if (DEBUG) fprintf(stderr, "analyzing traffic... ");
	analyze_packet(temp, info, packet, ENABLED);
	if (DEBUG) fprintf(stderr, "done\n");
	break;
      }
    }
  }
  if (DEBUG) fprintf(stderr,"update_node_stats: exiting...");
}

/**
 * update_filtered_ap()
 * --------------------
 * called when after channel scan, a specific ap to listen for
 * activity is specified.  Only 1 AP is listened on at a time!
 **/
void update_filtered_ap(struct access_point *ap)
{
  bss_t * temp;
  
  if (overview->bss_list_top == NULL){
    if (NULL == (temp = malloc(sizeof(bss_t))))
      {
	perror("malloc: update_filtered_ap()");
	return;
      }
    if (DEBUG) printf("update_filtered_ap(): malloc okay\n");

    memset(temp, 0, sizeof(bss_t));
  
    bzero(&temp->ssid,32);
    if (strlen(ap->ssid))
      strncpy(temp->ssid,ap->ssid,32);
    memcpy(&temp->bssid,ap->bssid,6);
    temp->channel = ap->channel;
    temp->wep_status = ap->wep_status;
    overview->bss_list_top = temp;
    overview->tot_num_ap++;
    bss_add_node(temp, ap->bssid, 0, NULL);
  }
}

/**
 * update_unfiltered_ap()
 * ---------------
 * Do dynamic discovery of new access points...  (daemonized
 * monitoring mode) possible to monitor multiple access points.
 * Then, it checks the current list in memory to see if this Access
 * Point is new, and if so, adds it into the bss_list.
 */
void update_unfiltered_ap(struct p802_11b_info *info)
{
  __u8 bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  __u8 null_addr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  bss_t	*temp;
  bss_t	*last; 

  if ((!info->channel) || (info->bssid == NULL))
    return;

   /* we don't care about b-cast addresses */
  if (0 == memcmp(bcast, info->bssid, 6))		
    return;

  /* we don't care about null bssid addresses */
  if (0 == memcmp (null_addr, info->bssid, 6))
    return;
  
  /* we don't care about invalid channels */
  if ((info->channel < 1)||(info->channel > 14))
    return;
  
  /**
   * check if bss_list exists, if so, see if this information is new,
   * and if so, add to the bss_list.
   */
  if (overview->bss_list_top == NULL){
    if (DEBUG) printf("update_unfiltered_ap(): no list adding new\n");
    overview->bss_list_top = new_bss(info);
    if (overview->bss_list_top != NULL)
      overview->tot_num_ap++;
  }
  else{
    for (temp = overview->bss_list_top; temp; temp= (bss_t*)temp->next ){
      if (0 == memcmp (&temp->bssid, info->bssid, 6)){
	return;
      }	  
      last = temp;
    }
    // if non-of the above, we have a new bss discovered
    last->next = new_bss(info);
    if (last->next != NULL)
      overview->tot_num_ap++;
  }
}

/**
 * update_error_stats()
 * --------------------
 * looks at packet abstraction's error stats, and update the
 * corresponding values...
 **/
void update_error_stats(struct packet_info *packet)
{
  if (packet->error_status == FCS_ERR){
    overview->fcs_error++;
    overview->fcs_error_byte += packet->packet_size;
  }
  if (packet->error_status == IPCHKSUM_ERR){
    overview->bad_ip_chksum++;
    overview->bad_ip_chksum_byte += packet->packet_size;
  }
  if (packet->error_status == IPHDRLEN_ERR){
    overview->bad_ip_chksum++;
    overview->bad_ip_chksum_byte += packet->packet_size;
  }
}

/////////////////////////////////////////////////////////////////
//  Public interface routines
/////////////////////////////////////////////////////////////////
     
/**
 * process_detailed_scan()
 * -----------------------
 * run through detailed scan, applying filtering if provided.
 **/
void process_detailed_scan(struct packet_info *packet, struct access_point *filter)
{
  struct p802_11b_info *info = NULL;
  
  if (packet->error_status){
    update_error_stats(packet);
    return;
  }

  if (packet->mac_proto == p802_11){
    info = parse_p802_11b_hdr((wlan_hdr_t *)packet->mac_pkt);
  }
  else if (packet->mac_proto == hfa384x){
    info = parse_hfa384x_hdr((prism2_hdr_t *)packet->mac_pkt);
  }
  else if (packet->mac_proto == wlanngp2){
    info = parse_wlanngp2_hdr((wlan_ng_hdr_t *)packet->mac_pkt);
  }
  else{
    return;
  }
  
  if (!info->status){
    return;
  }
  if (filter != NULL){
    update_filtered_ap(filter);
  }
  /** usually run when running daemonized... open discovery **/
  else{
    update_unfiltered_ap(info);
  }
  /** update packet's node statistics **/
  update_node_stats(info, packet);
}

/**
 * get_detailed_snapshot()
 * ----------------------
 * returns the results of current structure holding the detailed scan
 * related data.
 **/
detailed_overview_t *get_detailed_snapshot()
{
  return (overview);
}
