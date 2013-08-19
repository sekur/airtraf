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
 **  detailed_analysis.c
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

///////////////////////////////////////////////////////////////////
//  DATA ANALYSIS FUNCTIONS
///////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////
//  Analyze 802.11b protocol (mgmt, ctrl, data)
///////////////////////////////////////////////////////////////////
/**
 * analyze_mgmt_packet()
 * ---------------------
 * A routine that handles updaet of management packets
 **/
void analyze_mgmt_packet(bss_t *curr_bss, struct p802_11b_info *info, struct packet_info *packet)
{
  if (curr_bss->mgmt_data.mgmt_count == 0){
    gettimeofday(&curr_bss->mgmt_data.bndwth.old_time, NULL);
  }
  curr_bss->mgmt_data.mgmt_count++;
  curr_bss->mgmt_data.mgmt_byte += packet->packet_size;
  curr_bss->mgmt_data.bndwth.tot_byte = curr_bss->mgmt_data.mgmt_byte;

  switch(info->subtype)
    {
    case BEACON:
      curr_bss->mgmt_data.beacon++;
      break;
    case DISASSOC:
      curr_bss->mgmt_data.disassoc++;
      break;
    default:
      curr_bss->mgmt_data.other++;
      break;
    }
}

/**
 * analyze_ctrl_packet()
 * ---------------------
 * A routine that manages update of control packets
 **/
void analyze_ctrl_packet(bss_t *curr_bss, struct p802_11b_info *info, struct packet_info *packet)
{
  bss_node_t * temp;
  
  if (curr_bss->ctrl_data.control_count == 0){
    gettimeofday(&curr_bss->ctrl_data.bndwth.old_time, NULL);
  }    
  curr_bss->ctrl_data.control_count++;
  curr_bss->ctrl_data.control_byte += packet->packet_size;
  curr_bss->ctrl_data.bndwth.tot_byte = curr_bss->ctrl_data.control_byte;

  switch(info->subtype)
    {
    case ACK:
      curr_bss->ctrl_data.ack++;
      if ((temp = bss_find_node(curr_bss,info->da)) != NULL){
	temp->inc_packet++;
	temp->inc_byte += packet->packet_size;
      }
      break;
    default:
      curr_bss->ctrl_data.other++;
      break;
    }
}

/**
 * analyze_data_packet()
 * ---------------------
 * A routine that manages update of data packets
 **/
void analyze_data_packet(bss_t *curr_bss, struct p802_11b_info *info, struct packet_info *packet)
{
  if (curr_bss->normal_data.data_count == 0){
    gettimeofday(&curr_bss->normal_data.bndwth.old_time, NULL);
    gettimeofday(&curr_bss->normal_data.extband.old_time, NULL);
  }
  curr_bss->wep_status = info->wep;
  curr_bss->normal_data.data_count++;
  curr_bss->normal_data.data_byte += packet->packet_size;
  curr_bss->normal_data.bndwth.tot_byte = curr_bss->normal_data.data_byte;
  
  if((bss_find_node(curr_bss,info->sa) != NULL)||
     (bss_find_node(curr_bss,info->da) != NULL)){
    curr_bss->normal_data.internal_count++;
    curr_bss->normal_data.internal_byte += packet->packet_size;
  }
  else{
    curr_bss->normal_data.external_count++;
    curr_bss->normal_data.external_byte += packet->packet_size;
    curr_bss->normal_data.extband.tot_byte = curr_bss->normal_data.external_byte;
  }
}

/////////////////////////////////////////////////////////////////////////////////////
//  Analyze transport layer protocols (tcp, udp, icmp)
/////////////////////////////////////////////////////////////////////////////////////

/**
 * update_latency()
 * ----------------
 * A subroutine that does the latency calculation given the latency_t
 * struct holding latency data.
 **/
void update_latency(latency_t *lat, struct timeval *t_now)
{
  float t_diff;

  t_diff = get_time_diff(t_now, &lat->last_time);
  lat->last_time = *t_now;

  lat->num++;
  
  /** set current latency **/
  lat->curr = t_diff;

  /** get higest latency **/
  if (lat->curr > lat->high){
    lat->high = lat->curr;
  }

  /** get lowest latency (not 0) **/
  if (lat->low == 0){
    lat->low = lat->curr;
  }
  if ((lat->curr > 0) && (lat->curr < lat->low)){
    lat->low = lat->curr;
  }

  /** get avg latency **/
  lat->avg = ((lat->avg * (lat->num - 1)) + lat->curr) / lat->num;
}

/**
 * update_rtt_latency()
 * ----------------
 * A subroutine that does the latency calculation given the latency_t
 * struct holding latency data.
 * get the total RTT, but it is *most* likely that the
 * next ack we get is not the next ack in sequence, so we
 * need to compensate for the difference by subtracting the
 * skip in ack * interspacial latency (time between each
 * packet send) from the total latency seen.
 * !@# screw that, it doesn't work that way...  hrm...  maybe I don't
 * need this function after all...   and use the one above...
 **/
void update_rtt_latency(tcpconn_t *tcp_conn, struct tcphdr *thdr, struct timeval *t_now)
{
  float t_diff;
  latency_t * lat = &tcp_conn->total_rtt;

  t_diff = get_time_diff(t_now, &lat->last_time);

  lat->num++;
  
  /** estimation of total RTT in case the latest ack to transmitted
      data is not in sequential order...  compensate for window size
      effect by subtracting the outgoing_latency rate * difference
      between sent & acked seq number.  **/
  //  lat->curr = t_diff -
  //    ((ntohl(thdr->ack_seq) - tcp_conn->tracked_seq_num - 1) * (tcp_conn->outgoing_latency.curr));

  // screw the above, the seq #'s skip around...  damn it!
  /** now just look to make sure that the ack is greater...  assume
      that packets are sent fairly fast...  **/
  lat->curr = t_diff;
  
  /** get higest latency **/
  if (lat->curr > lat->high){
    lat->high = lat->curr;
  }

  /** get lowest latency (not 0) **/
  if (lat->low == 0){
    lat->low = lat->curr;
  }
  if ((lat->curr > 0) && (lat->curr < lat->low)){
    lat->low = lat->curr;
  }

  /** get avg latency **/
  lat->avg = ((lat->avg * (lat->num - 1)) + lat->curr) / lat->num;
}

////////////////////////////////////////////////////////////////////////
//  TCP individual connections related functions
////////////////////////////////////////////////////////////////////////

/**
 * find_tcp_conn()
 * ---------------
 * a helper function to analyze_tcp_packet routine, used to identifiy
 * whether the given packet is part of existing client/server
 * connection, or a new connection.  Searches the found tcp_entry
 * object's tcpconn list to see if one of the multiple connections
 * discovered matches this packet's unique port identifier.
 * returns (NULL) if new, (pointer to tcpconn_t entry) if existing.
 **/
tcpconn_t * find_tcp_conn(tcptable_t *tcp_entry, struct packet_info *packet, int type)
{
  struct tcphdr *thdr = (struct tcphdr*)packet->trans_pkt;
  tcpconn_t * temp = tcp_entry->tcpconn_head;

  if (tcp_entry->num_connected == 0) return (NULL);

  while (temp != NULL){
    if ((temp->unique_port == ntohs(thdr->dest))||
	(temp->unique_port == ntohs(thdr->source))){
      return (temp);
    }
    temp = temp->next;
  }
  return (NULL);
}

/**
 * add_new_tcp_conn()
 * -------------------
 * If new tcp connection is discovered, then we fill in info about
 * it...  We only add new SYN conn. request related info, and
 * initialize the data entry for further analysis.
 **/
void add_new_tcp_conn(tcptable_t *tcp_entry, struct packet_info *packet, int type)
{
  struct timeval temp;
  tcpconn_t * tcp_conn = NULL;
  struct tcphdr *thdr = ((struct tcphdr *)packet->trans_pkt);

  if (NULL == (tcp_conn = malloc(sizeof(tcpconn_t)))) return;
  memset(tcp_conn, 0, sizeof(tcpconn_t));
  gettimeofday(&temp, NULL);
  tcp_conn->initiator = type;
  tcp_conn->unique_port = ntohs(thdr->source);
  tcp_conn->conn_status = 1;

  tcp_conn->next = NULL;
  if (tcp_entry->tcpconn_head == NULL){
    tcp_entry->tcpconn_head = tcp_conn;
    tcp_entry->tcpconn_tail = tcp_conn;
  }
  else{
    tcp_entry->tcpconn_tail->next = tcp_conn;
    tcp_entry->tcpconn_tail = tcp_conn;
  }
  tcp_entry->num_connected++;
}

/////////////////////////////////////////////////////////////////////////////
//  TCP table entry (ip, service port)  related functions
/////////////////////////////////////////////////////////////////////////////

/**
 * find_tcp_table()
 * ---------------
 * a helper function to analyze_tcp_packet routine, used to identifiy
 * whether the given packet is part of existing client/server
 * connection, or a new connection.
 * returns (NULL) if new, (pointer to tcptable_t entry) if existing.
 **/
tcptable_t *  find_tcp_table(bss_node_t *curr_node, struct packet_info *packet, int type)
{
  struct in_addr target_addr;
  struct tcphdr *thdr = (struct tcphdr*)packet->trans_pkt;
  tcptable_t * temp = curr_node->tcpinfo_head;
  
  if (curr_node->tcp_connections == 0) return (NULL);

  switch (type)
    {
    case OUTGOING:
      target_addr.s_addr = ((struct iphdr*)packet->net_pkt)->daddr;
      break;
    case INCOMING:
      target_addr.s_addr = ((struct iphdr*)packet->net_pkt)->saddr;
      break;
    default:
      return (NULL);
      break;
    }

  while (temp != NULL){
    if ((temp->other_addr.s_addr == target_addr.s_addr)&&
	((temp->service_port == ntohs(thdr->dest))||
	 (temp->service_port == ntohs(thdr->source)))){
      return (temp);
    }
    temp = temp->next;
  }
  return (NULL);
}

/**
 * add_new_tcp_entry()
 * -------------------
 * If new tcp connection is discovered, then we fill in info about
 * it...  We only add new SYN conn. request related info, and
 * initialize the data entry for further analysis.
 **/
void add_new_tcp_entry(bss_node_t *curr_node, struct packet_info *packet, int type)
{
  struct timeval temp;
  tcptable_t * new_entry = NULL;
  struct tcphdr *thdr = ((struct tcphdr *)packet->trans_pkt);

  if (NULL == (new_entry = malloc(sizeof(tcptable_t)))) return;
  memset(new_entry, 0, sizeof(tcptable_t));
  gettimeofday(&temp, NULL);
  new_entry->incoming_rate.old_time = temp;
  new_entry->outgoing_rate.old_time = temp;
  new_entry->total_rate.old_time = temp;

  new_entry->initiator = type;
  switch (type)
    {
    case OUTGOING:
      new_entry->service_port = ntohs(thdr->dest);
      new_entry->other_addr.s_addr = ((struct iphdr*)packet->net_pkt)->daddr;
      break;
    case INCOMING:
      new_entry->service_port = ntohs(thdr->dest);
      new_entry->other_addr.s_addr = ((struct iphdr*)packet->net_pkt)->saddr;
      break;
    }
  
  new_entry->next = NULL;
  if (curr_node->tcpinfo_head == NULL){
    curr_node->tcpinfo_head = new_entry;
    curr_node->tcpinfo_tail = new_entry;
  }
  else{
    curr_node->tcpinfo_tail->next = new_entry;
    curr_node->tcpinfo_tail = new_entry;
  }
  curr_node->tcp_connections++;
}

/**
 * get_tcp_table_entry()
 * -----------------------
 * a helper routine to be able to access & retrieve the table_entry by
 * providing the index...
 **/
tcptable_t * get_tcp_table_entry(bss_node_t *node, int pos)
{
  int c= 0;
  tcptable_t * temp;

  if (node == NULL) return (NULL);
  if (node->tcp_connections == 0) return (NULL);
  if (pos >= node->tcp_connections) return (NULL);

  temp = node->tcpinfo_head;
  while ((temp != NULL) && (c < pos)){
    temp = temp->next;
    c++;
  }
  if (c != pos)
    return (NULL);
  else
    return (temp);
}

////////////////////////////////////////////////////////////////////////////////////////////
//  Main TCP ANALYSIS functions
////////////////////////////////////////////////////////////////////////////////////////////

#define TCP_DEBUG 0

/**
 * analyze_tcp_packet()
 * -------------------
 * a function that performs the tcp detailed analysis, assessing the
 * connection state of the given packet, whether it is a new
 * connection request, existing connection stream, FIN packet, or RST
 * packet.
 * Furthermore, it performs assessment of the window size of
 * connection, whether the window size decreased/increased, whether it
 * is retransmission, and calculates the latency, bandwidth observed,
 * for incoming/outgoing as well as overall.
 **/
void analyze_tcp_packet(bss_node_t *curr_node, struct packet_info *packet, int type)
{
  struct timeval temp;
  tcptable_t *tcp_entry = find_tcp_table(curr_node, packet, type);
  tcpconn_t *tcp_conn = NULL;
  struct tcphdr *thdr = (struct tcphdr*)packet->trans_pkt;

  /**  First Update the TOTAL tcp related count/byte for wireless node **/
  curr_node->tcp_total_count++;
  curr_node->tcp_total_byte += packet->packet_size;

  /** Add new entry ONLY if its the first SYN packet requesting
      connection.  Else, keep track of info sent via pre-existing
      connections.  **/
  if (tcp_entry == NULL){
    if (curr_node->tcp_connections >= MAX_TCP_CONN){
      /** hopefully this won't happen...  but it could! **/
      return;
    }    
    if ((thdr->syn)&&(!thdr->ack)){
      add_new_tcp_entry(curr_node, packet, type);
      tcp_entry = curr_node->tcpinfo_tail;
    }
    else{
      /** update count/byte for the existing connections **/
      curr_node->tcp_existing_count++;
      curr_node->tcp_existing_byte += packet->packet_size;
      return;
    }
  }
  
  ////////////////////////////////////////////////////////////////////////////////////
  //  AT this point we have the TCP (ip, service) handler
  ////////////////////////////////////////////////////////////////////////////////////
  
  /** first do overall update **/
  tcp_entry->total_count++;
  tcp_entry->total_byte += packet->packet_size;
  tcp_entry->total_rate.tot_byte += packet->packet_size;

  gettimeofday(&temp, NULL);  
  /** then do incoming/outgoing update **/
  switch (type)
    {
    case OUTGOING:
      tcp_entry->outgoing_count++;
      tcp_entry->outgoing_byte += packet->packet_size;
      tcp_entry->outgoing_rate.tot_byte += packet->packet_size;
      /** update interspacial latency between packets **/
      if (tcp_entry->outgoing_count != 0){
	update_latency(&tcp_entry->outgoing_latency, &temp);
      }
      else{
	tcp_entry->outgoing_latency.last_time = temp;
      }    
      break;
    case INCOMING:
      tcp_entry->incoming_count++;
      tcp_entry->incoming_byte += packet->packet_size;
      tcp_entry->incoming_rate.tot_byte += packet->packet_size;
      if (tcp_entry->incoming_count != 0){
	update_latency(&tcp_entry->incoming_latency, &temp);
      }
      else{
	tcp_entry->incoming_latency.last_time = temp;
      }         
      break;
    }
  
  /** now lets see if this TCP packet is part of existing connection
      streams **/
  tcp_conn = find_tcp_conn(tcp_entry, packet, type);

  if (tcp_conn == NULL){
    if (tcp_entry->num_connected >= MAX_TCP_CONN_THREAD){
      return;
    }
    if ((thdr->syn)&&(!thdr->ack)){
      add_new_tcp_conn(tcp_entry, packet, type);
      tcp_conn = tcp_entry->tcpconn_tail;
    }
    else{
      /** here there's nothing for us to do...  **/
      return;
    }
  }

  ////////////////////////////////////////////////////////////////////////////////////////////////
  //  AT this point we have the 'thread-like' unique point-point connection
  ///////////////////////////////////////////////////////////////////////////////////////////////
  
  /** check if connection should be still open? **/
  if (thdr->rst){
    if (tcp_conn->conn_status){
      tcp_conn->conn_status = 0;
      tcp_entry->reset_count++;
      tcp_entry->closed_connections++;
    }
  }
  else if ((thdr->fin)&&(thdr->ack)){
    if (tcp_conn->conn_status){
      tcp_conn->conn_status = 0;
      tcp_entry->closed_connections++;
    }
  }
    /** first do overall update **/
  tcp_conn->total_count++;
  tcp_conn->total_byte += packet->packet_size;
  
  gettimeofday(&temp, NULL);    
  switch (type)
    {
    case OUTGOING:
      if (ntohs(thdr->window) != tcp_conn->out_window){
	tcp_conn->out_old_window = tcp_conn->out_window;
	tcp_conn->out_window = ntohs(thdr->window);
      }
      else
	tcp_conn->out_window = ntohs(thdr->window);
      
      /** update count/byte **/
      tcp_conn->outgoing_count++;
      tcp_conn->outgoing_byte += packet->packet_size;
      //      tcp_conn->outgoing_rate.tot_byte += packet->packet_size;

      /** update interspacial latency between packets **/
      if (tcp_conn->outgoing_count != 0){
	update_latency(&tcp_conn->outgoing_latency, &temp);
      }
      else{
	tcp_conn->outgoing_latency.last_time = temp;
      }

      if (ntohl(thdr->seq) != 0){
	tcp_conn->curr_outgoing_seq_num = ntohl(thdr->seq);
	if (ntohl(thdr->seq) > tcp_conn->last_outgoing_seq_num){
	  tcp_conn->last_outgoing_seq_num = ntohl(thdr->seq);
	}
	else{
	  tcp_conn->retransmit_count++;
	  tcp_conn->retransmit_byte += packet->packet_size;

	  /** also update this data to the rest of the objects **/
	  tcp_entry->retransmit_count++;
	  tcp_entry->retransmit_byte += packet->packet_size;

	  curr_node->tcp_retransmit_count++;
	  curr_node->tcp_retransmit_byte += packet->packet_size;
	}	
      }

      /** if packet contains ack **/
      if (thdr->ack){
	if (ntohl(thdr->ack_seq) > tcp_conn->acked_incoming_seq_num){
	  /** start RTT tracking... **/
	  if (!tcp_conn->tracking_rtt){
	    tcp_conn->tracked_seq_num = ntohl(thdr->seq);
	    tcp_conn->total_rtt.last_time = temp;
	    tcp_conn->tracking_rtt = ENABLED;
	  }
	  tcp_conn->acked_incoming_seq_num = ntohl(thdr->ack_seq);
	}
	else{
	  tcp_conn->outgoing_dup_ack++;
	}
      }
      break;
    case INCOMING:
      if (thdr->window != tcp_conn->inc_window){
	tcp_conn->inc_old_window = tcp_conn->inc_window;
	tcp_conn->inc_window = thdr->window;
      }
      else
	tcp_conn->inc_window = thdr->window;

      /** update count/byte **/
      tcp_conn->incoming_count++;
      tcp_conn->incoming_byte += packet->packet_size;
      //      tcp_conn->incoming_rate.tot_byte += packet->packet_size;

      /** update interspacial latency between packets **/
      if (tcp_conn->incoming_count != 0){
	update_latency(&tcp_conn->incoming_latency, &temp);
      }
      else{
	tcp_conn->incoming_latency.last_time = temp;
      }

      if (ntohl(thdr->seq) != 0){
	tcp_conn->curr_incoming_seq_num = ntohl(thdr->seq);
	if (ntohl(thdr->seq) > tcp_conn->last_incoming_seq_num)
	  tcp_conn->last_incoming_seq_num = ntohl(thdr->seq);
	else{
	  tcp_conn->retransmit_count++;
	  tcp_conn->retransmit_byte += packet->packet_size; 

	  /** also update this data to the rest of the objects **/
	  tcp_entry->retransmit_count++;
	  tcp_entry->retransmit_byte += packet->packet_size;

	  curr_node->tcp_retransmit_count++;
	  curr_node->tcp_retransmit_byte += packet->packet_size;
	}	
      }
      /** if packet contains ack **/
      if (thdr->ack){
	if (ntohl(thdr->ack_seq) > tcp_conn->acked_outgoing_seq_num){
	  /** if tracking_rtt, then update latest RTT **/
	  if (tcp_conn->tracking_rtt){
	    if (ntohl(thdr->ack_seq) > tcp_conn->tracked_seq_num){
	      update_rtt_latency(tcp_conn, thdr, &temp);
	      tcp_conn->tracking_rtt = DISABLED;
	    }
	  }
	  tcp_conn->acked_outgoing_seq_num = ntohl(thdr->ack_seq); 
	}
	else{
	  tcp_conn->incoming_dup_ack++;
	}
      }      
      break;
    }

  if (TCP_DEBUG){
    fprintf(stderr, "tcp packet:  seq# %u, ack# %u", ntohl(thdr->seq), ntohl(thdr->ack_seq));
    switch (type){
    case INCOMING:
      fprintf(stderr, " INCOMING\n");
      break;
    case OUTGOING:
      fprintf(stderr, " OUTGOING\n");
      break;
    }
  }
}

void analyze_udp_packet(bss_node_t *curr_node, struct packet_info *packet, int type)
{
  switch (type)
    {
    case OUTGOING:
      break;
    case INCOMING:
      break;
    }
}

void analyze_icmp_packet(bss_node_t *curr_node, struct packet_info *packet, int type)
{
  switch (type)
    {
    case OUTGOING:
      break;
    case INCOMING:
      break;
    }
}

/**
 * analyze_trans_proto()
 * ---------------------
 * this function gets called when protocol analysis is enabled.
 * Performs higher level analysis for TCP, UDP, ICMP, and OTHER type
 * of packet observed.
 * Main analysis cases are OUTGOING, INCOMING, and BACKGROUND.
 **/
void analyze_trans_proto(bss_t *curr_bss, bss_node_t *curr_node, struct packet_info *packet, int type)
{
  switch (type)
    {
    case OUTGOING:
      switch(packet->trans_proto)
	{
	case TCP:
	  if (curr_bss->transport_data.tcp.count == 0){
	    gettimeofday(&curr_bss->transport_data.tcp.band.old_time, NULL);
	  }
	  /** we analyze only 1st fragment of tcp if ip fragmented the
	      packet along the way **/
	  if ((ntohs(((struct iphdr*)packet)->frag_off) & 0x3fff) == 0)
	    analyze_tcp_packet(curr_node, packet, OUTGOING);
	  
	  curr_bss->transport_data.tcp.count++;
	  curr_bss->transport_data.tcp.byte += packet->packet_size;
	  curr_bss->transport_data.tcp.out_count++;
	  curr_bss->transport_data.tcp.out_byte += packet->packet_size;
	  curr_bss->transport_data.tcp.band.tot_byte = curr_bss->transport_data.tcp.byte;
	  break;
	case UDP:
	  if (curr_bss->transport_data.udp.count == 0){
	    gettimeofday(&curr_bss->transport_data.udp.band.old_time, NULL);
	  }
	  analyze_udp_packet(curr_node, packet, OUTGOING);
	  curr_bss->transport_data.udp.count++;
	  curr_bss->transport_data.udp.byte += packet->packet_size;
	  curr_bss->transport_data.udp.out_count++;
	  curr_bss->transport_data.udp.out_byte += packet->packet_size;
	  curr_bss->transport_data.tcp.band.tot_byte = curr_bss->transport_data.tcp.byte;
	  break;
	case ICMP:
	  if (curr_bss->transport_data.icmp.count == 0){
	    gettimeofday(&curr_bss->transport_data.icmp.band.old_time, NULL);
	  }
	  analyze_icmp_packet(curr_node, packet, OUTGOING);
	  curr_bss->transport_data.icmp.count++;
	  curr_bss->transport_data.icmp.byte += packet->packet_size;
	  curr_bss->transport_data.icmp.out_count++;
	  curr_bss->transport_data.icmp.out_byte += packet->packet_size;
	  curr_bss->transport_data.tcp.band.tot_byte = curr_bss->transport_data.tcp.byte;
	  break;
	default:
	  if (curr_bss->transport_data.other.count == 0){
	    gettimeofday(&curr_bss->transport_data.other.band.old_time, NULL);
	  }
	  curr_bss->transport_data.other.count++;
	  curr_bss->transport_data.other.byte += packet->packet_size;
	  curr_bss->transport_data.other.out_count++;
	  curr_bss->transport_data.other.out_byte += packet->packet_size;	      
	  curr_bss->transport_data.tcp.band.tot_byte = curr_bss->transport_data.tcp.byte;
	  break;
	}
      break;
    case INCOMING:
      switch(packet->trans_proto)
	{
	case TCP:
	  if (curr_bss->transport_data.tcp.count == 0){
	    gettimeofday(&curr_bss->transport_data.tcp.band.old_time, NULL);
	  }
	  if ((ntohs(((struct iphdr*)packet)->frag_off) & 0x3fff) == 0)
	    analyze_tcp_packet(curr_node, packet, INCOMING);

	  curr_bss->transport_data.tcp.count++;
	  curr_bss->transport_data.tcp.byte += packet->packet_size;
	  curr_bss->transport_data.tcp.in_count++;
	  curr_bss->transport_data.tcp.in_byte += packet->packet_size;
	  curr_bss->transport_data.tcp.band.tot_byte = curr_bss->transport_data.tcp.byte;
	  break;
	case UDP:
	  if (curr_bss->transport_data.udp.count == 0){
	    gettimeofday(&curr_bss->transport_data.udp.band.old_time, NULL);
	  }
	  analyze_udp_packet(curr_node, packet, INCOMING);
	  curr_bss->transport_data.udp.count++;
	  curr_bss->transport_data.udp.byte += packet->packet_size;
	  curr_bss->transport_data.udp.in_count++;
	  curr_bss->transport_data.udp.in_byte += packet->packet_size;
	  curr_bss->transport_data.udp.band.tot_byte = curr_bss->transport_data.udp.byte;
	  break;
	case ICMP:
	  if (curr_bss->transport_data.icmp.count == 0){
	    gettimeofday(&curr_bss->transport_data.icmp.band.old_time, NULL);
	  }
	  analyze_icmp_packet(curr_node, packet, INCOMING);
	  curr_bss->transport_data.icmp.count++;
	  curr_bss->transport_data.icmp.byte += packet->packet_size;
	  curr_bss->transport_data.icmp.in_count++;
	  curr_bss->transport_data.icmp.in_byte += packet->packet_size;
	  curr_bss->transport_data.icmp.band.tot_byte = curr_bss->transport_data.icmp.byte;
	  break;
	default:
	  if (curr_bss->transport_data.other.count == 0){
	    gettimeofday(&curr_bss->transport_data.other.band.old_time, NULL);
	  }
	  curr_bss->transport_data.other.count++;
	  curr_bss->transport_data.other.byte += packet->packet_size;
	  curr_bss->transport_data.other.in_count++;
	  curr_bss->transport_data.other.in_byte += packet->packet_size;	      
	  curr_bss->transport_data.other.band.tot_byte = curr_bss->transport_data.other.byte;
	  break;
	}
      break;
    case BACKGROUND:
      switch(packet->trans_proto)
	{
	case TCP:
	  if (curr_bss->transport_data.tcp.ext_count == 0){
	    gettimeofday(&curr_bss->transport_data.tcp.extband.old_time, NULL);
	  }
	  curr_bss->transport_data.tcp.ext_count++;
	  curr_bss->transport_data.tcp.ext_byte += packet->packet_size;
	  curr_bss->transport_data.tcp.extband.tot_byte = curr_bss->transport_data.tcp.ext_byte;
	  break;
	case UDP:
	  if (curr_bss->transport_data.udp.ext_count == 0){
	    gettimeofday(&curr_bss->transport_data.udp.extband.old_time, NULL);
	  }
	  curr_bss->transport_data.udp.ext_count++;
	  curr_bss->transport_data.udp.ext_byte += packet->packet_size;
	  curr_bss->transport_data.udp.extband.tot_byte = curr_bss->transport_data.udp.ext_byte;
	  break;
	case ICMP:
	  if (curr_bss->transport_data.icmp.ext_count == 0){
	    gettimeofday(&curr_bss->transport_data.icmp.extband.old_time, NULL);
	  }
	  curr_bss->transport_data.icmp.ext_count++;
	  curr_bss->transport_data.icmp.ext_byte += packet->packet_size;
	  curr_bss->transport_data.icmp.extband.tot_byte = curr_bss->transport_data.icmp.ext_byte;
	  break;
	default:
	  if (curr_bss->transport_data.other.ext_count == 0){
	    gettimeofday(&curr_bss->transport_data.other.extband.old_time, NULL);
	  }
	  curr_bss->transport_data.other.ext_count++;
	  curr_bss->transport_data.other.ext_byte += packet->packet_size;
	  curr_bss->transport_data.other.extband.tot_byte = curr_bss->transport_data.other.ext_byte;
	  break;
	}
      break;
    }
}

/////////////////////////////////////////////////////////////////////////////
//  MAIN: analyze packet interface
/////////////////////////////////////////////////////////////////////////////

/**
 * analyze_packet()
 * ---------------
 * The main decode/dissector function that given the fresh packet
 * retrieved from the driver, calls, sorts, and delegates proper
 * handling of the packet based on its type.
 **/
void analyze_packet(bss_t *curr_bss, struct p802_11b_info *info, struct packet_info *packet, int proto)
{
  struct iphdr *ip_pkt;
  bss_node_t *curr_node;
  int noproto = 0;
  int internal = 0;

  /** OVERALL ANALYSIS **/
  if (curr_bss->overall_count == 0){
    gettimeofday(&curr_bss->bndwth.old_time, NULL);
  }
  curr_bss->overall_count++;
  curr_bss->overall_byte += packet->packet_size;
  curr_bss->bndwth.tot_byte = curr_bss->overall_byte;
  
  /* frame type analysis */
  switch(info->type)
    {
    case FT_MGMT:
      analyze_mgmt_packet(curr_bss, info, packet);
      noproto = 1; // don't do higher level proto analysis
      break;
    case FT_CTRL:
      analyze_ctrl_packet(curr_bss, info, packet);
      return;  // controls are scary...
      break;
    case FT_DATA:
      analyze_data_packet(curr_bss, info, packet);
      break;
    }

  /** if packet is from a known source **/
  if ((curr_node = bss_find_node(curr_bss,info->sa)) != NULL){
    internal = 1;
    if (curr_node->tot_packet == 0){
      gettimeofday(&curr_node->bndwth.old_time, NULL);
    }
    switch (packet->net_proto)
      {
      case 0:
	// no network protocol
	break;
      case IPv4:
	ip_pkt = (struct iphdr *)packet->net_pkt;
	curr_node->ip_addr.s_addr = ip_pkt->saddr;
	if (curr_bss->network_data.ip.count == 0){
	  gettimeofday(&curr_bss->network_data.ip.band.old_time, NULL);
	}
	curr_bss->network_data.ip.count++;
	curr_bss->network_data.ip.byte += packet->packet_size;
	curr_bss->network_data.ip.out_count++;
	curr_bss->network_data.ip.out_byte += packet->packet_size;
	curr_bss->network_data.ip.band.tot_byte = curr_bss->network_data.ip.byte;
	if (proto){
	  analyze_trans_proto(curr_bss, curr_node, packet, OUTGOING);
	}
	break;
      case IPv6:
	if (curr_bss->network_data.ipv6.count == 0){
	  gettimeofday(&curr_bss->network_data.ipv6.band.old_time, NULL);
	}
	curr_bss->network_data.ipv6.count++;
	curr_bss->network_data.ipv6.byte += packet->packet_size;
	curr_bss->network_data.ipv6.out_count++;
	curr_bss->network_data.ipv6.out_byte += packet->packet_size;	
	curr_bss->network_data.ipv6.band.tot_byte = curr_bss->network_data.ipv6.byte;
	break;
      default:
	if (noproto){
	  break;
	}
	if (curr_bss->network_data.other.count == 0){
	  gettimeofday(&curr_bss->network_data.other.band.old_time, NULL);
	}
	curr_bss->network_data.other.count++;
	curr_bss->network_data.other.byte += packet->packet_size;
	curr_bss->network_data.other.out_count++;
	curr_bss->network_data.other.out_byte += packet->packet_size;
	curr_bss->network_data.other.band.tot_byte = curr_bss->network_data.other.byte;
	break;
      }    
    curr_node->out_packet++;
    curr_node->tot_packet++;
    curr_node->out_byte += packet->packet_size; /** fixed this 11/23/02 **/
    curr_node->bndwth.tot_byte = curr_node->out_byte + curr_node->inc_byte;

    if (packet->driver_proto == AIRONET_MOD){
      curr_node->avg_signal_str = ((curr_node->avg_signal_str * (curr_node->out_packet - 1))
				   + packet->driver_pkt->signal) / curr_node->out_packet;
    }
  }

  /** if packet is to a known destination **/
  if ((curr_node = bss_find_node(curr_bss,info->da)) != NULL){
    internal = 1;
    if (curr_node->tot_packet == 0){
      gettimeofday(&curr_node->bndwth.old_time, NULL);
    }
    switch (packet->net_proto)
      {
      case 0:
	// no network protocol
	break;
      case IPv4:
	ip_pkt = (struct iphdr *)packet->net_pkt;
	curr_node->ip_addr.s_addr = ip_pkt->daddr;
	if (curr_bss->network_data.ip.count == 0){
	  gettimeofday(&curr_bss->network_data.ip.band.old_time, NULL);
	}
	curr_bss->network_data.ip.count++;
	curr_bss->network_data.ip.byte += packet->packet_size;
	curr_bss->network_data.ip.in_count++;
	curr_bss->network_data.ip.in_byte += packet->packet_size;
	curr_bss->network_data.ip.band.tot_byte = curr_bss->network_data.ip.byte;
	if (proto){
	  analyze_trans_proto(curr_bss, curr_node, packet, INCOMING);
	}
	break;
      case IPv6:
	if (curr_bss->network_data.ipv6.count == 0){
	  gettimeofday(&curr_bss->network_data.ipv6.band.old_time, NULL);
	}
	curr_bss->network_data.ipv6.count++;
	curr_bss->network_data.ipv6.byte += packet->packet_size;
	curr_bss->network_data.ipv6.in_count++;
	curr_bss->network_data.ipv6.in_byte += packet->packet_size;	
	curr_bss->network_data.ipv6.band.tot_byte = curr_bss->network_data.ipv6.byte;
	break;
      default:
	if (noproto){
	  break;
	}
	if (curr_bss->network_data.other.count == 0){
	  gettimeofday(&curr_bss->network_data.other.band.old_time, NULL);
	}
	curr_bss->network_data.other.count++;
	curr_bss->network_data.other.byte += packet->packet_size;
	curr_bss->network_data.other.in_count++;
	curr_bss->network_data.other.in_byte += packet->packet_size;
	curr_bss->network_data.other.band.tot_byte = curr_bss->network_data.other.byte;
	break;
      }    
    curr_node->inc_packet++;
    curr_node->tot_packet++;
    curr_node->inc_byte += packet->packet_size;
    curr_node->bndwth.tot_byte = curr_node->out_byte + curr_node->inc_byte;
  }
  /** background traffic (most likely broadcast) **/
  if (!internal){
    switch (packet->net_proto)
      {
      case 0:
	// no network protocol
	break;
      case IPv4:
	if (curr_bss->network_data.ip.ext_count == 0){
	  gettimeofday(&curr_bss->network_data.ip.extband.old_time, NULL);
	}
	curr_bss->network_data.ip.ext_count++;
	curr_bss->network_data.ip.ext_byte += packet->packet_size;
	curr_bss->network_data.ip.extband.tot_byte = curr_bss->network_data.ip.ext_byte;
	if (proto){
	  analyze_trans_proto(curr_bss, NULL, packet, BACKGROUND);
	}
	break;
      case IPv6:
	if (curr_bss->network_data.ipv6.ext_count == 0){
	  gettimeofday(&curr_bss->network_data.ipv6.extband.old_time, NULL);
	}
	curr_bss->network_data.ipv6.ext_count++;
	curr_bss->network_data.ipv6.ext_byte += packet->packet_size;
	curr_bss->network_data.ipv6.extband.tot_byte = curr_bss->network_data.ipv6.ext_byte;
	break;
      default:
	if (curr_bss->network_data.other.ext_count == 0){
	  gettimeofday(&curr_bss->network_data.other.extband.old_time, NULL);
	}
	curr_bss->network_data.other.ext_count++;
	curr_bss->network_data.other.ext_byte += packet->packet_size;
	curr_bss->network_data.other.extband.tot_byte = curr_bss->network_data.other.ext_byte;
	break;
      }    
  }
}
