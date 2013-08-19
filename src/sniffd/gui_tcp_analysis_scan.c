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
 **  gui_tcp_analysis_scan.c
 **
 ****************************************************************
 **
 **   Copyright (c) 2001,2002 all rights reserved.
 **
 **   Author: Peter K. Lee <saint@elixar.net>
 **
 ***************************************************************/

#include <ncurses.h>
#include <panel.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "definition.h"
#include "sniff_include.h"

extern int GUI_DEBUG;

/** view related defines **/
#define CONNECTIONS 0
#define STATISTICS 1
#define PERF_LATENCY 2
#define PERF_BANDWIDTH 3

/**
 * print_tcp_stat_screen()
 * -------------------
 * displays the main background screen
 **/
void print_tcp_stat_screen(WINDOW ** statwin, PANEL ** statpanel, int card, char *iface)
{
  if (GUI_DEBUG) fprintf(stderr,"making overall window\n");
  /** make the overall wireless traffic monitor box window **/
  *statwin = newwin(LINES - 2, COLS, 1, 0);
  *statpanel = new_panel(*statwin);
  stdwinset(*statwin);
  wtimeout(*statwin, -1);
  wattrset(*statwin, BOXATTR);
  colorwin(*statwin);
  box(*statwin, ACS_VLINE, ACS_HLINE);
  wmove(*statwin, 0, 1);
  if (card == AIRONET)
    wprintw(*statwin, " TCP Performance Analysis: listening using Cisco Aironet (%s) ", iface);
  else if (card == PRISMII)
    wprintw(*statwin, " TCP Performance Analysis: listening using PrismII-compatible (%s) ", iface);
  else if (card == HOSTAP)
    wprintw(*statwin, " TCP Performance Analysis: listening using HostAP driver (%s) ", iface);
  else if (card == HERMES)
    wprintw(*statwin, " TCP Performance Analysis: listening using Hermes-compatible (%s) ", iface);
  else if (card == WLANNG)
    wprintw(*statwin, " TCP Performance Analysis: listening using Wlan-ng driver (%s) ", iface);
  wattrset(*statwin, STDATTR);
  update_panels();
  doupdate();
}

///////////////////////////////////////////////////////////////////////////////////
//  ACTIVITY OVERVIEW routines
///////////////////////////////////////////////////////////////////////////////////

/**
 * print_tcp_activity_overview_labels()
 * --------------------------------
 * displays the Activity Overview window, and prints the labels
 * associated with it.
 **/
void print_tcp_activity_overview_labels(WINDOW ** scanwin, PANEL ** scanpanel, int highlight)
{
  *scanwin = newwin(LINES - 5, 30, 3, 1);
  *scanpanel = new_panel(*scanwin);
  wattrset(*scanwin, BOXATTR);
  colorwin(*scanwin);
  box(*scanwin, ACS_VLINE, ACS_HLINE);
  mvwprintw(*scanwin, 0, 2, " Activity Overview ");

  wattrset(*scanwin, ACTIVEATTR);
  mvwprintw(*scanwin, 2, 2, "Access Point Information");
  wattrset(*scanwin, STDATTR);
  mvwprintw(*scanwin, 4, 3, "SSID:             ");
  mvwprintw(*scanwin, 5, 3, "BSSID: ");
  mvwprintw(*scanwin, 6, 3, "WEP: ");
  mvwprintw(*scanwin, 7, 3, "Channel:");
  mvwprintw(*scanwin, 8, 3, "Total # Nodes:");

  wattrset(*scanwin, BOXATTR);
  wmove(*scanwin, 10, 6);
  whline(*scanwin, ACS_HLINE, 15);
  
  wattrset(*scanwin, ACTIVEATTR);
  mvwprintw(*scanwin, 12, 2, "Selected Wireless Node");
  wattrset(*scanwin, STDATTR);
  mvwprintw(*scanwin, 14, 3, "MAC: ");
  mvwprintw(*scanwin, 15, 3, "IP Addr: ");

  wattrset(*scanwin, BOXATTR);
  mvwprintw(*scanwin, 17, 2, "TCP Related-Info");
  wattrset(*scanwin, STDATTR);  
  mvwprintw(*scanwin, 19, 3, "Total # Conns: ");
  mvwprintw(*scanwin, 20, 3, "Total pkts:    ");
  mvwprintw(*scanwin, 21, 3, "Total bytes: ");
  mvwprintw(*scanwin, 22, 3, "Existing pkts: ");
  mvwprintw(*scanwin, 23, 3, "Existing bytes: ");
  mvwprintw(*scanwin, 24, 3, "Retran pkts: ");
  mvwprintw(*scanwin, 25, 3, "Retran bytes: ");

  mvwprintw(*scanwin, 27, 3, "Waste (%%): ");

  wattrset(*scanwin, ACTIVEATTR);
  mvwprintw(*scanwin, 30, 2, "Data Setting");
  wattrset(*scanwin, STDATTR);
  mvwprintw(*scanwin, 32, 3, "Current View: ");
  
  wattrset(*scanwin, BOXATTR);
  wmove(*scanwin, 34, 6);
  whline(*scanwin, ACS_HLINE, 15);
 
  mvwprintw(*scanwin, 35, 3, "Press 'V' to view other");
  mvwprintw(*scanwin, 36, 3, "types of data");

  wattrset(*scanwin, STDATTR);
  mvwprintw(*scanwin, LINES - 7, 2, "Elapsed: "); 
  
  update_panels();
  doupdate();
}

/**
 * print_tcp_activity_overview_results()
 * ---------------------------------
 * displays the updated activity overview snapshot results
 **/
void print_tcp_activity_overview_results(WINDOW * win, int selected, int view)
{
  bss_t * ap = get_detailed_snapshot()->bss_list_top;
  bss_node_t * node = bss_get_node(ap, selected);
  if (ap == NULL)
    return;
  
  wattrset(win, HIGHATTR);
  /** access point info **/  
  mvwprintw(win, 4, 10, ap->ssid);
  mvwprintw(win, 5, 10, hexdump((__u8*)&ap->bssid,6));
  mvwprintw(win, 6, 10, "%s", ap->wep_status ? "encrypted " : "opensystem");
  mvwprintw(win, 7, 13, "%02d", ap->channel);
  mvwprintw(win, 8, 18, "%3d", ap->num-1);
  
  if ((selected)&&(node != NULL)){
    /** wireless node info **/
    mvwprintw(win, 14, 13, "%s ", hexdump((__u8*)&node->mac_addr,6)); 
    mvwprintw(win, 15, 13, "%s", inet_ntoa(node->ip_addr));
    
    /** tcp connection info **/
    mvwprintw(win, 19, 18, "%8d", node->tcp_connections);
    mvwprintw(win, 20, 18, "%8d", node->tcp_total_count);
    mvwprintw(win, 21, 18, "%8d", node->tcp_total_byte);
    mvwprintw(win, 22, 18, "%8d", node->tcp_existing_count);
    mvwprintw(win, 23, 18, "%8d", node->tcp_existing_byte);
    mvwprintw(win, 24, 18, "%8d", node->tcp_retransmit_count);
    mvwprintw(win, 25, 18, "%8d", node->tcp_retransmit_byte);
    
    mvwprintw(win, 27, 18, "%6.2f %%", (float)node->tcp_retransmit_byte /
	      (float) node->tcp_total_byte * 100);
  }

  /** data setting **/
  switch (view){
  case CONNECTIONS:
    mvwprintw(win, 32, 17, "%s", "Connections");
    break;
  case STATISTICS:
    mvwprintw(win, 32, 17, "%s", "Statistics ");
    break;
  case PERF_LATENCY:
    mvwprintw(win, 32, 17, "%s", "  Latency  ");
    break;
  case PERF_BANDWIDTH:
    mvwprintw(win, 32, 17, "%s", " Bandwidth ");
    break;
  }
  
  update_panels();
  doupdate();
}

//////////////////////////////////////////////////////////////////////////////////
//  DETAILED PROTOCOL BREAKDOWN routines
//////////////////////////////////////////////////////////////////////////////////

void print_tcp_breakdown_labels(WINDOW ** breakwin, PANEL ** breakpanel, int view)
{
  *breakwin = newwin(LINES / 2 - 2, COLS - 32, 3, 31);
  *breakpanel = new_panel(*breakwin);
  wattrset(*breakwin, BOXATTR);
  colorwin(*breakwin);
  box(*breakwin, ACS_VLINE, ACS_HLINE);
  mvwprintw(*breakwin, 0, 2, " TCP Performance Breakdown for Selected Node");

  wattrset(*breakwin, BOXATTR);
  mvwprintw(*breakwin, 3, 3, "Connections:");
  mvwprintw(*breakwin, 2, 24, "Service");
  mvwprintw(*breakwin, 3, 24, "   Port");

  wattrset(*breakwin, STDATTR);
  switch (view)
    {
    case CONNECTIONS:
      mvwprintw(*breakwin, 2, 37, "-Connections-");
      mvwprintw(*breakwin, 3, 34, "Total|Open|Closed");
      mvwprintw(*breakwin, 2, 54, "Reset");
      mvwprintw(*breakwin, 3, 54, "Count");
      mvwprintw(*breakwin, 2, 61, "  Total");
      mvwprintw(*breakwin, 3, 61, "Packets");
      mvwprintw(*breakwin, 2, 72, "Total");
      mvwprintw(*breakwin, 3, 72, "Bytes");
      wattrset(*breakwin, BOXATTR);
      mvwprintw(*breakwin, 3, 80, "STATUS");    
      break;
    case STATISTICS:
      mvwprintw(*breakwin, 2, 36, " -Incoming-");
      mvwprintw(*breakwin, 3, 35, "Count | Bytes");
      mvwprintw(*breakwin, 2, 53, " -Outgoing-");
      mvwprintw(*breakwin, 3, 52, "Count | Bytes");
      mvwprintw(*breakwin, 2, 69, " -Retransmit-");
      mvwprintw(*breakwin, 3, 69, "Count | Bytes");
      break;
    case PERF_LATENCY:
      mvwprintw(*breakwin, 2, 35, "  Incoming (ms)");
      mvwprintw(*breakwin, 3, 35, "Observed|Actual");
      mvwprintw(*breakwin, 2, 53, "  Outgoing (ms)");
      mvwprintw(*breakwin, 3, 53, "Observed|Actual");
      mvwprintw(*breakwin, 2, 72, "Round-trip");
      mvwprintw(*breakwin, 3, 72, " time (ms)");
      break;
    case PERF_BANDWIDTH:
      mvwprintw(*breakwin, 2, 35, "Incoming (Kbps)");
      mvwprintw(*breakwin, 3, 35, "Current|Highest");
      mvwprintw(*breakwin, 2, 52, "Outgoing (Kbps)");
      mvwprintw(*breakwin, 3, 52, "Current|Highest");
      mvwprintw(*breakwin, 2, 72, "Total (Kbps)");
      mvwprintw(*breakwin, 3, 69, "Current|Highest");
      break;
    }

  update_panels();
  doupdate();
}

/**
 * get_curr_rtt_time()
 * --------------------
 * helper routine for the tcp_breakdown_row routine, to be able to
 * gather the rtt time observed by each distinct connection, get'em
 * all, and then find the average RTT seen...
 * REQ: tcp_entry number connected is > 0...  but then it HAS to be
 * since otherwise, it wouldn't show up in the gui in the first place...
 **/
float get_curr_rtt_time(tcptable_t *tcp_entry)
{
  tcpconn_t * tcp_conn = tcp_entry->tcpconn_head;
  float total_rtt = 0;

  while (tcp_conn != NULL){
    total_rtt += tcp_conn->total_rtt.curr;
    tcp_conn = tcp_conn->next;
  }
  return (total_rtt / tcp_entry->num_connected * 1000);
}

/**
 * print_tcp_breakdown_row()
 * ---------------------------
 * helper function in printing out individual rows (network/transport)
 * type protocols.
 **/
void print_tcp_breakdown_row(WINDOW *win, int row, tcptable_t *tcp_entry, int view)
{
  wattrset(win, ACTIVEATTR);
  mvwprintw(win, row, 3, "%s", (tcp_entry->initiator == 1) ? "TO  " : "FROM");
  wattrset(win, HIGHATTR);
  mvwprintw(win, row, 9, "                ");
  mvwprintw(win, row, 9, "%s", inet_ntoa(tcp_entry->other_addr));
  mvwprintw(win, row, 26, "%5d", tcp_entry->service_port);

  switch (view)
    {
    case CONNECTIONS:
      mvwprintw(win, row, 34, "%5d%5d%5d",
		tcp_entry->num_connected,
		tcp_entry->num_connected - tcp_entry->closed_connections,
		tcp_entry->closed_connections);
      mvwprintw(win, row, 53, "%5d", tcp_entry->reset_count);
      mvwprintw(win, row, 59, "%8d", tcp_entry->total_count);
      mvwprintw(win, row, 67, "%10d", tcp_entry->total_byte);
      if (tcp_entry->num_connected == tcp_entry->closed_connections)
	mvwprintw(win, row, 80, "CLOSED");
      else
	mvwprintw(win, row, 80, " OPEN ");
      break;
    case STATISTICS:
      mvwprintw(win, row, 32, "%7d%9d",
		tcp_entry->incoming_count,
		tcp_entry->incoming_byte);
      mvwprintw(win, row, 49, "%7d%9d",
		tcp_entry->outgoing_count,
		tcp_entry->outgoing_byte);
      mvwprintw(win, row, 66, "%7d%9d",
		tcp_entry->retransmit_count,
		tcp_entry->retransmit_byte);
      break;
    case PERF_LATENCY:
      mvwprintw(win, row, 32, "                ");
      mvwprintw(win, row, 49, "                ");
      mvwprintw(win, row, 37, "%4.2f", tcp_entry->incoming_latency.curr * 1000);
      mvwprintw(win, row, 45, "%4.2f", tcp_entry->incoming_latency.low * 1000);
      mvwprintw(win, row, 55, "%4.2f", tcp_entry->outgoing_latency.curr * 1000);
      mvwprintw(win, row, 63, "%4.2f", tcp_entry->outgoing_latency.low * 1000);
      mvwprintw(win, row, 74, "%4.2f", get_curr_rtt_time(tcp_entry));
      break;
    case PERF_BANDWIDTH:
      mvwprintw(win, row, 35, "                                       ");
      mvwprintw(win, row, 75, "       ");
      mvwprintw(win, row, 35, "%-6.2f", tcp_entry->incoming_rate.curr);
      mvwprintw(win, row, 43, "%-6.2f", tcp_entry->incoming_rate.high);
      mvwprintw(win, row, 52, "%-6.2f", tcp_entry->outgoing_rate.curr);
      mvwprintw(win, row, 60, "%-6.2f", tcp_entry->outgoing_rate.high);
      mvwprintw(win, row, 69, "%-6.2f", tcp_entry->total_rate.curr);
      mvwprintw(win, row, 77, "%-6.2f", tcp_entry->total_rate.high);
      break;
    }
}

/**
 * print_tcp_breakdown_results()
 * ---------------------------------
 * displays the updated breakdown snapshot results
 **/
void print_tcp_breakdown_results(WINDOW * win, int view, int select_node, int offset)
{
  int i;
  int max_view = (LINES /2) - 10;
  int last_item = 0;

  bss_t * ap = get_detailed_snapshot()->bss_list_top;
  bss_node_t *node;
  tcptable_t * tcp_entry;

  if ((ap == NULL)||(select_node == 0)) return;

  wattrset(win, STDATTR);
  node = bss_get_node(ap, select_node);

  if (node == NULL){
    mvwprintw(win, LINES/2 - 4, 4, "ERROR!");
    return;
  }
  
  if ((offset + max_view) < node->tcp_connections){
    last_item = offset + max_view;
    mvwprintw(win, LINES/2 - 4, 4, ">> More >> ");
  }
  else{
    last_item = node->tcp_connections;
    mvwprintw(win, LINES/2 - 4, 4, "-- End  --");
  }
  tcp_entry = get_tcp_table_entry(node, offset);

  for (i = offset; i < last_item; i++){
    if (tcp_entry == NULL) break;
    print_tcp_breakdown_row(win, i + 5 - offset, tcp_entry, view);
    tcp_entry = tcp_entry->next;
  }
  
  update_panels();
  doupdate();
}

/////////////////////////////////////////////////////////////////
//  Available wireless node list routines
/////////////////////////////////////////////////////////////////

void print_tcp_nodelist_labels(WINDOW ** win, PANEL ** panel)
{
  *win = newwin(LINES / 2 - 3, COLS - 32, LINES / 2 + 1, 31);
  *panel = new_panel(*win);
  wattrset(*win, BOXATTR);
  colorwin(*win);
  box(*win, ACS_VLINE, ACS_HLINE);
  mvwprintw(*win, 0, 2, " Available Wireless Nodes ");

  wattrset(*win, BOXATTR);
  mvwprintw(*win, 2, 4, "ID");
  mvwprintw(*win, 2, 10, "MAC Address");
  mvwprintw(*win, 2, 30, "IP Address");
  mvwprintw(*win, 2, 48, "TCP Conns");
  mvwprintw(*win, 2, 60, "Avg. Signal Strength");

  update_panels();
  doupdate();
}

/**
 * print_tcp_nodelist_row()
 * ---------------------------
 * helper function in printing out individual rows (network/transport)
 * type protocols.
 **/
void print_tcp_nodelist_row(WINDOW *win, int row, bss_node_t *node, int id, int selected)
{
  if (selected){
    wattrset(win, ACTIVEATTR);
    mvwprintw(win, row, 2, ">");
    wattrset(win, STDATTR);
    mvwprintw(win, row, 4, "%02d", id);
    mvwprintw(win, row, 10, hexdump((__u8*)&node->mac_addr,6));
    mvwprintw(win, row, 30, "                 ");
    mvwprintw(win, row, 30, "%s", inet_ntoa(node->ip_addr));
    mvwprintw(win, row, 48, "%6d", node->tcp_connections);
    mvwprintw(win, row, 65, "%6.2f", node->avg_signal_str);
  }
  else{
    wattrset(win, HIGHATTR);
    mvwprintw(win, row, 2, " ");
    mvwprintw(win, row, 4, "%02d", id);
    mvwprintw(win, row, 10, hexdump((__u8*)&node->mac_addr,6));
    mvwprintw(win, row, 30, "                 ");
    mvwprintw(win, row, 30, "%s", inet_ntoa(node->ip_addr));
    mvwprintw(win, row, 48, "%6d", node->tcp_connections);
    mvwprintw(win, row, 65, "%-6.2f", node->avg_signal_str);
  }
}

/**
 * print_tcp_nodelist_results()
 * ---------------------------------
 * displays the updated wireless node list results
 **/
void print_tcp_nodelist_results(WINDOW * win, int * selected_node, int offset)
{
  int i;
  int max_view = win->_maxy - 6;
  int last_item = 0;
  int selected = 0;
  
  bss_t * ap = get_detailed_snapshot()->bss_list_top;
  bss_node_t * node;
  
  if (ap == NULL)
    return;
  
  wattrset(win, STDATTR);

  if (ap->num < 2){
    mvwprintw(win, 4, (win->_maxx - 26) /2, "No Detected Wireless Nodes!");
    return;
  }

  node = bss_get_node(ap, offset);
  
  if (*selected_node == 0){
    *selected_node = 1;
  }
  mvwprintw(win, 4, (win->_maxx - 26) /2, "                            ");
  
  if ((offset + max_view) < ap->num){
    last_item = offset + max_view;
    mvwprintw(win, win->_maxy - 1, 4, ">> More >>");
  }
  else{
    last_item = ap->num;
    mvwprintw(win, win->_maxy - 1, 4, "-- End  --");
  }
  for (i = offset; i < last_item; i++){
    if (node == NULL) break;
    if (i == *selected_node){
      selected = 1;
    }
    else{
      selected = 0;
    }
    print_tcp_nodelist_row(win, i + 4 - offset, node, i, selected);
    node = node->next;
  }

  update_panels();
  doupdate();
}

///////////////////////////////////////////////////////////////////
//  scrolling routines
///////////////////////////////////////////////////////////////////

void scrollbreakdownwin(int direction, int select_node, int * offset)
{
  int max_view = LINES/2 - 9;
  
  bss_node_t *node;
  bss_t * ap = get_detailed_snapshot()->bss_list_top;

  if ((ap == NULL)||(select_node == 0)) return;

  node = bss_get_node(ap, select_node);
  switch (direction)
    {
    case SCROLLUP:
      if (*offset > 0){
	*offset = *offset - 1;
      }
      break;
    case SCROLLDOWN:
      if (*offset <= (node->tcp_connections - max_view)){
	*offset = *offset + 1;
      }
      break;
    }
}

void scrollnodelistwin(WINDOW *win, int direction, int * select_node, int * list_pos)
{
  int max_view = win->_maxy - 6;
  
  bss_t * ap = get_detailed_snapshot()->bss_list_top;

  if ((ap == NULL)||(*select_node == 0)) return;
  
  switch (direction)
    {
    case SCROLLUP:
      if (*select_node > 1){
	*select_node = *select_node - 1;
      }
      if (*list_pos == 1) break;
      if (*select_node < *list_pos){
	*list_pos = *list_pos - 1;
      }
      break;
    case SCROLLDOWN:
      if (*select_node < (ap->num - 1)){
	*select_node = *select_node + 1;
      }
      if (*list_pos == (ap->num - max_view)) break;
      if (*select_node > (*list_pos + max_view  - 1)){
	*list_pos = *list_pos + 1;
      }
      break;
    }
}

/**
 * reset_active_win()
 * ------------------
 * handy function for turning "ACTIVE" status on & off on a given
 * window.
 **/
void reset_active_win(WINDOW *win, int toggle)
{
  if (toggle){
    wattrset(win, ACTIVEATTR);
    mvwprintw(win, win->_maxy, win->_maxx - 10, " ACTIVE ");    
  }
  else{
    wattrset(win, BOXATTR);
    wmove(win, win->_maxy, win->_maxx - 10);
    whline(win, ACS_HLINE, 8);	    
  }
}

  
////////////////////////////////////////////////////////////////////
//  MAIN tcp analysis GUI interface
///////////////////////////////////////////////////////////////////

int start_tcp_analysis_mon(struct SETTINGS* mySettings)
{
  WINDOW * statwin;
  WINDOW * msgwin;
  WINDOW * scanwin;
  WINDOW * breakwin;
  WINDOW * listwin;
  WINDOW * capturewin;

  PANEL * statpanel;
  PANEL * msgpanel;
  PANEL * scanpanel;
  PANEL * breakpanel;
  PANEL * listpanel;
  PANEL * capturepanel;

  int exitloop;

  int first_instance = 1;
  int paused = 0; // used to pause screen
  
  int ch;
  int break_pos = 0; // used to mark breakdown position
  int list_pos = 1; // used to mark list position
  
  int nodelist_win = 1;
  int curr_view = 0;
  int select_node = 0;
  int node_count = 0;  // tracks whether there's change
  
  char elapsed[10];
  
  struct timeval tv_start;
  struct timeval tv_curr;
  struct timeval tv_old;
  struct timeval tv_new;

  print_tcp_stat_screen(&statwin,&statpanel, mySettings->card_type, mySettings->interface);
  print_tcp_activity_overview_labels(&scanwin,&scanpanel, curr_view);
  print_tcp_breakdown_labels(&breakwin,&breakpanel, curr_view);
  print_tcp_nodelist_labels(&listwin,&listpanel);
  if (mySettings->capture_mode == CAPTURE_MODE_PLAYBACK)
    make_capture_controls(&capturewin, &capturepanel);
  
  update_panels();
  doupdate();

  move(LINES - 1, 1);
  pausekeyhelp();
  viewkeyhelp();
  changewinkeyhelp();
  scrollkeyhelp();
  stdexitkeyhelp();
  update_panels();
  doupdate();

  leaveok(statwin, TRUE);
  exitloop = 0;

  /** initialize listwin to have ACTIVE key focus **/
  reset_active_win(listwin, 1);
  
  gettimeofday(&tv_start,NULL);
  tv_old = tv_start;

  /*
   * Data Display Loop
   */
  while ((!exitloop) && (!sysexit)) {
    ch = ERR;
    if (check_for_keystroke() != ERR)
      ch = wgetch(statwin);
    if (ch != ERR) {
      switch (ch)
	{
	case KEY_UP:
	  if (!nodelist_win)
	    scrollbreakdownwin(SCROLLUP, select_node, &break_pos);
	  else{
	    scrollnodelistwin(listwin, SCROLLUP, &select_node, &list_pos);
	    /**after changing wireless node, reset the breakdown
	       window **/
	    del_panel(breakpanel);
	    delwin(breakwin);
	    update_panels();
	    doupdate();

	    print_tcp_breakdown_labels(&breakwin,&breakpanel, curr_view);
	    if (nodelist_win){
	      reset_active_win(breakwin,0);
	      reset_active_win(listwin,1);
	    }
	    else{
	      reset_active_win(listwin,0);
	      reset_active_win(breakwin,1);
	    }
	    break_pos = 0;
	  }
	  break;
	case KEY_DOWN:
	  if (!nodelist_win)
	    scrollbreakdownwin(SCROLLDOWN, select_node, &break_pos);
	  else{
	    scrollnodelistwin(listwin, SCROLLDOWN, &select_node, &list_pos);
	    /**after changing wireless node, reset the breakdown
	       window **/
	    del_panel(breakpanel);
	    delwin(breakwin);
	    update_panels();
	    doupdate();

	    print_tcp_breakdown_labels(&breakwin,&breakpanel, curr_view);
	    if (nodelist_win){
	      reset_active_win(breakwin,0);
	      reset_active_win(listwin,1);
	    }
	    else{
	      reset_active_win(listwin,0);
	      reset_active_win(breakwin,1);
	    }
	    break_pos = 0;
	  }
	  break;
	case 12:
	case 'l':
	case 'L':
	  refresh_screen();
	  break;
	case 'p':
	case 'P':
	  if (mySettings->capture_mode == CAPTURE_MODE_PLAYBACK){
	    parse_capture_key(mySettings, ch);
	    break;
	  }
	  switch (paused)
	    {
	    case 0:
	      show_paused_win(&msgwin,&msgpanel,
		    "Analysis PAUSED...", "P-continue | X-Exit");
	      update_panels();
	      doupdate();
	      paused = 1;
	      break;
	    case 1:
	      del_panel(msgpanel);
	      delwin(msgwin);
	      update_panels();
	      doupdate();
	      refresh_screen();
	      paused = 0;
	      break;
	    }
	  break;
	case 'v':
	case 'V':
	  del_panel(breakpanel);
	  delwin(breakwin);
	  if (curr_view == PERF_BANDWIDTH){
	    curr_view = CONNECTIONS;
	  }
	  else{
	    curr_view++;
	  }
	  print_tcp_breakdown_labels(&breakwin,&breakpanel, curr_view);
	  if (nodelist_win){
	    reset_active_win(breakwin,0);
	    reset_active_win(listwin,1);
	  }
	  else{
	    reset_active_win(listwin,0);
	    reset_active_win(breakwin,1);
	  }
	  update_panels();
	  doupdate();
	  break;
	case 'w':
	case 'W':
	  if (nodelist_win){
	    nodelist_win = 0;
	    reset_active_win(listwin,0);
	    reset_active_win(breakwin,1);
	  }
	  else{
	    nodelist_win = 1;
	    reset_active_win(breakwin,0);
	    reset_active_win(listwin,1);
	  }
	  break;
	case 'Q':
	case 'q':
	case 'X':
	case 'x':
	case 24:
	case 27:
	  if (paused){
	    del_panel(msgpanel);
	    delwin(msgwin);
	  }
	  exitloop = 1;
	  break;
	default:
	  if (mySettings->capture_mode == CAPTURE_MODE_PLAYBACK){
	    parse_capture_key(mySettings, ch);
	  }
	  break;
	}	  
    }
    if(!paused){
      gettimeofday(&tv_new, NULL);

      if (GUI_DEBUG) fprintf(stderr,"doing packet stuff\n");

      /**
       * if it is first instance, and we haven't found a base
       * station yet, then just loop on, waiting for perhaps some
       * keystroke that will find a base channel for us...
       **/
      if (first_instance){
	if (get_detailed_snapshot()->bss_list_top != NULL){
	  first_instance = 0;
	}
	else{
	  continue;
	}
      }

      print_tcp_activity_overview_results(scanwin, select_node, curr_view);
      print_tcp_breakdown_results(breakwin, curr_view, select_node, break_pos);
      print_tcp_nodelist_results(listwin, &select_node, list_pos);      

      if (get_detailed_snapshot()->bss_list_top->num != node_count){
	del_panel(breakpanel);
	delwin(breakwin);
	del_panel(listpanel);
	delwin(listwin);
	if (mySettings->capture_mode == CAPTURE_MODE_PLAYBACK){
	  del_panel(capturepanel);
	  delwin(capturewin);
	}
	update_panels();
	doupdate();
	
	print_tcp_breakdown_labels(&breakwin,&breakpanel, curr_view);
	print_tcp_nodelist_labels(&listwin,&listpanel);
	if (nodelist_win){
	  reset_active_win(breakwin,0);
	  reset_active_win(listwin,1);
	}
	else{
	  reset_active_win(listwin,0);
	  reset_active_win(breakwin,1);
	}
	if (mySettings->capture_mode == CAPTURE_MODE_PLAYBACK)
	  make_capture_controls(&capturewin, &capturepanel);
	node_count = get_detailed_snapshot()->bss_list_top->num;
	if (node_count == 1){
	  del_panel(scanpanel);
	  delwin(scanwin);
	  update_panels();
	  doupdate();

	  print_tcp_activity_overview_labels(&scanwin,&scanpanel, curr_view);
	  select_node = 0;
	}
      }
      
      if (mySettings->capture_mode == CAPTURE_MODE_PLAYBACK)
	print_capture_update(capturewin, mySettings);
      
      wattrset(scanwin, HIGHATTR);
      gettimeofday(&tv_curr, NULL);
      get_elapsed_time(&tv_curr, &tv_start, elapsed);
      mvwprintw(scanwin, LINES - 7, 15, "%s", elapsed);
    }
  } // end loop
  del_panel(statpanel);
  delwin(statwin);
  del_panel(scanpanel);
  delwin(scanwin);
  del_panel(breakpanel);
  delwin(breakwin);
  del_panel(listpanel);
  delwin(listwin);
  if (mySettings->capture_mode == CAPTURE_MODE_PLAYBACK){
    del_panel(capturepanel);
    delwin(capturewin);
  }

  update_panels();
  doupdate();
  if (sysexit){
    if (paused){
      del_panel(msgpanel);
      delwin(msgwin);
    }
    sysexit = 0;
    return (0);
  }
  else{
    return (1);
  }
}
