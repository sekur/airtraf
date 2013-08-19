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
 **  gui_channel_scan.c
 **
 ****************************************************************
 **
 **   Copyright (c) 2001 all rights reserved.
 **
 **   Author: Peter K. Lee <pkl@duke.edu>
 **
 ***************************************************************/

#include <ncurses.h>
#include <panel.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "definition.h"
#include "sniff_include.h"

// Channel rotations to maximize hopping for US and international frequencies
// borrowed from kismet!
static int us_channels[] = {1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, -1};
static int intl_channels[] = {1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, -1};
static int *airtraf_channels;
static int chan_range = 0;

extern int GUI_DEBUG;
extern pthread_mutex_t engine_lock;
extern int channel_change;

/**
 * print_stat_screen()
 * -------------------
 * displays the main background screen
 **/
void print_stat_screen(WINDOW ** statwin, PANEL ** statpanel, int card, char *iface)
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
    wprintw(*statwin, " Channel Scanning: listening using Cisco Aironet (%s) ", iface);
  else if (card == PRISMII)
    wprintw(*statwin, " Channel Scanning: listening using PrismII-compatible (%s) ", iface);
  else if (card == HOSTAP)
    wprintw(*statwin, " Channel Scanning: listening using Host-AP driver (%s) ", iface);
  else if (card == HERMES)
    wprintw(*statwin, " Channel Scanning: listening using Hermes-compatible (%s) ", iface);
  wattrset(*statwin, STDATTR);
  update_panels();
  doupdate();
}

///////////////////////////////////////////////////////////////////////////////////
//  ACTIVITY OVERVIEW routines
///////////////////////////////////////////////////////////////////////////////////

/**
 * print_activity_overview_labels()
 * --------------------------------
 * displays the Activity Overview window, and prints the labels
 * associated with it.
 **/
void print_activity_overview_labels(WINDOW ** scanwin, PANEL ** scanpanel)
{
  int i;
  
  *scanwin = newwin(LINES - 5, 25, 3, 1);
  *scanpanel = new_panel(*scanwin);

  wattrset(*scanwin, BOXATTR);
  colorwin(*scanwin);
  box(*scanwin, ACS_VLINE, ACS_HLINE);
  mvwprintw(*scanwin, 0, 2, " Activity Overview ");

  wattrset(*scanwin, STDATTR);
  mvwprintw(*scanwin, 2, 2, "Total Networks:");
  mvwprintw(*scanwin, 4, 2, "Scan Mode:");

  wattrset(*scanwin, STDATTR);
  mvwprintw(*scanwin, 7, 2, "Channel");
  mvwprintw(*scanwin, 7, 11, "APs");
  mvwprintw(*scanwin, 7, 16, "Packets");

  for (i = 1; i < chan_range+1; i++){
    wattrset(*scanwin, ACTIVEATTR);
    mvwprintw(*scanwin, i+8, 3, " %02d ", i);
  }

  wattrset(*scanwin, STDATTR);
  mvwprintw(*scanwin, LINES - 7, 2, "Elapsed: "); 
  
  update_panels();
  doupdate();
}

void print_activity_overview_label_update(WINDOW * scanwin, int highlight)
{
  int i;

  for (i = 1; i < chan_range+1; i++){
    wattrset(scanwin, ACTIVEATTR);
    if (i == highlight){
      wattrset(scanwin, ERRTXTATTR);
    }
    mvwprintw(scanwin, i+8, 3, " %02d ", i);
  }
}

/**
 * print_activity_overview_results()
 * ---------------------------------
 * displays the updated activity overview snapshot results
 **/
void print_activity_overview_results(WINDOW * win, int *total, int card)
{
  int i;
  int ap_count;
  int pkt_count;

  struct channel_overview *snapshot;
  struct access_point *ap;
  
  wattrset(win, HIGHATTR);
  snapshot = get_channel_snapshot();
  *total = snapshot->num_det_aps;
  
  mvwprintw(win, 2, 19, "%d", snapshot->num_det_aps);

  if (card == AIRONET){
    mvwprintw(win, 4, 14, "       ");
    mvwprintw(win, 4, 14, "Refresh");    
  }
  else if (pkt_card_is_chan_hop(card)){
    mvwprintw(win, 4, 14, "       ");
    mvwprintw(win, 4, 14, "Hopping");
  }
  else{
    mvwprintw(win, 4, 14, "       ");
    mvwprintw(win, 4, 14, "Unknown");
  }
  
  for(i = 1; i < chan_range+1; i++){
    ap_count = 0;
    pkt_count = 0;
    if ((ap = snapshot->all_chan[i]) != NULL){
      while (ap != NULL){
	ap_count++;
	pkt_count += ap->packet_count;
	ap = ap->next;
      }
      mvwprintw(win, i+8, 12, "   ");
      mvwprintw(win, i+8, 12, "%d", ap_count);
      mvwprintw(win, i+8, 15, "        ");
      mvwprintw(win, i+8, 15, "%7d", pkt_count);
    }
    else{
      mvwprintw(win, i+8, 12, "   ");
      mvwprintw(win, i+8, 12, "0");
      mvwprintw(win, i+8, 15, "        ");
      mvwprintw(win, i+8, 15, "%7d", 0);
    }
  }
  update_panels();
  doupdate();
}

//////////////////////////////////////////////////////////////////////////////////
//  DETAILED BREAKDOWN routines
//////////////////////////////////////////////////////////////////////////////////

void print_breakdown_labels(WINDOW ** breakwin, PANEL ** breakpanel)
{
  *breakwin = newwin(LINES - 20, COLS - 27, 3, 26);
  *breakpanel = new_panel(*breakwin);
  wattrset(*breakwin, BOXATTR);
  colorwin(*breakwin);
  box(*breakwin, ACS_VLINE, ACS_HLINE);
  mvwprintw(*breakwin, 0, 2, " Detailed Breakdown ");

  wattrset(*breakwin, STDATTR);
  mvwprintw(*breakwin, 2, 2, "CH");
  mvwprintw(*breakwin, 2, 6, "TYPE");
  mvwprintw(*breakwin, 2, 11, "SSID");
  mvwprintw(*breakwin, 2, 39, "BSSID");
  mvwprintw(*breakwin, 2, 53, "WEP");
  mvwprintw(*breakwin, 2, 60, "MGMT");
  mvwprintw(*breakwin, 2, 66, "CTRL");
  mvwprintw(*breakwin, 2, 73, "DATA");
  mvwprintw(*breakwin, 2, 79, "CRYPT");
  mvwprintw(*breakwin, 2, 86, "SIGNAL");
  
  update_panels();
  doupdate();
}

/**
 * print_breakdown_results()
 * ---------------------------------
 * displays the updated breakdown snapshot results
 **/
void print_breakdown_results(WINDOW * win, int offset)
{
  int i;
  int position = 0;
  int ap_counter = 0;
  int total;

  struct channel_overview *snapshot;
  struct access_point *ap;

  snapshot = get_channel_snapshot();

  wattrset(win, ACTIVEATTR);
  total = snapshot->num_det_aps;
  if ((total-offset) <= (LINES - 27)){
    mvwprintw(win, LINES - 22, 2, "-- End -- ");
  }
  else{
    mvwprintw(win, LINES - 22, 2, ">> More >>");
  }
  wattrset(win, HIGHATTR);
  for(i = 1; i < chan_range+1; i++){
    if ((ap = snapshot->all_chan[i]) != NULL){
      while (ap != NULL){
	ap_counter++;
	if ((offset < ap_counter)&&(position < (LINES - 27))){
	  position++;
	  switch (ap->status)
	    {
	    case AP_STATUS_NEW:
	    case AP_STATUS_RENEW:
	      wattrset(win, ALERTATTR);
	      break;
	    case AP_STATUS_ACTIVE:
	      wattrset(win, HIGHATTR);
	      break;
	    case AP_STATUS_INACTIVE:
	      wattrset(win, BOXATTR);
	      break;
	    }
	  mvwprintw(win, position+3, 2, "%02d", ap->channel);
	  switch(ap->traffic_type){
	  case p802_11b_ADHOC:
	    mvwprintw(win, position+3, 6, "AD-H ");
	    break;
	  case p802_11b_AP2STA:
	  case p802_11b_STA2AP:
	  case p802_11b_AP2AP:
	    mvwprintw(win, position+3, 6, " AP  ");
	    break;
	  default:
	    mvwprintw(win, position+3, 6, " --- ");
	    break;	    
	  }
	  mvwprintw(win, position+3, 11, "                                 ");
	  if (!strncmp(ap->ssid," ",32))
	    mvwprintw(win, position+3, 11, "<cloaked>");
	  else
	    mvwprintw(win, position+3, 11, ap->ssid);
	  mvwprintw(win, position+3, 39, hexdump((__u8*)&ap->bssid,6));
	  mvwprintw(win, position+3, 53, "%s", ap->wep_status ? "crypt" : "open   ");
	  mvwprintw(win, position+3, 59, "%5d", ap->mgmt_count);
	  mvwprintw(win, position+3, 65, "%4d", ap->ctrl_count);
	  mvwprintw(win, position+3, 71, "%6d", ap->data_count);
	  mvwprintw(win, position+3, 78, "%5d", ap->encrypt_count);
	  mvwprintw(win, position+3, 86, "%-6.1f", ap->signal_str);
	}
	ap = (struct access_point *)ap->next;
      }
    }
  }
  update_panels();
  doupdate();
}

/////////////////////////////////////////////////////////////////
//  STATUS update routines
/////////////////////////////////////////////////////////////////

/**
 * print_status_labels()
 * ---------------------
 * display the status window...
 **/
void print_status_labels(WINDOW ** borderwin, PANEL ** borderpanel)
{
  *borderwin = newwin(15, COLS - 27, LINES - 17, 26);
  *borderpanel = new_panel(*borderwin);
  wattrset(*borderwin, BOXATTR);
  colorwin(*borderwin);
  box(*borderwin, ACS_VLINE, ACS_HLINE);
  mvwprintw(*borderwin, 0, 2, " Current Status ");
  update_panels();
  doupdate();
}

void make_status_window(WINDOW ** statuswin, PANEL ** statuspanel)
{
  *statuswin = newwin(13, COLS - 28, LINES - 16, 27);
  *statuspanel = new_panel(*statuswin);
  wattrset(*statuswin, BOXATTR);
  colorwin(*statuswin);
  scrollok(*statuswin, 1);
  wattrset(*statuswin, HIGHATTR);
  update_panels();
  doupdate();
}

void fill_line_blank(WINDOW * win, int line)
{
  int i;
  for (i = 0; i < win->_maxx; i++)
    mvwprintw(win, line, i, " ");
}

void print_status_msg(WINDOW * statuswin, int *location, char * msg)
{
  void scrollstatuswin(WINDOW*,int);

  if (*location > 12){
    scrollstatuswin(statuswin, SCROLLUP);
    wmove(statuswin, 12, 0);
    fill_line_blank(statuswin, 12);
    mvwprintw(statuswin, 12, 2, msg);
  }
  else{
    wmove(statuswin, *location, 0);
    fill_line_blank(statuswin, *location);
    mvwprintw(statuswin, *location, 2, msg);    
  }
  *location = *location + 1;
  update_panels();
  doupdate();
}

void update_status_stats(WINDOW *statuswin, int *location, int * snap, int * redraw)
{
  int i;
  int ap_count;
  char message[100];
  
  struct channel_overview *snapshot;
  struct access_point *ap;
  
  snapshot = get_channel_snapshot();

  for(i = 1; i < chan_range+1; i++){
    ap_count = 0;
    if ((ap = snapshot->all_chan[i]) != NULL){
      while (ap != NULL){
	switch (ap->status)
	  {
	  case AP_STATUS_NEW:
	    if (!beep()) flash();
	    wattrset(statuswin, STDATTR);
	    snprintf(message,100,"Detected new network '%s' (%s) on Channel %02d",
		     ((strlen(ap->ssid)==1)&&(!strncmp(" ",ap->ssid,1))) ? "<cloaked>" : ap->ssid,
		     hexdump((__u8*)&ap->bssid,6), ap->channel);
	    print_status_msg(statuswin, location, message);
	    ap->status = AP_STATUS_ACTIVE;
	    break;
	  case AP_STATUS_RENEW:
	    if (!beep()) flash();
	    wattrset(statuswin, STDATTR);
	    snprintf(message,100,"Detected reactivated network '%s' (%s) on Channel %02d",
		     ap->ssid, hexdump((__u8*)&ap->bssid,6), ap->channel);
	    print_status_msg(statuswin, location, message);
	    ap->status = AP_STATUS_ACTIVE;
	    break; 
	  case AP_STATUS_MARK_INACTIVE:
	    wattrset(statuswin, STDATTR);
	    snprintf(message,100,"Marked inactive network '%s' (%s) on Channel %02d",
		     ap->ssid, hexdump((__u8*)&ap->bssid,6), ap->channel);
	    print_status_msg(statuswin, location, message);
	    ap->status = AP_STATUS_INACTIVE;
	    break;
	  }
      	ap_count++;
	ap = (struct access_point *)ap->next;
      }
    }
    if ( ap_count < snap[i]){
      wattrset(statuswin, ALERTATTR);
      print_status_msg(statuswin, location, "Removed inactive network from list...");
      *redraw = ENABLED;
    }
    snap[i] = ap_count;
  }
  wattrset(statuswin, HIGHATTR);
}

/**
 * show_scanning_win()
 * -------------------
 * Pop up "scanning" window, displaying the selected message
 **/
void show_scanning_win(WINDOW ** win, PANEL ** panel, char * message)
{
    *win = newwin(5, 50, (LINES - 5) / 2, (COLS - 50) / 2);
    *panel = new_panel(*win);

    wattrset(*win, ERRBOXATTR);
    colorwin(*win);
    box(*win, ACS_VLINE, ACS_HLINE);

    wattrset(*win, ERRTXTATTR);
    mvwprintw(*win, 1, 5, "%s", message);
    update_panels();
    doupdate();
}

///////////////////////////////////////////////////////////////////
//  scrolling routines
///////////////////////////////////////////////////////////////////

void scrollstatuswin(WINDOW *statuswin, int direction)
{
  if (direction == SCROLLUP) {
    wscrl(statuswin, 1);
    fill_line_blank(statuswin, 12);
  } else {
    wscrl(statuswin, -1);
    fill_line_blank(statuswin, 0);
  }
  update_panels();
  doupdate();
}

void scrollbreakwin(WINDOW *breakwin, int *offset, int total, int direction)
{
  if (direction == SCROLLDOWN) {
    if ((total-*offset) >= (LINES - 27)){
      *offset = *offset +1;
    }
 
  } else {
    if (*offset > 0){
      *offset = *offset - 1;
    }
  }
  update_panels();
  doupdate();
}
  
////////////////////////////////////////////////////////////////////
//  main aplist channel scanning routine
///////////////////////////////////////////////////////////////////

int start_ap_mon(struct SETTINGS* mySettings)
{
  WINDOW * statwin;
  WINDOW * msgwin;
  WINDOW * scanwin;
  WINDOW * breakwin;
  WINDOW * statusborder;
  WINDOW * statuswin;

  PANEL * statpanel;
  PANEL * msgpanel;
  PANEL * scanpanel;
  PANEL * breakpanel;
  PANEL * statusborderpanel;
  PANEL * statuspanel;

  int exitloop;
  int force_scan;
  
  int ch;
  int break_pos = 0;
  int total = 0;

  int curr_win = 0;
  int status_snap[15];
  int status_msg_count = 0;

  int redraw = DISABLED;
  
  int chan_status;
  int channel =1;
  char chan_msg[100];
  int wextok = 0;
  int resp;

  char elapsed[10];
  
  struct timeval tv_start;
  struct timeval tv_curr;
  struct timeval tv_old;
  struct timeval tv_new;

  float t_diff = 0;
  float t_clean_filter = 0;
  //  float channel_hop_interval = CHANNEL_HOP_INTERVAL;
  float channel_hop_interval = 2;

  bzero(status_snap, sizeof(int) *15);

  if (mySettings->card_type == AIRONET)
    channel_hop_interval = 10;
  
  print_stat_screen(&statwin,&statpanel, mySettings->card_type, mySettings->interface);
  print_activity_overview_labels(&scanwin,&scanpanel);
  print_breakdown_labels(&breakwin,&breakpanel);
  print_status_labels(&statusborder,&statusborderpanel);
  make_status_window(&statuswin,&statuspanel);
  print_status_msg(statuswin,&status_msg_count, "Performing Initial Channel Scan...");
  
  show_scanning_win(&msgwin,&msgpanel,
		    "Performing Initial Scan: please wait...");
  update_panels();
  doupdate();

  move(LINES - 1, 1);

  printkeyhelp("F", "-force new scan  ", stdscr, HIGHATTR, STATUSBARATTR);
  scrollkeyhelp();
  stdexitkeyhelp();
  update_panels();
  doupdate();

  leaveok(statwin, TRUE);
  exitloop = 0;
  force_scan = ENABLED;
  
  gettimeofday(&tv_start,NULL);
  tv_old = tv_start;

  if (pkt_card_is_chan_hop(mySettings->card_type)){
    channel = 1;
    channel_change = 1;
    pthread_mutex_lock(&engine_lock);
    
    if ((chan_status = select_channel(mySettings, channel)) < 1){
      pthread_mutex_unlock(&engine_lock);
      channel_change = 0;
      wextok = 0;
      force_scan = DISABLED;
      del_panel(breakpanel);
      delwin(breakwin);
      del_panel(msgpanel);
      delwin(msgwin);
      update_panels();
      doupdate();

      print_breakdown_labels(&breakwin, &breakpanel);
      
    REDISPLAY:
      errbox("No wireless extension support detected! (wrong interface?)",
	     "F-force retry | X-Exit menu", &resp);
      switch(resp)
	{
	case 'f':
	case 'F':
	  goto FORCE;
	  break;
	case 'x':
	case 'X':
	  exitloop=1;
	  break;
	default:
	  goto REDISPLAY;
	  break;
	}
    }
    else{
      // grab the range of the allowed channel spectrum
      chan_range = channel_range(mySettings);
      if (chan_range==14)
	airtraf_channels = intl_channels;
      else if (chan_range==11)
	airtraf_channels = us_channels;
      else
	airtraf_channels = NULL;
      pthread_mutex_unlock(&engine_lock);
      print_activity_overview_label_update(scanwin,0);	    
      channel_change = 0;
      wextok = 1;
    }
  }
  
  /*
   * Data Display Loop
   */
  while ((!exitloop) && (!sysexit)) {
    ch = ERR;
    if (check_for_keystroke() != ERR)
      ch = wgetch(statwin);
    if (ch != ERR) {
      if (!force_scan){
	switch (ch)
	  {
	  case KEY_UP:
	    if (curr_win)
	      scrollstatuswin(statuswin, SCROLLUP);
	    else{
	      if (break_pos > 0){
		break_pos--;
	      }
	      //scrollbreakwin(breakwin, break_pos, total, SCROLLUP);
	    }
	    break;
	  case KEY_DOWN:
	    if (curr_win)
	      scrollstatuswin(statuswin, SCROLLDOWN);
	    else{
	      if ((total-break_pos) > (LINES - 27)){
		break_pos++;
	      }
	      //scrollbreakwin(breakwin, &break_pos, total, SCROLLDOWN);
	    }
	     
	    break;
	  case 12:
	  case 'l':
	  case 'L':
	    refresh_screen();
	    break;
	  case 'f':
	  case 'F':
	  FORCE:
	    force_scan = ENABLED;
	    gettimeofday(&tv_old, NULL);
	    del_panel(scanpanel);
	    delwin(scanwin);
	    del_panel(breakpanel);
	    delwin(breakwin);
	    del_panel(statuspanel);
	    delwin(statuswin);
	    update_panels();
	    doupdate();
	    
  	    break_pos = 0;
	    status_msg_count = 0;
	    bzero(status_snap, sizeof(int) * 15);
	    print_activity_overview_labels(&scanwin,&scanpanel);
	    print_breakdown_labels(&breakwin,&breakpanel);
	    make_status_window(&statuswin,&statuspanel);
	    show_scanning_win(&msgwin, &msgpanel, "Forcing Re-Scan: please wait...");
	    print_status_msg(statuswin,&status_msg_count, "Channel Re-Scan Forced...");
	    free_channel_scan();
	    initialize_channel_scan();
	    
	    if (pkt_card_is_chan_hop(mySettings->card_type)){
	      channel = 1;
	      channel_change = 1;
	      pthread_mutex_lock(&engine_lock);
	      if ((chan_status = select_channel(mySettings, channel)) < 1){
		pthread_mutex_unlock(&engine_lock);
		channel_change = 0;
		wextok = 0;
		force_scan = DISABLED;
		del_panel(breakpanel);
		delwin(breakwin);
		del_panel(msgpanel);
		delwin(msgwin);
		update_panels();
		doupdate();
		print_breakdown_labels(&breakwin, &breakpanel);		
		errbox("Dude, it doesn't 'just' work because you force it! :) ",
		       ANYKEY_MSG, &resp);
		goto REDISPLAY;
	      }
	      else{
		pthread_mutex_unlock(&engine_lock);
		channel_change = 0;
		wextok = 1;
	      }
	    }	  
	    update_panels();
	    doupdate();
	    break;
	  case 'Q':
	  case 'q':
	  case 'X':
	  case 'x':
	  case 24:
	  case 27:
	    exitloop = 1;
	    break;
	  default:
	    break;
	  }	  
      }
      else{
	// ignore keystrokes...	
      }
    }
    if((pkt_card_is_chan_hop(mySettings->card_type))&&(!wextok)){
      continue;
    }
    if(force_scan){
      gettimeofday(&tv_new, NULL);      
      t_diff = get_time_diff(&tv_new, &tv_old);
 
      /** show progress... not necessary but looks nice!**/
      if (t_diff > CHANNEL_SCAN_INTERVAL){
	wattrset(msgwin, IPSTATLABELATTR);
	mvwprintw(msgwin, 3, (3*channel)+2, "   ");
	update_panels();
	doupdate();
	
	if (channel != chan_range){
	  channel++;
	  if (pkt_card_is_chan_hop(mySettings->card_type)){
	    channel_change = 1;
	    pthread_mutex_lock(&engine_lock);
	    if (airtraf_channels != NULL)
	      select_channel(mySettings, airtraf_channels[channel-1]);
	    else
	      select_channel(mySettings, channel);
	    pthread_mutex_unlock(&engine_lock);
	    channel_change = 0;
	  }
	  tv_old = tv_new;
	}
	else{
	  del_panel(breakpanel);
	  delwin(breakwin);
	  del_panel(msgpanel);
	  delwin(msgwin);
	  update_panels();
	  doupdate();
	  
	  print_breakdown_labels(&breakwin, &breakpanel);
	  print_activity_overview_results(scanwin, &total, mySettings->card_type);
	  print_breakdown_results(breakwin,break_pos);
	  update_status_stats(statuswin, &status_msg_count, status_snap, &redraw);
	  update_panels();
	  doupdate();
	  print_status_msg(statuswin, &status_msg_count, "Initial Channel Scan Complete!");
	  print_status_msg(statuswin, &status_msg_count, "Entering Continuous Scan Mode...");
	  update_panels();
	  doupdate();
	  
	  force_scan = DISABLED; 
	}
      }	
    }
    /** do continuous scanning & refresh otherwise **/
    else{
/*       if (mySettings->card_type == AIRONET){ */
/* 	print_activity_overview_results(scanwin, &total, mySettings->card_type); */
/* 	print_breakdown_results(breakwin, break_pos); */
/* 	update_status_stats(statuswin, &status_msg_count, status_snap, &redraw); */
/* 	wattrset(scanwin, HIGHATTR); */
/* 	gettimeofday(&tv_curr, NULL); */
/* 	get_elapsed_time(&tv_curr, &tv_start, elapsed); */
/* 	mvwprintw(scanwin, LINES - 7, 15, "%s", elapsed); */
/*       } */
      if (pkt_card_is_chan_hop(mySettings->card_type)){
	gettimeofday(&tv_new, NULL);      
	t_diff = get_time_diff(&tv_new, &tv_old);
	
 	if (t_diff > channel_hop_interval){
	  t_clean_filter += t_diff;
	  if (t_clean_filter > 5){
	    clean_filter();
	    t_clean_filter = 0;
	  }
	  if (channel != chan_range)
	    channel++;	
	  else{
	    channel = 1;
	    del_panel(scanpanel);
	    delwin(scanwin);
	    print_activity_overview_labels(&scanwin,&scanpanel);
	  }

	  channel_change = 1;
	  pthread_mutex_lock(&engine_lock);
	    if (airtraf_channels != NULL)
	      select_channel(mySettings, airtraf_channels[channel-1]);
	    else
	      select_channel(mySettings, channel);	  
	  pthread_mutex_unlock(&engine_lock);
	  channel_change = 0;
	  
	  memset(chan_msg, 0, sizeof(char)*100);
	  if (mySettings->card_type == AIRONET)
	    print_activity_overview_label_update(scanwin,0);	    
	  else if (chan_range == 14)
	    print_activity_overview_label_update(scanwin,intl_channels[channel-1]);
	  else if (chan_range == 11)
	    print_activity_overview_label_update(scanwin,us_channels[channel-1]);
	  else
	    print_activity_overview_label_update(scanwin,channel);

	  tv_old = tv_new;
	}
	print_activity_overview_results(scanwin, &total, mySettings->card_type);
	update_status_stats(statuswin, &status_msg_count, status_snap, &redraw);
	if (redraw == ENABLED){
	  del_panel(breakpanel);
	  delwin(breakwin);
	  update_panels();
	  doupdate();
	  print_breakdown_labels(&breakwin,&breakpanel);
	  redraw = DISABLED;
	}
	print_breakdown_results(breakwin, break_pos);
	
	wattrset(scanwin, HIGHATTR);
	gettimeofday(&tv_curr, NULL);
	get_elapsed_time(&tv_curr, &tv_start, elapsed);
	mvwprintw(scanwin, LINES - 7, 15, "%s", elapsed);
      }
    }
  } // end loop
  del_panel(statpanel);
  delwin(statwin);
  del_panel(scanpanel);
  delwin(scanwin);
  del_panel(breakpanel);
  delwin(breakwin);
  del_panel(statusborderpanel);
  delwin(statusborder);
  del_panel(statuspanel);
  delwin(statuswin);
  update_panels();
  doupdate();
  if (sysexit){
    if (force_scan){
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
