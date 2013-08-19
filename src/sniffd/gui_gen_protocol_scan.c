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
 **  gui_gen_protocol_scan.c
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
#include <pthread.h>

#include "definition.h"
#include "sniff_include.h"

extern int GUI_DEBUG;

/**
 * print_stat_screen()
 * -------------------
 * displays the main background screen
 **/
void print_proto_stat_screen(WINDOW ** statwin, PANEL ** statpanel, int card, char *iface)
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
    wprintw(*statwin, " General Protocol Scanning: listening using Cisco Aironet (%s) ", iface);
  else if (card == PRISMII)
    wprintw(*statwin, " General Protocol Scanning: listening using PrismII-compatible (%s) ", iface);
  else if (card == HOSTAP)
    wprintw(*statwin, " General Protocol Scanning: listening using HostAP driver (%s) ", iface);
  else if (card == HERMES)
    wprintw(*statwin, " General Protocol Scanning: listening using Hermes-compatible (%s) ", iface);
  else if (card == WLANNG)
    wprintw(*statwin, " General Protocol Scanning: listening using Wlan-ng driver (%s) ", iface);
  wattrset(*statwin, STDATTR);
  update_panels();
  doupdate();
}

///////////////////////////////////////////////////////////////////////////////////
//  ACTIVITY OVERVIEW routines
///////////////////////////////////////////////////////////////////////////////////

/**
 * print_proto_activity_overview_labels()
 * --------------------------------
 * displays the Activity Overview window, and prints the labels
 * associated with it.
 **/
void print_proto_activity_overview_labels(WINDOW ** scanwin, PANEL ** scanpanel, int highlight)
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
  mvwprintw(*scanwin, 4, 3, "SSID: ");
  mvwprintw(*scanwin, 5, 3, "BSSID: ");
  mvwprintw(*scanwin, 6, 3, "WEP: ");
  mvwprintw(*scanwin, 7, 3, "Channel:");

  wattrset(*scanwin, ACTIVEATTR);
  mvwprintw(*scanwin, 10, 2, "Usage Rating (x/overall)");

  wattrset(*scanwin, BOXATTR);
  mvwprintw(*scanwin, 12, 3, "MAC Layer (802.11b)");
  mvwprintw(*scanwin, 17, 3, "Network Layer");
  mvwprintw(*scanwin, 22, 3, "Transport Layer");
  mvwprintw(*scanwin, 28, 3, "Background Traffic");
  
  wattrset(*scanwin, STDATTR);  
  mvwprintw(*scanwin, 13, 5, "Management: ");
  mvwprintw(*scanwin, 14, 5, "Control:    ");
  mvwprintw(*scanwin, 15, 5, "Data: ");

  mvwprintw(*scanwin, 18, 5, "IP:         ");
  mvwprintw(*scanwin, 19, 5, "IPv6:       ");
  mvwprintw(*scanwin, 20, 5, "Other:      ");

  mvwprintw(*scanwin, 23, 5, "TCP:        ");
  mvwprintw(*scanwin, 24, 5, "UDP:        ");
  mvwprintw(*scanwin, 25, 5, "ICMP:       ");
  mvwprintw(*scanwin, 26, 5, "Other:      ");

  mvwprintw(*scanwin, 29, 5, "Noise:      ");

  wattrset(*scanwin, ACTIVEATTR);
  mvwprintw(*scanwin, 32, 2, "Overall Bandwidth");
  wattrset(*scanwin, STDATTR);
  mvwprintw(*scanwin, 34, 3, "Rate:       ");
  
  mvwprintw(*scanwin, LINES - 7, 2, "Elapsed: "); 
  
  update_panels();
  doupdate();
}

/**
 * print_proto_activity_overview_results()
 * ---------------------------------
 * displays the updated activity overview snapshot results
 **/
void print_proto_activity_overview_results(WINDOW * win)
{
  bss_t * ap = get_detailed_snapshot()->bss_list_top;
  if (ap == NULL)
    return;
  
  wattrset(win, HIGHATTR);
  /** access point info **/  
  mvwprintw(win, 4, 10, ap->ssid);
  mvwprintw(win, 5, 10, hexdump((__u8*)&ap->bssid,6));
  mvwprintw(win, 6, 10, "%s", ap->wep_status ? "encrypted " : "opensystem");
  mvwprintw(win, 7, 13, "%02d", ap->channel);

  /** usage rating **/
  /** MAC layer **/
  mvwprintw(win, 13, 18, "%6.2f %%  ", ap->mgmt_data.bndwth.curr/
	    (ap->bndwth.curr * 1000) *100);
  mvwprintw(win, 14, 18, "%6.2f %%  ", ap->ctrl_data.bndwth.curr/
	    (ap->bndwth.curr * 1000) *100);
  mvwprintw(win, 15, 18, "%6.2f %%  ",
	    (ap->normal_data.bndwth.curr - ap->normal_data.extband.curr)/
	    (ap->bndwth.curr) * 100);  

  /** network layer **/
  mvwprintw(win, 18, 18, "%6.2f %%  ", ap->network_data.ip.band.curr/
	    (ap->bndwth.curr * 1000) *100);
  mvwprintw(win, 19, 18, "%6.2f %%  ", ap->network_data.ipv6.band.curr/
	    (ap->bndwth.curr * 1000) *100);
  mvwprintw(win, 20, 18, "%6.2f %%  ", ap->network_data.other.band.curr/
	    (ap->bndwth.curr * 1000) *100);

  /** transport layer **/
  mvwprintw(win, 23, 18, "%6.2f %%  ", ap->transport_data.tcp.band.curr/
	    (ap->bndwth.curr * 1000) *100);
  mvwprintw(win, 24, 18, "%6.2f %%  ", ap->transport_data.udp.band.curr/
	    (ap->bndwth.curr * 1000) *100);
  mvwprintw(win, 25, 18, "%6.2f %%  ", ap->transport_data.icmp.band.curr/
	    (ap->bndwth.curr * 1000) *100);
  mvwprintw(win, 26, 18, "%6.2f %%  ", ap->transport_data.other.band.curr/
	    (ap->bndwth.curr * 1000) *100);

  /** background traffic **/
  mvwprintw(win, 29, 18, "%6.2f %%  ", ap->normal_data.extband.curr/
	    (ap->bndwth.curr) * 100);

  /** overall bandwidth **/
  mvwprintw(win, 34, 10, "%7.3f Mbps", ap->bndwth.curr);
  
  update_panels();
  doupdate();
}

//////////////////////////////////////////////////////////////////////////////////
//  DETAILED PROTOCOL BREAKDOWN routines
//////////////////////////////////////////////////////////////////////////////////

void print_proto_breakdown_labels(WINDOW ** breakwin, PANEL ** breakpanel)
{
  *breakwin = newwin(LINES / 2 - 1, COLS - 32, 3, 31);
  *breakpanel = new_panel(*breakwin);
  wattrset(*breakwin, BOXATTR);
  colorwin(*breakwin);
  box(*breakwin, ACS_VLINE, ACS_HLINE);
  mvwprintw(*breakwin, 0, 2, " Internal Usage Breakdown ");

  wattrset(*breakwin, BOXATTR);
  mvwprintw(*breakwin, 2, 17, "    Incoming");
  mvwprintw(*breakwin, 3, 17, " Pkts");
  mvwprintw(*breakwin, 3, 27, "Bytes");
  mvwprintw(*breakwin, 2, 34, "    Outgoing");
  mvwprintw(*breakwin, 3, 34, " Pkts");
  mvwprintw(*breakwin, 3, 44, "Bytes");
  mvwprintw(*breakwin, 2, 51, "      Total");
  mvwprintw(*breakwin, 3, 51, " Pkts");
  mvwprintw(*breakwin, 3, 61, "Bytes");
  mvwprintw(*breakwin, 2, 72, " Overall");
  mvwprintw(*breakwin, 3, 72, "   Rates");

  wattrset(*breakwin, ACTIVEATTR);
  mvwprintw(*breakwin, 4, 2, "MAC Layer");
  mvwprintw(*breakwin, 9, 2, "Network Layer");
  mvwprintw(*breakwin, 14, 2, "Transport Layer");

  wattrset(*breakwin, STDATTR);
  mvwprintw(*breakwin, 5, 4, "Management:");
  mvwprintw(*breakwin, 6, 4, "Control:   ");
  mvwprintw(*breakwin, 7, 4, "Data:");

  mvwprintw(*breakwin, 10, 4, "IP:        ");
  mvwprintw(*breakwin, 11, 4, "IPv6:      ");
  mvwprintw(*breakwin, 12, 4, "Other:     ");

  mvwprintw(*breakwin, 15, 4, "TCP:       ");
  mvwprintw(*breakwin, 16, 4, "UDP:       ");
  mvwprintw(*breakwin, 17, 4, "ICMP:      ");
  mvwprintw(*breakwin, 18, 4, "Other:     ");

  update_panels();
  doupdate();
}

/**
 * print_proto_breakdown_row()
 * ---------------------------
 * helper function in printing out individual rows (network/transport)
 * type protocols.
 **/
void print_proto_breakdown_row(WINDOW *win, int row, proto_info_t *proto)
{
  mvwprintw(win, row, 15, "%7d", proto->in_count );
  mvwprintw(win, row, 22, "%10d", proto->in_byte );
  mvwprintw(win, row, 32, "%7d", proto->out_count );
  mvwprintw(win, row, 39, "%10d", proto->out_byte );
  mvwprintw(win, row, 49, "%7d", proto->count );
  mvwprintw(win, row, 56, "%10d", proto->byte );
  mvwprintw(win, row, 68, "%7.2f Kbps", proto->band.curr );  
}

/**
 * print_proto_breakdown_results()
 * ---------------------------------
 * displays the updated breakdown snapshot results
 **/
void print_proto_breakdown_results(WINDOW * win)
{
  void * temp;

  bss_t * ap = get_detailed_snapshot()->bss_list_top;
  if (ap == NULL)
    return;
  
  wattrset(win, HIGHATTR);
  temp = (void *) &ap->mgmt_data;
  mvwprintw(win, 5, 20, "--");
  mvwprintw(win, 5, 30, "--");
  mvwprintw(win, 5, 37, "--");
  mvwprintw(win, 5, 47, "--");
  mvwprintw(win, 5, 49, "%7d", ((mgmt_t *)temp)->mgmt_count );
  mvwprintw(win, 5, 56, "%10d", ((mgmt_t *)temp)->mgmt_byte );
  mvwprintw(win, 5, 68, "%7.2f Kbps", ((mgmt_t *)temp)->bndwth.curr ); 

  temp = (void *) &ap->ctrl_data;
  mvwprintw(win, 6, 20, "--");
  mvwprintw(win, 6, 30, "--");
  mvwprintw(win, 6, 37, "--");
  mvwprintw(win, 6, 47, "--");
  mvwprintw(win, 6, 49, "%7d", ((control_t *)temp)->control_count );
  mvwprintw(win, 6, 56, "%10d", ((control_t *)temp)->control_byte );
  mvwprintw(win, 6, 68, "%7.2f Kbps", ((control_t *)temp)->bndwth.curr );

  temp = (void *) &ap->normal_data;
  mvwprintw(win, 7, 20, "--");
  mvwprintw(win, 7, 30, "--");
  mvwprintw(win, 7, 37, "--");
  mvwprintw(win, 7, 47, "--");
  mvwprintw(win, 7, 49, "%7d", ((data_t *)temp)->internal_count );
  mvwprintw(win, 7, 56, "%10d", ((data_t *)temp)->internal_byte );
  mvwprintw(win, 7, 68, "%7.2f Kbps", (ap->normal_data.bndwth.curr - ap->normal_data.extband.curr)* 1000);

  /** network layer data **/
  print_proto_breakdown_row(win, 10, &ap->network_data.ip);
  print_proto_breakdown_row(win, 11, &ap->network_data.ipv6);
  print_proto_breakdown_row(win, 12, &ap->network_data.other);

  /** transport layer data **/
  print_proto_breakdown_row(win, 15, &ap->transport_data.tcp);
  print_proto_breakdown_row(win, 16, &ap->transport_data.udp);
  print_proto_breakdown_row(win, 17, &ap->transport_data.icmp);
  print_proto_breakdown_row(win, 18, &ap->transport_data.other);
  
  update_panels();
  doupdate();
}

/////////////////////////////////////////////////////////////////
//  Background Traffic details routines
/////////////////////////////////////////////////////////////////

void print_proto_background_labels(WINDOW ** bgwin, PANEL ** bgpanel)
{
  *bgwin = newwin(LINES / 2 - 3, COLS - 32, LINES / 2 + 2, 31);
  *bgpanel = new_panel(*bgwin);
  wattrset(*bgwin, BOXATTR);
  colorwin(*bgwin);
  box(*bgwin, ACS_VLINE, ACS_HLINE);
  mvwprintw(*bgwin, 0, 2, " Background Traffic Breakdown ");

  wattrset(*bgwin, BOXATTR);
  mvwprintw(*bgwin, 2, 22, "   Total");
  mvwprintw(*bgwin, 3, 22, " Packets");
  mvwprintw(*bgwin, 2, 32, "   Total");
  mvwprintw(*bgwin, 3, 32, "   Bytes");
  mvwprintw(*bgwin, 2, 47, " Overall");
  mvwprintw(*bgwin, 3, 47, "   Rates");

  wattrset(*bgwin, ACTIVEATTR);
  mvwprintw(*bgwin, 4, 2, "MAC Layer");
  mvwprintw(*bgwin, 7, 2, "Network Layer");
  mvwprintw(*bgwin, 12, 2, "Transport Layer");

  wattrset(*bgwin, STDATTR);
  mvwprintw(*bgwin, 5, 4, "Data:      ");
  
  mvwprintw(*bgwin, 8, 4, "IP:        ");
  mvwprintw(*bgwin, 9, 4, "IPv6:      ");
  mvwprintw(*bgwin, 10, 4, "Other:     ");

  mvwprintw(*bgwin, 13, 4, "TCP:       ");
  mvwprintw(*bgwin, 14, 4, "UDP:       ");
  mvwprintw(*bgwin, 15, 4, "ICMP:      ");
  mvwprintw(*bgwin, 16, 4, "Other:     ");

  update_panels();
  doupdate();
}

/**
 * print_proto_background_row()
 * ---------------------------
 * helper function in printing out individual rows (network/transport)
 * type protocols.
 **/
void print_proto_background_row(WINDOW *win, int row, proto_info_t *proto)
{
  mvwprintw(win, row, 20, "%10d", proto->ext_count );
  mvwprintw(win, row, 30, "%10d", proto->ext_byte );
  mvwprintw(win, row, 45, "%7.2f Kbps", proto->extband.curr );  
}

/**
 * print_proto_background_results()
 * ---------------------------------
 * displays the updated breakdown snapshot results
 **/
void print_proto_background_results(WINDOW * win)
{
  void * temp;

  bss_t * ap = get_detailed_snapshot()->bss_list_top;
  if (ap == NULL)
    return;
  
  wattrset(win, HIGHATTR);

  temp = (void *) &ap->normal_data;
  mvwprintw(win, 5, 20, "%10d", ((data_t *)temp)->external_count );
  mvwprintw(win, 5, 30, "%10d", ((data_t *)temp)->external_byte );
  mvwprintw(win, 5, 45, "%7.2f Kbps", (ap->normal_data.extband.curr)* 1000);

  /** network layer data **/
  print_proto_background_row(win, 8, &ap->network_data.ip);
  print_proto_background_row(win, 9, &ap->network_data.ipv6);
  print_proto_background_row(win, 10, &ap->network_data.other);

  /** transport layer data **/
  print_proto_background_row(win, 13, &ap->transport_data.tcp);
  print_proto_background_row(win, 14, &ap->transport_data.udp);
  print_proto_background_row(win, 15, &ap->transport_data.icmp);
  print_proto_background_row(win, 16, &ap->transport_data.other);
  
  update_panels();
  doupdate();
}
  
////////////////////////////////////////////////////////////////////
//  MAIN general protocol analysis GUI interface
///////////////////////////////////////////////////////////////////

int start_gen_proto_mon(struct SETTINGS* mySettings)
{
  WINDOW * statwin;
  WINDOW * msgwin;
  WINDOW * scanwin;
  WINDOW * breakwin;
  WINDOW * bgwin;
  WINDOW * capturewin;
  
  PANEL * statpanel;
  PANEL * msgpanel;
  PANEL * scanpanel;
  PANEL * breakpanel;
  PANEL * bgpanel;
  PANEL * capturepanel;

  int exitloop;

  int first_instance = 1;
  int paused = 0; // used to pause screen
  
  int ch;

  char elapsed[10];
  
  struct timeval tv_start;
  struct timeval tv_curr;
  struct timeval tv_old;
  struct timeval tv_new;

  print_proto_stat_screen(&statwin,&statpanel, mySettings->card_type, mySettings->interface);
  print_proto_activity_overview_labels(&scanwin,&scanpanel, 0);
  print_proto_breakdown_labels(&breakwin,&breakpanel);
  print_proto_background_labels(&bgwin,&bgpanel);

  if (mySettings->capture_mode == CAPTURE_MODE_PLAYBACK)
    make_capture_controls(&capturewin, &capturepanel);
  
  update_panels();
  doupdate();

  move(LINES - 1, 1);
  pausekeyhelp();
  stdexitkeyhelp();
  update_panels();
  doupdate();

  leaveok(statwin, TRUE);
  exitloop = 0;
  
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

      print_proto_activity_overview_results(scanwin);
      print_proto_breakdown_results(breakwin);
      print_proto_background_results(bgwin);
      
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
  del_panel(bgpanel);
  delwin(bgwin);
     
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
