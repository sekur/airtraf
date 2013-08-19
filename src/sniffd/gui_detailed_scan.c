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
 **  gui_detailed_scan.c
 **
 ****************************************************************
 **
 **   Copyright (c) 2001, 2002 all rights reserved.
 **
 **   Author: Peter K. Lee <saint@elixar.net>
 **
 ***************************************************************/

#include <ncurses.h>
#include <panel.h>
#include <string.h>
#include <arpa/inet.h>

#include "definition.h"
#include "sniff_include.h"

/*===========================================================*/
/* Global Variables */

int GUI_DEBUG = 0;

int scroll_loc;
int node_loc;
int max_x, max_y;

////////////////////////////////////////////////////////////////////////////////////
//  Packet Type General Information
////////////////////////////////////////////////////////////////////////////////////

void print_wt_labels(WINDOW * win)
{
    wattrset(win, BOXATTR);
    mvwprintw(win, 2, 2, "BSSID: ");
    mvwprintw(win, 2, 26, "SSID: ");
    mvwprintw(win, 2, 55, "WEP: ");
    mvwprintw(win, 2, 75, "CHANNEL: ");
    mvwprintw(win, 2, COLS - 22, "TIME: ");
    mvwprintw(win, 4, 2, "Management Frames:");
    mvwprintw(win, 12, 2, "Control Frames:");
    mvwprintw(win, 19, 2, "Data Frames:");
    mvwprintw(win, 28, 2, "Corrupt Frames:   (count)  (bytes)");
    mvwprintw(win, 35, 2, "OVERALL ACTIVITY:");
    //    mvwprintw(win, 40, 2, "Link Quality Analysis:");
    
    wattrset(win, STDATTR);
    /** management **/
    mvwprintw(win, 5,  5, "Beacon:");
    mvwprintw(win, 6,  5, "Disassoc:");
    mvwprintw(win, 7,  5, "Other:");
    mvwprintw(win, 8,  5, "Total Packets:");
    mvwprintw(win, 9,  5, "Total Bytes:");
    wattrset(win, ACTIVEATTR);
    mvwprintw(win, 10, 5, "Bandwidth:");
    /** control **/
    wattrset(win, STDATTR);
    mvwprintw(win, 13, 5, "Acknowledgement:");
    mvwprintw(win, 14, 5, "Other:");
    mvwprintw(win, 15, 5, "Total Packets:");
    mvwprintw(win, 16, 5, "Total Bytes:");
    wattrset(win, ACTIVEATTR);
    mvwprintw(win, 17, 5, "Bandwidth:");
    /** data **/
    wattrset(win, STDATTR);
    mvwprintw(win, 20, 5, "External Packets:");
    mvwprintw(win, 21, 5, "External Bytes:");
    mvwprintw(win, 22, 5, "Internal Packets:");
    mvwprintw(win, 23, 5, "Internal Bytes:");
    mvwprintw(win, 24, 5, "Total Packets:");
    mvwprintw(win, 25, 5, "Total Bytes:");
    wattrset(win, ACTIVEATTR);
    mvwprintw(win, 26, 5, "Bandwidth:"); 
    /** corrupted **/
    wattrset(win, STDATTR);
    mvwprintw(win, 29, 5, "Bad MAC addr:");
    mvwprintw(win, 30, 5, "Bad IP chksum:");
    mvwprintw(win, 31, 5, "FCS error:");
    mvwprintw(win, 32, 5, "Filtered data:");
    wattrset(win, ACTIVEATTR);
    mvwprintw(win, 33, 5, "Overall:");
    /** OVERALL **/
    wattrset(win, STDATTR);
    mvwprintw(win, 36, 5, "Total Packets:");
    mvwprintw(win, 37, 5, "Total Bytes:");
    wattrset(win, ACTIVEATTR);
    mvwprintw(win, 38, 5, "Bandwidth:"); 
    /** Link Quality **/
    //    wattrset(win, STDATTR);
    //    mvwprintw(win, 41, 5, "Link Utilization:");
    //    mvwprintw(win, 42, 5, "Background Noise:");
    //    mvwprintw(win, 43, 5, "Packet Loss:");
    
    update_panels();
    doupdate();
}
void printstatrow(WINDOW * win, int row, int col, unsigned long long number)
{
  wmove(win,row,col);
  printlargenum(number, win);
}

void printdetails(WINDOW * win)
{
  detailed_overview_t *overview = get_detailed_snapshot();
  bss_t *info = overview->bss_list_top;
  
  if ((overview == NULL)||(info == NULL)) return;
  
  wattrset(win, HIGHATTR);
  if (info != NULL){
    mvwprintw(win, 2, 10, hexdump((__u8*)&info->bssid,6));
    mvwprintw(win, 2, 33, info->ssid);
    mvwprintw(win, 2, 61, "%s", info->wep_status ? "encrypted " : "opensystem");
    mvwprintw(win, 2, 85, "%d", info->channel);
    
    /** management **/
    printstatrow(win, 5, 21, info->mgmt_data.beacon);
    printstatrow(win, 6, 21, info->mgmt_data.disassoc);
    printstatrow(win, 7, 21, info->mgmt_data.other);
    printstatrow(win, 8, 21, info->mgmt_data.mgmt_count);
    printstatrow(win, 9, 21, info->mgmt_data.mgmt_byte);
    mvwprintw(win,10, 22, "%8.2f Kbps", info->mgmt_data.bndwth.curr);
    /** control **/
    printstatrow(win,13, 21, info->ctrl_data.ack);
    printstatrow(win,14, 21, info->ctrl_data.other);
    printstatrow(win,15, 21, info->ctrl_data.control_count);
    printstatrow(win,16, 21, info->ctrl_data.control_byte);
    mvwprintw(win,17, 22, "%8.2f Kbps", info->ctrl_data.bndwth.curr);
    /** data **/
    printstatrow(win, 20, 21, info->normal_data.external_count);
    printstatrow(win, 21, 21, info->normal_data.external_byte);
    printstatrow(win, 22, 21, info->normal_data.internal_count);
    printstatrow(win, 23, 21, info->normal_data.internal_byte);
    printstatrow(win, 24, 21, info->normal_data.data_count);
    printstatrow(win, 25, 21, info->normal_data.data_byte);
    mvwprintw(win,26, 22, "%8.4f Mbps", info->normal_data.bndwth.curr);
    /** corrupt **/

    mvwprintw(win,29, 21, "%5d  %7d", overview->bad_mac,
	      overview->bad_mac_byte);
    mvwprintw(win,30, 21, "%5d  %7d", overview->bad_ip_chksum,
	      overview->bad_ip_chksum_byte);
    mvwprintw(win,31, 21, "%5d  %7d", overview->fcs_error,
	      overview->fcs_error_byte);
    mvwprintw(win,32, 21, "%5d  %7d", overview->filtered_data,
	      overview->filtered_data_byte);
    mvwprintw(win,33, 21, "%5d  %7d", overview->corrupt_tot,
	      overview->corrupt_tot_byte);
    	      
    /** overall **/
    printstatrow(win, 36, 21, info->overall_count);
    printstatrow(win, 37, 21, info->overall_byte);
    mvwprintw(win,38, 22, "%8.4f Mbps", info->bndwth.curr);

    /** link quality **/
    //    mvwprintw(win,41, 23, "%7.2f %%", info->link_utilization);
    //    mvwprintw(win,42, 23, "%7.2f %%", info->background_noise);
    //    mvwprintw(win,43, 23, "%7.2f %%", info->packet_loss);
  }
}

void markactive(int curwin, WINDOW * tw, int paused)
{
    WINDOW *win1;
    int x1, y1;

    win1 = tw;

    getmaxyx(win1, y1, x1);

    if (!paused){
      wmove(win1, --y1, x1 - 10);
      wattrset(win1, ACTIVEATTR);
      wprintw(win1, " Active ");
    }
    else{
      wmove(win1, --y1, x1- 10);
      wattrset(win1, ACTIVEATTR);
      wprintw(win1, " Paused ");
    }

}

////////////////////////////////////////////////////////
//  Scroller & Connected Nodes Stuff
////////////////////////////////////////////////////////

void make_node_win(WINDOW **win, PANEL **panel, WINDOW **bwin, PANEL **bpanel)
{
  *bwin = newwin(LINES - 8, COLS - 40, 5, 39);
  *bpanel = new_panel(*bwin);
  wattrset(*bwin, BOXATTR);
  colorwin(*bwin);
  box(*bwin, ACS_VLINE, ACS_HLINE);
  wmove(*bwin, 0, 1);
  wprintw(*bwin, " Connected Nodes ");
  
  *win = newwin(LINES - 10, COLS - 42, 6, 40);
  *panel = new_panel(*win);
  wattrset(*win, BOXATTR);
  colorwin(*win);

  update_panels();
  doupdate();
}

void prepare_node_win(WINDOW *nodewin)
{
  scroll_loc = node_loc = 0;

  getmaxyx(nodewin, max_y, max_x);  
}

void show_node_win(WINDOW *nodewin)
{
  int count = 0;
  int index = scroll_loc;
  int pos;
  int fit, remainder;
  bss_t * info = get_detailed_snapshot()->bss_list_top;
  bss_node_t * temp_node = bss_get_node(info, index);

  if (info == NULL) return;
  
  fit = max_y / NODE_ROW_SIZE;
  remainder = max_y % NODE_ROW_SIZE;

  while (temp_node != NULL){
    if (!temp_node->status){
      temp_node = temp_node->next;
      continue;
    }
    pos = (count * NODE_ROW_SIZE) +1;
    wattrset(nodewin,BOXATTR);
    if (temp_node->ip_addr.s_addr != 0){
      mvwprintw(nodewin, pos, 0,
		"MAC address %d:  %s -       IP: (%s) ", count,
		hexdump((__u8 *)&temp_node->mac_addr,6),
		inet_ntoa(temp_node->ip_addr));
    }
    else{
      mvwprintw(nodewin, pos, 0,
		"MAC address %d:  %s -       IP: (%s) ", count,
		hexdump((__u8 *)&temp_node->mac_addr,6),
		"Unknown");
    }
    wattrset(nodewin,ACTIVEATTR);
    if (0 == memcmp(&temp_node->mac_addr,
		    &info->bssid, 6))
      mvwprintw(nodewin, pos, 30, " AP");
    else
      mvwprintw(nodewin, pos, 30, " STA");
    wattrset(nodewin,STDATTR);
    mvwprintw(nodewin, pos+1, 5,
	      "incoming packets:                outgoing packets: ");
    mvwprintw(nodewin, pos+2, 5,
	      "incoming bytes:                  outgoing bytes: ");
    mvwprintw(nodewin, pos+3, 5, "avg.signal strength: ");
    wattrset(nodewin, ACTIVEATTR);
    mvwprintw(nodewin, pos+4, 5, "Bandwidth: ");
    
    wattrset(nodewin,HIGHATTR);
    printstatrow(nodewin, pos+1, 25, temp_node->inc_packet);
    printstatrow(nodewin, pos+1, 56, temp_node->out_packet);
    printstatrow(nodewin, pos+2, 25, temp_node->inc_byte);
    printstatrow(nodewin, pos+2, 56, temp_node->out_byte);
    mvwprintw(nodewin, pos+3, 29, "%-10.2f", temp_node->avg_signal_str);
    mvwprintw(nodewin, pos+4, 29, "%-8.4f Mbps", temp_node->bndwth.curr);
    count++;
    temp_node = temp_node->next;
    if (count == fit){
      break;
    }
  }
}

void scroll_nodewin(WINDOW *nodewin, int node_entry_count, int direction)
{
  int temp;

  wattrset(nodewin, STDATTR);

  if (direction == SCROLLUP) {
    if (scroll_loc > 0){
      scroll_loc--;
    }
    else{
      scroll_loc = 0;
    }
  }
  else {
    temp = (node_entry_count * NODE_ROW_SIZE) - max_y;
    if (temp < 0){
      scroll_loc = 0;
    }
    else{
      temp = (temp/NODE_ROW_SIZE) + 1;
      if (scroll_loc < temp){
	scroll_loc++;
      }
      else{
	scroll_loc = temp;
      }
    }
  }
}

/* void page_nodewin(WINDOW *nodewin, int direction) */
/* { */
/*     int i = 1; */

/*     if (direction == SCROLLUP) { */
/* 	while ((i <= LINES - 7) && (table->lastvisible != table->tail)) { */
/* 	    i++; */
/* 	    scrollethwin(table, direction, idx); */
/* 	} */
/*     } else { */
/* 	while ((i <= LINES - 7) && (table->firstvisible != table->head)) { */
/* 	    i++; */
/* 	    scrollethwin(table, direction, idx); */
/* 	} */
/*     } */
/* } */

/////////////////////////////////////////////////////////////////////
//  CHANNEL Panel STUFF
/////////////////////////////////////////////////////////////////////

void prepare_channel_win(WINDOW * win)
{
  int i;
  int loc = 17;
  
  wattrset(win, IPSTATLABELATTR);
  wmove(win, 0, 1);
  wprintw(win, "CHANNEL STATUS:");

  for(i = 1; i < 15; i++){
    mvwprintw(win, 0, loc, "%d", i);
    if (i <10){
      loc += 3;
    }
    else{
      loc +=4;
    }
  }
}

/** highlight available channels for viewing **/
/* void show_channel_stats(WINDOW * win) */
/* { */
/*   int i; */
/*   int loc = 17; */
  
/*   wattrset(win, ERRTXTATTR); */

/*   for(i = 1; i < 15; i++){ */
/*     if (active_channel[i] != NULL){ */
/*       mvwprintw(win, 0, loc, "%d", i); */
/*     } */
/*     if (i < 10){ */
/*       loc += 3;       */
/*     } */
/*     else{ */
/*       loc += 4; */
/*     } */
/*   } */
/* } */

/* void find_active_channel(bss_t *info) */
/* { */
/*   bss_t * curr_info = info; */

/*   while(curr_info) */
/*     { */
/*       if (curr_info->channel > 0){ */
/* 	active_channel[curr_info->channel] = curr_info; */
/*       } */
/*       curr_info = curr_info->next; */
/*     } */
/* } */

/* void goto_next_channel() */
/* { */
/*   int curr_chan; */
/*   int i; */
  
/*   if (active_bss != NULL){ */
/*     curr_chan = active_bss->channel; */
/*   } */
/*   else{ */
/*     return; */
/*   } */

/*   for(i = (curr_chan + 1); i < 15; i++){ */
/*     if (active_channel[i] != 0){ */
/*       active_bss = (bss_t *)active_channel[i]; */
/*       return; */
/*     } */
/*   } */
/*   for(i = 1; i < curr_chan; i++){ */
/*     if (active_channel[i] != 0){ */
/*       active_bss = (bss_t *)active_channel[i]; */
/*       return; */
/*     } */
/*   } */
/* } */

/* void goto_prev_channel() */
/* { */
/*   int curr_chan; */
/*   int i; */
  
/*   if (active_bss != NULL){ */
/*     curr_chan = active_bss->channel; */
/*   } */
/*   else{ */
/*     return; */
/*   } */

/*   for(i = (curr_chan-1); i > 0; i--){ */
/*     if (active_channel[i] != 0){ */
/*       active_bss = (bss_t *)active_channel[i]; */
/*       return; */
/*     } */
/*   } */
/*   for(i = 14; i > curr_chan; i--){ */
/*     if (active_channel[i] != 0){ */
/*       active_bss = (bss_t *)active_channel[i]; */
/*       return; */
/*     } */
/*   } */
/* } */


////////////////////////////////////////////////////////////////////
//  main wireless traffic monitor routine
///////////////////////////////////////////////////////////////////

int start_wt_mon(struct SETTINGS *mySettings)
{
  WINDOW *statwin;
  WINDOW *nodeborder;
  WINDOW *nodewin;
  WINDOW *channelwin;
  WINDOW *capturewin;
    
  PANEL *statpanel;
  PANEL *nodeborderpanel;
  PANEL *nodepanel;
  PANEL *channelpanel;
  PANEL *capturepanel;

  int exitloop;

  int ch;

  int first_instance = 1;
  int paused = 0;  // used to pause screen
    
  int curwin = 0;

  int node_count = 0;
  
  struct timeval tv_start;
  struct timeval tv_curr;
  struct timeval tv_pot_reset;
  struct timeval tv_old;
  struct timeval tv_new;

  char elapsed[10];

  char sp_buf[10];

  if (GUI_DEBUG) fprintf(stderr,"making overall window\n");
  /** make the overall wireless traffic monitor box window **/
  statwin = newwin(LINES - 3, COLS, 1, 0);
  statpanel = new_panel(statwin);
  stdwinset(statwin);
  wtimeout(statwin, -1);
  wattrset(statwin, BOXATTR);
  colorwin(statwin);
  box(statwin, ACS_VLINE, ACS_HLINE);
  wmove(statwin, 0, 1);
  wprintw(statwin, " Statistics for %s ", mySettings->interface);
  wattrset(statwin, STDATTR);
  print_wt_labels(statwin);
  printdetails(statwin);
  update_panels();
  doupdate();

  if (GUI_DEBUG) fprintf(stderr,"making node window\n");
  /** make the node connection traffic monitor box window **/
  make_node_win(&nodewin, &nodepanel, &nodeborder, &nodeborderpanel);
  prepare_node_win(nodewin);
  show_node_win(nodewin);
  update_panels();
  doupdate();

  if (GUI_DEBUG) fprintf(stderr,"making channel window\n");
  /** make the channel display info (shows active channels) **/
  channelwin = newwin(1, COLS, LINES - 2, 0);
  channelpanel = new_panel(channelwin);
  wattrset(channelwin, IPSTATLABELATTR);
  wmove(channelwin, 0, 0);
  sprintf(sp_buf, "%%%dc", COLS);
  wprintw(channelwin, sp_buf, ' ');
  prepare_channel_win(channelwin);
  //  show_channel_stats(channelwin);

  /** if we're doing playback, display the controls... **/
  if (mySettings->capture_mode == CAPTURE_MODE_PLAYBACK)
    make_capture_controls(&capturewin, &capturepanel);
  
  if (GUI_DEBUG) fprintf(stderr,"making other stuff\n");
  /** make the bottom key binding panel **/
  move(LINES - 1, 1);
  scrollkeyhelp();
  channelkeyhelp();
  pausekeyhelp();
  stdexitkeyhelp();

  markactive(curwin, nodeborder, paused);
  update_panels();
  doupdate();

  gettimeofday(&tv_start, NULL);
  tv_old = tv_start;
  tv_pot_reset = tv_start;
    
  leaveok(statwin, TRUE);
   
  exitloop = 0;
  //    dispmode(options->actmode, unitstring);

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
	  scroll_nodewin(nodewin, node_count, SCROLLUP);
	  break;
	case KEY_DOWN:
	  scroll_nodewin(nodewin, node_count, SCROLLDOWN);
	  break;
	case KEY_PPAGE:
	case '-':
	  scroll_nodewin(nodewin, node_count, SCROLLUP);
	  //	    pageethwin(nodewin, SCROLLDOWN);
	  break;
	case KEY_NPAGE:
	case ' ':
	  scroll_nodewin(nodewin, node_count, SCROLLDOWN);
	  //	    pageethwin(nodewin, SCROLLUP);
	  break;
	case KEY_RIGHT:
	  //goto_next_channel();
	  break;
	case KEY_LEFT:
	  //goto_prev_channel();
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
	      paused = 1;
	      break;
	    case 1:
	      paused = 0;
	      break;
	    }    
	  markactive(curwin, nodeborder, paused);
	  update_panels();
	  doupdate();
	  break;
	case 12:
	case 'l':
	case 'L':
	  refresh_screen();
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
	  node_count = get_detailed_snapshot()->bss_list_top->num;
	  first_instance = 0;
	}
	else{
	  continue;
	}
      }

      /**
       * since we found a base station, lets see if there are more
       * than one...
       **/
      //      find_active_channel(bss_list);
      //      show_channel_stats(channelwin);
      //      if (active_bss == NULL){
      //	active_bss = bss_list;
      //      }
      //      node_count = active_bss->num;
      
      printdetails(statwin);
      show_node_win(nodewin);

      if (mySettings->capture_mode == CAPTURE_MODE_PLAYBACK)
	print_capture_update(capturewin, mySettings);
      
      if (get_detailed_snapshot()->bss_list_top->num != node_count){
	del_panel(nodeborderpanel);
	delwin(nodeborder);
	del_panel(nodepanel);
	delwin(nodewin);
	if (mySettings->capture_mode == CAPTURE_MODE_PLAYBACK){
	  del_panel(capturepanel);
	  delwin(capturewin);
	}
	update_panels();
	doupdate();
	
	make_node_win(&nodewin, &nodepanel, &nodeborder, &nodeborderpanel);
	if (mySettings->capture_mode == CAPTURE_MODE_PLAYBACK)
	  make_capture_controls(&capturewin, &capturepanel);
	node_count = get_detailed_snapshot()->bss_list_top->num;
      }
      update_panels();
      doupdate();
      
      wattrset(statwin, HIGHATTR);
      gettimeofday(&tv_curr, NULL);
      get_elapsed_time(&tv_curr, &tv_start, elapsed);
      mvwprintw(statwin, 2, COLS - 15, "%s", elapsed);
    }
  } // end loop
  del_panel(channelpanel);
  delwin(channelwin);
  del_panel(nodeborderpanel);
  delwin(nodeborder);
  del_panel(nodepanel);
  delwin(nodewin);
  del_panel(statpanel);
  delwin(statwin);
  if (mySettings->capture_mode == CAPTURE_MODE_PLAYBACK){
    del_panel(capturepanel);
    delwin(capturewin);
  }
  update_panels();
  doupdate();
  if (sysexit){
    sysexit = 0;
    return (0);
  }
  else{
    return (1);
  }
}
