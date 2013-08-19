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
 **  mon_ids.c
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

#include "definition.h"
#include "sniff_include.h"

/**************************
 * local global variables *
 **************************/

int MAX_STAT_ROW = 0;

/*===========================================================*/

void print_ids_labels(WINDOW *win)
{
  wattrset(win, BOXATTR);
  wmove(win, 0, 35 * COLS / 80);
  whline(win, ACS_HLINE, 23 * COLS / 80);

  wmove(win, 0, 25 * COLS / 80);
  wprintw(win, " Probe ");
  wmove(win, 0, 30 * COLS / 80);
  wprintw(win, " Assoc ");
  wmove(win, 0, 35 * COLS / 80);
  wprintw(win, " ReAssoc ");
  wmove(win, 0, 41 * COLS / 80);
  wprintw(win, " DisAssoc ");
  wmove(win, 0, 49 * COLS / 80);
  wprintw(win, " Auth ");
  wmove(win, 0, 53 * COLS / 80);
  wprintw(win, " DeAuth ");
  wmove(win, 0, 60 * COLS / 80);
  wprintw(win, " Status ");
  wmove(win, 0, 70 * COLS / 80);
  wprintw(win, " Diagnosis ");
  update_panels();
  doupdate();
}

void print_ids_statrow(WINDOW * win, node_stat_t * node, int seq_num)
{
  int diagnosis = 0;
  
  mvwprintw(win, seq_num, 2, "%2d: ", seq_num);
  mvwprintw(win, seq_num, 6, hexdump((__u8*)&node->node_mac, 6));
  mvwprintw(win, seq_num, 18, " -> ");
  mvwprintw(win, seq_num, 22, hexdump((__u8*)&node->dest_mac, 6));
  mvwprintw(win, seq_num, 25 * COLS / 80, "%6d", node->probe_request);
  mvwprintw(win, seq_num, 30 * COLS / 80, "%6d", node->assoc_request);
  mvwprintw(win, seq_num, 35 * COLS / 80, "%6d", node->reassoc_request);
  mvwprintw(win, seq_num, 41 * COLS / 80, "%6d", node->disassoc_count);
  mvwprintw(win, seq_num, 49 * COLS / 80 -1, "%6d", node->auth_count);
  mvwprintw(win, seq_num, 53 * COLS / 80, "%6d", node->deauth_count);
  mvwprintw(win, seq_num, 60 * COLS / 80 - 1, "%d-%d-%d-%d-%d",
	    node->assoc_status,
	    node->reassoc_status,
	    node->auth_status,
	    node->disassoc_status,
	    node->deauth_status);
  diagnosis = node->assoc_status + node->reassoc_status + node->auth_status;
  if (diagnosis == 0){
    mvwprintw(win, seq_num, 70 * COLS/ 80, "  Normal ");
  }
  else{
    mvwprintw(win, seq_num, 70 * COLS/ 80, "Suspicious");
  }
}

void print_ids_details(WINDOW * win, ids_t *info, int page_num)
{
  int start_loc = page_num * MAX_STAT_ROW;
  int curr_loc = 0;
  int end_loc = start_loc + MAX_STAT_ROW;
  __u8 null_addr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  int seq_num = 1 + (page_num * MAX_STAT_ROW);
  
  if (info != NULL){
    if (!(start_loc < info->node_count)){
      start_loc = 0;
      end_loc = MAX_STAT_ROW - 1;
    }
    if (end_loc < info->node_count){
      mvwprintw(win, LINES * 0.6, 2, " >> More >> ");
    }
    else{
      mvwprintw(win, LINES * 0.6, 2, " << END! >> ");
    }
    wattrset(win, HIGHATTR);
    for (curr_loc = start_loc; curr_loc < end_loc; curr_loc++){
      if (&info->nodes[curr_loc] == NULL){
	break;
      }
      if (0 == memcmp(null_addr, info->nodes[curr_loc].node_mac, 6)){
	break;
      }
      print_ids_statrow(win, &info->nodes[curr_loc],seq_num);
      seq_num++;
    }    
    update_panels();
    doupdate();
  }
}

void print_help_win(WINDOW * win)
{
  wattrset(win, BOXATTR);
  mvwprintw(win, 0, 1, " How to Interpret Above Statistics ");
  mvwprintw(win, 2, 3, " First of all, statistics are listed by mac addresses. ");
  mvwprintw(win, 3, 3, " The '->' denotes the mac address to which the last detected packet was transmitted to. ");
  mvwprintw(win, 4, 3, " The Status reflects the intelligently determined characteristic of the node. ");
  mvwprintw(win, 6, 3, " Status Code: ");
  mvwprintw(win, 7, 3, " ----------- ");
  mvwprintw(win, 8, 3, " (assoc status)-(reassoc status)-(auth status)-(disassoc status)-(deauth status)");
  mvwprintw(win, 10, 4, "0 usually represents 'OK', any other shows failure status. ");
  mvwprintw(win, 12, 4, "*NOTE: the above packets are unfiltered. (meaning, it is possible to see lot of corrupt packets)");
  mvwprintw(win, 13, 4, "       Therefore, be reasonable when viewing data for suspicious activity...  Looking at the destination ");
  mvwprintw(win, 14, 4, "       address can give a clue as to whether the detected activity is valid/invalid.");
  
}

////////////////////////////////////////////////////////////////////
//  main intrusion detection monitor routine
///////////////////////////////////////////////////////////////////

void start_ids_mon(char *iface)
{
  WINDOW *statwin;
  PANEL *statpanel;

  WINDOW *overallwin;
  PANEL *overallpanel;

  WINDOW *helpwin;
  PANEL *helppanel;

  /** stat display information **/
  int stat_page = 0;
  
  int ch;
  int exitloop;
  int paused = 0;

  ids_t *ids_info = NULL;

  MAX_STAT_ROW = LINES * 0.6 - 2;

  overallwin = newwin(LINES -2, COLS, 1, 0);
  overallpanel = new_panel(overallwin);
  stdwinset(overallwin);
  wtimeout(overallwin, -1);
  wattrset(overallwin, BOXATTR);
  colorwin(overallwin);
  box(overallwin, ACS_VLINE, ACS_HLINE);
  
  /** make the ids list based on mac addresses **/
  statwin = newwin(LINES * 0.6, COLS, 1, 0);
  statpanel = new_panel(statwin);
  stdwinset(statwin);
  wtimeout(statwin, -1);
  wattrset(statwin, BOXATTR);
  colorwin(statwin);
  box(statwin, ACS_VLINE, ACS_HLINE);
  wmove(statwin, 0, 1);
  wprintw(statwin, " IDS Statistics for %s ", iface);
  print_ids_labels(statwin);
  print_ids_details(statwin, NULL, 0);

  /** make ids help window **/
  helpwin = newwin(LINES * 0.4 - 1, COLS, LINES * 0.6 + 1, 0);
  helppanel = new_panel(helpwin);
  wattrset(helpwin, BOXATTR);
  colorwin(helpwin);
  box(helpwin, ACS_VLINE, ACS_HLINE);
  print_help_win(helpwin);
  
  /** make the bottom key binding panel **/
  move(LINES - 1, 1);
  scrollkeyhelp();
  stdexitkeyhelp();

  update_panels();
  doupdate();
  
  leaveok(statwin, TRUE);
  
  exitloop = 1;

  /**
   * Data-gathering loop
   */
  while(!exitloop){
    ch = ERR;
    if (check_for_keystroke() != ERR)
      ch = wgetch(statwin);
    if (ch != ERR) {
      switch (ch)
	{
	case KEY_UP:
	  if (stat_page > 0){
	    stat_page --;
	    colorwin(statwin);
	  }
	  break;
	case KEY_DOWN:
	  if (((stat_page +1) * MAX_STAT_ROW) < ids_info->node_count){
	    stat_page ++;
	    colorwin(statwin);
	  } 
	  break;
	case KEY_PPAGE:
	case '-':
	  //scroll_nodewin(nodewin, SCROLLDOWN);
	  //	    pageethwin(nodewin, SCROLLDOWN);
	  break;
	case KEY_NPAGE:
	case ' ':
	  //scroll_nodewin(nodewin, SCROLLUP);
	  //	    pageethwin(nodewin, SCROLLUP);
	  break;
	case 'p':
	case 'P':
	  switch (paused)
	    {
	    case 0:
	      paused = 1;
	      break;
	    case 1:
	      paused = 0;
	      break;
	    }    
	  //	  markactive(curwin, nodeborder, paused);
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
	  break;
	}
    }
    if (!paused){
      // blah do stuff
      print_ids_details(statwin, ids_info, stat_page);
    }
  } // end loop
  del_panel(statpanel);
  delwin(statwin);

  del_panel(helppanel);
  delwin(helpwin);

  del_panel(overallpanel);
  delwin(overallwin);
  
  update_panels();
  doupdate();
}
