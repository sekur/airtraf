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
 **  gui_main.c
 **
 ****************************************************************
 **
 **   Copyright (c) 2001,2002 all rights reserved.
 **
 **   Author: Peter K. Lee <pkl@duke.edu>
 **
 ***************************************************************/

/*=============================================================*/
/* System Includes */

#include <ncurses.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/types.h>
#include <sys/time.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <errno.h>
#include <pthread.h>

#include "definition.h"
#include "sniff_include.h"

///////////////////////////////////////////////////////////////
//  HELPER FUNCTIONS
///////////////////////////////////////////////////////////////

/**
 * check_for_keystroke()
 * --------------------
 * the helper function for all the GUI interface that checks if there
 * are keystrokes to be read and processed
 **/
int check_for_keystroke()
{
  fd_set fds;
  int ret_val;
  struct timeval tv;
  
  /**
   * a litle loop to check for keystrokes in INTERACTIVE MODE
   **/
  FD_ZERO(&fds);
  FD_SET(0,&fds);
  tv.tv_sec = 0;
  tv.tv_usec = DEFAULT_UPDATE_DELAY;
  
  do {
    ret_val = select(1, &fds, NULL, NULL, &tv);
  } while ((ret_val < 0) && (errno == EINTR));
  
  if (FD_ISSET(0, &fds)){
    return (1);
  }
  else{
    return (ERR);
  }
}

/**
 * change_channel()
 * ---------------
 * A simple routine for changing the channel the wireless card is
 * sniffing on (a necessity for prismII chipset cards)
 * returns: a new socket handler
 **/
int change_channel(int channel)
{
  if ( (channel < 1) || (channel > 14) ){
    return (ERR);
  }
  /** do some driver level channel setting function... **/

  /** then driver level new socket creation, returning socket file
      descriptor **/
  
  return (OK);
}

/**
 * select_specified_ap()
 * ---------------------
 * display menu with all discovered access point, allows user to
 * select a specified access point to listen on.
 **/
void select_specified_ap(struct MENU *menu, struct access_point **chosen, int *abort)
{
  int i;
  int row;

  int endloop = 0;
  int aborted;
  int index = 0;
  int ap_pos;

  char holder[100];
  char description[200];
  
  struct access_point *ap;
  struct channel_overview *snapshot;

  snapshot = get_channel_snapshot();
  
  /** shouldn't happen...**/
  if (snapshot == NULL){
    *abort = 1;
    return;
  }
  
  initmenu(menu, snapshot->num_active_aps + 6, 55,
	     10, (COLS - 55) / 2);

  ap_pos = 0;
  for (i = 1; i < 15; i++){
    if ((ap = snapshot->all_chan[i]) != NULL){
      while (ap != NULL){
	if (ap->status != AP_STATUS_INACTIVE){
	  ap_pos++;
	  memset(holder, 0, sizeof(char)*100);
	  snprintf(holder, strlen((char*)ap->ssid) + 26,
		   " ^%d^ %s %s CH:%02d",ap_pos, hexdump((__u8*)&ap->bssid, 6),
		   ap->ssid, ap->channel);
	  memset(description, 0, sizeof(char)*200);
	  snprintf(description, 200,
		   "Select to view data for this access point, WEP Status: %s",
		   ap->wep_status ? "encrypted" : "opensystem");
	  additem(menu, holder, description);
	}
	ap = (struct access_point*)ap->next;
      }
    }
  }  
  additem(menu, NULL, NULL);
  additem(menu, " ^C^lear Target Access Point",
	  "Clear selection of Current Target Access Point");
  additem(menu, NULL, NULL);
  additem(menu, " E^x^it menu", "Exit this menu");
  
  row = 1;
  do {
    showmenu(menu);
    operatemenu(menu, &row, &aborted);
    if (row <= snapshot->num_det_aps){
      index = row;
      endloop = 1;
    }
    else if (row == snapshot->num_det_aps + 2){
      *chosen = NULL;
      endloop = 1;      
    }
    else{
      *abort = 1;
      endloop = 1;
    }
  } while (!endloop);
  
  if (index != 0){
    ap_pos = 0;
    for (i = 1; i < 15; i++){
      if ((ap = snapshot->all_chan[i]) != NULL){
	while (ap != NULL){
	  if (ap->status != AP_STATUS_INACTIVE){
	    ap_pos++;
	    if (ap_pos == index){
	      *chosen = ap;
	      return;
	    }	    
	  }
	  ap = (struct access_point*)ap->next;	  
	}
      }
    }
  }
}

/**
 * print_selected_ap_screen()
 * ------------------------------
 * displays current target access point to the top of the screen
 **/
void print_selected_ap_screen(WINDOW **win, PANEL **panel)
{
  *win = newwin(8, 35, 5, (COLS - 35) / 2);
  *panel = new_panel(*win);
  wattrset(*win, BOXATTR);
  colorwin(*win);
  box(*win, ACS_VLINE, ACS_HLINE);

  wattrset(*win, ACTIVEATTR);
  mvwprintw(*win, 1, 3, "Current Target Access Point");
  wattrset(*win, STDATTR);
  mvwprintw(*win, 3, 3, "SSID:             ");
  mvwprintw(*win, 4, 3, "BSSID: ");
  mvwprintw(*win, 5, 3, "WEP: ");
  mvwprintw(*win, 6, 3, "Channel:");

  update_panels();
  doupdate();
}

/**
 * print_selected_ap_results()
 * ------------------------------
 * update the current target access point
 **/
void print_selected_ap_results(WINDOW *win, PANEL *panel, struct access_point *ap)
{
  wattrset(win, HIGHATTR);
  if (ap == NULL){
    mvwprintw(win, 3, 10, "   --              ");
    mvwprintw(win, 4, 10, "   --              ");
    mvwprintw(win, 5, 10, "   --              ");
    mvwprintw(win, 6, 13, "--              ");
  }
  else{
    mvwprintw(win, 3, 10, "                    ");
    mvwprintw(win, 4, 10, "                    ");
    mvwprintw(win, 6, 13, "      ");       
    mvwprintw(win, 3, 10, ap->ssid);
    mvwprintw(win, 4, 10, hexdump((__u8*)&ap->bssid,6));
    mvwprintw(win, 5, 10, "%s", ap->wep_status ? "encrypted " : "opensystem");
    mvwprintw(win, 6, 13, "%02d", ap->channel);
  }
  update_panels();
  doupdate();
}

/**
 * print_system_screen()
 * ------------------------
 * displays system data to the left of the screen
 **/
void print_system_screen(WINDOW **win, PANEL **panel)
{
  *win = newwin(12, 35, (LINES - 11) / 2 , 5);
  *panel = new_panel(*win);
  wattrset(*win, BOXATTR);
  colorwin(*win);
  box(*win, ACS_VLINE, ACS_HLINE);

  wattrset(*win, ACTIVEATTR);
  mvwprintw(*win, 1, 3, "System Information");
  wattrset(*win, STDATTR);
  mvwprintw(*win, 3, 3, "Card Settings: ");
  mvwprintw(*win, 4, 3, "Interface: ");
  mvwprintw(*win, 5, 3, "Runtime Mode: ");
  mvwprintw(*win, 6, 3, "Logging Mode: ");
  mvwprintw(*win, 7, 3, "Capture Mode: ");
  mvwprintw(*win, 8, 3, "Engine Status: ");
  
  mvwprintw(*win, 10, 3, "Uptime: ");

  update_panels();
  doupdate();
}

/**
 * print_system_results()
 * ------------------------------
 * update the current system settings
 **/
void print_system_results(WINDOW *win, PANEL *panel, struct SETTINGS *mySettings, int engine_status, char *uptime)
{
  wattrset(win, HIGHATTR);
  if (mySettings->card_type == AIRONET)
    mvwprintw(win, 3, 19, "Cisco Aironet");
  else if (mySettings->card_type == PRISMII)
    mvwprintw(win, 3, 19, "Prism2        ");
  else if (mySettings->card_type == HOSTAP)
    mvwprintw(win, 3, 19, "HostAP        ");
  else if (mySettings->card_type == HERMES)
    mvwprintw(win, 3, 19, "Hermes        ");
  else if (mySettings->card_type == WLANNG)
    mvwprintw(win, 3, 19, "Wlan-ng       ");

  mvwprintw(win, 4, 19, mySettings->interface);

  if (mySettings->capture_mode != CAPTURE_MODE_PLAYBACK)
    mvwprintw(win, 5, 19, "Real-Time ");
  else
    mvwprintw(win, 5, 19, "Simulation");

  if (mySettings->logging_mode)
    mvwprintw(win, 6, 19, "Enabled ");
  else
    mvwprintw(win, 6, 19, "Disabled");

  if (mySettings->capture_mode)
    mvwprintw(win, 7, 19, "ON ");
  else
    mvwprintw(win, 7, 19, "OFF");

  if (engine_status)
    mvwprintw(win, 8, 19, "ON ");
  else
    mvwprintw(win, 8, 19, "OFF");

  mvwprintw(win, 10, 12, uptime);
  
  update_panels();
  doupdate();
}

///////////////////////////////////////////////////////////////////
//  CAPTURE related functions
//////////////////////////////////////////////////////////////////

void makecapturemenu(struct MENU *menu)
{
    initmenu(menu, 8, 40, (LINES) / 2 - 1, (COLS - 40) / 16);
    additem(menu, " Change Output ^F^ilename",
	    "Allows you to specify the name of output file");
    additem(menu, " ^O^verwrite Mode",
	    "Toggle overwriting of existing file");
    additem(menu, " Set Capture ^I^nterval",
	    "Specify the desired capture generation interval");
    additem(menu, NULL, NULL);
    additem(menu, " ^A^ccept and Begin",
	    "Select the specified options and start the capture process!");
    additem(menu, " E^x^it and Abort Capture",
	    "Abort the selection and Returns to main menu");
}

void makecapturestatwin(WINDOW **win, PANEL **panel)
{
  *win = newwin(5, 43, (LINES) / 2 - 1, (COLS - 40) / 16 + 40);
  *panel = new_panel(*win);

  wattrset(*win, BOXATTR);
  colorwin(*win);
  box(*win, ACS_VLINE, ACS_HLINE);

  mvwprintw(*win, 0, 1, " Current Settings ");
  wattrset(*win, STDATTR);
  mvwprintw(*win, 1, 2, "Output Filename:");
  mvwprintw(*win, 2, 2, "Overwrite:");
  mvwprintw(*win, 3, 2, "Interval (secs):");
}

void showcapturesetting(WINDOW *win, struct SETTINGS *mySettings)
{
  wattrset(win, HIGHATTR);
  mvwprintw(win, 1, 20, "                    ");
  mvwprintw(win, 1, 20, mySettings->capture_file);
  mvwprintw(win, 2, 20, "%s", mySettings->capture_overwrite ? "YES" : " NO");
  mvwprintw(win, 3, 20, "%-5.1f", mySettings->capture_interval);
}

/**
 * read_filename()
 * ---------------
 * a function that pops up a curses dialog requesting the filename to
 * be read.
 **/
void read_filename(struct SETTINGS *mySettings, int *aborted)
{
  WINDOW *win;
  PANEL *panel;
  struct FIELDLIST fieldlist;

  win = newwin(6, 60, (LINES - 6) / 2, (COLS - 60) / 4);
  panel = new_panel(win);

  wattrset(win, DLGBOXATTR);
  colorwin(win);
  box(win, ACS_VLINE, ACS_HLINE);
  wmove(win, 4, 2);
  stdkeyhelp(win);

  wattrset(win, DLGTEXTATTR);
  wmove(win, 2, 2);
  wprintw(win, "Filename:");
  initfields(&fieldlist, 1, 45, (LINES - 6) / 2 + 2, (COLS - 60) / 4 + 12);
  addfield(&fieldlist, 20, 0, 0, mySettings->capture_file);

  fillfields(&fieldlist, aborted);

  if (!(*aborted)) {
    strcpy(mySettings->capture_file, fieldlist.list->buf);
  }
  destroyfields(&fieldlist);
  del_panel(panel);
  delwin(win);
}

void read_capture_interval(struct SETTINGS *mySettings, int *aborted)
{
  WINDOW *win;
  PANEL *panel;
  struct FIELDLIST fieldlist;
  double temp_interval = mySettings->capture_interval;
  int resp;
  int exitloop = 0;

  win = newwin(6, 60, (LINES - 6) / 2, (COLS - 60) / 4);
  panel = new_panel(win);

  wattrset(win, DLGBOXATTR);
  colorwin(win);
  box(win, ACS_VLINE, ACS_HLINE);
  wmove(win, 4, 2);
  stdkeyhelp(win);

  wattrset(win, DLGTEXTATTR);
  wmove(win, 1, 2);
  wprintw(win, "Select Interval (0.1< x <1000):");
  initfields(&fieldlist, 1, 45, (LINES - 6) / 2 + 2, (COLS - 60) / 4 + 2);
  addfield(&fieldlist, 10, 0, 0, "");

  do{
    fillfields(&fieldlist, aborted);
    if (!(*aborted)) {
      temp_interval = atof(fieldlist.list->buf);
      if ((temp_interval < 0.1) || (temp_interval > 1000))
	errbox("Invalid interval value", ANYKEY_MSG, &resp);
      else exitloop = 1;
    }
    else exitloop = 1;
  } while (!exitloop);

  if (!(*aborted)){
    mySettings->capture_interval = (float)temp_interval;
  }

  destroyfields(&fieldlist);
  del_panel(panel);
  delwin(win);
}

/**
 * set_capture_options()
 * -----------------------
 * sets various options for running Capture Mode, i.e. specify output
 * file, capture interval, capture duration, etc.
 **/
int set_capture_options(struct SETTINGS *mySettings)
{
  int exitloop = 0;
  int row = 1;
  int aborted;
  int choice = 0;
  
  struct MENU menu;

  WINDOW * curr_statwin;
  PANEL * curr_statpanel;

  switch(mySettings->capture_mode){
  case CAPTURE_MODE_RECORD:
    makecapturemenu(&menu);
    makecapturestatwin(&curr_statwin, &curr_statpanel);
    showcapturesetting(curr_statwin, mySettings);
    do{
      showmenu(&menu);
      operatemenu(&menu, &row, &aborted);
      switch(row){
      case 1:
	// launch select filename menu
	read_filename(mySettings, &aborted);
	break;
      case 2:
	// toggle choice
	if (mySettings->capture_overwrite){
	  mySettings->capture_overwrite = DISABLED;
	}
	else{
	  mySettings->capture_overwrite = ENABLED;
	}
	break;
      case 3:
	// launch set interval menu
	read_capture_interval(mySettings, &aborted);
	break;
      case 5:
	exitloop = 1;
	choice = 1; // for now
	break;
      case 6:
	exitloop = 1;
	choice = 0;
	break;
      }
      showcapturesetting(curr_statwin, mySettings);
    } while (!exitloop);
    destroymenu(&menu);
    del_panel(curr_statpanel);
    delwin(curr_statwin);
    update_panels();
    doupdate();
    return (choice);
    break;
  case CAPTURE_MODE_PLAYBACK:
    read_filename(mySettings, &aborted);
    if (!aborted){
      return (1);
    }
    break;
  }
  return (0);
}

/**
 * print_capture_screen()
 * ------------------------
 * displays capture data to the right of the screen
 **/
void print_capture_screen(WINDOW **win, PANEL **panel)
{
  *win = newwin(12, 35, (LINES - 11) / 2 , COLS - 40);
  *panel = new_panel(*win);
  wattrset(*win, BOXATTR);
  colorwin(*win);
  box(*win, ACS_VLINE, ACS_HLINE);

  wattrset(*win, ACTIVEATTR);
  mvwprintw(*win, 1, 3, "Capture Information");
  wattrset(*win, STDATTR);
  mvwprintw(*win, 3, 3, "Mode: ");
  mvwprintw(*win, 4, 3, "File: ");
  mvwprintw(*win, 5, 3, "Size: ");
  mvwprintw(*win, 6, 3, "Date: ");
  mvwprintw(*win, 7, 3, "Time: ");
  mvwprintw(*win, 8, 3, "Duration: ");

  mvwprintw(*win, 10, 3, "Status: ");

  update_panels();
  doupdate();
}

/**
 * print_capture_results()
 * ------------------------------
 * update the current capture settings
 **/
void print_capture_results(WINDOW *win, PANEL *panel, struct SETTINGS *mySettings)
{
  struct tm *tm;
  time_t curr;
  char dstr[26];
  char tstr[26];

  wattrset(win, HIGHATTR);
  switch(mySettings->capture_mode){
  case CAPTURE_MODE_OFF:
    mvwprintw(win, 3, 10, "Not Selected    ");
    break;
  case CAPTURE_MODE_PLAYBACK:
    mvwprintw(win, 3, 10, "Session Playback");
    break;
  case CAPTURE_MODE_RECORD:
    mvwprintw(win, 3, 10, "Session Record  ");
    break;
  }
  mvwprintw(win, 4, 10, "                    ");
  mvwprintw(win, 4, 10, "\"%s\"", mySettings->capture_file);
  mvwprintw(win, 5, 10, "                    ");
  mvwprintw(win, 5, 10, "%d bytes", mySettings->capture_size);

  if (mySettings->capture_timestamp != NULL){
    tm = localtime(mySettings->capture_timestamp);
    strftime(dstr, sizeof(dstr), "%B %d, %Y", tm);
    mvwprintw(win, 6, 10, "%s", dstr);
    strftime(tstr, sizeof(tstr), "%I:%M %p", tm);
    mvwprintw(win, 7, 10, "%s", tstr);
  }
  else{
    // below temporarily
    curr = time((time_t *)NULL);
    tm = localtime(&curr);
    strftime(dstr, sizeof(dstr), "%B %d, %Y", tm);
    mvwprintw(win, 6, 10, "%s", dstr);
    strftime(tstr, sizeof(tstr), "%I:%M %p", tm);
    mvwprintw(win, 7, 10, "%s", tstr);
  }
  mvwprintw(win, 8, 14, "%6.2f sec", mySettings->capture_duration);
  switch(mySettings->capture_status){
  case CAPTURE_STATUS_INACTIVE:
    mvwprintw(win, 10, 11, "Inactive    ");
    break;
  case CAPTURE_STATUS_ACTIVE:
    mvwprintw(win, 10, 11, "Running    ");
    break;
  case CAPTURE_STATUS_COMPLETE:
    mvwprintw(win, 10, 11, "Completed  ");
    break;
  case CAPTURE_STATUS_DATA_READY:
    mvwprintw(win, 10, 11, "Data Ready ");
    break;
  case CAPTURE_STATUS_DATA_EXISTS:
    mvwprintw(win, 10, 11, "File Exists");
    break;
  case CAPTURE_STATUS_DATA_ERROR:
    mvwprintw(win, 10, 11, "Data Error ");
    break;
  }
  
  update_panels();
  doupdate();
}

/**
 * operate_main_menu()
 * ------------------------
 * since main menu requires refresh & update of displayed information,
 * do that here...
 **/
void operate_main_menu(struct MENU *menu, int *position,
		       int *aborted, struct SETTINGS *mySettings,
		       WINDOW *system_win, PANEL *system_panel,
		       WINDOW *capture_win, PANEL *capture_panel,
		       int detailed_scan_active, char *elapsed,
		       struct timeval *tv_start){
  struct ITEM *itemptr;
  struct timeval tv_curr;
  int row = *position;
  int exitloop = 0;
  int ch;
  char *keyptr;
  
  menukeyhelp();
  *aborted = 0;
  menumoveto(menu, &itemptr, row);
  
  menu->descwin = newwin(1, COLS, LINES - 2, 0);
  menu->descpanel = new_panel(menu->descwin);

  wmove(menu->menuwin, row, 1);
  showitem(menu, itemptr, SELECTED);
  
  /*
   * Print item description
   */
  wattrset(menu->descwin, DESCATTR);
  colorwin(menu->descwin);
  wmove(menu->descwin, 0, 0);
  wprintw(menu->descwin, " %s", itemptr->desc);
  update_panels();
  doupdate();
  
  wmove(menu->menuwin, row, 2);
  do {
    ch = ERR;
    if (check_for_keystroke() != ERR)
      ch = wgetch(menu->menuwin);
    if (ch != ERR) {
      wmove(menu->menuwin, row, 1);
      showitem(menu, itemptr, NOTSELECTED);
      switch (ch) {
      case KEY_UP:
	if (row == 1)
	  row = menu->itemcount;
	else
	  row--;
	
	itemptr = itemptr->prev;
	
	if (itemptr->itemtype == SEPARATOR) {
	  row--;
	  itemptr = itemptr->prev;
	}
	break;
      case KEY_DOWN:
	if (row == menu->itemcount)
	  row = 1;
	else
	  row++;
	
	itemptr = itemptr->next;
	if (itemptr->itemtype == SEPARATOR) {
	  row++;
	  itemptr = itemptr->next;
	}
	break;
      case 12:
	refresh_screen();
	break;
      case 13:
	exitloop = 1;
	break;
	/* case 27: exitloop = 1;*aborted = 1;row=menu->itemcount;break; */
      case '^':
	break;		/* ignore caret key */
      default:
	keyptr = strchr(menu->shortcuts, toupper(ch));
	if ((keyptr != NULL)
	    && keyptr - menu->shortcuts < menu->itemcount) {
	  row = keyptr - menu->shortcuts + 1;
	  menumoveto(menu, &itemptr, row);
	  exitloop = 1;
	}
      }
      wmove(menu->menuwin, row, 1);
      showitem(menu, itemptr, SELECTED);
      /*
       * Print item description
       */
      wattrset(menu->descwin, DESCATTR);
      colorwin(menu->descwin);
      wmove(menu->descwin, 0, 0);
      wprintw(menu->descwin, " %s", itemptr->desc);
      update_panels();
      doupdate();
  
      wmove(menu->menuwin, row, 2);
    }    
    gettimeofday(&tv_curr, NULL);
    get_elapsed_time(&tv_curr, tv_start, elapsed);
    
    print_system_results(system_win, system_panel, mySettings,
			 detailed_scan_active, elapsed);
    print_capture_results(capture_win, capture_panel, mySettings);
    update_panels();
    doupdate();
  } while (!(exitloop));

  wmove(menu->menuwin, row, 1);
  showitem(menu, itemptr, NOTSELECTED);
  
  *position = row;		/* position of executed option is in *position */
  del_panel(menu->descpanel);
  delwin(menu->descwin);
  update_panels();
  doupdate();
}

/**
 * prompt_exit()
 * -------------
 * A routine to ask user if they wish to quit, and exit based on
 * answer.
 **/
void prompt_exit(int *aborted)
{
  WINDOW *win;
  PANEL *panel;
  int response;
  
  //  struct FIELDLIST fieldlist;
  //  char answer[3];

  //  memset(answer, 0, sizeof(answer));
  
  win = newwin(4, 50, (LINES - 4) / 2, (COLS - 50) / 2);
  panel = new_panel(win);

  wattrset(win, ERRBOXATTR);
  colorwin(win);
  box(win, ACS_VLINE, ACS_HLINE);
  wmove(win, 2, 2);
  wprintw(win, "Press 'y' to exit, 'n' to cancel");

  wattrset(win, ERRTXTATTR);
  wmove(win, 1, 2);
  wprintw(win, "Are you sure you want to exit?");

  update_panels();
  doupdate();

  *aborted = -1;
  do {
    response = wgetch(win);
    switch(response){
    case 'y':
    case 'Y':
      *aborted = 0;
      break;
    case 'n':
    case 'N':
      *aborted = 1;
      break;
    }
  } while (*aborted == -1);
  
  del_panel(panel);
  delwin(win);
}

////////////////////////////////////////////////////////////////////////////////////////////////
//  MAIN PUBLIC INTERFACE FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////

#define SCAN_CHANNEL 1
#define SELECT_TARGET 2
// -- //
#define DETAILED_AP 4
#define GEN_PROTO 5
#define TCP_ANALYSIS 6
// -- //
#define BEGIN_CAPTURE 8
#define END_CAPTURE 9
#define LOAD_CAPTURE 10
#define UNLOAD_CAPTURE 11
// -- //
#define CONFIGURE 13
// -- //
#define EXIT_PROGRAM 15

/**
 * program_interface()
 * ------------------
 * Internal program handler for the entire ncurses GUI
 **/
void program_interface(struct SETTINGS *mySettings)
{
  struct MENU menu;
  struct MENU ap_select;

  WINDOW * selected_ap_win;
  WINDOW * system_win;
  WINDOW * capture_win;
  
  PANEL * selected_ap_panel;
  PANEL * system_panel;
  PANEL * capture_panel;
  
  struct access_point *chosen = NULL;

  int channel_scanned = 0;
  int detailed_scan_active = 0;
  int endloop = 0;
  int row = 1;

  int abort;
  int resp;
  int aborted;
  int cancel_exit;

  char elapsed[1];

  struct timeval tv_start;
  struct timeval tv_curr;
  struct timeval tv_old;
  
  draw_desktop();
   
  attrset(STATUSBARATTR);
  mvprintw(0, 1, "AirTraf: %s '02", VERSION_INFO);
    
  attrset(STATUSBARATTR);
  mvprintw(LINES - 1, 1, "LINUX! - For any questions, contact me at saint@elixar.com");
  about();
  
  initmenu(&menu, 17, 35, (LINES - 16) / 2, (COLS - 35) / 2);
  
  additem(&menu, " ^S^can Channels for AP Activity",
	  "Displays list of ALL available access points");
  additem(&menu, " ^C^hange selected target AP",
	  "Allows you to select the access point you wish to analyze");
  additem(&menu, NULL, NULL);
  additem(&menu, " Detailed ^A^ccess Point monitor",
	  "Displays detailed wireless traffic information");
  additem(&menu, " ^G^eneral protocol statistics",
	  "Displays general protocol breakdown (MAC, Network, Transport)");
  additem(&menu, " TCP ^P^erformance Analysis",
	  "Displays detailed analysis of TCP performance");
  //  additem(&menu, " Ser^v^ice Breakdown by Port",
  //	  "Displays service usage breakdown for TCP & UDP connections");
  //  additem(&menu, " ^I^ntrusion detection statistics",
  //	  "Displays statistics for unauthorized activity (broken)");
  //  additem(&menu, " ^T^est access point security",
  //	  "Displays results of security check on specified AP (not yet available)");
  //  additem(&menu, NULL, NULL);
  //  additem(&menu, " Show ^D^ecoded data",
  //	  "Displays decoded data for higher protocol connections");
  //  additem(&menu, " Set Decode ^F^ilters...",
  //	  "Allows you to select filters for decoding data");
  additem(&menu, NULL, NULL);
  additem(&menu, " ^B^egin Capture process...",
	  "Allows you to start capturing this current session");
  additem(&menu, " ^E^nd Capture process",
	  "Allows you to stop capturing this current session");
  additem(&menu, " ^L^oad Capture file...",
	  "Allows you to load pre-recorded session info for playback");
  additem(&menu, " ^U^nload Capture file",
	  "Allows you to return back to Real-Time analysis mode");
  additem(&menu, NULL, NULL);
  additem(&menu, " C^o^nfigure...", "Set various program options (coming soon!)");
  additem(&menu, NULL, NULL);
  additem(&menu, " E^x^it", "Exits program");

  endloop = 0;

  gettimeofday(&tv_start,NULL);
  tv_old = tv_start;
  
  print_selected_ap_screen(&selected_ap_win, &selected_ap_panel);
  print_selected_ap_results(selected_ap_win, selected_ap_panel, chosen);

  print_system_screen(&system_win, &system_panel);
  gettimeofday(&tv_curr, NULL);
  get_elapsed_time(&tv_curr, &tv_start, elapsed);
  print_system_results(system_win, system_panel, mySettings,
		       detailed_scan_active, elapsed);
  
  print_capture_screen(&capture_win, &capture_panel);
  print_capture_results(capture_win, capture_panel, mySettings);
  
  do {
    showmenu(&menu);
    operate_main_menu(&menu, &row, &aborted, mySettings,
		      system_win, system_panel,
		      capture_win, capture_panel,
		      detailed_scan_active, elapsed,
		      &tv_start);
    
    switch (row) {

    case SCAN_CHANNEL: /** Channel Scan **/
      if (mySettings->capture_status == CAPTURE_STATUS_ACTIVE){
	errbox("Cannot perform 'Channel Scan' while 'Capture' is Active...",
	       ANYKEY_MSG, &resp);
	break;
      }
      if (detailed_scan_active){
	stop_sniffer_engine(mySettings);
	free_potential_structs();
	free_detailed_scan();
	detailed_scan_active = 0;
      }
      if (channel_scanned){
	free_channel_scan();
      }
      mySettings->scan_mode = CHANNEL_SCAN;
      initialize_channel_scan();
      start_sniffer_engine(mySettings);
      if (start_ap_mon(mySettings))
	stop_sniffer_engine(mySettings);
      channel_scanned = 1;
      abort = 0;
      if (get_channel_snapshot()->num_det_aps < 1){
	errbox("No Activity found on any channels, please scan again!",
	       ANYKEY_MSG, &resp);
	break;
      }
      /** as soon as we get out, have user pick access point **/
      select_specified_ap(&ap_select, &chosen, &abort);
      destroymenu(&ap_select);
      print_selected_ap_results(selected_ap_win, selected_ap_panel, chosen);
      if (abort){
	break;
      }
      break;

    case SELECT_TARGET: /** Change Current Active Access Point **/
      if (!channel_scanned){
	errbox("Channels have not yet been scanned...  Please scan channels first!",
	       ANYKEY_MSG, &resp);
	break;
      }
      if (mySettings->capture_status == CAPTURE_STATUS_ACTIVE){
	errbox("Cannot change/clear Target AP during 'Capture'...",
	       ANYKEY_MSG, &resp);
	break;
      }
      if (get_channel_snapshot()->num_det_aps < 1){
	errbox("No Activity found on any channels, please scan until you pick up activity!",
	       ANYKEY_MSG, &resp);
	break;
      }
      abort = 0;
      select_specified_ap(&ap_select, &chosen, &abort);
      destroymenu(&ap_select);
      print_selected_ap_results(selected_ap_win, selected_ap_panel, chosen);
      if (abort){
	break;
      }
      else{
	if (detailed_scan_active){
	  stop_sniffer_engine(mySettings);
	  free_potential_structs();
	  free_detailed_scan();
	  detailed_scan_active = 0;
	}
      }
      break;

    case DETAILED_AP: /** Detailed Access Point Monitor **/
      if (!channel_scanned){
	errbox("Channels have not yet been scanned...  Please scan channels first!",
	       ANYKEY_MSG, &resp);
	break;
      }
      if (chosen == NULL){
	errbox("You have not chosen access point yet!",
	       ANYKEY_MSG, &resp);
	break;
      }
      if ((!detailed_scan_active)&&
	  (mySettings->capture_mode != CAPTURE_MODE_PLAYBACK)){
	/** no need for locks & alerts since engine not running here **/
	if (pkt_card_is_chan_hop(mySettings->card_type)){
	  select_channel(mySettings, chosen->channel);
	}
	mySettings->scan_mode = DETAILED_SCAN;
	mySettings->chosen_ap = (void *)chosen;
	initialize_detailed_scan();
	init_potential_structs();
	detailed_scan_active = 1;
	start_sniffer_engine(mySettings);
      }
      if (!start_wt_mon(mySettings)){
	detailed_scan_active = 0;
      }
      break;

    case GEN_PROTO: /** General Protocol Scan **/
      if (!channel_scanned){
	errbox("Channels have not yet been scanned...  Please scan channels first!",
	       ANYKEY_MSG, &resp);
	break;
      }
      if (chosen == NULL){
	errbox("You have not chosen access point yet!",
	       ANYKEY_MSG, &resp);
	break;
      }
      if ((!detailed_scan_active)&&
	  (mySettings->capture_mode != CAPTURE_MODE_PLAYBACK)){
	/** no need for locks & alerts since engine not running here **/
	if (pkt_card_is_chan_hop(mySettings->card_type)){
	  select_channel(mySettings, chosen->channel);
	}
	mySettings->scan_mode = DETAILED_SCAN;
	mySettings->chosen_ap = (void *)chosen;
	initialize_detailed_scan();
	init_potential_structs();
	detailed_scan_active = 1;
	start_sniffer_engine(mySettings);
      }
      if (!start_gen_proto_mon(mySettings)){
	detailed_scan_active = 0;
      }
      break;

    case TCP_ANALYSIS:  /** TCP Performance Analysis **/
      if (!channel_scanned){
	errbox("Channels have not yet been scanned...  Please scan channels first!",
	       ANYKEY_MSG, &resp);
	break;
      }
      if (chosen == NULL){
	errbox("You have not chosen access point yet!",
	       ANYKEY_MSG, &resp);
	break;
      }
      if ((!detailed_scan_active)&&
	  (mySettings->capture_mode != CAPTURE_MODE_PLAYBACK)){
	/** no need for locks & alerts since engine not running here **/
	if (pkt_card_is_chan_hop(mySettings->card_type)){
	  select_channel(mySettings, chosen->channel);
	}
	mySettings->scan_mode = DETAILED_SCAN;
	mySettings->chosen_ap = (void *)chosen;
	initialize_detailed_scan();
	init_potential_structs();
	detailed_scan_active = 1;
	start_sniffer_engine(mySettings);
      }
      if (!start_tcp_analysis_mon(mySettings)){
	detailed_scan_active = 0;
      }

      break;
      
    case 100: /** Service Breakdown by Port **/
      if (!channel_scanned){
	errbox("Channels have not yet been scanned...  Please scan channels first!",
	       ANYKEY_MSG, &resp);
	break;
      }
      if (chosen == NULL){
	errbox("You have not chosen access point yet!",
	       ANYKEY_MSG, &resp);
	break;
      }
      /** for now... **/
      else{
	errbox("Coming very very soon!!!",
	       ANYKEY_MSG, &resp);
	break;
      }
      if ((!detailed_scan_active)&&
	  (mySettings->capture_mode != CAPTURE_MODE_PLAYBACK)){
	/** no need for locks & alerts since engine not running here **/
	if (pkt_card_is_chan_hop(mySettings->card_type)){
	  select_channel(mySettings, chosen->channel);
	}
	mySettings->scan_mode = DETAILED_SCAN;
	mySettings->chosen_ap = (void *)chosen;
	initialize_detailed_scan();
	init_potential_structs();
	detailed_scan_active = 1;
	start_sniffer_engine(mySettings);
      }
      if (!start_gen_proto_mon(mySettings)){
	detailed_scan_active = 0;	
      }
      break;
      
    case 101: /** Intrusion Detection **/
      errbox("Closed for re-modeling... :)",
	     ANYKEY_MSG, &resp);
      //      start_sniffer_engine(mySettings);
      //      start_ids_mon(mySettings->interface);
      //      stop_sniffer_engine(mySettings);
      break;

    case 102: /** Test Access Point Security **/
      errbox("Coming very very soon!!!",
	     ANYKEY_MSG, &resp);
      break;
      
    case 103: /** Decode data **/
      break;
      
    case 104: /** Set Decode Filters **/
      //config_filters(&ofilter);
      //savefilters(&ofilter);
      break;

    case BEGIN_CAPTURE: /** Start Capture process **/
      if (!channel_scanned){
	errbox("Channels have not yet been scanned...  Please scan channels first!",
	       ANYKEY_MSG, &resp);
	break;
      }
      if (chosen == NULL){
	errbox("You have not chosen access point yet!",
	       ANYKEY_MSG, &resp);
	break;
      }
      if (mySettings->capture_status == CAPTURE_STATUS_ACTIVE){
	errbox("You already have a 'Capture' session active!",
	       ANYKEY_MSG, &resp);
	break;
      }
      mySettings->capture_mode = CAPTURE_MODE_RECORD;
      if (!set_capture_options(mySettings)){
	mySettings->capture_mode = CAPTURE_MODE_OFF;
	break;
      }
      if (!init_capture(mySettings)){
	mySettings->capture_mode = CAPTURE_MODE_OFF;
	errbox("Error Initializing Capture File!",
	       ANYKEY_MSG, &resp);
	break;
      }
      if (!detailed_scan_active){
	/** no need for locks & alerts since engine not running here **/
	if (pkt_card_is_chan_hop(mySettings->card_type))
	  select_channel(mySettings, chosen->channel);
	mySettings->scan_mode = DETAILED_SCAN;
	mySettings->chosen_ap = (void *)chosen;
	initialize_detailed_scan();
	init_potential_structs();
	detailed_scan_active = 1;
	start_sniffer_engine(mySettings);
      }
      start_capture_engine(mySettings);
      mySettings->capture_status = CAPTURE_STATUS_ACTIVE;
      break;
      
    case END_CAPTURE: /** End Capture process **/
      if (mySettings->capture_status != CAPTURE_STATUS_ACTIVE){
	errbox("You must START Capture before you can END it!",
	       ANYKEY_MSG, &resp);
	break;
      }
      if (mySettings->capture_mode != CAPTURE_MODE_RECORD){
	break;
      }
      stop_capture_engine(mySettings);
      free_capture();
      mySettings->capture_mode = CAPTURE_MODE_OFF;
      mySettings->capture_status = CAPTURE_STATUS_COMPLETE;
      break;
      
    case LOAD_CAPTURE: /** Load Capture File **/
      if (mySettings->capture_status == CAPTURE_STATUS_ACTIVE){
	errbox("You already have a 'Capture' session active!",
	       ANYKEY_MSG, &resp);
	break;
      }
      if (detailed_scan_active){
	errbox("There's already a RT-session going on!",
	       ANYKEY_MSG, &resp);
	break;
      }
      mySettings->capture_mode = CAPTURE_MODE_PLAYBACK;
      mySettings->capture_status = CAPTURE_STATUS_INACTIVE;
      if (!set_capture_options(mySettings)){
	mySettings->capture_mode = CAPTURE_MODE_OFF;
	break;
      }
      if (!init_capture(mySettings)){
	errbox("Error Initializing Capture File!",
	       ANYKEY_MSG, &resp);
	mySettings->capture_mode = CAPTURE_MODE_OFF;
	mySettings->capture_status = CAPTURE_STATUS_INACTIVE;
	break;
      }
      if (get_detailed_snapshot() == NULL)
	initialize_detailed_scan();
      if (!start_capture_engine(mySettings)){
	errbox("Error reading Capture File!", ANYKEY_MSG, &resp);
	mySettings->capture_mode = CAPTURE_MODE_OFF;
	mySettings->capture_status = CAPTURE_STATUS_INACTIVE;
	break;
      }
      chosen = mySettings->chosen_ap;
      print_selected_ap_results(selected_ap_win, selected_ap_panel, chosen);
      /** temporarily **/
      channel_scanned = 1;
      mySettings->capture_status = CAPTURE_STATUS_ACTIVE;
      break;
      
    case UNLOAD_CAPTURE: /** Unload Capture File **/
      if (mySettings->capture_mode == CAPTURE_MODE_PLAYBACK){
	free(mySettings->chosen_ap);
	mySettings->chosen_ap = NULL;
	mySettings->capture_size = 0;
	mySettings->capture_duration = 0;
	chosen = NULL;
	free_detailed_scan();
	free_capture();
	/** force re-scan **/
	channel_scanned = 0;
	mySettings->capture_mode = CAPTURE_MODE_OFF;
	mySettings->capture_status = CAPTURE_STATUS_INACTIVE;
	print_selected_ap_results(selected_ap_win, selected_ap_panel, chosen);
	break;
      }
      else{
	errbox("No Loaded Capture file!",
	       ANYKEY_MSG, &resp);
	break;
      }
      break;
    case CONFIGURE:
      //setoptions(options, &ports);
      //saveoptions(options);
      break;
    case EXIT_PROGRAM:
      prompt_exit(&cancel_exit);
      if (!cancel_exit){
	endloop = 1;	
      }
      break;
    }

    /** do some updates... **/
    gettimeofday(&tv_curr, NULL);
    get_elapsed_time(&tv_curr, &tv_start, elapsed);

    print_system_results(system_win, system_panel, mySettings,
			 detailed_scan_active, elapsed);
    print_capture_results(capture_win, capture_panel, mySettings);
    
  } while ((!endloop) && (!sysexit));
  del_panel(selected_ap_panel);
  delwin(selected_ap_win);
  del_panel(system_panel);
  delwin(system_win);
  del_panel(capture_panel);
  delwin(capture_win);
  
  destroymenu(&menu);
  erase();
  update_panels();
  doupdate();
}
  
