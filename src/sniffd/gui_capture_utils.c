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
 **  gui_capture_utils.c
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

void make_capture_controls(WINDOW **win, PANEL **panel)
{
  *win = newwin(11, 25, LINES - 16, COLS - 30);
  *panel = new_panel(*win);
  stdwinset(*win);
  wtimeout(*win, -1);
  wattrset(*win, DLGBOXATTR);
  colorwin(*win);
  box(*win, ACS_VLINE, ACS_HLINE);
  wattrset(*win, DLGTEXTATTR);
  mvwprintw(*win, 1, 2, "Capture Controls");
  mvwprintw(*win, 9, 2, "Duration: ");
  wattrset(*win, DLGHIGHATTR);
  mvwprintw(*win, 2, 2, "F");
  mvwprintw(*win, 3, 2, "f");
  mvwprintw(*win, 4, 2, "P");
  mvwprintw(*win, 5, 2, "S");
  mvwprintw(*win, 6, 2, "b");
  mvwprintw(*win, 7, 2, "B");
  mvwprintw(*win, 8, 2, "R");
  
  wattrset(*win, DLGTEXTATTR);
  mvwprintw(*win, 2, 3, "- Fast Forward");
  mvwprintw(*win, 3, 3, "- Step Forward");
  mvwprintw(*win, 4, 3, "- Play");
  mvwprintw(*win, 5, 3, "- Stop");
  mvwprintw(*win, 6, 3, "- Step Back");
  mvwprintw(*win, 7, 3, "- Fast Back");
  mvwprintw(*win, 8, 3, "- Reset Data");
  update_panels();
  doupdate();
}

void print_capture_update(WINDOW *win, struct SETTINGS *mySettings)
{
  wattrset(win, DLGHIGHATTR);
  mvwprintw(win, 9, 13, "%6.2f sec", mySettings->capture_duration);
}

void parse_capture_key(struct SETTINGS *mySettings, int ch)
{
  switch(ch){
  case 'F':
    // do fast auto-forward
    if (!get_capture_status()){
      mySettings->capture_command = CAPTURE_PB_FF;
      start_capture_engine(mySettings);
    }
    break;
  case 'f':
    // do step forward
    if (!get_capture_status())
      capture_playback_forward(mySettings);
    break;
  case 'B':
    // do fast auto-rewind
    if (!get_capture_status()){
      mySettings->capture_command = CAPTURE_PB_RR;
      start_capture_engine(mySettings);      
    }
    break;
  case 'b':
    // do step rewind
    if (!get_capture_status()){
      capture_playback_rewind(mySettings);
      capture_playback_rewind(mySettings);
      capture_playback_forward(mySettings);      
    }
    break;
  case 'R':
  case 'r':
    if (!get_capture_status()){
      capture_playback_beginning(mySettings);      
    }
    break;
  case 'S':
  case 's':
    // stop
    if (get_capture_status()){
      stop_capture_engine(mySettings);
      mySettings->capture_command = CAPTURE_PB_STOP;
      capture_playback_forward(mySettings);
    }
    break;
  case 'P':
  case 'p':
    // start simulation play
    if (!get_capture_status()){
      mySettings->capture_command = CAPTURE_PB_PLAY;
      start_capture_engine(mySettings);
    }
    break;
  }
  
}
