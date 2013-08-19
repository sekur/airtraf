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
/***

deskman.c - desktop management routines

Written by Gerard Paul Java
Copyright (c) Gerard Paul Java 1997, 1998

This software is open source; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed WITHOUT ANY WARRANTY; without even the
implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License in the included COPYING file for
details.

***/

#include <ncurses.h>
#include <stdlib.h>
#include <panel.h>
#include <string.h>
#include "stdwinset.h"
#include "deskman.h"
#include "error.h"

/* Attribute variables */

int STDATTR;
int HIGHATTR;
int BOXATTR;
int ACTIVEATTR;
int ALERTATTR;
int BARSTDATTR;
int BARHIGHATTR;
int DLGTEXTATTR;
int DLGBOXATTR;
int DLGHIGHATTR;
int DESCATTR;
int STATUSBARATTR;
int IPSTATLABELATTR;
int IPSTATATTR;
int PTRATTR;
int FIELDATTR;
int ERRBOXATTR;
int ERRTXTATTR;
int OSPFATTR;
int UDPATTR;
int IGPATTR;
int IGMPATTR;
int IGRPATTR;
int GREATTR;
int ARPATTR;
int UNKNATTR;


/*  draw the basic desktop common to my screen-oriented programs */

void draw_desktop(void)
{
    int row;			/* counter for desktop construction */
    char sp_buf[10];
    
    sprintf(sp_buf, "%%%dc", COLS);
    scrollok(stdscr, 0);
    attrset(STATUSBARATTR);
    move(0, 0);
    printw(sp_buf, ' ');	/* these two print the top n' bottom */
    move(LINES - 1, 0);
    printw(sp_buf, ' ');	/* lines */

    attrset(FIELDATTR);

    for (row = 1; row <= LINES - 2; row++) {	/* draw the background */
	move(row, 0);
	printw(sp_buf, ' ');
    }

    refresh();
}

/* for some reason, the ncurses box routine does not color
   its inside.  it would therefore be better to call this
   routine before drawing the box.
 */  

void colorwin(WINDOW * win)
{
    int ctr;
    char *blankpad;
    blankpad = (char *) malloc(sizeof(char) * (COLS + 1));

    strcpy(blankpad, "");

    for (ctr = 0; ctr <= win->_maxx; ctr++) {
	strcat(blankpad, " ");
    }

    scrollok(win, 0);
    for (ctr = 0; ctr <= win->_maxy; ctr++) {
	wmove(win, ctr, 0);
	wprintw(win, "%s", blankpad);
    }
    scrollok(win, 1);
    free(blankpad);
}

void coloreol()
{
    char *blankpad;
    int y, x;
    int i;

    blankpad = (char *) malloc(sizeof(char) * (COLS + 1));
    strcpy(blankpad, "");
    getyx(stdscr, y, x);

    for (i = x; i <= COLS - 1; i++)
	strcat(blankpad, " ");

    printw(blankpad);
    free(blankpad);
}

void about()
{
    WINDOW *win;
    PANEL *panel;
    int ch;

    win = newwin(15, 50, (LINES - 15) / 2, (COLS - 50) / 2);
    panel = new_panel(win);

    stdwinset(win);
    wtimeout(win, -1);
    wattrset(win, BOXATTR);
    colorwin(win);
    box(win, ACS_VLINE, ACS_HLINE);
    wattrset(win, STDATTR);
    mvwprintw(win, 1, 2, "-=[ AirTraf ]=-");
    mvwprintw(win, 2, 2, "A Wireless Network Analysis/Statistics Utility");
    mvwprintw(win, 5, 2, "Written by Peter K. Lee");
    mvwprintw(win, 6, 2, "Copyright (c) Elixar, Inc. 2001-2002");
    mvwprintw(win, 8, 2, "This program is distributed under the terms of");
    mvwprintw(win, 9, 2, "the GNU General Public License Version 2 or");
    mvwprintw(win, 10, 2, "any later version. See the included COPYING");
    mvwprintw(win, 11, 2, "file for details.");

    wattrset(win, HIGHATTR);
    mvwprintw(win, 13, 2, ANYKEY_MSG);

    update_panels();
    doupdate();

    do {
	ch = wgetch(win);
	if (ch == 12)
	    refresh_screen();
    } while (ch == 12);

    del_panel(panel);
    delwin(win);
    update_panels();
    doupdate();
}

void show_sort_statwin(WINDOW **statwin, PANEL **panel)
{
    *statwin = newwin(5, 30, (LINES - 5) / 2, (COLS - 30) / 2);
    *panel = new_panel(*statwin);
    
    wattrset(*statwin, BOXATTR);
    colorwin(*statwin);
    box(*statwin, ACS_VLINE, ACS_HLINE);
    
    wattrset(*statwin, STDATTR);
    mvwprintw(*statwin, 2, 2, "Sorting, please wait...");
}

void printnomem()
{
    attrset(ERRTXTATTR);
    mvprintw(0, 68, " Memory Low ");
}

void printipcerr()
{
    attrset(ERRTXTATTR);
    mvprintw(0, 68, "  IPC Error ");
}

void printkeyhelp(char *keytext, char *desc, WINDOW * win,
                  int highattr, int textattr)
{
    wattrset(win, highattr);
    wprintw(win, "%s", keytext);
    wattrset(win, textattr);
    wprintw(win, "%s", desc);
}

void stdkeyhelp(WINDOW * win)
{
    printkeyhelp("Enter", "-accept  ", win, DLGHIGHATTR, DLGTEXTATTR);
    printkeyhelp("Ctrl+X", "-cancel", win, DLGHIGHATTR, DLGTEXTATTR);
}

void sortkeyhelp(void)
{
    printkeyhelp("S", "-sort  ", stdscr, HIGHATTR, STATUSBARATTR);
}

void stdexitkeyhelp(void)
{
    printkeyhelp("X", "-exit", stdscr, HIGHATTR, STATUSBARATTR);
    coloreol(stdscr);
}

void changewinkeyhelp(void)
{
  printkeyhelp("W", "-change active window  ", stdscr, HIGHATTR, STATUSBARATTR);
}

void scrollkeyhelp(void)
{
  printkeyhelp("Up/Down/PgUp/PgDn", "-scroll window  ", stdscr, HIGHATTR, STDATTR);
}

void channelkeyhelp(void)
{
  printkeyhelp("Left/Right", "-change channels  ", stdscr, HIGHATTR, STATUSBARATTR);
}

void viewkeyhelp(void)
{
  printkeyhelp("V", "-toggle view  ", stdscr, HIGHATTR, STATUSBARATTR);
}

void pausekeyhelp(void)
{
  printkeyhelp("P", "-pause  ", stdscr, HIGHATTR, STATUSBARATTR);  
}

void menukeyhelp(void)
{
    move(LINES - 1, 1);
    printkeyhelp("Up/Down", "-Move selector  ", stdscr, HIGHATTR, STATUSBARATTR);
    printkeyhelp("Enter", "-execute", stdscr, HIGHATTR, STATUSBARATTR);
    coloreol(stdscr);
}

void listkeyhelp()
{
    move(LINES - 1, 1);
    printkeyhelp("Up/Down", "-move pointer  ", stdscr, HIGHATTR, STATUSBARATTR);
    printkeyhelp("Enter", "-select  ", stdscr, HIGHATTR, STATUSBARATTR);
    stdexitkeyhelp();
}

void tabkeyhelp(WINDOW * win)
{
    printkeyhelp("Tab", "-next field  ", win, DLGHIGHATTR, DLGTEXTATTR);
}

void indicate(char *message)
{
    char sp_buf[10];
    attrset(STATUSBARATTR);
    sprintf(sp_buf, "%%%dc", COLS);
    mvprintw(LINES - 1, 0, sp_buf, ' ');
    mvprintw(LINES - 1, 1, message);
    refresh();
}

void printlargenum(unsigned long long i, WINDOW * win)
{
    if (i < 100000000)		/* less than 100 million */
	wprintw(win, "%9llu", i);
    else if (i < 1000000000)	/* less than 1 billion */
	wprintw(win, "%8lluK", i / 1000);
    else if (i < 100000000000ULL)	/* less than 100 billion */
	wprintw(win, "%8lluM", i / 1000000);
    else if (i < 100000000000000ULL)	/* less than 100 trillion */
	wprintw(win, "%8lluG", i / 1000000000ULL);
    else
	wprintw(win, "%8lluT", i / 1000000000000ULL);
}

/**
 * show_paused_win()
 * -------------------
 * Pop up "paused" window, displaying the selected message
 **/
void show_paused_win(WINDOW ** win, PANEL ** panel, char * message, char *message2)
{
    *win = newwin(4, 30, (LINES - 5) / 2, (COLS - 30) / 2);
    *panel = new_panel(*win);

    wattrset(*win, ERRBOXATTR);
    colorwin(*win);
    box(*win, ACS_VLINE, ACS_HLINE);

    wattrset(*win, ERRTXTATTR);
    mvwprintw(*win, 1, 3, "%s", message);
    wattrset(*win, ERRBOXATTR);
    mvwprintw(*win, 2, 3, "%s", message2);
    update_panels();
    doupdate();
}

void infobox(char *text, char *prompt)
{
    WINDOW *win;
    PANEL *panel;
    
    win = newwin(4, 50, (LINES - 4) / 2, (COLS - 50) / 2);
    panel = new_panel(win);
    wattrset(win, BOXATTR);
    colorwin(win);
    box(win, ACS_VLINE, ACS_HLINE);
    wattrset(win, STDATTR);
    mvwprintw(win, 1, 2, text);
    wattrset(win, HIGHATTR);
    mvwprintw(win, 2, 2, prompt);
    update_panels();
    doupdate();
    wgetch(win);
    del_panel(panel);
    delwin(win);

    update_panels();
    doupdate();
}

void standardcolors(int color)
{
  if ((color) && (has_colors())) {
    init_pair(1, COLOR_BLUE, COLOR_WHITE);
    init_pair(2, COLOR_BLACK, COLOR_CYAN);
    init_pair(3, COLOR_CYAN, COLOR_BLUE);
    init_pair(4, COLOR_YELLOW, COLOR_RED);
    init_pair(5, COLOR_WHITE, COLOR_RED);
    init_pair(6, COLOR_BLUE, COLOR_CYAN);
    init_pair(7, COLOR_BLUE, COLOR_WHITE);
    init_pair(9, COLOR_RED, COLOR_WHITE);
    init_pair(10, COLOR_GREEN, COLOR_BLUE);
    init_pair(11, COLOR_CYAN, COLOR_BLACK);
    init_pair(12, COLOR_RED, COLOR_CYAN);
    init_pair(14, COLOR_YELLOW, COLOR_BLUE);
    init_pair(15, COLOR_YELLOW, COLOR_BLACK);
    init_pair(16, COLOR_WHITE, COLOR_CYAN);
    init_pair(17, COLOR_YELLOW, COLOR_CYAN);
    init_pair(18, COLOR_RED, COLOR_BLUE);
    
    STDATTR = COLOR_PAIR(14) | A_BOLD;
    HIGHATTR = COLOR_PAIR(3) | A_BOLD;
    BOXATTR = COLOR_PAIR(3);
    ACTIVEATTR = COLOR_PAIR(10) | A_BOLD;
    ALERTATTR = COLOR_PAIR(18) | A_BOLD;
    BARSTDATTR = COLOR_PAIR(15) | A_BOLD;
    BARHIGHATTR = COLOR_PAIR(11) | A_BOLD;
    DESCATTR = COLOR_PAIR(2);
    DLGTEXTATTR = COLOR_PAIR(2);
    DLGBOXATTR = COLOR_PAIR(6);
    DLGHIGHATTR = COLOR_PAIR(12);
    STATUSBARATTR = STDATTR;
    IPSTATLABELATTR = COLOR_PAIR(2);
    IPSTATATTR = COLOR_PAIR(12);
    PTRATTR = COLOR_PAIR(10) | A_BOLD;
    FIELDATTR = COLOR_PAIR(1);
    ERRBOXATTR = COLOR_PAIR(5) | A_BOLD;
    ERRTXTATTR = COLOR_PAIR(4) | A_BOLD;
    OSPFATTR = COLOR_PAIR(2);
    UDPATTR = COLOR_PAIR(9);
    IGPATTR = COLOR_PAIR(12);
    IGMPATTR = COLOR_PAIR(10) | A_BOLD;
    IGRPATTR = COLOR_PAIR(16) | A_BOLD;
    ARPATTR = COLOR_PAIR(5) | A_BOLD;
    GREATTR = COLOR_PAIR(1);
    UNKNATTR = COLOR_PAIR(4) | A_BOLD;
    } else {
      STDATTR = A_NORMAL;
      HIGHATTR = A_BOLD;
      BOXATTR = A_NORMAL;
      ACTIVEATTR = A_BOLD;
      BARSTDATTR = A_REVERSE;
      BARHIGHATTR = A_BOLD;
      DESCATTR = A_NORMAL;
      DLGBOXATTR = A_REVERSE;
      DLGTEXTATTR = A_REVERSE;
      DLGHIGHATTR = A_BOLD;
      STATUSBARATTR = A_REVERSE;
      IPSTATLABELATTR = A_REVERSE;
      IPSTATATTR = A_STANDOUT;
      PTRATTR = A_BOLD;
      FIELDATTR = A_BOLD;
      ERRBOXATTR = A_BOLD;
      ERRTXTATTR = A_NORMAL;
      OSPFATTR = A_REVERSE;
      UDPATTR = A_BOLD;
      IGPATTR = A_REVERSE;
      IGMPATTR = A_REVERSE;
      IGRPATTR = A_REVERSE;
      ARPATTR = A_BOLD;
      GREATTR = A_BOLD;
      UNKNATTR = A_BOLD;
    }
}

void refresh_screen(void)
{
    endwin();
    doupdate();
    curs_set(0);
}
