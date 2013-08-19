/***

options.c - implements the configuration section of the utility
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

#include <curses.h>
#include <panel.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "links.h"
#include "serv.h"
#include "options.h"
#include "deskman.h"
#include "attrs.h"
#include "stdwinset.h"
#include "menurt.h"
#include "input.h"
#include "landesc.h"
#include "error.h"
#include "promisc.h"
#include "dirs.h"
#include "instances.h"

#define ALLOW_ZERO 1
#define DONT_ALLOW_ZERO 0

void makeoptionmenu(struct MENU *menu)
{
    initmenu(menu, 19, 40, (LINES - 19) / 2 - 1, (COLS - 40) / 16);
    additem(menu, " ^R^everse DNS lookups",
	    "Toggles resolution of IP addresses into host names");
    additem(menu, " TCP/UDP ^s^ervice names",
	    "Displays TCP/UDP service names instead of numeric ports");
    additem(menu, " Force ^p^romiscuous mode",
	    "Toggles capture of all packets by LAN interfaces");
    additem(menu, " ^C^olor",
	    "Turns color on or off (restart IPTraf to effect change)");
    additem(menu, " ^L^ogging",
	    "Toggles logging of traffic to a data file");
    additem(menu, " Acti^v^ity mode",
	    "Toggles activity indicators between kbits/s and kbytes/s");
    additem(menu, " Source ^M^AC addrs in traffic monitor",
            "Toggles display of source MAC addresses in the IP Traffic Monitor");
    additem(menu, NULL, NULL);
    additem(menu, " ^T^imers...", "Configures timeouts and intervals");
    additem(menu, NULL, NULL);
    additem(menu, " ^A^dditional ports...",
	    "Allows you to add port numbers higher than 1023 for the service stats");
    additem(menu, " ^D^elete port/range...",
	    "Deletes a port or range of ports earlier added");
    additem(menu, NULL, NULL);
    additem(menu, " ^E^thernet/PLIP host descriptions...",
	    "Manages descriptions for Ethernet/PLIP addresses");
    additem(menu, " ^F^DDI host descriptions...",
	    "Manages descriptions for FDDI addresses");
    additem(menu, NULL, NULL);
    additem(menu, " E^x^it configuration", "Returns to main menu");
}

void maketimermenu(struct MENU *menu)
{
    initmenu(menu, 7, 35, (LINES - 19) / 2 + 7, (COLS - 35) / 2);
    additem(menu, " TCP ^t^imeout...",
	    "Sets the length of time before inactive TCP entries are considered idle");
    additem(menu, " ^L^ogging interval...",
	    "Sets the time between loggings for interface, host, and service stats");
    additem(menu, " ^S^creen update interval...",
	    "Sets the screen update interval in seconds (set to 0 for fastest updates)");
    additem(menu, " TCP closed/idle ^p^ersistence...",
	    "Determines how long closed/idle/reset entries stay onscreen");
    additem(menu, " E^x^it menu", "Returns to the configuration menu");
}

void printoptonoff(unsigned int option, WINDOW * win)
{
    if (option)
	wprintw(win, " On");
    else
	wprintw(win, "Off");
}

void indicatesetting(int row, struct OPTIONS *options, WINDOW * win)
{
    wmove(win, row, 30);
    wattrset(win, HIGHATTR);

    switch (row) {
    case 1:
	printoptonoff(options->revlook, win);
	break;
    case 2:
	printoptonoff(options->servnames, win);
	break;
    case 3:
	printoptonoff(options->promisc, win);
	break;
    case 4:
	printoptonoff(options->color, win);
	break;
    case 5:
	printoptonoff(options->logging, win);
	break;
    case 6:
	wmove(win, row, 25);
	if (options->actmode == KBITS)
	    wprintw(win, " kbits/s");
	else
	    wprintw(win, "kbytes/s");
        break;
    case 7:
        printoptonoff(options->mac, win);
        break;
    }
   
}

void saveoptions(struct OPTIONS *options)
{
    int fd;
    int bw;
    int response;

    fd = open(CONFIGFILE, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);

    if (fd < 0) {
	errbox("Cannot create config file", ANYKEY_MSG, &response);
	return;
    }
    bw = write(fd, options, sizeof(struct OPTIONS));

    if (bw < 0)
	errbox("Unable to write config file", ANYKEY_MSG, &response);

    close(fd);
}

void setdefaultopts(struct OPTIONS *options)
{
    options->revlook = 0;
    options->promisc = 0;
    options->servnames = 0;
    options->color = 1;
    options->logging = 0;
    options->actmode = KBITS;
    options->mac = 0;
    options->timeout = 15;
    options->logspan = 3600;
    options->updrate = 0;
    options->closedint = 0;
}

void loadoptions(struct OPTIONS *options)
{
    int fd;
    int br;

    setdefaultopts(options);
    fd = open(CONFIGFILE, O_RDONLY);

    if (fd < 0)
	return;

    br = read(fd, options, sizeof(struct OPTIONS));

    close(fd);
}

void updatetimes(struct OPTIONS *options, WINDOW * win)
{
    wattrset(win, HIGHATTR);
    mvwprintw(win, 9, 25, "%3u mins", options->timeout);
    mvwprintw(win, 10, 25, "%3u mins", options->logspan / 60);
    mvwprintw(win, 11, 25, "%3u secs", options->updrate);
    mvwprintw(win, 12, 25, "%3u mins", options->closedint);
}

void showoptions(struct OPTIONS *options, WINDOW * win)
{
    int i;

    for (i = 1; i <= 7; i++)
	indicatesetting(i, options, win);

    updatetimes(options, win);
}

void settimeout(unsigned int *value, const char *units, int allow_zero,
		int *aborted)
{
    WINDOW *dlgwin;
    PANEL *dlgpanel;
    struct FIELDLIST field;
    int resp;
    unsigned int tmval = 0;

    dlgwin = newwin(7, 40, (LINES - 7) / 2, (COLS - 40) / 4);
    dlgpanel = new_panel(dlgwin);

    wattrset(dlgwin, DLGBOXATTR);
    colorwin(dlgwin);
    box(dlgwin, ACS_VLINE, ACS_HLINE);

    wattrset(dlgwin, DLGTEXTATTR);
    wmove(dlgwin, 2, 2);
    wprintw(dlgwin, "Enter value in %s", units);
    wmove(dlgwin, 5, 2);
    stdkeyhelp(dlgwin);

    initfields(&field, 1, 10, (LINES - 7) / 2 + 3, (COLS - 40) / 4 + 2);
    addfield(&field, 3, 0, 0, "");

    do {
	fillfields(&field, aborted);

	if (!(*aborted)) {
	    tmval = atoi(field.list->buf);
	    if ((!allow_zero) && (tmval == 0))
		errbox("Invalid timeout value", ANYKEY_MSG, &resp);
	}
    } while (((!allow_zero) && (tmval == 0)) && (!(*aborted)));

    if (!(*aborted))
	*value = tmval;

    del_panel(dlgpanel);
    delwin(dlgwin);

    destroyfields(&field);
    update_panels();
    doupdate();
}

void setoptions(struct OPTIONS *options, struct porttab **ports)
{
    int row = 1;
    int trow = 1;        /* row for timer submenu */
    int aborted;
    int resp;

    struct MENU menu;
    struct MENU timermenu;
    
    WINDOW *statwin;
    PANEL *statpanel;

    if (!is_first_instance) {
	errbox("Only the first instance of IPTraf can configure",
	       ANYKEY_MSG, &resp);
	return;
    }
    makeoptionmenu(&menu);
    
    statwin = newwin(14, 35, (LINES - 19) / 2 - 1, (COLS - 40) / 16 + 40);
    statpanel = new_panel(statwin);

    wattrset(statwin, BOXATTR);
    colorwin(statwin);
    box(statwin, ACS_VLINE, ACS_HLINE);
    wmove(statwin, 8, 1);
    whline(statwin, ACS_HLINE, 33);
    mvwprintw(statwin, 0, 1, " Current Settings ");
    wattrset(statwin, STDATTR);
    mvwprintw(statwin, 1, 2, "Reverse DNS lookups:");
    mvwprintw(statwin, 2, 2, "Service names:");
    mvwprintw(statwin, 3, 2, "Promiscuous:");
    mvwprintw(statwin, 4, 2, "Color:");
    mvwprintw(statwin, 5, 2, "Logging:");
    mvwprintw(statwin, 6, 2, "Activity mode:");
    mvwprintw(statwin, 7, 2, "MAC addresses:");
    mvwprintw(statwin, 9, 2, "TCP timeout:");
    mvwprintw(statwin, 10, 2, "Log interval:");
    mvwprintw(statwin, 11, 2, "Update interval:");
    mvwprintw(statwin, 12, 2, "Closed/idle persist:");
    showoptions(options, statwin);

    do {
	showmenu(&menu);
	operatemenu(&menu, &row, &aborted);

	switch (row) {
	case 1:
	    options->revlook = ~(options->revlook);
	    break;
	case 2:
	    options->servnames = ~(options->servnames);
	    break;
	case 3:
	    options->promisc = ~(options->promisc);
	    break;
	case 4:
	    options->color = ~(options->color);
	    break;
	case 5:
	    options->logging = ~(options->logging);
	    break;
	case 6:
	    options->actmode = ~(options->actmode);
	    break;
	case 7:
	    options->mac = ~(options->mac);
	    break;
	case 9:
            maketimermenu(&timermenu);
	    do {
	        showmenu(&timermenu);
	        operatemenu(&timermenu, &trow, &aborted);
	        
	        switch(trow) {
	        case 1:
	            settimeout(&(options->timeout), "minutes", DONT_ALLOW_ZERO,
		           &aborted);
	            if (!aborted)
		        updatetimes(options, statwin);
	            break;
		case 2:
	            settimeout((unsigned int *) &(options->logspan), "minutes",
		               DONT_ALLOW_ZERO, &aborted);
	            if (!aborted) {
		        options->logspan = options->logspan * 60;
		        updatetimes(options, statwin);
	            }
	            break;
	        case 3:
	            settimeout(&options->updrate, "seconds", ALLOW_ZERO, &aborted);
	            if (!aborted)
		        updatetimes(options, statwin);
	            break;
	        case 4:
	            settimeout(&options->closedint, "minutes", ALLOW_ZERO,
		               &aborted);
	            if (!aborted)
		        updatetimes(options, statwin);
	            break;
	        }
	    } while (trow != 5);
	    
	    destroymenu(&timermenu);
	    update_panels();
	    doupdate();
	    break;
	case 11:
	    addmoreports(ports);
	    break;
	case 12:
	    removeaport(ports);
	    break;
	case 14:
	    ethdescmgr(LINK_ETHERNET);
	    break;
	case 15:
	    ethdescmgr(LINK_FDDI);
	    break;
	}

	indicatesetting(row, options, statwin);
    } while (row != 17);

    destroymenu(&menu);
    del_panel(statpanel);
    delwin(statwin);
    update_panels();
    doupdate();
}
