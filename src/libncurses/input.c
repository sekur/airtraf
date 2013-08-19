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

input.c - a custom keyboard input module     
Written by Gerard Paul Java
Copyright (c) Gerard Paul Java 1997

This module is distributed WITHOUT ANY WARRANTY; without even the
implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

This module may be included in software provided the above copyright
notice is preserved.  Acknowledgement of this work is appreciated but
not required.

***/

#include <curses.h>
#include <panel.h>
#include "input.h"
#include "deskman.h"
#include "attrs.h"

void initfields(struct FIELDLIST *list, int leny, int lenx, int begy,
		int begx)
{
    list->list = NULL;
    list->fieldwin = newwin(leny, lenx, begy, begx);
    list->fieldpanel = new_panel(list->fieldwin);
    stdwinset(list->fieldwin);
    wtimeout(list->fieldwin, -1);
    wattrset(list->fieldwin, DLGTEXTATTR);
    colorwin(list->fieldwin);
    update_panels();
    doupdate();
}

void addfield(struct FIELDLIST *list, unsigned int len,
	      unsigned int y, unsigned int x, char *initstr)
{
    struct FIELD *newfield;
    int i;

    newfield = malloc(sizeof(struct FIELD));

    if (list->list == NULL) {
	list->list = newfield;
	newfield->prevfield = newfield;
	newfield->nextfield = newfield;
    } else {
	newfield->prevfield = list->list->prevfield;
	list->list->prevfield->nextfield = newfield;
	list->list->prevfield = newfield;
	newfield->nextfield = list->list;
    }

    newfield->xpos = x;
    newfield->ypos = y;
    newfield->len = len;
    newfield->tlen = strlen(initstr);
    newfield->buf = malloc(len + 1);
    bzero(newfield->buf, len + 1);
    strncpy(newfield->buf, initstr, len);

    if (newfield->tlen > (len))
	newfield->tlen = len;

    wattrset(list->fieldwin, FIELDATTR);
    wmove(list->fieldwin, y, x);
    for (i = 1; i <= len; i++)
	wprintw(list->fieldwin, " ");

    wmove(list->fieldwin, y, x);
    wprintw(list->fieldwin, "%s", newfield->buf);

    update_panels();
    doupdate();
}

void getinput(struct FIELDLIST *list, struct FIELD *field, int *exitkey)
{
    int ch;
    int y, x;
    int endloop = 0;

    wmove(list->fieldwin, field->ypos, field->xpos);
    wattrset(list->fieldwin, FIELDATTR);
    wprintw(list->fieldwin, "%s", field->buf);
    update_panels();
    doupdate();

    do {
	ch = wgetch(list->fieldwin);
	switch (ch) {
#ifndef DISABLEBS
	case KEY_BACKSPACE:
#endif
	case 7:
	case 8:
	case KEY_DC:
	case KEY_LEFT:
	    if (field->tlen > 0) {
		getyx(list->fieldwin, y, x);
		x--;
		wmove(list->fieldwin, y, x);
		wprintw(list->fieldwin, " ");
		wmove(list->fieldwin, y, x);
		field->tlen--;
		field->buf[field->tlen] = '\0';
	    }
	    break;
	case 9:
	case 27:
	case 24:
	case 13:
	case 10:
	case KEY_UP:
	case KEY_DOWN:
	    endloop = 1;
	    *exitkey = ch;

	    break;
	case 12:
	    refresh_screen();
	    break;
	default:
	    if ((field->tlen < field->len) && ((ch >= 32) && (ch <= 127))) {
		wprintw(list->fieldwin, "%c", ch);
		if (ch == ' ') {
		    getyx(list->fieldwin, y, x);
		    wmove(list->fieldwin, y, x);
		}
		field->buf[field->tlen + 1] = '\0';
		field->buf[field->tlen] = ch;
		field->tlen++;
	    }
	    break;
	}

	doupdate();
    } while (!endloop);
}

void fillfields(struct FIELDLIST *list, int *aborted)
{
    struct FIELD *field;
    int exitkey;
    int exitloop = 0;

    field = list->list;

    curs_set(1);
    do {
	getinput(list, field, &exitkey);

	switch (exitkey) {
	case 9:
	case KEY_DOWN:
	    field = field->nextfield;
	    break;
	case KEY_UP:
	    field = field->prevfield;
	    break;
	case 13:
	case 10:
	    *aborted = 0;
	    exitloop = 1;
	    break;
	case 27:
	case 24:
	    *aborted = 1;
	    exitloop = 1;
	    break;
	}
    } while (!exitloop);

    curs_set(0);
}

void destroyfields(struct FIELDLIST *list)
{
    struct FIELD *ptmp;
    struct FIELD *pnext;

    list->list->prevfield->nextfield = NULL;
    ptmp = list->list;
    pnext = list->list->nextfield;

    do {
	free(ptmp);

	ptmp = pnext;
	if (pnext != NULL) {
	    pnext = pnext->nextfield;
	}
    } while (ptmp != NULL);

    del_panel(list->fieldpanel);
    delwin(list->fieldwin);
}
