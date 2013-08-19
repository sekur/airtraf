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
   menu.h - declaration file for my menu library
   Copyright (c) Gerard Paul R. Java 1997

***/


#ifndef __menurt_h__
#define __menurt_h__

#define SELECTED 1
#define NOTSELECTED 0

#define SEPARATOR 0
#define REGULARITEM 1

#define OPTIONSTRLEN_MAX 50
#define DESCSTRLEN_MAX 81
#define SHORTCUTSTRLEN_MAX 25

struct ITEM {
    char option[OPTIONSTRLEN_MAX];
    char desc[DESCSTRLEN_MAX];
    unsigned int itemtype;
    struct ITEM *prev;
    struct ITEM *next;
};

struct MENU {
    struct ITEM *itemlist;
    struct ITEM *selecteditem;
    struct ITEM *lastitem;
    int itemcount;
    int postn;
    int x1, y1;
    int x2, y2;
    unsigned int menu_maxx;
    WINDOW *menuwin;
    PANEL *menupanel;
    WINDOW *descwin;
    PANEL *descpanel;
    char shortcuts[SHORTCUTSTRLEN_MAX];
};

extern void initmenu(struct MENU *menu, int y1, int x1, int y2, int x2);
extern void additem(struct MENU *menu, char *item, char *desc);
extern void showitem(struct MENU *menu, struct ITEM *itemptr, int selected);
extern void showmenu(struct MENU *menu);
extern void menumoveto(struct MENU *menu, struct ITEM **itemptr, unsigned int row);
extern void operatemenu(struct MENU *menu, int *row, int *aborted);
extern void destroymenu(struct MENU *menu);

#endif
