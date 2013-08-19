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

input.h - structure declarations and function prototypes for input.c
Written by Gerard Paul Java
Copyright (c) Gerard Paul Java 1997

***/

#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include "stdwinset.h"

#define CTRL_X 24

struct FIELD {
    char *buf;
    unsigned int len;
    unsigned int tlen;
    unsigned int xpos;
    unsigned int ypos;
    struct FIELD *prevfield;
    struct FIELD *nextfield;
};

struct FIELDLIST {
    struct FIELD *list;
    WINDOW *fieldwin;
    PANEL *fieldpanel;
};

void initfields(struct FIELDLIST *list, int leny, int lenx, int begy, int begx);
void addfield(struct FIELDLIST *list, unsigned int len, unsigned int y,
	      unsigned int x, char *initstr);
void getinput(struct FIELDLIST *list, struct FIELD *field, int *exitkey);
void fillfields(struct FIELDLIST *list, int *aborted);
void destroyfields(struct FIELDLIST *list);
