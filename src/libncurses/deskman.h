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
/*
   deskman.h - header file for deskman.c
   Written by Gerard Paul Java
   Copyright (c) Gerard Paul Java 1997, 1998

 */

#ifndef __deskman_H__
#define __deskman_H__

void about();

void draw_desktop(void);
void colorwin(WINDOW * win);
void printnomem();
void printipcerr();
void printkeyhelp(char *keytext, char *desc, WINDOW * win,
                  int highattr, int textattr);
void stdkeyhelp(WINDOW * win);
void channelkeyhelp(void);
void viewkeyhelp(void);
void pausekeyhelp(void);
void sortkeyhelp(void);
void tabkeyhelp(WINDOW * win);
void changewinkeyhelp();
void scrollkeyhelp();
void stdexitkeyhelp();
void menukeyhelp();
void listkeyhelp();
void indicate(char *message);
void printlargenum(unsigned long long i, WINDOW *win);
void show_paused_win(WINDOW ** win, PANEL ** panel, char * message, char *message2);
void infobox(char *text, char *prompt);
void standardcolors(int color);
void refresh_screen(void);
void show_sort_statwin();

#endif
