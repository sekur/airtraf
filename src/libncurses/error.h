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

error.h - public declaration for error box
Written by Gerard Paul Java
Copyright (c) Gerard Paul Java 1997

***/

#ifndef __error_H__
#define __error_H__

#define ANYKEY_MSG "Press a key to continue"
#define ABORT_MSG "Press a key to abort"

void errbox(char *message, char *prompt, int *response);
void write_error(char *message, int daemonized);

#endif
