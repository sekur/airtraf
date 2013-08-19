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
 **  capture_engine.h
 **
 ****************************************************************
 **
 **   Copyright (c) 2001,2002 all rights reserved.
 **
 **   Author: Peter K. Lee <saint@elixar.net>
 **
 ***************************************************************/

#ifndef __capture_engine_h__
#define __capture_engine_h__

#include "definition.h"

// INIT ROUTINES
int init_capture(struct SETTINGS *mySettings);

void free_capture();

// REQUESTS
int capture_playback_forward(struct SETTINGS *mySettings);
int capture_playback_rewind(struct SETTINGS *mySettings);
int capture_playback_beginning(struct SETTINGS *mySettings);

// ENGINE CONTROLS
int start_capture_engine(struct SETTINGS *mySettings);

void ask_stop_capture_engine();

void stop_capture_engine(struct SETTINGS *mySettings);

int get_capture_status();

#endif // logger_h
