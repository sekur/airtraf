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
 **  channel_scan.h
 **
 ****************************************************************
 **
 **   Copyright (c) Elixar, Inc. 2001,2002 all rights reserved.
 **
 **   Author: Peter K. Lee <saint@elixar.com>
 **
 ***************************************************************/

#ifndef __channel_scan_H__
#define __channel_scan_H__

#include "definition.h"

///////////////////////////////////////////////////////////////////
//  MAIN channel scan interface routines
///////////////////////////////////////////////////////////////////

/** initialize, reserve memory map **/
void initialize_channel_scan();

/** destroy all traces of its existance **/
void free_channel_scan();

/** clean up the filter (ap) **/
void clean_filter();

/** main entrance call to do ap discovery/analysis **/
void process_channel_scan(struct packet_info *packet);

/** returns the current snapshot of results **/
struct channel_overview *get_channel_snapshot();

/** performs update on access point status **/
void update_all_ap_status();

/** wrapper call to issue wireless extension ioctl call **/
int channel_range(struct SETTINGS*);

/** wrapper call to issue wireless extension ioctl call **/
int select_channel(struct SETTINGS*, int channel);
  
#endif
