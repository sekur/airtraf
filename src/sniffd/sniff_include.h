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
 **  sniff_include.h
 **
 ****************************************************************
 **
 **   Copyright (c) 2001 all rights reserved.
 **
 **   Author: Peter K. Lee <pkl@duke.edu>
 **
 ***************************************************************/

#ifndef __sniff_include_H__
#define __sniff_include_H__

/* set below to enable DEBUG & DUMP_TO_SCREEN */
#define DEBUG           DISABLED
#define DUMP_TO_SCREEN  ENABLED

/*----------------------------------------------------------------*/
/* AIRTRAF INCLUDES USED THROUGHOUT THE PROGRAM                   */
/*----------------------------------------------------------------*/

#include <ncurses.h>
#include <panel.h>

/** from libairtraf **/
#include "crc-32.h"
#include "frame_info.h"
#include "logger.h"
#include "packet_card.h"
#include "utility.h"

/** from libairgui **/
#include "attrs.h"
#include "error.h"
#include "deskman.h"
#include "input.h"
#include "menurt.h"
#include "stdwinset.h"

/** from sniffd **/
#include "capture_engine.h"
#include "channel_scan.h"
#include "detailed_analysis.h"
#include "detailed_scan.h"
#include "gui_main.h"
#include "gui_capture_utils.h"
#include "gui_channel_scan.h"
#include "gui_detailed_scan.h"
#include "gui_gen_protocol_scan.h"
#include "gui_tcp_analysis_scan.h"
#include "mon_ids.h"
#include "server.h"
#include "runtime.h"
#include "packet_abstraction.h"
#include "p802_11b_parser.h"
#include "sniffer_engine.h"

#endif
