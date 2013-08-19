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
 **  detailed_analysis.h
 **
 ****************************************************************
 **
 **   Copyright (c) 2001 all rights reserved.
 **
 **   Author: Peter K. Lee <pkl@duke.edu>
 **
 ***************************************************************/

#ifndef __detailed_analysis_H__
#define __detailed_analysis_H__

#include "definition.h"

///////////////////////////////////////////////////////////
//  MAIN detailed analysis interface routine
///////////////////////////////////////////////////////////

tcptable_t * get_tcp_table_entry(bss_node_t *, int pos);

void analyze_packet(bss_t *curr_bss, struct p802_11b_info *info, struct packet_info *packet, int type);

#endif
