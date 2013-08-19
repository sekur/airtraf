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
 **  detailed_scan.h
 **
 ****************************************************************
 **
 **   Copyright (c) 2001,2002 all rights reserved.
 **
 **   Author: Peter K. Lee <saint@elixar.net>
 **
 ***************************************************************/

#ifndef __detailed_scan_H__
#define __detailed_scan_H__

#include "definition.h"

//////////////////////////////////////////////////////////////
// INITIALIZATION routines
//////////////////////////////////////////////////////////////

/**
 * initialization code for creating a new list of potential_nodes, and
 * setting temporary addresses all to 0xff
 **/
void initialize_detailed_scan();

/**
 * reset bss_list (bss_t) structs recursively
 **/
void reset_bss_list(bss_t *info);

/**
 * free up memory space associated with detailed scan structures
 **/
void free_detailed_scan();

/**
 * initialization code for creating potential filtering structures
 **/
void init_potential_structs();

/**
 * clear up the potential filtering structures
 **/
void clear_potential_structs();

/**
 * gets pointer to current potential nodes struct
 **/
void * get_p_nodes();

/**
 * gets pointer to current potential ap struct
 **/
void * get_p_aps();

/**
 * free up memory space associated with potential structures
 **/
void free_potential_structs();

/**
 * resetting code to prevent structure from stagnating and growing too
 * large...  (segfault potential after many hours)
 **/
void reset_potential_structs();

//////////////////////////////////////////////////////////////

/**
 * should be called before resetting potential structs
 **/
void track_bad_data();

/**
 * should be called periodically to not display potentially erroneous
 * data
 **/
void clean_up_bss_nodes();

void update_all_bandwidth();

bss_node_t * bss_get_node(bss_t *curr, int pos);
bss_node_t * bss_find_node (bss_t *curr, __u8 *addr);

///////////////////////////////////////////////////////////
//  MAIN detailed scan interface routine
///////////////////////////////////////////////////////////

void process_detailed_scan(struct packet_info *packet, struct access_point *filter);

detailed_overview_t *get_detailed_snapshot();

#endif
