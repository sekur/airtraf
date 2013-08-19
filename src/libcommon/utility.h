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
 **  utility.h
 **
 ****************************************************************
 **
 **   Copyright (c) 2001, 2002 all rights reserved.
 **
 **   Author: Peter K. Lee <saint@elixar.net>
 **
 ***************************************************************/

#ifndef __utility_H__
#define __utility_H__

#include "definition.h"
#include <netinet/ip.h>
#include <time.h>

/**
 * dummy hex dump utility for generating hex output
 */
char *hexdump(__u8*, int);

void genatime(time_t , char *);

float get_time_diff(struct timeval*, struct timeval*);

void get_elapsed_time(struct timeval*, struct timeval*, char *);

int verify_chksum(struct iphdr*);

void dump_bsss(bss_t *);

#endif
