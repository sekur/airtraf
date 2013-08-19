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
 **  p802_11b_parser.h
 **
 ****************************************************************
 **
 **   Copyright (c) 2001,2002 all rights reserved.
 **
 **   Author: Peter K. Lee <saint@elixar.net>
 **
 ***************************************************************/

#ifndef __p802_11b_parser_H__
#define __p802_11b_parser_H__

#include "definition.h"

//////////////////////////////////////////////////////////////////
//  802.11b header parser function
//////////////////////////////////////////////////////////////////

void initialize_p802_11b_parser();

struct p802_11b_info *parse_p802_11b_hdr(wlan_hdr_t *);

struct p802_11b_info *parse_hfa384x_hdr(prism2_hdr_t *hdr);

struct p802_11b_info *parse_wlanngp2_hdr(wlan_ng_hdr_t *hdr);
#endif
