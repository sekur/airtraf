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
 **  packet_card.h
 **
 ****************************************************************
 **
 **   Copyright (c) 2001 all rights reserved.
 **
 **   Author: Peter K. Lee <pkl@duke.edu>
 **
 ***************************************************************/

#ifndef __packet_card_H__
#define __packet_card_H__

#include <linux/if_packet.h>

// creates & opens a socket
int pkt_card_sock_open (struct SETTINGS*);

// reads from socket 
int pkt_card_sock_read (int, char *, int, struct sockaddr_ll*);

// closes socket
int pkt_card_sock_close (struct SETTINGS*);

// keeps interface state up
int pkt_card_ifup (struct SETTINGS*);

// changes channel (wireless extensions)
int pkt_card_chan_set(struct SETTINGS*, int channel);

// finds channel range (wireless extensions)
int pkt_card_channel_range(struct SETTINGS*);

// check if passed card_type requries channel hopping
int pkt_card_is_chan_hop(int);

#endif
