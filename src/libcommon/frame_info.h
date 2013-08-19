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
/******************************************************************************
**
** AirIDS:
**    a wireless (802.11) intrusion detection system.
**
** frame_info.h
**
*************
**
** Copyright (c) 2001 all rights reserved, by Michael Lynn 
**
** Author: Michael Lynn abaddon@bsd.sh
**
** NOTES:
** this is still very very beta, use at your own risk...
** also most of this code is going to change soon...
** so if you dont like it bitch and ill fix the part your 
** bitching about...maybe...
**
** there is still lots more to come...
**
******************************************************************************/

#ifndef __FRAME_INFOH__
#define __FRAME_INFOH__



/* this should be kosher for linux kernel >= 2.4.x, maybe 2.2.x, dont know */
#define ETH_P_80211_RAW	(ETH_P_ECONET + 1)

/* new ioctl calls */
#define P80211_IFSFRAMEINFO	(SIOCDEVPRIVATE + 2)
#define P80211_IFGFRAMEINFO	(SIOCDEVPRIVATE + 3)

/* 
 * This is the AirIDS hardware independant
 * frame into structure, used in lue of the
 * original struct because most of those 
 * values i dont care about, and/or were 
 * static...
 *
 * This gives us a common structure for all
 * cards, so the AirIDS system can work better
 * it pays to write your own driver code ;)...
 */
struct airids_frame_info {
    unsigned char	card_type:2;			/* type of card */
#define AIRIDS_CARDTYPE_PRISM2	0
#define AIRIDS_CARDTYPE_AIRONET	1
#define AIRIDS_CARDTYPE_LUCENT	2			/* who knows, maybe someday */
    unsigned char	fcs_error:1;			/* 0 for good, 1 for no bueno */
    unsigned char	undecrypt:1;			/* 0 for good, 1 for no bueno */
    unsigned char	channel:4;				/* the channel the frame came on */
    unsigned char	signal;					/* signal strength */
    unsigned long	time;					/* time stamp from the card */
};




#endif /* #ifndef __FRAMEINFOH__ */


