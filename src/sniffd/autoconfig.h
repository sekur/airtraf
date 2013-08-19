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
 **  autoconfig.h
 **
 ****************************************************************
 **
 **   Copyright (c) Elixar, Inc. 2001,2002 all rights reserved.
 **
 **   Author: Peter K. Lee <saint@elixar.com>
 **
 ***************************************************************/

#ifndef __autoconfig_H__
#define __autoconfig_H__

/* List of compatible drivers for running AirTraf */
static char *compat_drivers[] = {
  "airo_cs",   // cisco driver
  "airo",      // cisco driver
  "prism2_cs",  // linux-wlan-ng driver
  "prism2",    // old HostAP driver
  "hostap_cs", // newer HostAP driver
  "hostap",    // same as above (not PC card version)
  "orinoco_cs",// orinoco driver
  "orinoco",   // orinoco driver
  (char*)-1
};
#define DRV_INCOMPAT -1
#define DRV_AIRO_CS 0
#define DRV_AIRO 1
#define DRV_PRISM2_CS 2
#define DRV_PRISM2 3
#define DRV_HOSTAP_CS 4
#define DRV_HOSTAP 5
#define DRV_ORINOCO_CS 6
#define DRV_ORINOCO 7

/* Paths */
#define PROC_NET_WIRELESS "/proc/net/wireless"
#define PROC_IOPORTS "/proc/ioports"

#define IFNAMSIZ 16
#define DRVNAMSIZ 24

/* Linked-list of available wireless_devices */
typedef struct
{ 
  char ifname[IFNAMSIZ + 1];   /** interface name of wireless device **/
  char real_ifname[IFNAMSIZ +1]; /** actual (real) interface name **/
  char iwname[IFNAMSIZ + 1]; /**  Wireless/protocol name **/
  char drvname[DRVNAMSIZ + 1]; /** Driver name **/
  char version[DRVNAMSIZ + 1];   /** Driver version info **/
  unsigned short int base_addr; /** Device Base IO Addr **/
  unsigned char irq;  /** Device IRQ **/
  short int flags;
  short int compat_id; /** Compatibility ID **/
  void * next;
} wireless_devices;

/* Prototype for handling display of each single interface on the
 * system - see iw_enum_devices() */
typedef int (*iw_enum_handler)(int skfd, char * ifname, wireless_devices * iwlist, int * count);

///////////////////////////////////////////////////////////////////
//  MAIN autoconfig interface routines
///////////////////////////////////////////////////////////////////

/** initialize, enumerate **/
int init_autoconfig(wireless_devices *, int *);

/** print **/
void print_autoconfig(wireless_devices *, int *);

/** ask for device (if autoconfig discovered more than 1)**/
wireless_devices * prompt_device(wireless_devices *, int *);

/** enable monitor **/
int enable_monitor(wireless_devices *, int force);

/** disable monitor **/
int disable_monitor(wireless_devices *);

/** set flag **/
int set_flag(int, char *, short);

/** clear flag **/
int clr_flag(int, char *, short);

#endif
