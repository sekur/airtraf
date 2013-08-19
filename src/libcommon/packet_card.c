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
 **  packet_card.c
 **
 ****************************************************************
 **
 **   Copyright (c) 2001 all rights reserved.
 **
 **   Author: Peter K. Lee <pkl@duke.edu>
 **
 **
 ***************************************************************/

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h> // wireless extensions
#include <math.h> // math stuff...
//#include <net/if.h>

#include "definition.h"
#include "frame_info.h"
#include "packet_card.h"
#include "../sniffd/autoconfig.h"

/*=============================================================*/
/* Local Static Definitions */

#ifndef SIOCIWFIRSTPRIV
#define SIOCIWFIRSTPRIV SIOCDEVPRIVATE
#endif

static int dummy_sock;

/*=============================================================*/
/* Local Global Variables */

/*=============================================================*/
/* Function Prototypes */

/*=============================================================*/
/* Function Definitions */

/**
 * pkt_card_sock_open()
 * --------------------
 * low-level code for opening up a listening socket using the
 * PF_PACKET interface.
 **/
int pkt_card_sock_open (struct SETTINGS *mySettings)
{
  int msock_h = 0;
  int arptype;
  struct sockaddr_ll sock_addr;  /* socket address */
  struct sockaddr_nl nl_addr;    /* netlink address */
  struct ifreq req;
  int myset = 10;  // socket option to reuse address

  /** open dummy socket to talk to the driver (channel switch ioctls
      calls, ifstate modifier, etc...) **/
  if ((dummy_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
    perror ("can't open generic socket!");
    close(dummy_sock);
    exit (-1);
  }

  switch (mySettings->card_type){
  case AIRONET:
    /*
     * Create socket with msocket_h handle
     */
    if (( msock_h= socket (PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
      perror ("Could not create socket");
      fprintf(stderr,"You usually have to be root to open raw sockets\n");
      exit(0);
    }
    /*
     * Initialize ifreq structure, set the device name
     */
    memset(&req, 0, sizeof(struct ifreq));
  
    strcpy(req.ifr_name, mySettings->interface);

    if(mySettings->signal_support){
      /*
       * Get the current state of driver
       */
      if(ioctl(msock_h, P80211_IFGFRAMEINFO, &req) < 0){
	perror ("Could not get info");
	fprintf(stderr,"make sure your driver has signal strength capabilities.\n");
	exit(0);
      }
      req.ifr_flags = 1; // turn on airids_hdr
      if(ioctl(msock_h, P80211_IFSFRAMEINFO, &req) < 0){
	perror ("Could not set info");
	exit(0);
      }
    }

    /*
     * Get the Interface Index
     */
    if(ioctl(msock_h, SIOCGIFINDEX, &req) < 0) {
      perror ("Could not get index");
      fprintf(stderr,"make sure you specified the proper interface.\n");
      exit(0);
    }

    memset(&sock_addr, 0, sizeof (struct sockaddr_ll));
    sock_addr.sll_ifindex = req.ifr_ifindex;
    sock_addr.sll_protocol = htons(ETH_P_ALL);
    sock_addr.sll_family = AF_PACKET;

    if (bind(msock_h, (struct sockaddr *) &sock_addr,sizeof (struct sockaddr_ll)) < 0){
      perror ("Call to bind failed");
      exit(0);
    }  
    break;
    
  case PRISMII:
    if (( msock_h = socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK)) < 0){
      perror ("Could not create socket");
      fprintf(stderr,"You usually have to be root to open raw sockets\n");
      exit(0);
    }
    /*
     * Set socket options to specify receive timeout value and enable
     * reuseaddr.
     */
    if (setsockopt(msock_h, SOL_SOCKET, SO_REUSEADDR, &myset, sizeof(myset)) < 0){
      perror ("Could not set socket options");
      exit(0);
    }

    memset(&nl_addr, 0, sizeof(nl_addr));
    nl_addr.nl_family = AF_NETLINK;
    nl_addr.nl_pid = (unsigned int) getpid();
    nl_addr.nl_groups =  PRISM2_MONITOR_GROUP;
    
    if (bind(msock_h, (struct sockaddr *) &nl_addr, sizeof(nl_addr)) < 0) {
      perror("bind");
      close(msock_h);
      exit(-1);
    }
    break;
    
  case HERMES:
  case HOSTAP:
  case WLANNG:
    /*
     * Create socket with msocket_h handle
     */
    if (( msock_h= socket (PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
      perror ("Could not create socket");
      fprintf(stderr,"You usually have to be root to open raw sockets\n");
      exit(0);
    }
    /*
     * Initialize ifreq structure, set the device name
     */
    memset(&req, 0, sizeof(struct ifreq));
  
    strcpy(req.ifr_name, mySettings->interface);

    /*
     * Get the HW Addr family
     */
    if (ioctl(msock_h, SIOCGIFHWADDR, &req) != 0) {
      perror("ioctl(SIOCGIFHWADDR)");
      close(msock_h);
      exit(-1);
    }
    arptype = req.ifr_hwaddr.sa_family;

    if (arptype != ARPHRD_IEEE80211 && arptype != ARPHRD_IEEE80211_PRISM) {
      close(msock_h);
      fprintf(stderr, "Unsupported arptype 0x%04x\nUsually a result of card not being properly set to monitor mode.\n", arptype);
      fprintf(stderr, "Check the version of your driver and make sure you're using a compatible driver with monitoring capabilities.\n");
      exit(-1);
    }
    
    /*
     * Get the Interface Index
     */
    if(ioctl(msock_h, SIOCGIFINDEX, &req) < 0) {
      perror ("Could not get index");
      close(msock_h);
      fprintf(stderr,"make sure you specified the proper interface.\n");
      exit(-1);
    }

    memset(&sock_addr, 0, sizeof (struct sockaddr_ll));
    sock_addr.sll_ifindex = req.ifr_ifindex;
    sock_addr.sll_protocol = htons(ETH_P_ALL);
    sock_addr.sll_family = AF_PACKET;

    if (bind(msock_h, (struct sockaddr *) &sock_addr,sizeof (struct sockaddr_ll)) < 0){
      perror ("Call to bind failed");
      exit(0);
    }
    break;
  }
  return (msock_h);
}

/**
 * pkt_card_sock_read()
 * --------------------
 * low-level code for reading packets from the card
 * returns: len packet received
 * param_ret: sockaddr_ll
 **/
int pkt_card_sock_read(int msock_h, char *buf, int maxlen,
		       struct sockaddr_ll *fromaddr)
{ 
  fd_set fds;
  int ret_val, recvlen;
  int fromlen;
  struct timeval tv;

  recvlen = 0;
  FD_ZERO(&fds);
  FD_SET(msock_h,&fds);
  tv.tv_sec = 0;
  tv.tv_usec = DEFAULT_UPDATE_DELAY;
  
  do {
    ret_val = select(msock_h+1, &fds, NULL, NULL, &tv);    
  } while ((ret_val < 0)&&(errno == EINTR)); 

  if (FD_ISSET(msock_h ,&fds)) {
    fromlen = sizeof(struct sockaddr_pkt);
    recvlen =recvfrom(msock_h,buf,maxlen,0,
		      (struct sockaddr *)fromaddr, &fromlen);
  }

  return (recvlen);
}

/**
 * pkt_card_sock_close()
 * ---------------------
 * low-level code for closing the opened socket, resetting driver
 * state if necessary
 **/
int pkt_card_sock_close(struct SETTINGS* mySettings)
{
  struct ifreq req;
  int msock_h = mySettings->sniff_socket;

  /*
   * Initialize ifreq structure, set the device name
   */
  memset(&req, 0, sizeof(struct ifreq));
  strcpy(req.ifr_name, mySettings->interface);
  
  if(mySettings->signal_support){
    /*
     * Get the current state of driver
     */
    if(ioctl(msock_h, P80211_IFGFRAMEINFO, &req) < 0){
      perror ("Could not get info");
      exit(0);
    }
    req.ifr_flags = 0; // turn off airids_hdr
    if(ioctl(msock_h, P80211_IFSFRAMEINFO, &req) < 0){
      perror ("Could not set info");
      exit(0);
    }
  }
  if (msock_h >= 0) close(msock_h);
  if (dummy_sock >= 0) close(dummy_sock);
  return (1);
}

/**
 * iw_float2freq()
 * ---------------
 * simple frequency manipulation...  helper function
 **/
void iw_float2freq(double in, struct iw_freq * out)
{
  out->e = (short) (floor(log10(in)));
  if(out->e > 8)
    {
      out->m = ((long) (floor(in / pow(10,out->e - 6)))) * 100;
      out->e -= 8;
    }
  else
    {
      out->m = in;
      out->e = 0;
    }
}

//extern int set_flag(int, char*, short);

/**
 * pkt_card_ifup()
 * -----------------------
 * see if the interface's configuration status is UP, and reset it to
 * be UP if it killed itself for any reason.
 * actually, just set it to be UP... over & over & over again. :)
 **/
int pkt_card_ifup(struct SETTINGS* mySettings)
{
  if (set_flag(dummy_sock, mySettings->interface, (IFF_UP|IFF_RUNNING)) > 0)
    return (1);
  else
    return (0);
}

/**
 * pkt_card_is_chan_hop()
 * -----------------------
 * return true if the card_type passed requires channel hopping.
 **/
int pkt_card_is_chan_hop(int card_type)
{
 if ((card_type==AIRONET)||(card_type==PRISMII)||(card_type==HOSTAP)||(card_type==HERMES)||(card_type==WLANNG))
   return (1);
 else
   return (0);
}

/**
 * pkt_card_channel_range()
 * ---------------------
 * Function that checks whether the specified interface has US only
 * channel limit, or is international...
 **/
int pkt_card_channel_range(struct SETTINGS* mySettings)
{
  int i;
  
  for (i = 1; i < 15; i++){
    if (pkt_card_chan_set(mySettings, i) == ERR_IO)
      return (--i);
  }
  return (--i);
}

/**
 * pkt_card_chan_set()
 * ------------------
 * lowest card routine to issue ioctl calls to the prism2 card,
 * requesting that the wireless card change channel to the specified
 * channel.
 **/
int pkt_card_chan_set(struct SETTINGS* mySettings, int channel)
{
  struct iwreq wrq;
  double freq;
  int *ptr;
  unsigned char m_channel = channel;
  unsigned char monitor_cmd[100];
  FILE * fh = NULL;
  
  /**
   * Initialize iwreq structure, set the device name
   **/
  memset(&wrq, 0, sizeof(struct iwreq));
  if ((mySettings->card_type==AIRONET)||(mySettings->card_type == PRISMII)||(mySettings->card_type == HOSTAP)){
    strcpy(wrq.ifr_name, mySettings->interface);

    freq = (double) channel;
    iw_float2freq(freq, &(wrq.u.freq));

    if(ioctl(dummy_sock, SIOCSIWFREQ, &wrq) < 0){
      return ERR_IO;
    }
  }
  else if (mySettings->card_type == HERMES){
    ptr = (int *) wrq.u.name;
    ptr[0] = 1;
    ptr[1] = m_channel;
    strcpy(wrq.ifr_ifrn.ifrn_name, mySettings->interface);
    
    if(ioctl(dummy_sock, SIOCIWFIRSTPRIV + 0x8, &wrq) < 0){
      return ERR_IO;
    }
  }
  else if (mySettings->card_type == WLANNG){
    memset(monitor_cmd, 0, sizeof(unsigned char) * 100);
    snprintf(monitor_cmd, 100, "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=true stripfcs=true keepwepflags=true prismheader=true",
	     mySettings->interface, channel);
    if ((fh = popen(monitor_cmd, "r")) < 0) {
      fprintf(stderr, "error: Could not popen ``%s''.  Aborting.\n", monitor_cmd);
      return ERR_IO;
    }
  }
  return (1);
}
