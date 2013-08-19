/* scanchan.c - Utility to scan 2.4GHz channels to see which channels
 *              are Active or Not-Active. 
 * 
 * This utility has been modified from Prismdump (Copyright by Axis
 * Communications) as well as Prismexplode (by sublimation.org)
 * 
 * This utility is written for use with IEEE 802.11 adapters based
 * on Intersil's PRISM II chipset (PCMCIA). 
 * The linux driver for these cards can be found on www.linux-wlan.com
 * It has been verified with a LinkSys WPC11 IEEE 802.11 adapter. 
 * 
 * Copyright (c)2001 by Elixar.net  Durham, NC.
 * Comments/Bug reports should be sent to: Peter K. Lee (pkl@duke.edu)
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

/*=============================================================*/
/* System Includes */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/errno.h>
#include <unistd.h>
#include <asm/types.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

/*=============================================================*/
/* Local Static Definitions */

#define MAX_BUFFER_SIZE 4000	/* Size of receive buffer */
#define WTAP_PKTHDR_SIZE (sizeof(struct wtap_pkthdr)-4)
#define DEVNAME_LEN 16
#define __WLAN_ATTRIB_PACK__       __attribute__ ((packed))
#define ROWWIDTH  32
#define SSID_SIZE 32
#define WTAP_ENCAP_IEEE_802_11 18
#define MAX_CHANNEL 14

/*=============================================================*/
/* Local Global Variables */

static unsigned int stop_scanning = 0;
__u8 dummybuf[32];
__u8 dummybuf2[32];
__u8 llc[7] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08 };

/*=============================================================*/
/* Local Structs */

struct wtap_pkthdr
{
  struct timeval ts;
  __u32 caplen;
  __u32 len;
  int pkt_encap;
};

typedef struct
{
  unsigned char version:2;
  unsigned char type:2;
  unsigned char subtype:4;
  unsigned char toDS:1;
  unsigned char fromDS:1;
  unsigned char morefrag:1;
  unsigned char retry:1;
  unsigned char pwr:1;
  unsigned char moredata:1;
  unsigned char wep:1;
  unsigned char rsvd:1;
}
frame_control_t;

typedef struct
{
  __u16 frame_control __attribute__ ((packed));
  __u16 duration_id __attribute__ ((packed));
  __u8 mac1[6] __attribute__ ((packed));
  __u8 mac2[6] __attribute__ ((packed));
  __u8 mac3[6] __attribute__ ((packed));
  __u16 sequence __attribute__ ((packed));
  __u8 mac4[6] __attribute__ ((packed));
}
wlan_hdr_t;

/*=============================================================*/
/* Function Definitions */

void stop_signal ()
{
  fprintf (stderr,"Received CTRL-C - scanning aborted\n");
  stop_scanning = 1;
  exit(0);
}

int set_channel(int channel)
{
  int result;
  int result_i;
  FILE *fp;
  unsigned char result_code[10];
  unsigned char wlanctl_cmd[100];
  
  sprintf(wlanctl_cmd,"wlanctl-ng wlan0 lnxreq_wlansniff channel=%d enable=true",channel);
  fp = popen(wlanctl_cmd, "r");
   
  if(fp <0){
    perror("Could not execute wlanctl-ng");
    exit(0);
  }
  result = fscanf(fp,"message=%c", &result_i);
  
  if((result < 0) || (result == 0)){
    perror("Could not put into promiscuous mode!");
    exit(0);
  }
  pclose(fp);
  return result;
}
  

/*=============================================================*/
/* Main Program */

int main (int argc, char *argv[])
{
  /* message buffer related variables */
  unsigned char msgbuf[MAX_BUFFER_SIZE];   // holds the raw read from socket
  unsigned char *sframe_ptr = &msgbuf[0]; // ptr to frame
						   // past the preamble
  wlan_hdr_t *packet_hdr;                  // holds the entire
					   // ieee802.11 packet
  frame_control_t *fc;                     // holds frame control
					   // related info.
  struct wtap_pkthdr packet_hdr_info;      // holds wtap related stuff
					   // (don't need this...)
  int recvlen;                             // result from recv call

  /* Stores SSID discovered from beacon frames */
  __u8 ssid[32]="";
  
  /* channel related variables */
  int i_channel;                           // iterative channel number
  int known_channel;
  unsigned char channel_map[MAX_CHANNEL];  // hrm...

  /* socket specific related variables */
  struct sockaddr_ll nl_sk_addr;
  struct ifreq req;
  int msocket_h;
  
  struct timeval tv; // socket option for timeout
  int myset = 10;  // socket option to reuse address
  int result;

  fprintf (stderr, "ScanChan 1.3.0 (C)2001,2002 Elixar.net\n");

  setpriority (PRIO_PROCESS, 0, -20);
  signal (SIGINT, stop_signal);

  fprintf (stderr, "Use CTRL-C to stop scanning\n\n");

  /*
   * Create socket with msocket_h handle
   */
  if (( msocket_h= socket (PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
      perror ("Could not create socket");
      exit(0);
    }

  /* get the interface index */
  memset(&req, 0, sizeof(struct ifreq));
  strcpy(req.ifr_name,"wlan0");
  
  /*
   * Set socket options to specify receive timeout value and enable
   * reuseaddr.
   */
  if ((result = setsockopt (msocket_h, SOL_SOCKET, SO_REUSEADDR, &myset, sizeof(myset))) < 0)
    {
      perror ("Could not set socket options");
      exit(0);
    }
  memset (&nl_sk_addr, 0, sizeof (struct sockaddr_ll));
  nl_sk_addr.sll_ifindex = req.ifr_ifindex;
  nl_sk_addr.sll_protocol = htons(ETH_P_ALL);
  nl_sk_addr.sll_family = AF_PACKET;

  memset(channel_map, 0, MAX_CHANNEL);
  
  /*
   * Loop through and try to receive packet from specified
   * channels.  If its active, then loop until you get a
   * management frame.  If its not active, then move on to the
   * next available channel.
   */
  for(i_channel=1; (i_channel < 15)&&(stop_scanning != 1); i_channel++)
    {
      int scan_status;  // 1 if done, 0 if not (loop conditional)
      int scan_counter; // in case beacon frame cannot be read (encrypted?)
      int info_ptr;
      
      fprintf(stderr, "Scanning Channel: %d...", i_channel);

      result = set_channel(i_channel);

      if (bind
	  (msocket_h, (struct sockaddr *) &nl_sk_addr,
	   sizeof (struct sockaddr_ll)) < 0)
	{
	  perror ("\nCall to bind failed");
	  return 1;
	}
      
      scan_status = 0;
      scan_counter = 0;
      recvlen = 0;
      info_ptr = 36;
	
      while(scan_status == 0)
	{
	  fd_set fds;
	  struct timeval tv;
	  
	  /* local information */
	  int buf_len, ret_val;
	  int temp_buf_size = 0;
	  int tag_number = 0;
	  int tag_length = 0;
	  int t;
	  	  
	  memset (msgbuf, 0, MAX_BUFFER_SIZE);
	  FD_ZERO(&fds);
	  FD_SET(msocket_h,&fds);
	  tv.tv_sec = 1;
	  tv.tv_usec = 0;

	  ret_val = select(msocket_h+1, &fds, NULL,NULL, &tv);

	  if (!ret_val)
	    {
	      fprintf(stderr,"\t No\n");
	      scan_status = 1;
	    }
	  else
	    {
	    read_again:
	      if ((recvlen = recv(msocket_h,msgbuf,MAX_BUFFER_SIZE,0)) < 0){
		fprintf(stderr,"?");
		if (errno == EINTR)
		  goto read_again;
		fprintf(stderr,"?");
	      }	      
	      scan_counter++;

	      /* Setup Wiretap packet header (sort of unnecessary in
		 our case) */
	      gettimeofday (&packet_hdr_info.ts, NULL);
	      
	      /* Cast msgbuf into 802.11 structs */
	      packet_hdr = (wlan_hdr_t *) sframe_ptr;
	      fc = (frame_control_t *)&packet_hdr->frame_control;
	      
	      /* Check if frame is a management beacon frame.
	       * If not, then we listen until we get one.
	       */
	      if ((fc->type ==0) && (fc->subtype == 8)) // beacon packet
		{

		  while(tag_number != 3){
		    tag_number = sframe_ptr[info_ptr];  //read tag_number
		    info_ptr++;                         //next
		    tag_length = sframe_ptr[info_ptr];  //read tag_length
		    info_ptr++;                         //next
		    
		    if(tag_number == 0){
		      temp_buf_size = (tag_length & 0xff)+1;
		      snprintf(ssid,temp_buf_size,"%s",&sframe_ptr[info_ptr]);
		    }
		    if(tag_number == 3){
		      known_channel = sframe_ptr[info_ptr];		      
		    }
		    // move info_ptr to next tag number
		    info_ptr += tag_length;
		  }

		  if(i_channel == known_channel){
		    fprintf(stderr,"\t Active: SSID=%s Channel=%02u Primary\n",
			    ssid,known_channel);
		  }
		  else{
		    fprintf(stderr,"\t used by %s\n",ssid);
		  }
		  scan_status = 1;		  
		}
	      else // not beacon packet
		{
		  if(scan_counter > 25) // we're just not getting a beacon.
		    {
		      fprintf(stderr,"\t unknown activity detected \n");
		      scan_status = 1;  // quit trying...
		    }
		  else // try again :)
		    {
		      scan_status = 0;
		    }
		}
	    }
	} // end while loop
    } // end for loop
  
  fprintf (stderr,
	   "\nExiting - %d channels were successfully scanned\n", (i_channel-1));

  return 0;
}
