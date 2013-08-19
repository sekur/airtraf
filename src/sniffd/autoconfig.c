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
 **  autoconfig.c
 **
 **  The code in this section borrowed heavily from Wireless
 **  Extensions written by Jean Tourrihes, as well as some from
 **  Net-Tools (ifconfig, etc.)
 ** 
 **  NOTE: driver detection/enumeration section is purely my
 **  creation...
 **
 ****************************************************************
 **
 **   Copyright (c) Elixar, Inc. 2001, 2002 all rights reserved.
 **
 **   Author: Peter K. Lee <saint@elixar.net>
 **
 ***************************************************************/

#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if_arp.h>   /* For ARPHRD_ETHER */
#include <sys/socket.h> /* For AF_INET & struct sockaddr */
#include <netinet/in.h>   /* For struct sockaddr_in */
#include <netinet/if_ether.h>
#include <linux/wireless.h> /* For wireless extensions */

#include "autoconfig.h"

////////////////////////////////////////////////////////////////////////////////////
//  Auto-Config Helper Operations (LIBRARY TYPE)
////////////////////////////////////////////////////////////////////////////////////

/**
 * set_flag()
 * -----------
 * Set a certain interface flag.
 **/
int set_flag(int skfd, char *ifname, short flag)
{
  struct ifreq ifr;

  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  ifr.ifr_name[IFNAMSIZ] = '\0';
  if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0){
    return (-1);
  }
  ifr.ifr_flags |= flag;
  if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0){
    return (-1);
  }
  return (1);
}

/**
 * clr_flag()
 * ----------
 * Clear a certain interface flag.
 **/
int clr_flag(int skfd, char *ifname, short flag)
{
  struct ifreq ifr;

  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  ifr.ifr_name[IFNAMSIZ] = '\0';
  if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0){
    return (-1);
  }
  ifr.ifr_flags &= ~flag;
  if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0){
    return (-1);
  }
  return (1);
}

/**
 * iw_set_ext()
 * -------------
 * Wrapper to push some Wireless Parameter in the driver
 **/
static inline int iw_set_ext(int skfd,		/* Socket to the kernel */
			     char *ifname,	/* Device name */
			     int request,	/* WE ID */
			     struct iwreq *pwrq)/* Fixed part of the request */
{
  /* Set device name */
  strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
  pwrq->ifr_name[IFNAMSIZ] = '\0';
  /* Do the request */
  return(ioctl(skfd, request, pwrq));
}

/**
 * iw_get_ext()
 * ------------
 * Wrapper to extract some Wireless Parameter out of the driver
 **/
static inline int iw_get_ext(int skfd,		/* Socket to the kernel */
			     char *ifname,	/* Device name */
			     int request,	/* WE ID */
			     struct iwreq *pwrq)/* Fixed part of the request */
{
  /* Set device name */
  strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
  pwrq->ifr_name[IFNAMSIZ] = '\0';
  
  /* Do the request */
  return(ioctl(skfd, request, pwrq));
}

/**
 * iw_get_ifname()
 * ---------------
 * Extract the interface name out of /proc/net/wireless or /proc/net/dev.
 **/
static inline char *iw_get_ifname(char *name,   /* Where to store the name */
				  int nsize,    /* Size of name buffer */
				  char *buf)    /* Current position in buffer */
{
  char *end;

  /* Skip leading spaces */
  while(isspace(*buf))
    buf++;

  /* Get name up to ": "
   * Note : we compare to ": " to make sure to process aliased interfaces
   * properly. Doesn't work on /proc/net/dev, because it doesn't guarantee
   * a ' ' after the ':'*/
  end = strstr(buf, ": ");

  /* Not found ??? To big ??? */
  if((end == NULL) || (((end - buf) + 1) > nsize))
    return(NULL);

  /* Copy */
  memcpy(name, buf, (end - buf));
  name[end - buf] = '\0';

  return(end + 2);
}

/**
 * iw_sockets_open()
 * -----------------
 * Open a socket.
 * Depending on the protocol present, open the right socket. The socket
 * will allow us to talk to the driver.
 */
int iw_sockets_open(void)
{
  static const int families[] = {
    AF_INET, AF_IPX, AF_AX25, AF_APPLETALK
  };
  unsigned int  i;
  int sock;

  /*
   * Now pick any (exisiting) useful socket family for generic queries
   * Note : don't open all the socket, only returns when one matches,
   * all protocols might not be valid.
   * Workaround by Jim Kaba <jkaba@sarnoff.com>
   * Note : in 99% of the case, we will just open the inet_sock.
   * The remaining 1% case are not fully correct...
   */

  /* Try all families we support */
  for(i = 0; i < sizeof(families)/sizeof(int); ++i)
    {
      /* Try to open the socket, if success returns it */
      sock = socket(families[i], SOCK_DGRAM, 0);
      if(sock >= 0)
        return sock;
  }

  return (-1);
}

//////////////////////////////////////////////////////////////////////////
//  PROCEDURAL HELPER FUNCTIONS (actually does something)
//////////////////////////////////////////////////////////////////////////

/**
 * iw_enum_devices()
 * -----------------
 * Enumerate devices and call specified routine
 * The new way just use /proc/net/wireless, so get all wireless interfaces,
 * whether configured or not. This is the default if available.
 * The old way use SIOCGIFCONF, so get only configured interfaces (wireless
 * or not).
 */
void iw_enum_devices(int skfd, iw_enum_handler fn, wireless_devices * iwlist, int * count)
{
  char buff[1024];
  FILE * fh;
  struct ifconf ifc;
  struct ifreq *ifr;
  int i;

  /* Check if /proc/net/wireless is available */
  fh = fopen(PROC_NET_WIRELESS, "r");

  if (fh != NULL){
    /* Success : use data from /proc/net/wireless */

    /* Eat 2 lines of header */
    fgets(buff, sizeof(buff), fh);
    fgets(buff, sizeof(buff), fh);

    /* Read each device line */
    while(fgets(buff, sizeof(buff), fh)){
      char name[IFNAMSIZ + 1];
      char *s;

      /* Extract interface name */
      s = (char *) iw_get_ifname(name, sizeof(name), buff);

      if(!s)
       /* Failed to parse, complain and continue */
       fprintf(stderr, "Cannot parse " PROC_NET_WIRELESS "\n");
      else
       /* Got it, Verify this interface */
       (*fn)(skfd, name, iwlist, count);
    }
    fclose(fh);
  }
  else{
    /* Get list of configured devices using "traditional" way */
    ifc.ifc_len = sizeof(buff);
    ifc.ifc_buf = buff;
    if(ioctl(skfd, SIOCGIFCONF, &ifc) < 0){
      fprintf(stderr, "SIOCGIFCONF: %s\n", strerror(errno));
      return;
    }
    ifr = ifc.ifc_req;
    /* Verify them */
    for(i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; ifr++)
      (*fn)(skfd, ifr->ifr_name, iwlist, count);
  }
}

/**
 * check_wext()
 * ------------
 * Function that checks whether the specified interface has support
 * for wireless extensions.
 **/
int check_wext(int skfd, char * ifname, char * iwname)
{
  struct iwreq wrq;

  /* Get wireless name */
  if(iw_get_ext(skfd, ifname, SIOCGIWNAME, &wrq) < 0){
      /* If no wireless name : no wireless extensions */
      /* But let's check if the interface exists at all */
      struct ifreq ifr;

      strcpy(ifr.ifr_name, ifname);
      if(ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0)
	return(-ENODEV);
      else
	return(-ENOTSUP);
  }
  else{
      strncpy(iwname, wrq.u.name, IFNAMSIZ);
      iwname[IFNAMSIZ] = '\0';
  }
  return(1);
}

/**
 * check_driver()
 * --------------
 * Function that given a ifname (interface name), attempts IO memory
 * mapping and in turn auto-discoveres what driver is loaded for the
 * given interface.
 **/
int check_driver(int skfd, char *ifname, char *drvname, char *version,
		 unsigned short int * base_addr, unsigned char * irq,
		 short int * flags)
{
  char buf[1024];
  char addr_buf[4 +1];
  char t_addr_buf[4 +1];
  char t_drv_buf[DRVNAMSIZ +1];
  struct ifreq ifr;
  FILE * fh;

  /** lets find the base_io mem address **/
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(skfd, SIOCGIFMAP, &ifr) < 0)
    return (-1);
  else{
    *base_addr = ifr.ifr_map.base_addr;
    *irq = ifr.ifr_map.irq;
  }
  /** lets grab the devices's flagged settings **/
  if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0)
    return (-1);
  else{
    *flags = ifr.ifr_flags;
  }
  memset(addr_buf, 0, sizeof(addr_buf));
  snprintf(addr_buf, sizeof(addr_buf), "%04x", *base_addr);
  
  /** lets crawl through /proc/ioports and see if we can get a
      base_addr mapping between the interface & driver... **/
  fh = fopen(PROC_IOPORTS, "r");
  if (fh != NULL){
    int result;
    do{
      memset(buf, 0, sizeof(buf));
      if (fgets(buf, sizeof(buf), fh) != NULL){
	result = sscanf(buf, " %04s%*s : %s", t_addr_buf, t_drv_buf);
	if (!strncmp(addr_buf, t_addr_buf, sizeof(addr_buf)))
	  strncpy(drvname, t_drv_buf, sizeof(t_drv_buf));
      }
      else break;
    } while ( result > 0);
  }
  return (1);
}




/**
 * check_drv_compat()
 * ------------------
 * check if the given driver is in the compatibility list for running
 * AirTraf...
 **/
int check_drv_compat(char * drvname, int * id)
{
  int i;
  for (i=0; (int) compat_drivers[i] != -1; i++){
    if (!strncmp(compat_drivers[i], drvname, DRVNAMSIZ +1)){
      *id = i;
      return (1); // just true...
    }
  }
  return (0);
}

/**
 * verify_autoconfig()
 * -------------------
 * Function that verifies passed up interface.  First checks to see if
 * its a properly configured interface.  Then it checks to see if its
 * a wireless device.  After, it attempts to determine the driver type
 * of the wireless device, and version info reported by the driver.
 *
 * Manages the 'wireless_devices' list of configured wireless devices.
 **/
static int verify_autoconfig(int skfd, char * ifname, wireless_devices * iwlist, int * count)
{
  wireless_devices * temp = iwlist;
  char iwname[IFNAMSIZ + 1];
  int id;
  
  memset((char *)iwname, 0, sizeof(iwname));

  /** check if it is a wireless device **/
  if (check_wext(skfd, ifname, iwname) > 0){
    /** SUCCESS, found a wireless device **/
    if (*count == 0){ // if this is the first detected device
      memset((wireless_devices *) temp, 0, sizeof(wireless_devices));
    }
    else{ // if not, then proceed until we're at end of list
      while ( temp->next != NULL){
	temp = (wireless_devices *) temp->next;
      }
      /** Time to hog some more memory... ;) **/
      if (NULL == (temp->next = malloc(sizeof(wireless_devices)))){
	perror ("malloc: new wireless_devices");
	exit (-1);
      }
      /** its okay to move on now... **/
      temp = (wireless_devices *) temp->next;
      memset((wireless_devices *) temp, 0, sizeof(wireless_devices));
    }
    /** copy ifname into iwlist **/
    strncpy(temp->ifname, ifname, IFNAMSIZ);
    temp->ifname[IFNAMSIZ] = '\0';
    /** copy iwname into iwlist **/
    strncpy(temp->iwname, iwname, IFNAMSIZ);
    temp->iwname[IFNAMSIZ] = '\0';
    *count = *count + 1; // increment wireless detection count

    /** check if we can get the driver associated with the given ifname... **/
    if (check_driver(skfd, ifname, temp->drvname, temp->version, &temp->base_addr, &temp->irq, &temp->flags) > 0){
      /** now lets find out if the found driver is compatible with AirTraf... **/
      if (check_drv_compat(temp->drvname, &id))
	temp->compat_id = id;
      else
	temp->compat_id = DRV_INCOMPAT;;      
    }
  }
  return (1);
}

/**
 * print_autoconfig
 * ----------------
 * Just print the retrieved information passed via the iwlist.
 **/
void print_autoconfig(wireless_devices * iwlist, int *num_dev)
{
  wireless_devices * temp = iwlist;
  FILE *fp;
  unsigned char modinfo_cmd[100];
  unsigned char temp_buf[1024];

  printf("You have (%d) wireless devices configured in your system\n", *num_dev);

  if (*num_dev > 0){
    while (temp != NULL){
      printf("Found %s: %s on IRQ: %d, BaseAddr: 0x%04x Status: %s\n",
	     temp->ifname, temp->iwname, temp->irq, temp->base_addr,
	     (temp->flags & IFF_UP) ? "UP" : "DOWN" );
      if (temp->drvname != NULL){
	printf("\tUsing Driver: (%s)\n", temp->drvname);
	snprintf(modinfo_cmd, 100, "modinfo -n %s", temp->drvname);
	fp = popen(modinfo_cmd, "r");
	fgets(temp_buf, 1024, fp);
	printf("\tFilename: %s", temp_buf);	     
	snprintf(modinfo_cmd, 100, "modinfo -a %s", temp->drvname);
	fp = popen(modinfo_cmd, "r");
	fgets(temp_buf, 1024, fp);
	printf("\tAuthor: %s", temp_buf);
	if (temp->compat_id > -1)
	  printf("success: above driver's compatibility verified!\n\n");
      }
      else
	printf("\tUsing Driver: (UNKNOWN)\nAuto-Configuration Failed!\n");
      temp = temp->next;
    }    
  }
  else{
    printf("error: You cannot run AirTraf in this system's current configuration...  sorry.\n");
  }
}

/**
 * check_duplicate_if()
 * --------------------
 * Check if there are duplicate interface mappings discovered...
 * i.e. aironet (real:ethX) (fake:wifiX)
 **/
void check_duplicate_if(wireless_devices *target, wireless_devices *list)
{
  wireless_devices * temp = list;

  while(temp != NULL){
    if(target->base_addr == temp->base_addr){
      if (!strncmp("wifi",target->ifname,4)){
	strncpy(target->real_ifname, temp->ifname, IFNAMSIZ);
	target->real_ifname[IFNAMSIZ] = '\0';
      }
      if (!strncmp("wifi",temp->ifname,4)){
	strncpy(temp->real_ifname, target->ifname, IFNAMSIZ);
	temp->real_ifname[IFNAMSIZ] = '\0';
      }
    }
    temp = temp->next;
  }
}

/**
 * init_autoconfig()
 * -----------------
 * Main autoconfiguration initialization function.
 * 1) opens a generic raw socket.
 * 2) enumerate through available devices
 * 3) during enumeration check if the devices are wireless, and if so,
 * get as much info from them as possible (iwname, drvname, version,
 * etc.)
 * 4) print out all the discovered information back to the user.
 **/
int init_autoconfig(wireless_devices * iwlist, int * num_dev)
{
  wireless_devices * temp = iwlist;
  int skfd; /* genereic raw socket desc. */
  
  if ((skfd = iw_sockets_open()) < 0){
    perror ("socket");
    exit (-1);
  }
  
  iw_enum_devices(skfd, &verify_autoconfig, iwlist, num_dev);

  /** new lets check if there are dupes (wifi) **/
  if (*num_dev > 1){
    while(temp->next != NULL){
      check_duplicate_if(temp,temp->next);
      temp = (wireless_devices *) temp->next;
    }
  }
  /* Close the socket. */
  close(skfd);
}

/**
 * ask_permission()
 * ----------------
 * only called when the user has not specified "force" option.
 * Basically sanity check to get permission before attempting to put
 * the card into monitoring mode...
 **/
void ask_permission()
{
  unsigned char answer;
  
  printf("\nDo you wish to enable monitor mode for your interface at this time? [y|n] ");
  answer = getchar();
  if (answer != 'y'){
    printf("\nerror: AirTraf exiting... can't run while not in monitor mode.\n");
    exit (-1);
  }
}

/**
 * enable_monitor()
 * ----------------
 * put the card into monitor mode  Also, make use of the PROMISC
 * setting in ifconfig so it is tad bit more apparant at what state
 * the interface is in...
 **/
int enable_monitor(wireless_devices * iwdev, const int force)
{
  int skfd; /* genereic raw socket desc. */
  uid_t uid;
  unsigned char *ifname;
  unsigned char path[100];
  unsigned char monitor_cmd[255];
  unsigned char temp_result[100];
  char result_code;
  FILE * fh = NULL;

  if ((uid = getuid()) != 0){
    printf("monitor: [error] you need to be root to enable monitor mode...\n");
    goto MONITOR_FAIL;
  }
  if (iwdev != NULL){
    switch(iwdev->compat_id){
    case DRV_AIRO_CS:
    case DRV_AIRO:
      if (!force) ask_permission();
      /** check if its a wifix device, if so, then get the matching
	  interface to enable monitoring mode **/
      if (!strncmp("wifi",iwdev->ifname,4))
	if (iwdev->real_ifname != NULL)
	  ifname = iwdev->real_ifname;
	else goto MONITOR_FAIL;
      else ifname = iwdev->ifname;
      snprintf(path, sizeof(path), "/proc/driver/aironet/%s/Config", ifname);
      fh = fopen(path, "w");
      if (fh != NULL){
	if(fputs("Mode: rfmon", fh)) // put card into RFMON
	  if(fputs("Mode: y", fh)){  // listen to ANY SSID
	    fprintf(stderr,"monitor: [success] (%s) rfmon & any ssid set\n", iwdev->drvname);
	  } 
	  else {
	    fclose(fh);
	   goto MONITOR_FAIL; 
	  }
	else{
	  fclose(fh);
	  goto MONITOR_FAIL; 
	}
	/* everything went okay */
	fclose(fh);
	goto MONITOR_SUCCESS;
      }
      else{
	printf("monitor: [error] failed to access Aironet Configuration.\n");
	goto MONITOR_FAIL;
      }
      break;
      /** some serious hack & slash done here **/
      /** NOTE: should make direct ioctl call, not running external
	  script.  But for some...  ioctl not available...**/
    case DRV_PRISM2_CS:
      if (!force) ask_permission();
      memset(monitor_cmd, 0, sizeof(monitor_cmd));
      snprintf(monitor_cmd, sizeof(monitor_cmd), "wlanctl-ng %s lnxreq_wlansniff channel=1 enable=true stripfcs=true keepwepflags=true prismheader=true", iwdev->ifname);
      if ((fh = popen(monitor_cmd, "r")) < 0) {
	fprintf(stderr, "monitor: [error] Could not popen ``%s''.  Aborting.\n", monitor_cmd);
	goto MONITOR_FAIL;
      }
      fprintf(stderr, "monitor: [info] (%s) executed '%s'\n", iwdev->drvname, monitor_cmd);
      // verify that the resultcode=success
      while (fgets(temp_result, sizeof(temp_result), fh) != NULL){
	if (sscanf(temp_result," resultcode=%c", &result_code) > 0){
	  if (result_code == 's'){
	    pclose(fh);
	    goto MONITOR_SUCCESS;
	  }
	  else{
	    pclose(fh);
	    goto MONITOR_FAIL;
	  }
	}
      }
      break;
    case DRV_PRISM2:
      if (!force) ask_permission();
      memset(monitor_cmd, 0, sizeof(monitor_cmd));
      snprintf(monitor_cmd, sizeof(monitor_cmd), "iwpriv %s monitor 1", iwdev->ifname);
      if ((fh = popen(monitor_cmd, "r")) < 0) {
	fprintf(stderr, "monitor: [error] Could not popen ``%s''.  Aborting.\n", monitor_cmd);
	goto MONITOR_FAIL;
      }
      fprintf(stderr, "monitor: [info] (%s) executed '%s'\n", iwdev->drvname, monitor_cmd);
      if (fgets(temp_result, sizeof(temp_result), fh) != NULL){
	// hmm there's an error... should get nothing back
	fprintf(stderr, "monitor: [error] Failed to invoke monitor mode.\n");
	pclose(fh);
	goto MONITOR_FAIL;
      }
      else{
	pclose(fh);
	goto MONITOR_SUCCESS;
      }
      break;
    case DRV_HOSTAP_CS:
    case DRV_HOSTAP:
      if (!force) ask_permission();
      // hack for now... it DOES work... need to patch driver!
      //      fprintf(stderr,"error: HostAP monitor mode incompatible with AirTraf at this time...\n");
      //      exit(1);
      
      memset(monitor_cmd, 0, sizeof(monitor_cmd));
      snprintf(monitor_cmd, sizeof(monitor_cmd), "iwpriv %s monitor 3", iwdev->ifname);
      if ((fh = popen(monitor_cmd, "r")) < 0) {
	fprintf(stderr, "monitor: [error] Could not popen ``%s''.  Aborting.\n", monitor_cmd);
	goto MONITOR_FAIL;
      }
      fprintf(stderr, "monitor: [info] (%s) executed '%s'\n", iwdev->drvname, monitor_cmd);
      if (fgets(temp_result, sizeof(temp_result), fh) != NULL){
	// hmm there's an error... should get nothing back
	printf("monitor: [error] Failed to invoke monitor mode.\n");
	pclose(fh);
	goto MONITOR_FAIL;
      }
      else{
	pclose(fh);
	goto MONITOR_SUCCESS;	
      }
      break;
    case DRV_ORINOCO_CS:
    case DRV_ORINOCO:
      if (!force) ask_permission();
      memset(monitor_cmd, 0, sizeof(monitor_cmd));
      snprintf(monitor_cmd, sizeof(monitor_cmd), "iwpriv %s monitor 1 1", iwdev->ifname);
      if ((fh = popen(monitor_cmd, "r")) < 0) {
	fprintf(stderr, "monitor: [error] Could not popen ``%s''.  Aborting.\n", monitor_cmd);
	goto MONITOR_FAIL;
      }
      fprintf(stderr, "monitor: [info] (%s) executed '%s'\n", iwdev->drvname, monitor_cmd);
      if (fgets(temp_result, sizeof(temp_result), fh) != NULL){
	// hmm there's an error... should get nothing back
	printf("monitor: [error] Failed to invoke monitor mode.\n");
	pclose(fh);
	goto MONITOR_FAIL;
      }
      else{
	pclose(fh);
	goto MONITOR_SUCCESS;
      }
      break;
    case -1:
      fprintf(stderr, "monitor: [error] Incompatible driver (%s) for use with AirTraf.\n", iwdev->drvname);
      break;
    }
  }
  else{
    fprintf(stderr, "monitor: [error] No wireless device selected?  Internal failure!\n");
    goto MONITOR_FAIL;
  }
 MONITOR_FAIL:
  fprintf(stderr, "monitor: [error] (%s) failed to be placed into monitor mode!\n", iwdev->drvname);
  exit(0);

 MONITOR_SUCCESS:
  if ((skfd = iw_sockets_open()) < 0){
    perror ("monitor: [error] cannot open socket for interface manipulation!");
  }
  else{
    if (set_flag(skfd, iwdev->ifname, IFF_PROMISC) > 0)
      fprintf(stderr, "monitor: [success] (%s) flag updated to reflect PROMISC\n", iwdev->ifname);
    else
      fprintf(stderr, "monitor: [warning] (%s) flag failed to update properly\n", iwdev->ifname);
    close(skfd);    
  }
  printf("monitor: [success] (%s) placed into monitor mode!\n", iwdev->drvname);
  return (1);
}

/**
 * disable_monitor()
 * -----------------
 * return card back to mode it was before...
 **/
int disable_monitor(wireless_devices * iwdev)
{
  int skfd;
  uid_t uid;
  unsigned char *ifname;
  unsigned char path[100];
  FILE * fh;

  if ((uid = getuid()) != 0){
    fprintf(stderr,"unmonitor: [error] you need to be root to disable monitor mode...\n");
    return (0);
  }
  if (iwdev != NULL){
    switch(iwdev->compat_id){
    case DRV_AIRO_CS:
    case DRV_AIRO:
      /** check if its a wifix device, if so, then get the matching
	  interface to enable monitoring mode **/
      if (!strncmp("wifi",iwdev->ifname,4))
	if (iwdev->real_ifname != NULL)
	  ifname = iwdev->real_ifname;
	else{
	  fprintf(stderr,"unmonitor: [error] (%s) cannot find real interface!\n", iwdev->ifname);
	  return (0);
	}
      else ifname = iwdev->ifname;
      snprintf(path, 100, "/proc/driver/aironet/%s/Config", ifname);
      fh = fopen(path, "w");
      if (fh != NULL){
	if(fputs("Mode: i", fh)) // put card back into standard
				 // operation
	  fprintf(stderr,"unmonitor: [success] (%s) returned to infrastructure mode.\n", iwdev->drvname);
	else
	  fprintf(stderr,"unmonitor: [error] (%s) failed to return to infrastructure mode.\n", iwdev->drvname);
      }
      else{
	fclose(fh);
	fprintf(stderr,"unmonitor: [error] failed to access aironet Configuration...  cannot disable monitor mode.\n");
	return (0);
      }
      fclose(fh);
      break;
    case DRV_PRISM2:
      
	
    }
    /* update flag take off PROMISC */
    if ((skfd = iw_sockets_open()) < 0){
      perror ("unmonitor: [error] cannot open socket for interface manipulation!");
    }
    else{
      if (clr_flag(skfd, iwdev->ifname, IFF_PROMISC) > 0)
	fprintf(stderr,"unmonitor: [success] (%s) interface flag updated to take off PROMISC\n", iwdev->ifname);
      else
	fprintf(stderr,"unmonitor: [warning] (%s) interface flag failed to update properly\n", iwdev->ifname);
      close(skfd);
    }
    fprintf(stderr,"unmonitor: [success] (%s) card successfully placed out of monitor mode!\n", iwdev->drvname);
    
  }
  return (1);
}

/**
 * prompt_device()
 * ---------------
 * called if there are multiple wireless devices configured in the
 * system...  we need to know which one is going to be used for
 * AirTraf sniffing...
 **/
wireless_devices * prompt_device(wireless_devices * iwlist, int *num)
{
  wireless_devices * temp = iwlist;
  unsigned short index = 0;
  unsigned char answer[255];
  unsigned char *ans_ptr;
  int picked_index;
  int i;
  
  fprintf(stderr,"There are multiple wireless devices detected in your system.\n");
  fprintf(stderr,"The following are compatible devices...\n");

  while (temp != NULL){
    if (temp->drvname != NULL){
      if (temp->compat_id > -1){
	if (!strncmp("wifi",temp->ifname,4))
	  fprintf(stderr,"\t[%d]: %s (%s) -> %s *recommended*\n", ++index, temp->ifname, temp->drvname, temp->real_ifname);
	else
	  fprintf(stderr,"\t[%d]: %s (%s)\n", ++index, temp->ifname, temp->drvname);
      }
    }
    temp = temp->next;
  }

 PICK_CHOICE:
  memset(answer,0,sizeof(answer));
  ans_ptr = answer;
  fprintf(stderr,"\nPlease pick the device to use ([1-%d] - choice, x - cancel): ", index);
  if(fgets(answer,255,stdin)!= NULL){
    i = strlen(answer)-1;
    if(answer[i]=='\n') answer[i] = '\0';
    /** skip white-space **/
    while (isspace(*ans_ptr)) ans_ptr++;
    if (*ans_ptr == 0) goto SHOW_ERROR;
    if (*ans_ptr == 'x') exit(0);
    
    errno = 0;
    picked_index = strtol (ans_ptr, NULL, 0);
    if (errno) goto SHOW_ERROR;
    if ((picked_index < 1)||(picked_index > index)) goto SHOW_ERROR;

    index = 0;
    temp = iwlist;
    while (temp != NULL){
      if (temp->drvname != NULL){
	if (temp->compat_id > -1){
	  if (picked_index == ++index)
	    break;
	}
      }
      temp = temp->next;
    }
    return (temp);
  }
 SHOW_ERROR:
  printf("\nerror: invalid choice (%s)!  pick again, or 'x' to cancel.\n", answer);
  goto PICK_CHOICE;  
}



// TEMPORARY tester main routine
/* int main() */
/* { */
/*   int num_dev = 0; */
/*   int force = 0;  // prompt whether they want to force promiscuous mode */
/*   wireless_devices iwlist; */

/*   init_autoconfig(&iwlist, &num_dev); */
/*   if (num_dev == 1){ */
/*     enable_monitor(&iwlist, force) ? printf("Launching AirTraf...\n") : exit(-1); */
/*   } */
/*   else if (num_dev > 1) */
/*     enable_monitor(prompt_device(&iwlist, &num_dev), force); */

/*   return 0; */
/* } */
