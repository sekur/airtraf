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
 **  definition.h
 **
 ****************************************************************
 **
 **   Copyright (c) 2001,2002 all rights reserved.
 **
 **   Author: Peter K. Lee <saint@elixar.net>
 **
 ***************************************************************/

#ifndef __definition_h__
#define __definition_h__

#define VERSION_INFO "1.1"

#ifndef ARPHRD_IEEE80211
#define ARPHRD_IEEE80211 801
#endif
#ifndef ARPHRD_IEEE80211_PRISM
#define ARPHRD_IEEE80211_PRISM 802
#endif

/* common status definition */
#define DISABLED 0
#define ENABLED 1
#define ERROR     -1

/* card type def */
#define AIRONET         1
#define PRISMII         2
#define HOSTAP		3
#define HERMES		4
#define WLANNG          5

/* running mode */
#define DAEMONIZED      0
#define INTERACTIVE     1
#define ADHOC_MODE      1
#define SERVER_MODE     2

/* scanning mode */
#define DETAILED_SCAN   1
#define CHANNEL_SCAN    2

/* channel hopping intervals */
#define CHANNEL_SCAN_INTERVAL 0.5
#define CHANNEL_HOP_INTERVAL 0.2

/* gui defs */
#define SCROLLUP        0
#define SCROLLDOWN      1
#define NODE_ROW_SIZE   7
#define DEFAULT_UPDATE_DELAY 5000
#define TIME_TARGET_MAX 30
#define ERR_IO          -1
#define ERR_TIMEOUT     -2
#define ERR_REBIND      -3
#define MAX_BUFFER_SIZE 4096

/** prismII stuff **/
#define BIT(x) (1 << (x))
#define NETLINK_USERSOCK 2
#define PRISM2_MONITOR_GROUP BIT(0)
#define KILO	1e3
#define MEGA	1e6
#define GIGA	1e9

/** tcp table analysis **/
#define OUTGOING   1
#define INCOMING   2
#define BACKGROUND 3

#define DEVNAME_LEN     16
#define __WLAN_ATTRIB_PACK__       __attribute__ ((packed))
#define ROWWIDTH        32
#define SSID_SIZE       32
#define WTAP_ENCAP_IEEE_802_11 18
#define MAX_CHANNEL     14

#define SSID_SIZE	32

/** make these user configurable.... later **/
#define MAX_MAC	        100
#define MAX_TCP_CONN    200
#define MAX_TCP_CONN_THREAD  50

#define SYNCH_CMD       1
#define GET_DATA_CMD    2

/*************************
 * Frame Type Definitions
 *************************/
#define FT_MGMT         0
/** management sybtypes **/
#define ASSOC_REQ       0
#define ASSOC_RES       1
#define REASSOC_REQ     2
#define REASSOC_RES     3
#define PROBE_REQ       4
#define PROBE_RES       5
#define BEACON          8
#define ATIM            9
#define DISASSOC        10
#define AUTH            11
#define DEAUTH          12

#define FT_CTRL         1
/** control subtypes **/
#define ACK             13

#define FT_DATA         2

/* log file definitions */
#define CONNECT_LOG     1
#define ERROR_LOG       2
#define MAX_MSG_SIZE    256

#include <asm/types.h>
#include <sys/time.h>
#include <netinet/ip.h>

extern int sysexit;

/*----------------------------------------------------------------*/
/* AIRTRAF STRUCTURES USED THROUGHOUT THE PROGRAM                 */
/*----------------------------------------------------------------*/

#define CAPTURE_MODE_OFF 0
#define CAPTURE_MODE_RECORD 1
#define CAPTURE_MODE_PLAYBACK 2

#define CAPTURE_STATUS_INACTIVE 0
#define CAPTURE_STATUS_ACTIVE 1
#define CAPTURE_STATUS_COMPLETE 2
#define CAPTURE_STATUS_DATA_READY 3
#define CAPTURE_STATUS_DATA_ERROR 4
#define CAPTURE_STATUS_DATA_EXISTS 5

#define CAPTURE_PB_STOP 0
#define CAPTURE_PB_PLAY 1
#define CAPTURE_PB_FORWARD  2
#define CAPTURE_PB_FF              3
#define CAPTURE_PB_REWIND      4
#define CAPTURE_PB_RR              5

/**
 * SETTINGS object
 * ---------------
 * This object is crucial for passing around between functions, as it
 * holds the start up settings (command-line) that will determine how
 * data is acquired, what type of driver will be used, and in turn how
 * data will be processed.
 **/
struct SETTINGS
{
  /** run-time settings **/
  int card_type;
  char * interface;
  int runtime_mode;
  int conn_mode;
  char * logfile;
  int logging_mode;
  int signal_support;
  int sniff_socket;
  int scan_mode;
  void *chosen_ap;

  /** capture settings **/
  int capture_version;  // for later compatibility
  int capture_mode;
  char * capture_file;
  __u32 capture_size;
  __u32 capture_seq;
  time_t * capture_timestamp;
  float capture_interval;
  float capture_duration;
  int capture_overwrite;
  int capture_command;
  int capture_status;
};

/**
 * This is not yet used...  will be useful for NETLINK wlan-ng driver
 * interfacing...  later...
 **/
typedef struct
{
  __u32 did __attribute__ ((packed));
  __u16 status __attribute__ ((packed));
  __u16 len __attribute__ ((packed));
  __u32 data __attribute__ ((packed));
} p80211item_t;

/**
 * same as above...  this is the netlink header for wlan-ng driver...
 **/
typedef struct
{
  __u32 msgcode __attribute__ ((packed));
  __u32 msglen __attribute__ ((packed));
  __u8 devname[DEVNAME_LEN] __attribute__ ((packed));
  p80211item_t hosttime __attribute__ ((packed));
  p80211item_t mactime __attribute__ ((packed));
  p80211item_t channel __attribute__ ((packed));
  p80211item_t rssi __attribute__ ((packed));
  p80211item_t sq __attribute__ ((packed));
  p80211item_t signal __attribute__ ((packed));
  p80211item_t noise __attribute__ ((packed));
  p80211item_t rate __attribute__ ((packed));
  p80211item_t istx __attribute__ ((packed));
  p80211item_t frmlen __attribute__ ((packed));
} wlan_ng_hdr_t;

/**
 * hfa384x_descript object
 * -----------------------
 * This is part of the object returned by the prism2 host-ap driver,
 * happens to contain neat things like signal, and rate...
 **/
typedef struct
{
  /* HFA384X RX frame descriptor */
  __u16 status __attribute__ ((packed));
  __u32 time __attribute__ ((packed));
  __u8 silence __attribute__ ((packed));
  __u8 signal __attribute__ ((packed));
  __u8 rate __attribute__ ((packed));
  __u8 rxflow __attribute__ ((packed));
  __u32 reserved __attribute__ ((packed));
} hfa384x_descript_t;

/**
 * prism2 header object (host-ap)
 * ------------------------------
 * This is the prism2 header as host-ap driver running in monitor mode
 * 1, NETLINK device submits to user-space.  As can be seen, it has
 * some stupid fields that are not really useful for our purposes...
 **/
typedef struct
{
  hfa384x_descript_t frame_descriptor __attribute__ ((packed));
  
  /* 802.11 */
  __u16 frame_control __attribute__ ((packed));
  __u16 duration_id __attribute__ ((packed));
  __u8 mac1[6] __attribute__ ((packed));
  __u8 mac2[6] __attribute__ ((packed));
  __u8 mac3[6] __attribute__ ((packed));
  __u16 sequence __attribute__ ((packed));
  __u8 mac4[6] __attribute__ ((packed));
  __u16 data_len __attribute__ ((packed));

  /* 802.3 */
  __u8 dst_addr[6] __attribute__ ((packed));
  __u8 src_addr[6] __attribute__ ((packed));
  __u16 len __attribute__ ((packed));
  __u8 crap[6] __attribute__ ((packed));

} prism2_hdr_t;
   
/**
 * wireless 802.11b frame structure
 * -------------------------------
 * this is the pure 802.11b frame structure with no other nonsense.
 * Used for devices/drivers that returns unadulterated frame formats,
 * for our purposes, Cisco Aironet driver returns this in this form.
 **/
typedef struct
{
  __u16 frame_control __attribute__ ((packed));
  __u16 duration_id __attribute__ ((packed));
  __u8 mac1[6] __attribute__ ((packed));
  __u8 mac2[6] __attribute__ ((packed));
  __u8 mac3[6] __attribute__ ((packed));
  __u16 sequence __attribute__ ((packed));
  __u8 mac4[6] __attribute__ ((packed));
} wlan_hdr_t;

/**
 * frame control structure
 * -----------------------
 * useful for dissecting bits/such from the frame_control field in the
 * 802.11b frame.
 **/
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
} frame_control_t;


////////////////////////////////////////////////////////
//  packet parsing structs (easier interface)
////////////////////////////////////////////////////////

#define p802_11b_ADHOC  1
#define p802_11b_AP2STA 2
#define p802_11b_STA2AP 3
#define p802_11b_AP2AP  4

/**
 * 802.11b parsed header information
 * ---------------------------------
 * this object contains the interpreted values of the raw bytes in the
 * message buffer, some pointers to the location of relevant fields,
 * as well as other info (channel & ssid) if available (not all frames
 * contain them).
 * objective was to achieve passable object between functions, to
 * simplyfy the process of reading out the relevant information out of
 * the raw 802.11b frame format.  (since the fields differ for
 * different types of frames... mgmt, ctrl, data)
 **/
struct p802_11b_info
{
  __u8   type;
  __u16  subtype;
  __u8   datatype;
  __u8   wep;
  __u8   status;
  
  __u8 * bssid;
  __u8 * da;
  __u8 * sa;

  __u8 channel; // if available
  __u8 ssid[SSID_SIZE]; // if available
};


///////////////////////////////////////////////////////
//  packet abstraction layer structure
///////////////////////////////////////////////////////

#define OTHER  -1

/** error status **/
#define FCS_ERR      1
#define IPCHKSUM_ERR 2
#define IPHDRLEN_ERR 3

/** driver protocols... (special ioctls...) **/
#define AIRONET_MOD  1

/** mac layer protocols **/
#define p802_11  1
#define hfa384x  2
#define wlanngp2 3

/** network layer protocols **/
#define IPv4    1
#define IPv6    2

/** transport layer protocols **/
#define TCP     1
#define UDP     2
#define ICMP    3

/**
 * packet_info object
 * ------------------
 * this object is useful for achieving packet abstraction...
 * Basically we have a static single message buffer, (since we're
 * processing one packet at a time), and we construct this info
 * package by pointing to relevant positions from the message buffer
 * that contains the raw bytes.
 * Allows processing of different format of packets returned (by
 * different types of drivers...) into a common interface.
 **/
struct packet_info
{
  __u32 packet_size;
  __u32 net_pkt_size;
  __u8  error_status;

  /** protocol identifiers (as described above) **/
  __u8  driver_proto;
  __u8  mac_proto;
  __u8  net_proto;
  __u8  trans_proto;

  /** data details **/
  __u16 data_size;

  /** packet abstraction (for easier access) **/
  struct airids_frame_info *driver_pkt; // pointer to special driver info
  void *mac_pkt;                 // pointer to mac header inside msgbuf
  void *net_pkt;                 // pointer to network header inside msgbuf
  void *trans_pkt;               // pointer to transport header inside msgbuf  
  void *data;                     // pointer to data inside msgbuf
};

///////////////////////////////////////////////////////
//  channel scanning data structures (simple)
///////////////////////////////////////////////////////

#define AP_STATUS_NEW 1
#define AP_STATUS_RENEW 2
#define AP_STATUS_ACTIVE 3
#define AP_STATUS_MARK_INACTIVE 4
#define AP_STATUS_INACTIVE 5

/**
 * access point object
 * -------------------
 * the primary object used for channel scanning, doesn't contain as
 * complex data structure as in detailed scan access point, but
 * contains enough for general scanning purposes.
 **/
struct access_point
{
  __u8 channel;
  __u8 bssid[6];
  __u8 ssid[32];
  __u8 available_band;
  __u8 wep_status;
  __u8 traffic_type;

  __u16 mgmt_count;
  __u16 ctrl_count;
  __u16 data_count;
  __u32 packet_count;

  __u16 encrypt_count;

  struct timeval timestamp;
  __u8 status; // the current status about this object
  
  float signal_str;
  void *next;
};

/**
 * channel overview object
 * -----------------------
 * holds the access point objects as it is discovered during the
 * channel scan.  In format of array of linked-lists.
 * array represents the ~14 channels
 * linked-list represents the APs discovered in list per channel.
 **/
struct channel_overview
{
  unsigned int num_det_aps;
  unsigned int num_active_aps;
  struct access_point *all_chan[15];
};

///////////////////////////////////////////////////////
//  detailed scanning data structures (complex)
///////////////////////////////////////////////////////

/**
 * bandwidth measurement object
 * ----------------------------
 * a commonly shared object among many different statistics that
 * simplifies calculation of desired bandwidth characteristics, such
 * as current, high, low, and average bandwidth observed.
 **/
typedef struct
{
  __u32 old_count_frame;
  __u32 old_byte_tot;
  __u32 tot_byte;
  __u16 num;
  struct timeval old_time;
  float curr;
  float high;
  float low;
  float avg;
} bandwidth_t;

typedef struct
{
  struct timeval last_time;
  __u16 num;
  float curr;
  float high;
  float low;
  float avg;
} latency_t;

/**
 * tcpconn_t object
 * ----------------------
 * This object holds the actual TCP connection related info between a
 * client and server.  Since a given TCP connection to a server can be
 * multiple from a single client, this object will represent one of
 * each multiple connections, identified by the unique port # of the
 * client, regardless of the same destination port # of the server.
 **/
typedef struct
{
  __u16 unique_port;     // the unique port identifying this connection
  __u8 initiator;             // did our wireless node initiate or is it servicing?
  __u8 conn_status;      // (1) if active, (0) if reset or fin/acked.
  
    /** incoming (to wireless node) analysis **/
  __u16 inc_window;        // window size from incoming packet
  __u16 inc_old_window;  // previous window size from incoming packet
  __u32 incoming_count;
  __u32 incoming_byte;
  __u32 last_incoming_seq_num;// sequence # of latest incoming data
			      // (track retransmissions: if new < last)
  __u32 curr_incoming_seq_num;// sequence # of new incoming data
  __u32 acked_incoming_seq_num; // seq # of latest acked incoming data
  __u32 ack_outgoing_seq_num; // sequence # of received data by internet node
  __u8 incoming_dup_ack;      // count of duplicate acks received currently...
  latency_t incoming_latency; // inter-spacial time between incoming packets

  /** outgoing (to internet node) analysis **/
  __u16 out_window;        // window size from outgoing packet
  __u16 out_old_window;    // previous winndow size from outgoing packet
  __u32 outgoing_count;
  __u32 outgoing_byte;
  __u32 last_outgoing_seq_num;// sequence # of latest outgoing data
			      // (track retransmissions: if new < last)
  __u32 curr_outgoing_seq_num;// sequence # of new outgoing data
  __u32 acked_outgoing_seq_num; // seq # of latest acked outgoing data
  __u32 tracked_seq_num;      // sequence # being tracked for RTT
  __u8 outgoing_dup_ack;      // count of duplicate acks sent currently...
  latency_t outgoing_latency; // inter-spacial time between outgoing packets

   /** overall analysis **/
  __u32 total_count;
  __u32 total_byte;
  __u16 retransmit_count;     // # packets retransmitted
  __u32 retransmit_byte;      // # bytes retransmitted
  
  __u8 tracking_rtt;          // if tracking RTT, (1 yes, 0 no)   
  latency_t total_rtt;        // estimated RTT between wireless & internet

  void * next;
} tcpconn_t;

/**
 * tcp table object
 * ----------------
 * holds the tcp session info for the wireless node.
 * This object will hold each UNIQUE connection status, (ip, service
 * port) pair, and specific connection status information (ip, actual
 * port) will be managed on one-by-one basis.   This node will handle
 * cases where there are multiple connections for the same type of
 * service between a client and a server.
 **/
typedef struct
{
  struct in_addr other_addr; // whoever else connected with wireless node
  __u16 service_port; // the type of service port this connection represents
  __u8 initiator;             // did our wireless node initiate or is it servicing?

  /** incoming (to wireless node) analysis **/
  __u32 incoming_count;
  __u32 incoming_byte;
  latency_t incoming_latency; // inter-spacial time between incoming packets
  bandwidth_t incoming_rate;  // incoming bandwidth rate

  /** outgoing (to internet node) analysis **/
  __u32 outgoing_count;
  __u32 outgoing_byte;
  latency_t outgoing_latency; // inter-spacial time between outgoing packets
  bandwidth_t outgoing_rate;  // outgoing bandwidth rate

  /** overall analysis **/
  __u32 total_count;
  __u32 total_byte;
  __u16 retransmit_count;     // # packets retransmitted
  __u32 retransmit_byte;      // # bytes retransmitted
  __u16 reset_count;          // # times connection reset

  float avg_rtt_latency;       // estimated RTT between wireless & internet
  bandwidth_t total_rate;     // total bandwidth rate

  __u16 closed_connections; // # of closed connections
  __u16 num_connected;          // total # of connections to the same host
  
  /** collection of UNIQUE actual point-point connections
      between client & server **/
  tcpconn_t * tcpconn_head;
  tcpconn_t * tcpconn_tail;
  
  void * next; // pointer to next tcptable_t element
} tcptable_t;


/**
 * wireless node object
 * --------------------
 * holds information regarding MAC address, IP address, analysis
 * statisitics with regard to nodes connected to the discovered access
 * point.
 * Also, holds transport layer connections analysis.
 **/
typedef struct 
{
  /** identifier **/
  struct in_addr ip_addr;
  __u8  mac_addr[6];

  /** count/byte/band **/
  __u32 inc_packet;
  __u32 inc_byte;
  __u32 out_packet;
  __u32 out_byte;
  __u32 tot_packet;
  bandwidth_t bndwth;

  __u8  status; 

  /** signal **/
  __u32 tot_signal_str;
  float avg_signal_str;

  /** tcp analysis **/
  __u32 tcp_total_count;
  __u32 tcp_total_byte;
  __u16 tcp_retransmit_count;     // # packets retransmitted
  __u32 tcp_retransmit_byte;      // # bytes retransmitted
  __u16 tcp_existing_count;       // # packets from already existing connection
  __u32 tcp_existing_byte;         // # bytes from already existing connection
  /** collection of UNIQUE TCP connections
      determined via (IP, service Port) pairs **/
  __u16 tcp_connections;

  tcptable_t * tcpinfo_head;
  tcptable_t * tcpinfo_tail;

  void * next;
} bss_node_t;

/**
 * management info object
 * ----------------------
 * holds simple count/byte/others information regarding to management
 * frame traffic observed.
 **/
typedef struct
{
  __u32 mgmt_count;
  __u32 mgmt_byte;
  __u16 beacon;
  __u16 disassoc;
  __u16 other;
  bandwidth_t bndwth;
} mgmt_t;

/**
 * control info object
 * -------------------
 * holds simple count/byte/others information regarding to control
 * frame traffic observed.
 **/
typedef struct
{
  __u32 control_count;
  __u32 control_byte;
  __u16 ack;
  __u16 other;
  bandwidth_t bndwth;
} control_t;

/**
 * data info object
 * ----------------
 * holds simple count/byte/others information regarding to data frame
 * traffic observed.
 **/
typedef struct
{
  __u32 data_count;
  __u32 data_byte;
  __u32 external_count;
  __u32 external_byte;
  __u32 internal_count;
  __u32 internal_byte;
  bandwidth_t bndwth;
  bandwidth_t extband;
} data_t;

/**
 * protocol info object
 * --------------------
 * commonly shared object that contains desired statistics for given
 * protocols.
 **/
typedef struct
{
  /** internal analysis **/
  __u32 count;
  __u32 byte;
  __u32 out_count;
  __u32 out_byte;
  __u32 in_count;
  __u32 in_byte;
  bandwidth_t band;

  /** external analysis (background trafic, bcast, etc.) **/
  __u32 ext_count;
  __u32 ext_byte;
  bandwidth_t extband;
} proto_info_t;

/**
 * network protocol info object
 * ----------------------------
 * holds information with regard to IP, IPv6, and others.
 **/
typedef struct
{
  proto_info_t ip;
  proto_info_t ipv6;
  proto_info_t other;
} netproto_t;

/**
 * transport protocol info object
 * ------------------------------
 * holds information with regard to TCP (total/in/out), UDP
 * (total/in/out), and ICMP (total/in/out).  Also, information
 * regarding the traffic characteristics of unsupported protocols.
 **/
typedef struct
{
  proto_info_t tcp;
  proto_info_t udp;
  proto_info_t icmp;
  proto_info_t other;
} transproto_t;

/**
 * bss (access point) object
 * -------------------------
 * The main object responsible for keeping track of access point's
 * activity, as well as keeping together all connected wireless nodes
 * associated with this access point.
 **/
typedef struct
{
  __u8	         bssid[6];
  __u8           ssid[32];
  __u8           channel;
  __u8           available_band;
  __u8           wep_status;

  __u32          overall_count;
  __u32          overall_byte;  

  float          link_utilization;
  float          background_noise;
  float          packet_loss;

  mgmt_t         mgmt_data;
  control_t      ctrl_data;
  data_t         normal_data;
  netproto_t     network_data;
  transproto_t   transport_data;
  bandwidth_t    bndwth;
  
  __u8	       num;
  bss_node_t * addr_list_head;
  bss_node_t * addr_list_tail;
  
  void * next;
} bss_t;

//////////////////////////////////////////////////////////////////////
//  Data Decode Structures
//////////////////////////////////////////////////////////////////////

#define SERVICE_NAME_SIZE 10
#define STORE_DATA_SIZE 100

struct decode_rec_entry
{
  time_t		time;
  struct in_addr	ip_src;
  struct in_addr	ip_dst;
  __u16                 service_port;
  __u16                 other_port;
  __u8                   initiator;

  __u8 name[SERVICE_NAME_SIZE];
  __u8 data[STORE_DATA_SIZE];

  void *next;
};

struct decode_rec
{
  __u16 num_records;
  
  void *head;
  void *tail;
};


////////////////////////////////////////////////////////////////////////
//  IDS Structure... (broken)
////////////////////////////////////////////////////////////////////////

/* node statistics (ids) */
typedef struct
{
  __u8  node_mac[6];
  __u8  dest_mac[6];
  __u8	bssid[6];
  __u8  ssid[32];
  __u8  channel;
  __u16 probe_request;
  __u16 assoc_request;
  __u16 assoc_status;
  __u16 reassoc_request;
  __u16 reassoc_status;
  __u16 disassoc_count;
  __u16 disassoc_status;
  __u16 auth_count;
  __u16 auth_status;
  __u16 deauth_count;
  __u16 deauth_status;
} node_stat_t;

/* intrusion detection info */
typedef struct
{
  node_stat_t nodes[MAX_MAC];
  __u16 node_count;
} ids_t;

/////////////////////////////////////////////////////////////////////////
//  POTENTIAL structures (works as filters for countering corruption)
/////////////////////////////////////////////////////////////////////////

typedef struct
{
  __u8  mac_addr[6];
  __u32 time_of_entry;
  __u32 bytes_seen;
  __u8  status;  // whether to keep tracking bytes or not
} pnode_t;

/* potential node (temporal) structure */
typedef struct
{
  pnode_t nodes[MAX_MAC];
  __u8 num;
} potential_node_t;

/* potential AP (temporal) structure */
typedef struct
{
  struct access_point ap_list[MAX_MAC];
  __u8 num;
} potential_ap_t;

//////////////////////////////////////////////////////////////////
//  MAIN detailed scan overview structure
//////////////////////////////////////////////////////////////////

/**
 * detailed scan overview object
 * -----------------------------
 * this object holds together the 'access points' that have been
 * detected, as well as corrupted packets detected and filtered,
 * (since corruption can't really be attributed any single access
 * point.)
 **/
typedef struct
{
  struct in_addr sniffer_ip;
  struct in_addr poller_ip;
  
  __u16 bad_mac;
  __u32 bad_mac_byte;
  __u16 bad_ip_chksum;
  __u32 bad_ip_chksum_byte;
  __u16 fcs_error;
  __u32 fcs_error_byte;
  __u16 filtered_data;
  __u32 filtered_data_byte;

  __u16 corrupt_tot;
  __u32 corrupt_tot_byte;
  
  __u8  tot_num_ap;
  __u16 tot_num_nodes;
  
  bss_t * bss_list_top;
  //  ids_t * ids_info_top;
} detailed_overview_t;

#endif
