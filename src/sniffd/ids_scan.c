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
////////////////////////////////////////////////////////////////
// IDS RELATED FUNCTIONS  ( !@# NEEDS WORK!!!)
////////////////////////////////////////////////////////////////

/**
 * ids_find_node()
 * ---------------
 * search the ids data structure to see if the detected node already
 * exists.
 **/
int ids_find_node (ids_t *info, __u8 *addr)
{
  int c=0;

  while (c < info->node_count)
    {
     if (0 == memcmp(&info->nodes[c].node_mac,addr,6))
       return (c);
     c++;
    }
  return (-1);
}

/**
 * ids_add_node()
 * --------------
 * if the selected address does not exist in the data structure, add
 * it, and initialize its data
 **/
int ids_add_node (ids_t *info, __u8 *addr)
{
  if (DEBUG) printf("ids_add_node: adding node\n");

  /* we don't care about b-cast addresses */
  if (0 == memcmp(bcast, addr, 6)){
    return (0);
  }

  /* add a node into ids monitored list */
  if ((ids_find_node(info,addr) == -1) && (info->node_count < MAX_MAC)){
    memset(&info->nodes[info->node_count],0,sizeof(node_stat_t));
    memcpy(&info->nodes[info->node_count].node_mac, addr, 6);
    info->node_count++;
  }
  else{
    return (0);
  }

  if (DEBUG) printf("ids_add_node: exiting...\n");
  return (1);
}

/**
 * get_ids_info()
 * --------------
 * main routine for ids stuff, given the packet, it attempts to
 * dissect, evaluate, and manage the associated packet.
 **/
void get_ids_info(__u8 *wlan_hdr, __u8 *sa, __u8 *da, __u8 *bssid,
		      __u8* ssid, int subtype)
{
  int node_loc;
  int info_ptr;
  
  switch(subtype)
    {
    case ASSOC_REQ:
      if (ids_add_node(ids_info,sa)){
	node_loc = ids_find_node(ids_info,sa);
	ids_info->nodes[node_loc].assoc_request++;
	memcpy(&ids_info->nodes[node_loc].dest_mac, da, 6);
      }
      break;
    case ASSOC_RES: // status code
      info_ptr = 26;
      if (ids_add_node(ids_info,sa)){
	node_loc = ids_find_node(ids_info,sa);
	
	memcpy(&ids_info->nodes[node_loc].assoc_status, &wlan_hdr[info_ptr], 2);
	memcpy(&ids_info->nodes[node_loc].dest_mac, da, 6);
      }
      break;
    case REASSOC_REQ:
      if (ids_add_node(ids_info,sa)){
	node_loc = ids_find_node(ids_info,sa);
	ids_info->nodes[node_loc].reassoc_request++;
	memcpy(&ids_info->nodes[node_loc].dest_mac, da, 6);
      }
      break;
    case REASSOC_RES: // status code
      info_ptr = 26;
      if (ids_add_node(ids_info,sa)){
	node_loc = ids_find_node(ids_info,sa);
	
	memcpy(&ids_info->nodes[node_loc].reassoc_status, &wlan_hdr[info_ptr], 2);
	memcpy(&ids_info->nodes[node_loc].dest_mac, da, 6);
      }
      break;
    case PROBE_REQ:
      if (ids_add_node(ids_info,sa)){
	node_loc = ids_find_node(ids_info,sa);
	ids_info->nodes[node_loc].probe_request++;
	memcpy(&ids_info->nodes[node_loc].dest_mac, da, 6);	
      }
      break;
    /** not necessarily IDS, but contains AP info **/
    case PROBE_RES:
    case BEACON:
      check_ap_info(wlan_hdr, bssid, ssid, sa, da);
      break;
    case ATIM:
      break;
    case DISASSOC: 
      info_ptr = 24; // reason code
      if (ids_add_node(ids_info,sa)){
	node_loc = ids_find_node(ids_info,sa);
	ids_info->nodes[node_loc].disassoc_count++; 
	memcpy(&ids_info->nodes[node_loc].disassoc_status, &wlan_hdr[info_ptr], 2);
	memcpy(&ids_info->nodes[node_loc].dest_mac, da, 6);	
      }
      break;
    case AUTH:
      info_ptr = 28; // status code
      if (ids_add_node(ids_info,sa)){
	node_loc = ids_find_node(ids_info,sa);
	ids_info->nodes[node_loc].auth_count++;
	memcpy(&ids_info->nodes[node_loc].auth_status, &wlan_hdr[info_ptr], 2);
	memcpy(&ids_info->nodes[node_loc].dest_mac, da, 6);	
      }
      break;
    case DEAUTH:
      info_ptr = 24; // reason code
      if (ids_add_node(ids_info,sa)){
	node_loc = ids_find_node(ids_info,sa);
	ids_info->nodes[node_loc].deauth_count++;
	memcpy(&ids_info->nodes[node_loc].deauth_status, &wlan_hdr[info_ptr], 2);
	memcpy(&ids_info->nodes[node_loc].dest_mac, da, 6);
      }
      break;
    }
}

