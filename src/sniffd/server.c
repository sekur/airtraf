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
 **  server.c
 **
 ****************************************************************
 **
 **   Copyright (c) 2001 all rights reserved.
 **
 **   Author: Peter K. Lee <pkl@duke.edu>
 **
 ***************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#include "definition.h"
#include "sniff_include.h"

extern pthread_t thread;
extern pthread_cond_t start_cond;
extern pthread_mutex_t start_lock;
extern bss_t *bss_list;
extern pthread_mutex_t engine_lock;

#define MAX_CMD_SIZE 100

/*=============================================================*/
/* Function Prototypes */

int process_command(int, char *);
int issue_get_cmd(int, char *);
int send_bss_info(int);
int send_ids_info(int);

/*=============================================================*/
/* Function Definitions */

/**
 * process_command()
 * -----------------
 * a routine to parse the command sent by the polling server,
 * determine the action associated, and call appropriate action
 * functions.
 **/
int process_command(int fd, char * cmd)
{
  char action[10];
  char option[10];
  
  sscanf(cmd, "%s%s", action, option);

  if (!strcasecmp(action, "GET")){
    return issue_get_cmd(fd, option);
  }
  else if (!strcasecmp(action, "SYNCH")){
    return (0);
  }
  return (-1);
}

/**
 * issue_get_cmd()
 * ---------------
 * get the proper data requested by the GET command
 **/
int issue_get_cmd(int fd, char *option)
{
  if (!strcasecmp(option, "DATA")){
    return send_bss_info(fd);
  }
  if (!strcasecmp(option, "IDS")){
    return send_ids_info(fd);
  }
  return (-1);
}

/**
 * writen()
 * --------
 * write n bytes to a file descriptor
 **/
ssize_t writen(int fd, const void *vptr, size_t n)
{
  ssize_t nleft;
  ssize_t nwritten;
  const char *ptr;

  ptr = vptr;
  nleft = n;
  while (nleft > 0){
    if ((nwritten = write(fd, ptr, nleft)) <= 0){
      if (errno == EINTR)
	nwritten = 0; // call write() again!
      else
	return (ERROR); // error!
    }
    nleft -= nwritten;
    ptr += nwritten;
  }
  return (n);
}

/**
 * send_object_block()
 * -----------------------
 * send the object over the connection...
 **/
void send_object_block(int sockfd, void * content, ssize_t length)
{
  ssize_t write_len;
  
  do{
    write_len = writen(sockfd, content, length);
    if (write_len == ERROR){
      if (DEBUG) fprintf(stderr,"Error transmitting data\n");
    }
  } while (write_len == 0);
  if (DEBUG) fprintf(stderr,"Data: %d bytes sent\n",length);
}

/**
 * send_bss_info()
 * ---------------
 * send the bss_info requested from the polling server
 **/
ssize_t send_bss_info(int fd)
{
  ssize_t total_size = 0;
  
  detailed_overview_t * overview = get_detailed_snapshot();
  bss_t * bss_ap = NULL;
  bss_node_t * node = NULL;
  tcptable_t * tcp_entry = NULL;
  tcpconn_t * tcp_conn = NULL;

  if ((overview == NULL) || (overview->bss_list_top == NULL)){
    return (ERROR);
  }
  
  /** send overview over network **/
  send_object_block(fd, (void *)overview, sizeof(detailed_overview_t));
  total_size += sizeof(detailed_overview_t);
  
  /** send bss_ap over network **/
  bss_ap = overview->bss_list_top;
  while (bss_ap != NULL){
    send_object_block(fd, (void *)bss_ap, sizeof(bss_t));
    if (DEBUG) fprintf(stderr,"bss_ap sent\n");
    total_size += sizeof(bss_t);
    node = bss_ap->addr_list_head;
    while (node != NULL){
      send_object_block(fd, (void *)node, sizeof(bss_node_t));
      if (DEBUG) fprintf(stderr,"bss_node sent\n");
      total_size += sizeof(bss_node_t);
      tcp_entry = node->tcpinfo_head;
      while (tcp_entry != NULL){
	send_object_block(fd, (void *)tcp_entry, sizeof(tcptable_t));
	if (DEBUG) fprintf(stderr,"tcp_entry sent\n");
	total_size += sizeof(tcptable_t);
	tcp_conn = tcp_entry->tcpconn_head;
	while (tcp_conn != NULL){
	  send_object_block(fd, (void *)tcp_conn, sizeof(tcpconn_t));
	  if (DEBUG) fprintf(stderr,"tcp_conn sent\n");
	  total_size += sizeof(tcpconn_t);
	  tcp_conn = tcp_conn->next;
	}
	tcp_entry = tcp_entry->next;
      }
      node = node->next;
    }
    bss_ap = bss_ap->next;
  }
  return (total_size);
}

int send_ids_info(int fd)
{
  return (-1);
}

//////////////////////////////////////////////////////////////////
// MAIN ROUTINE : SERVER
/////////////////////////////////////////////////////////////////

/**
 * server()
 * --------
 * the threaded routine that opens up a port (2222) and listens for
 * connections from polling server so that data may be transmitted.
 **/
void *server(void *var)
{
  int listenfd;
  int connfd;
  socklen_t len;
  struct sockaddr_in servaddr, clientaddr;

  unsigned char logmsg[MAX_MSG_SIZE];
  unsigned char tempmsg[100];
  char buff[MAX_BUFFER_SIZE];
  char cmd[MAX_CMD_SIZE];

  int result;
  int myset = 10; // socket option to reuse address
  int transmit = 0;

  struct SETTINGS *mySettings = (struct SETTINGS*)var;
  
  /* we want this server to be the only thing running */
  pthread_mutex_lock(&start_lock);

  if (( listenfd = socket(AF_INET, SOCK_STREAM, 0) ) < 0){
    perror ("Could not create server socket\n");
    exit(0);
  }

  /*
   * Set socket options to enable resueaddr.
   */
  if ((result = setsockopt (listenfd, SOL_SOCKET, SO_REUSEADDR, &myset, sizeof(myset))) < 0)
    {
      perror ("Could not set socket options");
      exit(0);
    }

  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(2222);
  
  if (bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0){
    perror ("Call to bind failed\n");
    exit(0);
  }

  pthread_cond_broadcast(&start_cond);
  pthread_mutex_unlock(&start_lock);

  if (mySettings->logging_mode == ENABLED){
    bzero(logmsg,sizeof(logmsg));  
    sprintf(logmsg,"** AirTraf Server Started,  Listening on port 2222 **\n");
    write_log(CONNECT_LOG,logmsg);    
  }
  
  if (listen(listenfd, SOMAXCONN) < 0){
    perror("Listen error\n");
    exit(0);
  }
  
  while(!sysexit){
    int port_num;
    int recvlen;

    len = sizeof(clientaddr);
    if ((connfd = accept(listenfd, (struct sockaddr *) &clientaddr, &len)) < 0){
      perror ("Accept error\n");
      exit(0);
    }
    port_num = ntohs(clientaddr.sin_port);

    if (mySettings->logging_mode == ENABLED){
      bzero(logmsg, sizeof(logmsg));
      bzero(tempmsg, sizeof(tempmsg));
      sprintf(tempmsg,"Connection from %s, port %d:: ",
	      inet_ntop(AF_INET, &clientaddr.sin_addr, buff, sizeof(buff)),port_num);
      strncat(logmsg, tempmsg, sizeof(tempmsg));
    }

    bzero(cmd, MAX_CMD_SIZE);
    fprintf(stderr,"receiving command... ");
    /** first receive command from polling server **/
    if ((recvlen = recv(connfd,cmd,sizeof(cmd),0))<=0){
      perror ("error in receive\n");
      return (NULL);
    }
    fprintf(stderr,"OK (%s)\n", cmd);

    /** see what potential structs have filtered... **/
    track_bad_data();
    
    /** process the request by poll server **/
    transmit = process_command(connfd, cmd);

    /** write this transaction to log **/
    if (mySettings->logging_mode == ENABLED){
      bzero(tempmsg,sizeof(tempmsg));
      sprintf(tempmsg,"(%d total bytes sent)\n",transmit);
      strncat(logmsg, tempmsg, sizeof(tempmsg));
      write_log(CONNECT_LOG,logmsg);	
    }

    /** reinitialize sniffer data structures **/
    pthread_mutex_lock(&engine_lock);
    free_detailed_scan();
    clear_potential_structs();
    initialize_detailed_scan();
    pthread_mutex_unlock(&engine_lock);
    
    /** close connection **/    
    if (close(connfd) < 0){
      perror ("Close error");
      exit(0);
    }
    if (mySettings->logging_mode == ENABLED){
      flush_log(CONNECT_LOG);
    }
  }
  if (get_engine_status()){
    stop_sniffer_engine(mySettings);
  }
  if (close(listenfd) < 0){
    perror ("Close error");
    exit(0);
  }
  
  pthread_exit(&thread);
}
