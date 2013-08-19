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
 **  capture_engine.c
 **
 ****************************************************************
 **
 **   Copyright (c) 2001,2002 all rights reserved.
 **
 **   Author: Peter K. Lee <saint@elixar.net>
 **
 ***************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>

#include "definition.h"
#include "sniff_include.h"

pthread_t capture;
pthread_cond_t  capture_ready;
pthread_cond_t  capture_dead;
pthread_mutex_t capture_lock;

static int stop_capture;
static int capture_status = DISABLED;

FILE * capture_stream;
FILE * error_stream;

char atime[TIME_TARGET_MAX];


////////////////////////////////////////////////////////////////////////
//  Capture Init/Free Routines
////////////////////////////////////////////////////////////////////////

/**
 * init_capture()
 * --------------
 * initializes the capture file I/O stream, depending on the type of
 * capture being performed, creating/overwriting/reading
 * returns data status
 **/
int init_capture(struct SETTINGS *mySettings)
{
  FILE *fp;
  struct stat st;

  fp = fopen("error.log", "w");
  error_stream = fp;

  fprintf(error_stream, "capture mode=%d, status=%d\n",
	  mySettings->capture_mode,
	  mySettings->capture_status);
  fflush(error_stream);

  switch (mySettings->capture_mode){
  case CAPTURE_MODE_RECORD:
    if (mySettings->capture_overwrite){
      if ((fp = fopen(mySettings->capture_file, "wb")) == NULL){
	mySettings->capture_status = CAPTURE_STATUS_DATA_ERROR;
	return (0);
      }
    }
    else{
      if ((fp = fopen(mySettings->capture_file, "r")) != NULL){
	fclose(fp);
	mySettings->capture_status = CAPTURE_STATUS_DATA_EXISTS;
	return (0);
      }
      else{
	if ((fp = fopen(mySettings->capture_file, "wb")) == NULL){
	  mySettings->capture_status = CAPTURE_STATUS_DATA_ERROR;
	  return (0);
	}
      }
    }
    break;
  case CAPTURE_MODE_PLAYBACK:
    if ((fp = fopen(mySettings->capture_file, "rb")) == NULL){
      mySettings->capture_status = CAPTURE_STATUS_DATA_ERROR;
      return (0);
    }
    if (stat(mySettings->capture_file, &st)<0){
      mySettings->capture_status = CAPTURE_STATUS_DATA_ERROR;
      return (0);
    }
    mySettings->capture_size = st.st_size;
    break;
  default:
    mySettings->capture_status = CAPTURE_STATUS_DATA_ERROR;
    return (0);
  }
  capture_stream = fp;
  mySettings->capture_status = CAPTURE_STATUS_DATA_READY;
  return (1);
}

/**
 * free_capture()
 * ---------------
 * a quick routine to close the open file stream, as well as flush any
 * remaining data...
 **/
void free_capture()
{
  fflush(capture_stream);
  fclose(capture_stream);
}

///////////////////////////////////////////////////////////////////////////////
//  CAPTURE initialize/control (playback) functions
//////////////////////////////////////////////////////////////////////////////

#define CAPTURE_DEBUG  1
#define CAPTURE_DEBUG2 0
/**
 * capture_read_header()
 * -------------------------
 * when called, reads the initial header information, and allocates
 * the memory space, i.e. chosen_ap to point to the proper place.
 **/
int capture_read_header(struct SETTINGS *mySettings)
{
  __u16 total_read = 0;
  __u16 total_size = 0;
  __u16 len;
  struct access_point *ap;

  if (CAPTURE_DEBUG) fprintf(error_stream, "reading header...\n");
  fflush(error_stream);

  /** VERSION **/
  total_read += fread(&mySettings->capture_version, 1, sizeof(int), capture_stream);
  total_size += sizeof(int);
  if (CAPTURE_DEBUG2) fprintf(error_stream, "Header read in read=%lu, size=%lu\n",
			     (unsigned long)total_read, (unsigned long)total_size);
  fflush(error_stream);
  /** TIMESTAMP **/
  if (NULL == (mySettings->capture_timestamp = malloc(sizeof(time_t)))){
    if (CAPTURE_DEBUG) fprintf(error_stream, "malloc error!\n");
    fflush(error_stream);
    return (0);    
  }
  total_read += fread(mySettings->capture_timestamp, 1, sizeof(time_t), capture_stream);
  total_size += sizeof(time_t);
  if (CAPTURE_DEBUG2) fprintf(error_stream, "Header read in read=%lu, size=%lu\n",
			     (unsigned long)total_read, (unsigned long)total_size);
  fflush(error_stream);
  /** INTERVAL **/
  total_read += fread(&mySettings->capture_interval, 1, sizeof(float), capture_stream);
  total_size += sizeof(float);
  if (CAPTURE_DEBUG2) fprintf(error_stream, "Header read in read=%lu, size=%lu\n",
			     (unsigned long)total_read, (unsigned long)total_size);
  fflush(error_stream);
  /** CHOSEN ACCESS POINT **/
  if (NULL == (ap = malloc(sizeof(struct access_point)))){
    if (CAPTURE_DEBUG) fprintf(error_stream, "malloc error!\n");
    fflush(error_stream);
    return (0);
  }
  if (CAPTURE_DEBUG2) fprintf(error_stream, "Header read in read=%lu, size=%lu\n",
			     (unsigned long)total_read, (unsigned long)total_size);
  fflush(error_stream);
  mySettings->chosen_ap = ap;
  total_read += fread(ap, 1, sizeof(struct access_point), capture_stream);
  total_size += sizeof(struct access_point);
  if (CAPTURE_DEBUG2) fprintf(error_stream, "Header read in read=%lu, size=%lu\n",
			     (unsigned long)total_read, (unsigned long)total_size);
  fflush(error_stream);
  /** LENGTH **/
  total_read += fread(&len, 1, sizeof(__u16), capture_stream);
  if (total_size != len) return (0);
  total_size += sizeof(__u16);
  if (CAPTURE_DEBUG2) fprintf(error_stream, "Header read in read=%lu, size=%lu\n",
			     (unsigned long)total_read, (unsigned long)total_size);
  fflush(error_stream);
  if (total_read != total_size){
    return (0);
  }
  mySettings->capture_duration = 0;
  return (1);
}

/**
 * capture_playback_forward()
 * -------------------------------
 * reads in one step in the forward direction of the capture file
 **/
int capture_playback_forward(struct SETTINGS *mySettings)
{
  __u32 total_read = 0;
  __u32 total_size = 0;
  __u32 len;

  int node_count, tcp_entry_count, tcp_conn_count;
  
  /** overview already in memory, just get the memory address **/
  detailed_overview_t * overview = get_detailed_snapshot();
  bss_t * bss_ap = NULL;
  bss_node_t * node = NULL;
  tcptable_t * tcp_entry = NULL;
  tcpconn_t * tcp_conn = NULL;

  /** read sequence # into file (starts with 1)**/
  total_read += fread(&mySettings->capture_seq, 1, sizeof(__u32), capture_stream);
  total_size += sizeof(__u32);
  
  /** read overview into file **/
  total_read += fread(overview, 1, sizeof(detailed_overview_t), capture_stream);
  total_size += sizeof(detailed_overview_t);
  if (total_read != total_size){
    if (CAPTURE_DEBUG) fprintf(error_stream, "overview size doesn't match! read=%lu, size=%lu\n",
			       (unsigned long)total_read, (unsigned long)total_size);
    fflush(error_stream);
    return (0);
  }
  
  /** read bss_ap into file **/
  if (NULL == (bss_ap = malloc(sizeof(bss_t)))){
    if (CAPTURE_DEBUG) fprintf(error_stream, "malloc error!\n");
    fflush(error_stream);
    return (0);   
  }
  overview->bss_list_top = bss_ap;
  total_read += fread(bss_ap, 1, sizeof(bss_t), capture_stream);
  total_size += sizeof(bss_t);
  if (total_read != total_size){
    if (CAPTURE_DEBUG) fprintf(error_stream, "bss_ap size doesn't match! read=%lu, size=%lu\n",
			       (unsigned long)total_read, (unsigned long)total_size);
    fflush(error_stream);
    return (0);
  }

  if (NULL == (node = malloc(sizeof(bss_node_t)))){
    if (CAPTURE_DEBUG) fprintf(error_stream, "malloc error!\n");
    fflush(error_stream);
    return (0);   
  } 
  bss_ap->addr_list_head = node;
  for (node_count = 0; node_count < bss_ap->num; node_count++){
    /** read node into file **/
    total_read += fread(node, 1, sizeof(bss_node_t), capture_stream);
    total_size += sizeof(bss_node_t);
    if (total_read != total_size){
      if (CAPTURE_DEBUG) fprintf(error_stream, "node size doesn't match! read=%lu, size=%lu\n",
				 (unsigned long)total_read, (unsigned long)total_size);
      fflush(error_stream);
      return (0);
    }
    if (node->tcp_connections == 0){
      node->tcpinfo_head = NULL;
    }
    else{
      if (NULL == (tcp_entry = malloc(sizeof(tcptable_t)))){
	if (CAPTURE_DEBUG) fprintf(error_stream, "malloc error!\n");
	fflush(error_stream);
      }
      node->tcpinfo_head = tcp_entry;
      for (tcp_entry_count = 0; tcp_entry_count < node->tcp_connections; tcp_entry_count++){
	/** read tcp_entry into file **/
	total_read += fread(tcp_entry, 1, sizeof(tcptable_t),  capture_stream);
	total_size += sizeof(tcptable_t);
	if (total_read != total_size){
	  if (CAPTURE_DEBUG) fprintf(error_stream, "tcp_entry size doesn't match! read=%lu, size=%lu\n",
				     (unsigned long)total_read, (unsigned long)total_size);
	  fflush(error_stream);
	  return (0);
	}
	if (tcp_entry->num_connected == 0){
	  tcp_entry->tcpconn_head = NULL;
	}
	else{
	  if (NULL == (tcp_conn = malloc(sizeof(tcpconn_t)))){
	    if (CAPTURE_DEBUG) fprintf(error_stream, "malloc error!\n");
	    fflush(error_stream);
	  }
	  tcp_entry->tcpconn_head = tcp_conn;
	  for (tcp_conn_count = 0; tcp_conn_count < tcp_entry->num_connected; tcp_conn_count++){
	    /** read tcp_conn into file **/
	    total_read += fread(tcp_conn, 1, sizeof(tcpconn_t), capture_stream);
	    total_size += sizeof(tcpconn_t);
	    if (total_read != total_size){
	      if (CAPTURE_DEBUG) fprintf(error_stream, "tcp_conn size doesn't match! read=%lu, size=%lu\n",
					 (unsigned long)total_read, (unsigned long)total_size);
	      fflush(error_stream);
	      return (0);
	    }
	    if (tcp_conn_count == (tcp_entry->num_connected -1)){
	      tcp_conn->next = NULL;
	      continue;
	    }
	    if (NULL == (tcp_conn->next = malloc(sizeof(tcpconn_t)))){
	      if (CAPTURE_DEBUG) fprintf(error_stream, "malloc error!\n");
	      fflush(error_stream);
	    }
	    tcp_conn = tcp_conn->next;
	  }
	}
	if (tcp_entry_count == (node->tcp_connections - 1)){
	  tcp_entry->next = NULL;
	  continue;
	}
	if (NULL == (tcp_entry->next = malloc(sizeof(tcptable_t)))){
	  if (CAPTURE_DEBUG) fprintf(error_stream, "malloc error!\n");
	  fflush(error_stream);
	}      
	tcp_entry = tcp_entry->next;
      }
    }
    if (node_count == (bss_ap->num -1)){
      node->next = NULL;
      continue;
    }
    if (NULL == (node->next = malloc(sizeof(bss_node_t)))){
      if (CAPTURE_DEBUG) fprintf(error_stream, "malloc error!\n");
      fflush(error_stream);
    }
    node = node->next;
  }
  bss_ap->next = NULL;
  /** read total_size into file (for reverse) **/
  total_read += fread(&len, 1, sizeof(__u32), capture_stream);
  total_size += sizeof(__u32);
  
  if (total_read != total_size){
    if (CAPTURE_DEBUG) fprintf(error_stream, "TOTAL size doesn't match! read=%lu, size=%lu\n",
			       (unsigned long)total_read, (unsigned long)total_size);
    fflush(error_stream);
    return (0);
  }
  if (CAPTURE_DEBUG2) fprintf(error_stream, "Forward One, read=%lu, size=%lu\n",
			     (unsigned long)total_read, (unsigned long)total_size);
  fflush(error_stream);
  mySettings->capture_duration += mySettings->capture_interval;
  return (1);
}

/**
 * capture_playback_rewind()
 * -------------------------------
 * goes back one step in the reverse direction of the capture file
 **/
int capture_playback_rewind(struct SETTINGS *mySettings)
{
  __u32 total_read = 0;
  __u32 len;
  int fseek_status;

  if (mySettings->capture_duration < mySettings->capture_interval){
    return (0);
  }

  fseek_status = fseek(capture_stream, (long int) (0 - sizeof(__u32)), SEEK_CUR);
  // error check for fseek
  total_read = fread(&len, 1, sizeof(__u32), capture_stream);
  if (total_read != sizeof(__u32)){
    return (0);
  }

  fseek_status = fseek(capture_stream, (long int) (0 - len), SEEK_CUR);
  // error check for fseek
  mySettings->capture_duration -= mySettings->capture_interval;
  /** now we're back one snapshot **/
  return (1);
}

/**
 * capture_playback_beginning()
 * ----------------------------------
 * rewind the whole thing to beginning...
 **/
int capture_playback_beginning(struct SETTINGS *mySettings)
{
  rewind(capture_stream);
  if (!capture_read_header(mySettings)){
    return (0);
  }
  capture_playback_forward(mySettings);
  return (1);
}

/////////////////////////////////////////////////////////////////////////////////////////////////
//  Capture RECORD related functions
/////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * capture_write_header()
 * --------------------------
 * when called, writes the initial header information into the capture
 * file, including struct access point information regarding the
 * selected access point for monitoring, as well as some initial
 * settings required for proper parsing of the capture file at later
 * time.
 **/
int capture_write_header(struct SETTINGS *mySettings)
{
  __u16 total_write = 0;
  __u16 total_size = 0;
  static time_t curr;

  /** VERSION **/
  total_write += fwrite(&mySettings->capture_version, 1, sizeof(int), capture_stream);
  total_size += sizeof(int);
  /** TIMESTAMP **/
  curr = time((time_t*)NULL);
  mySettings->capture_timestamp = &curr;
  total_write += fwrite(mySettings->capture_timestamp, 1, sizeof(time_t), capture_stream);
  total_size += sizeof(time_t);
  /** INTERVAL **/
  total_write += fwrite(&mySettings->capture_interval, 1, sizeof(float), capture_stream);
  total_size += sizeof(float);
  /** CHOSEN ACCESS POINT **/
  total_write += fwrite(mySettings->chosen_ap, 1, sizeof(struct access_point), capture_stream);
  total_size += sizeof(struct access_point);
  /** LENGTH **/
  total_write += fwrite(&total_size, 1, sizeof(__u16), capture_stream);
  total_size += sizeof(__u16);
  
  if (total_write != total_size){
    return (0);
  }
  mySettings->capture_size = total_size;
  fflush(capture_stream);
  return (1);
}

/**
 * capture_write_snapshot()
 * ----------------------------
 * when called, takes the snapshot of the memory data structures, and
 * writes data into the specified file.
 **/
void capture_write_snapshot(struct SETTINGS *mySettings, __u32 * seq_id)
{
  __u32 total_write = 0;
  __u32 total_size = 0;
  
  detailed_overview_t * overview = get_detailed_snapshot();
  bss_t * bss_ap = NULL;
  bss_node_t * node = NULL;
  tcptable_t * tcp_entry = NULL;
  tcpconn_t * tcp_conn = NULL;
  
  if ((overview == NULL) || (overview->bss_list_top == NULL)){
    if (CAPTURE_DEBUG) fprintf(error_stream, "error!!!\n");
    fflush(error_stream);
    return;
  }
  /** write sequence # into file (starts with 1)**/
  *seq_id = *seq_id + 1;
  total_write += fwrite(seq_id, 1, sizeof(__u32), capture_stream);
  total_size += sizeof(__u32);
  
  /** write overview into file **/
  total_write += fwrite((void *)overview, 1, sizeof(detailed_overview_t), capture_stream);
  total_size += sizeof(detailed_overview_t);
  if (total_write != total_size){
    if (CAPTURE_DEBUG) fprintf(error_stream, "overview size doesn't match! write=%lu, size=%lu\n",
			       (unsigned long)total_write, (unsigned long)total_size);
    fflush(error_stream);
    return;
  }

  /** write bss_ap into file **/
  bss_ap = overview->bss_list_top;
  total_write += fwrite((void *)bss_ap, 1, sizeof(bss_t), capture_stream);
  total_size += sizeof(bss_t);
  if (total_write != total_size){
    if (CAPTURE_DEBUG) fprintf(error_stream, "bss_ap size doesn't match! write=%lu, size=%lu\n",
			       (unsigned long)total_write, (unsigned long)total_size);
    fflush(error_stream);
    return;
  }
  
  node = bss_ap->addr_list_head;
  while (node != NULL){
    /** write node into file **/
    total_write += fwrite((void *)node, 1, sizeof(bss_node_t), capture_stream);
    total_size += sizeof(bss_node_t);
    if (total_write != total_size){
      if (CAPTURE_DEBUG) fprintf(error_stream, "node size doesn't match! write=%lu, size=%lu\n",
				 (unsigned long)total_write, (unsigned long)total_size);
      fflush(error_stream);
      return;
    }
    tcp_entry = node->tcpinfo_head;
    while (tcp_entry != NULL){
      /** write tcp_entry into file **/
      total_write += fwrite(tcp_entry, 1, sizeof(tcptable_t),  capture_stream);
      total_size += sizeof(tcptable_t);
      if (total_write != total_size){
	if (CAPTURE_DEBUG) fprintf(error_stream, "tcp_entry size doesn't match! write=%lu, size=%lu\n",
				   (unsigned long)total_write, (unsigned long)total_size);
	fflush(error_stream);
	return;
      }
      tcp_conn = tcp_entry->tcpconn_head;
      while (tcp_conn != NULL){
	/** write tcp_conn into file **/
	total_write += fwrite(tcp_conn, 1, sizeof(tcpconn_t), capture_stream);
	total_size += sizeof(tcpconn_t);
	if (total_write != total_size){
	  if (CAPTURE_DEBUG) fprintf(error_stream, "tcp_conn size doesn't match! write=%lu, size=%lu\n",
				     (unsigned long)total_write, (unsigned long)total_size);
	  fflush(error_stream);
	  return;
	}
	tcp_conn = tcp_conn->next;
      }
      tcp_entry = tcp_entry->next;
    }
    node = node->next;
  }
  /** write total_size into file (for reverse) **/
  total_size += sizeof(__u32);
  total_write += fwrite(&total_size, 1, sizeof(__u32), capture_stream);

  if (total_write != total_size){
    if (CAPTURE_DEBUG) fprintf(error_stream, "TOTAL size doesn't match! write=%lu, size=%lu\n",
			       (unsigned long)total_write, (unsigned long)total_size);
    fflush(error_stream);
    return;
  }
  
  mySettings->capture_size += total_size;
  fflush(capture_stream);
}

/**
 * capture_engine() <thread>
 * ----------------------
 * the main engine that loops forever(until stopped) grabbing
 * snapshots of the current memory data structures, either reading
 * from file and updating the memory data structures, or writing to
 * file the current snapshots of memory data structures
 **/
void * capture_engine(void *var)
{
  struct SETTINGS *mySettings;
  struct timeval tv_old;
  struct timeval tv_new;
  unsigned long period = 50000;  // for 50ms
  unsigned long udelay = 10000;  // for 1ms
  __u32 seq_id = 0;
  float t_diff;

  pthread_mutex_lock(&capture_lock);

  mySettings = (struct SETTINGS*)var;
  gettimeofday(&tv_new, NULL);
  tv_old = tv_new;
  capture_status = ENABLED;
  pthread_cond_broadcast(&capture_ready);
  pthread_mutex_unlock(&capture_lock);
  if (CAPTURE_DEBUG2) fprintf(error_stream, "inside engine thread\n");
  fflush(error_stream);

  while (!stop_capture){
    gettimeofday(&tv_new, NULL);
    t_diff = get_time_diff(&tv_new, &tv_old);
    if (CAPTURE_DEBUG2) fprintf(error_stream, "t_diff = %6.5f \n", t_diff);
    fflush(error_stream);

    /** write snapshot into file **/
    switch (mySettings->capture_mode){
    case CAPTURE_MODE_RECORD:
      if (t_diff > mySettings->capture_interval){
	mySettings->capture_duration += mySettings->capture_interval;
	pthread_mutex_lock(&capture_lock);
	capture_write_snapshot(mySettings, &seq_id);
	pthread_mutex_unlock(&capture_lock);
	tv_old = tv_new;
      }
      usleep(period);
      break;
    case CAPTURE_MODE_PLAYBACK:
      switch(mySettings->capture_command){
      case CAPTURE_PB_FF:
	  pthread_mutex_lock(&capture_lock);
	  if (!capture_playback_forward(mySettings)){
	    stop_capture = 1;
	  }
	  pthread_mutex_unlock(&capture_lock);
	  tv_old = tv_new;
	  usleep(udelay);
	break;
      case CAPTURE_PB_RR:
	  pthread_mutex_lock(&capture_lock);
	  if (!capture_playback_rewind(mySettings)){
	    stop_capture = 1;
	  }
	  if (!capture_playback_rewind(mySettings)){
	    stop_capture = 1;
	  }
	  if (!capture_playback_forward(mySettings)){
	    stop_capture = 1;
	  }	  
	  pthread_mutex_unlock(&capture_lock);
	  tv_old = tv_new;
	  usleep(udelay);
	break;
      case CAPTURE_PB_PLAY:
	if (CAPTURE_DEBUG2) fprintf(error_stream, "doing playback... ");
	fflush(error_stream);
	if (t_diff > mySettings->capture_interval){
	  pthread_mutex_lock(&capture_lock);
	  if (!capture_playback_forward(mySettings)){
	    if (CAPTURE_DEBUG2) fprintf(error_stream, "failed!\n");
	    fflush(error_stream);
	    stop_capture = 1;
	  }
	  if (CAPTURE_DEBUG2) fprintf(error_stream, "ok!\n");
	  fflush(error_stream);
	  
	  pthread_mutex_unlock(&capture_lock);
	  tv_old = tv_new;
	}
	usleep(period);
	break;
      default:
	stop_capture = 1;
	break;
      }
      break;
    default:
      stop_capture = 1;
      break;
    }
  }
  if (CAPTURE_DEBUG) fprintf(error_stream,"capture_engine(): trying to exit...\n");
  fflush(error_stream);
  
  pthread_mutex_lock(&capture_lock);
  capture_status = DISABLED;  
  pthread_cond_broadcast(&capture_dead);
  pthread_mutex_unlock(&capture_lock);

  pthread_exit(&capture);
}

////////////////////////////////////////////////////////////
// PUBLIC: interface calls
////////////////////////////////////////////////////////////

int start_capture_engine(struct SETTINGS *mySettings)
{
  if (CAPTURE_DEBUG) fprintf(error_stream, "starting capture engine... mode=%d, status=%d\n",
			     mySettings->capture_mode,
			     mySettings->capture_status);
  fflush(error_stream);

  stop_capture = DISABLED;

  switch (mySettings->capture_mode){
  case CAPTURE_MODE_RECORD:
    /** first dumps in the header image into the file for later
	identification needs **/
    if (!capture_write_header(mySettings)){
      return (0);
    }
    /** lock stuff for the engine **/
    pthread_cond_init(&capture_ready, NULL);
    pthread_cond_init(&capture_dead, NULL);
    pthread_mutex_init(&capture_lock, NULL);
    pthread_mutex_lock(&capture_lock);
    
    /** launch the engine in a separate thread! **/
    pthread_create(&capture, NULL, capture_engine, (void *)mySettings);
    pthread_cond_wait(&capture_ready, &capture_lock);
    pthread_mutex_unlock(&capture_lock);
    break;
  case CAPTURE_MODE_PLAYBACK:
    switch (mySettings->capture_status){
    case CAPTURE_STATUS_DATA_READY:
      /** read the header of the file, see if its legit file **/
      if (!capture_read_header(mySettings)){
	return (0);
      }
      capture_playback_forward(mySettings);
      break;
    case CAPTURE_STATUS_ACTIVE:
    /** lock stuff for the engine **/
    pthread_cond_init(&capture_ready, NULL);
    pthread_cond_init(&capture_dead, NULL);
    pthread_mutex_init(&capture_lock, NULL);
    pthread_mutex_lock(&capture_lock);
    if (CAPTURE_DEBUG) fprintf(error_stream, "command=%d\n",
			       mySettings->capture_command);
    fflush(error_stream);
    /** launch the engine in a separate thread! **/
    pthread_create(&capture, NULL, capture_engine, (void *)mySettings);
    pthread_cond_wait(&capture_ready, &capture_lock);
    pthread_mutex_unlock(&capture_lock);
    break;
    default:
      return (0);
    }
    break;
  }
  return (1);
}

/**
 * ask_stop_capture_engine()
 * --------------------
 * a handy function call to stop the capture engine from collecting
 * data...
 **/
void ask_stop_capture_engine()
{
  stop_capture = ENABLED;
}

/**
 * stop_capture_engine()
 * ----------------------
 * function to FORCE capture engine to stop, or better yet, to WAIT
 * until the thing's dead.
 **/
void stop_capture_engine(struct SETTINGS *mySettings)
{
  pthread_mutex_lock(&capture_lock);
  stop_capture = ENABLED;
  pthread_cond_wait(&capture_dead, &capture_lock);
  pthread_mutex_unlock(&capture_lock);
  if (CAPTURE_DEBUG) fprintf(error_stream, "capture engine stopped\n");	
}

/**
 * get_capture_status()
 * -------------------
 * simple function that returns the runtime status of the engine.
 **/
int get_capture_status()
{
  return (capture_status);
}
