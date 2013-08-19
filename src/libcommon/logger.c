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
 **  logger.c
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
#include <time.h>
#include <string.h>

#include "definition.h"
#include "utility.h"

FILE * connect_log;
FILE * error_log;

unsigned char logmsg[MAX_MSG_SIZE];
char atime[TIME_TARGET_MAX];


/*=============================================================*/
/* Function Prototypess */

int write_into_log(int type, char * text);

/*=============================================================*/
/* Function Definitions */

int init_log(int type, char* filename)
{
  FILE *fp;

  if ((fp = fopen(filename,"a")) == NULL){
    fprintf(stderr,"file %s not found, creating new file\n",filename);
    if ((fp = fopen(filename,"w")) == NULL){
      fprintf(stderr,"file %s could not be created!\n",filename);
      exit(0);
    }
  }

  switch (type)
    {
    case CONNECT_LOG: connect_log = fp;
      break;
    case ERROR_LOG: error_log = fp;
      break;
    default: // do nothing?
      break;
    }
  return 1;
}

int write_log(int type, char * text)
{
  genatime(time((time_t *) NULL), atime);
  bzero(logmsg,sizeof(logmsg));
  sprintf(logmsg,"%s]   %s",atime,text);
  
  return write_into_log(type,logmsg);
}

int write_into_log(int type, char * text)
{
  int status = -1;

  switch (type)
    {
    case CONNECT_LOG: status = fprintf(connect_log, text);
      break;
    case ERROR_LOG: status = fprintf(error_log, text);
      break;
    default: // do nothing?
      break;
    }

  if (status < 0){
    fprintf(error_log, "Could not write to logfile!\n");
    return (-1);
  }
  return (1);
}

void flush_log(int type)
{
  switch (type)
    {
    case CONNECT_LOG: fflush(connect_log);
      break;
    case ERROR_LOG: fflush(error_log);
      break;
    default: // do nothing?
      break;
    }
}

void close_log(int type)
{
    switch (type)
    {
    case CONNECT_LOG: fclose(connect_log);
      break;
    case ERROR_LOG: fclose(error_log);
      break;
    default: // do nothing?
      break;
    }
}
