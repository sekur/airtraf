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
 **  db_utils.c
 **
 ****************************************************************
 **
 **   Copyright (c) 2001 all rights reserved.
 **
 **   Author: Peter K. Lee <pkl@duke.edu>
 **
 ***************************************************************/

/*=============================================================*/
/* System Includes */

#include <stdio.h>
#include <mysql.h>
#include <string.h>

#include "db_utils.h"
#include "definition.h"

/*=============================================================*/
/* Function Definitions */

MYSQL * db_connect(char *host_name, char *user_name, char *password, char *db_name,
		   unsigned int port_num, char *socket_name, unsigned int flags)
{
  MYSQL *conn; // pointer to connection handler

  conn = mysql_init(NULL); // initialize connection handler
  if (conn == NULL){
    print_error(NULL, "mysql_init() failed (probably out of memory)");
    return (NULL);
  }
  
#if defined(MYSQL_VERSION_ID) && MYSQL_VERSION_ID >= 32200 // 3.22 and up

  if (mysql_real_connect(conn, host_name, user_name, password, db_name,
			 port_num, socket_name, flags) == NULL){
    print_error(conn, "mysql_real_connect() failed");
    return (NULL);
  }
  
#else // pre 3.22

  if (mysql_real_connect(conn, host_name, user_name, password,
			 port_num, socket_name, flags) == NULL){
    print_error(conn, "mysql_real_connect() failed");
    return (NULL);
  }
  if (db_name != NULL){ // simulate effect of db_name parameter
    if (mysql_select_db(conn, db_name) != 0){
      print_error(conn, "mysql_select_db() failed");
      mysql_close(conn);
      return (NULL);
    }
  }
  
#endif
  
  return (conn); // connection successful
}

void db_disconnect(MYSQL *conn)
{
  mysql_close(conn);
}

void print_error(MYSQL *conn, char *message)
{
  fprintf(stderr, "%s\n", message);
  if (conn != NULL){
    fprintf(stderr, "Error %u (%s)\n",
	    mysql_errno(conn), mysql_error(conn)); 
  }
}

#if !defined(MYSQL_VERSION_ID) || MYSQL_VERSION_ID < 32224
#define mysql_field_count mysql_num_fields
#endif

int db_query(MYSQL *conn, char *query)
{
  long int affected_rows;
  
  if (mysql_query(conn,query) != 0){
    /* query failed */
    return QUERY_ERR;
  }
  /** return affected rows in case of query
      that does not return any rows **/
  if ((affected_rows = (long) mysql_affected_rows(conn)) != -1){
    return (affected_rows);
  }
  /** if it does return rows, then just say
      query went through okay **/
  else{
    return QUERY_OK;
  }
}

unsigned long db_get_result(MYSQL *conn, void ** vptr)
{
  static MYSQL_RES * tmp_res;
 
  tmp_res = mysql_store_result (conn);
  if (tmp_res == NULL){
    /* no result returned */
    if (mysql_field_count(conn) > 0){
      /* result was expected but error */
      print_error(conn, "problem processing result");
      return RESULT_ERR;
    }
    else{
      /* no result expected */
      return RESULT_NONE;
    }
  }
  else{
    /** return number of rows returned **/
    *vptr = (void *) tmp_res;
    return (unsigned long) mysql_num_rows(tmp_res);
  }
}

int db_get_row(MYSQL_RES *res_set, void ** vptr)
{
  MYSQL_ROW temp_row;

  temp_row = mysql_fetch_row(res_set);
  
  if (temp_row != NULL){
    *vptr = temp_row;
    return RESULT_OK;
  }
  else{
    return RESULT_ERR;
  }
  return 1;
}

int db_num_rows(MYSQL *conn)
{
  return mysql_field_count(conn);
}
