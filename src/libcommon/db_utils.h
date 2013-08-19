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
 **  db_utils.h
 **
 ****************************************************************
 **
 **   Copyright (c) 2001 all rights reserved.
 **
 **   Author: Peter K. Lee <pkl@duke.edu>
 **
 ***************************************************************/

#ifndef __db_utils_H__
#define __db_utils_H__

#include <mysql.h>

#define QUERY_ERR    -1
#define QUERY_OK      1
#define RESULT_ERR   -1
#define RESULT_NONE   0
#define RESULT_OK     1

MYSQL * db_connect(char *host_name, char *user_name, char *password, char *db_name,
		   unsigned int port_num, char *socket_name, unsigned int flags);

void    db_disconnect(MYSQL *);

int     db_query(MYSQL *conn, char *query);

unsigned long db_get_result(MYSQL *conn, void **);

int     db_get_row(MYSQL_RES *res_set, void **);

int     db_num_rows(MYSQL *conn);

void    print_error(MYSQL *, char *message);

#endif
