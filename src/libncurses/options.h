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

struct OPTIONS {
    unsigned int color:1,
                 logging:1, 
                 revlook:1, 
                 servnames: 1, 
                 promisc:1,
                 actmode:1,
                 mac:1,
                 dummy:9;
    unsigned int timeout;
    unsigned int logspan;
    unsigned int updrate;
    unsigned int closedint;
};

#define KBITS 0
#define KBYTES 1
#define DEFAULT_UPDATE_DELAY 50000     /* usec screen delay if update rate 0 */
#define HOSTMON_UPDATE_DELAY 100000
