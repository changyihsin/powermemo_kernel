/*
 *      powermemo.h
 *      
 *      Copyright 2010 BRASS LAB - All rights reserved
 * 			National Chiao Tung University, Hsinchu,TAIWAN R.O.C.
 * 			Developed by Ilter Suat <iltersuat@gmail.com>
 * 			    
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *      
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *      
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *      MA 02110-1301, USA.
 */

#ifndef _LINUX_POWERMEMO_H
#define _LINUX_POWERMEMO_H

#include <linux/time.h>

/* powermemo_avail is set to 1 when the powermemo module is inserted,
 * and it is set to 0 when removed 
 */
extern int powermemo_avail;  /* 1: available  0: not available */


typedef struct  {
  /*processor*/
  int (*process_slice_entry)(int pid,char *comm); /* comm[16] stores the process name */
  int (*process_slice_exit)(int pid);
	int (*markerfunc_entry)(int pid, int fid, char *funcname); /* These two are for functional level profiling */
	int (*markerfunc_exit)(int pid, int fid, char *funcname);
	int (*xmit_entry)(int pid,int bitrate, unsigned long packet_size);
	int (*rcv_entry)(int pid,int bitrate, unsigned long packet_size);
} powermemo_functions;


extern powermemo_functions powermemofuncs;

#endif
