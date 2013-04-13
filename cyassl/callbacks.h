/* callbacks.h
 *
 * Copyright (C) 2013 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#ifndef CYASSL_CALLBACKS_H
#define CYASSL_CALLBACKS_H

#include <sys/time.h>

#ifdef __cplusplus
    extern "C" {
#endif


enum { /* CALLBACK CONTSTANTS */
    MAX_PACKETNAME_SZ     =  24,
    MAX_CIPHERNAME_SZ     =  24,
    MAX_TIMEOUT_NAME_SZ   =  24,       
    MAX_PACKETS_HANDSHAKE =  14,       /* 12 for client auth plus 2 alerts */
    MAX_VALUE_SZ          = 128,       /* all handshake packets but Cert should
                                          fit here  */
};


typedef struct handShakeInfo_st {
    char   cipherName[MAX_CIPHERNAME_SZ + 1];    /* negotiated cipher */
    char   packetNames[MAX_PACKETS_HANDSHAKE][MAX_PACKETNAME_SZ + 1];
                                                 /* SSL packet names  */ 
    int    numberPackets;                        /* actual # of packets */
    int    negotiationError;                     /* cipher/parameter err */
} HandShakeInfo;


typedef struct timeval Timeval;


typedef struct packetInfo_st {
    char           packetName[MAX_PACKETNAME_SZ + 1]; /* SSL packet name */
    Timeval        timestamp;                       /* when it occured    */
    unsigned char  value[MAX_VALUE_SZ];             /* if fits, it's here */ 
    unsigned char* bufferValue;                     /* otherwise here (non 0) */
    int            valueSz;                         /* sz of value or buffer */
} PacketInfo;


typedef struct timeoutInfo_st {
    char       timeoutName[MAX_TIMEOUT_NAME_SZ + 1]; /* timeout Name */
    int        flags;                              /* for future use */
    int        numberPackets;                      /* actual # of packets */
    PacketInfo packets[MAX_PACKETS_HANDSHAKE];     /* list of all packets  */
    Timeval    timeoutValue;                       /* timer that caused it */
} TimeoutInfo;



#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* CYASSL_CALLBACKS_H */

