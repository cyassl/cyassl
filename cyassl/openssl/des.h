/* des.h
 *
 * Copyright (C) 2011 Sawtooth Consulting Ltd.
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


/*  des.h defines mini des openssl compatibility layer 
 *
 */



#ifndef CYASSL_DES_H_
#define CYASSL_DES_H_

#ifdef YASSL_PREFIX
#include "prefix_des.h"
#endif


#ifdef __cplusplus
    extern "C" {
#endif

typedef unsigned char DES_cblock[8];
typedef /* const */ DES_cblock const_DES_cblock;
typedef DES_cblock DES_key_schedule;


enum {
    DES_ENCRYPT = 1,
    DES_DECRYPT = 0
};


CYASSL_API void DES_set_key_unchecked(const_DES_cblock*, DES_key_schedule*);
CYASSL_API int  DES_key_sched(const_DES_cblock* key,DES_key_schedule* schedule);
CYASSL_API void DES_cbc_encrypt(const unsigned char* input,
                     unsigned char* output, long length,
                     DES_key_schedule* schedule, DES_cblock* ivec, int enc);
CYASSL_API void DES_ncbc_encrypt(const unsigned char* input,
                      unsigned char* output, long length,
                      DES_key_schedule* schedule, DES_cblock* ivec, int enc);

CYASSL_API void DES_set_odd_parity(DES_cblock*);
CYASSL_API void DES_ecb_encrypt(DES_cblock*, DES_cblock*, DES_key_schedule*,
                                int);

#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* CYASSL_DES_H_ */
