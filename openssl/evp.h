/* evp.h
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


/*  evp.h defines mini evp openssl compatibility layer 
 *
 */



#ifndef CYASSL_EVP_H_
#define CYASSL_EVP_H_

#ifdef YASSL_PREFIX
#include "prefix_evp.h"
#endif

#include "md5.h"
#include "sha.h"


#ifdef __cplusplus
    extern "C" {
#endif

typedef char EVP_MD;
typedef char EVP_CIPHER;

CYASSL_API const EVP_MD* EVP_md5(void);
CYASSL_API const EVP_MD* EVP_sha1(void);


typedef union {
    MD5_CTX md5;
    SHA_CTX sha;
} Hasher;


typedef struct EVP_MD_CTX {
    unsigned char macType;               /* md5 or sha for now */
    Hasher        hash;
} EVP_MD_CTX;


CYASSL_API void EVP_MD_CTX_init(EVP_MD_CTX* ctx);
CYASSL_API int  EVP_MD_CTX_cleanup(EVP_MD_CTX* ctx);

CYASSL_API int EVP_DigestInit(EVP_MD_CTX* ctx, const EVP_MD* type);
CYASSL_API int EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* data,
                                unsigned long sz);
CYASSL_API int EVP_DigestFinal(EVP_MD_CTX* ctx, unsigned char* md,
                               unsigned int* s);
CYASSL_API int EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md,
                                  unsigned int* s);
CYASSL_API int EVP_BytesToKey(const EVP_CIPHER*, const EVP_MD*,
                              const unsigned char*, const unsigned char*,
                              int, int, unsigned char*, unsigned char*);

#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* CYASSL_EVP_H_ */
