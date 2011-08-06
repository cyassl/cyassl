/* ctc_hmac.h
 *
 * Copyright (C) 2006-2011 Sawtooth Consulting Ltd.
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

#ifndef NO_HMAC

#ifndef CTAO_CRYPT_HMAC_H
#define CTAO_CRYPT_HMAC_H

#include "ctc_md5.h"
#include "ctc_sha.h"

#ifndef NO_SHA256
    #include "ctc_sha256.h"
#endif

#ifdef __cplusplus
    extern "C" {
#endif



enum {
    IPAD    = 0x36,
    OPAD    = 0x5C,
#ifndef NO_SHA256
    INNER_HASH_SIZE = SHA256_DIGEST_SIZE,
#else
    INNER_HASH_SIZE = SHA_DIGEST_SIZE,
    SHA256          = 2,                     /* hash type unique */
#endif
    HMAC_BLOCK_SIZE = MD5_BLOCK_SIZE
};


/* hash union */
typedef union {
    Md5 md5;
    Sha sha;
    #ifndef NO_SHA256
        Sha256 sha256;
    #endif
} Hash;

/* Hmac digest */
typedef struct Hmac {
    Hash    hash;
    word32  ipad[HMAC_BLOCK_SIZE  / sizeof(word32)];  /* same block size all*/
    word32  opad[HMAC_BLOCK_SIZE  / sizeof(word32)];
    word32  innerHash[INNER_HASH_SIZE / sizeof(word32)]; /* max size */
    byte    macType;                                     /* md5 sha or sha256 */
    byte    innerHashKeyed;                              /* keyed flag */
} Hmac;


/* does init */
CYASSL_API void HmacSetKey(Hmac*, int type, const byte* key, word32 keySz);
CYASSL_API void HmacUpdate(Hmac*, const byte*, word32);
CYASSL_API void HmacFinal(Hmac*, byte*);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* CTAO_CRYPT_HMAC_H */

#endif /* NO_HMAC */

