/* ctc_dsa.h
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

#ifndef NO_DSA

#ifndef CTAO_CRYPT_DSA_H
#define CTAO_CRYPT_DSA_H

#include "ctc_types.h"
#include "ctc_integer.h"
#include "ctc_random.h"

#ifdef __cplusplus
    extern "C" {
#endif


enum {
    DSA_PUBLIC   = 0,
    DSA_PRIVATE  = 1
};

/* DSA */
typedef struct DsaKey {
    mp_int p, q, g, y, x;
    int type;                               /* public or private */
} DsaKey;


CYASSL_API void InitDsaKey(DsaKey* key);
CYASSL_API void FreeDsaKey(DsaKey* key);

CYASSL_API int DsaSign(const byte* digest, byte* out, DsaKey* key, RNG* rng);
CYASSL_API int DsaVerify(const byte* digest, const byte* sig, DsaKey* key,
                         int* answer);

CYASSL_API int DsaPublicKeyDecode(const byte* input, word32* inOutIdx, DsaKey*,
                                  word32);
CYASSL_API int DsaPrivateKeyDecode(const byte* input, word32* inOutIdx, DsaKey*,
                                   word32);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* CTAO_CRYPT_DSA_H */
#endif /* NO_DSA */

