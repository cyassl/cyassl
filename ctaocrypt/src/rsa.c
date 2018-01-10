/* rsa.c
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <cyassl/ctaocrypt/settings.h>

#ifndef NO_RSA

#ifdef HAVE_FIPS
    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
    #define FIPS_NO_WRAPPERS

	#ifdef USE_WINDOWS_API
		#pragma code_seg(".fipsA$e")
		#pragma const_seg(".fipsB$e")
	#endif
#endif

#include <cyassl/ctaocrypt/rsa.h>
#include <cyassl/ctaocrypt/random.h>
#include <cyassl/ctaocrypt/error-crypt.h>
#include <cyassl/ctaocrypt/logging.h>

#ifdef NO_INLINE
    #include <cyassl/ctaocrypt/misc.h>
#else
    #include <ctaocrypt/src/misc.c>
#endif

#ifdef SHOW_GEN
    #ifdef FREESCALE_MQX
        #include <fio.h>
    #else
        #include <stdio.h>
    #endif
#endif

#ifdef HAVE_CAVIUM
    static int  InitCaviumRsaKey(RsaKey* key, void* heap);
    static int  FreeCaviumRsaKey(RsaKey* key);
    static int  CaviumRsaPublicEncrypt(const byte* in, word32 inLen, byte* out,
                                       word32 outLen, RsaKey* key);
    static int  CaviumRsaPrivateDecrypt(const byte* in, word32 inLen, byte* out,
                                        word32 outLen, RsaKey* key);
    static int  CaviumRsaSSL_Sign(const byte* in, word32 inLen, byte* out,
                                  word32 outLen, RsaKey* key);
    static int  CaviumRsaSSL_Verify(const byte* in, word32 inLen, byte* out,
                                    word32 outLen, RsaKey* key);
#endif

enum {
    RSA_PUBLIC_ENCRYPT  = 0,
    RSA_PUBLIC_DECRYPT  = 1,
    RSA_PRIVATE_ENCRYPT = 2,
    RSA_PRIVATE_DECRYPT = 3,

    RSA_BLOCK_TYPE_1 = 1,
    RSA_BLOCK_TYPE_2 = 2,

    RSA_MIN_SIZE = 512,
    RSA_MAX_SIZE = 4096,

    RSA_MIN_PAD_SZ   = 11      /* seperator + 0 + pad value + 8 pads */
};


int InitRsaKey(RsaKey* key, void* heap)
{
#ifdef HAVE_CAVIUM
    if (key->magic == CYASSL_RSA_CAVIUM_MAGIC)
        return InitCaviumRsaKey(key, heap);
#endif

    key->type = -1;  /* haven't decided yet */
    key->heap = heap;

/* TomsFastMath doesn't use memory allocation */
#ifndef USE_FAST_MATH
    key->n.dp = key->e.dp = 0;  /* public  alloc parts */

    key->d.dp = key->p.dp  = 0;  /* private alloc parts */
    key->q.dp = key->dP.dp = 0;  
    key->u.dp = key->dQ.dp = 0;
#endif

    return 0;
}


int FreeRsaKey(RsaKey* key)
{
    (void)key;

#ifdef HAVE_CAVIUM
    if (key->magic == CYASSL_RSA_CAVIUM_MAGIC)
        return FreeCaviumRsaKey(key);
#endif

/* TomsFastMath doesn't use memory allocation */
#ifndef USE_FAST_MATH
    if (key->type == RSA_PRIVATE) {
        mp_clear(&key->u);
        mp_clear(&key->dQ);
        mp_clear(&key->dP);
        mp_clear(&key->q);
        mp_clear(&key->p);
        mp_clear(&key->d);
    }
    mp_clear(&key->e);
    mp_clear(&key->n);
#endif

    return 0;
}

static int RsaPad(const byte* input, word32 inputLen, byte* pkcsBlock,
                   word32 pkcsBlockLen, byte padValue, RNG* rng)
{
    if (inputLen == 0)
        return 0;

    pkcsBlock[0] = 0x0;       /* set first byte to zero and advance */
    pkcsBlock++; pkcsBlockLen--;
    pkcsBlock[0] = padValue;  /* insert padValue */

    if (padValue == RSA_BLOCK_TYPE_1)
        /* pad with 0xff bytes */
        XMEMSET(&pkcsBlock[1], 0xFF, pkcsBlockLen - inputLen - 2);
    else {
        /* pad with non-zero random bytes */
        word32 padLen = pkcsBlockLen - inputLen - 1, i;
        int    ret    = RNG_GenerateBlock(rng, &pkcsBlock[1], padLen);

        if (ret != 0)
            return ret;

        /* remove zeros */
        for (i = 1; i < padLen; i++)
            if (pkcsBlock[i] == 0) pkcsBlock[i] = 0x01;
    }

    pkcsBlock[pkcsBlockLen-inputLen-1] = 0;     /* separator */
    XMEMCPY(pkcsBlock+pkcsBlockLen-inputLen, input, inputLen);

    return 0;
}


/* UnPad plaintext, set start to *output, return length of plaintext,
 * < 0 on error */
static int RsaUnPad(const byte *pkcsBlock, unsigned int pkcsBlockLen,
                       byte **output, byte padValue)
{
    word32 maxOutputLen = (pkcsBlockLen > 10) ? (pkcsBlockLen - 10) : 0,
           invalid = 0,
           i = 1,
           outputLen;

    if (pkcsBlock[0] != 0x0) /* skip past zero */
        invalid = 1;
    pkcsBlock++; pkcsBlockLen--;

    /* Require block type padValue */
    invalid = (pkcsBlock[0] != padValue) || invalid;

    /* verify the padding until we find the separator */
    if (padValue == RSA_BLOCK_TYPE_1) {
        while (i<pkcsBlockLen && pkcsBlock[i++] == 0xFF) {/* Null body */}
    }
    else {
        while (i<pkcsBlockLen && pkcsBlock[i++]) {/* Null body */}
    }

    if(!(i==pkcsBlockLen || pkcsBlock[i-1]==0)) {
        CYASSL_MSG("RsaUnPad error, bad formatting");
        return RSA_PAD_E;
    }

    outputLen = pkcsBlockLen - i;
    invalid = (outputLen > maxOutputLen) || invalid;

    if (invalid) {
        CYASSL_MSG("RsaUnPad error, bad formatting");
        return RSA_PAD_E;
    }

    *output = (byte *)(pkcsBlock + i);
    return outputLen;
}


static int RsaFunction(const byte* in, word32 inLen, byte* out, word32* outLen,
                       int type, RsaKey* key)
{
    #define ERROR_OUT(x) { ret = (x); goto done;}

    mp_int tmp;
    int    ret = 0;
    word32 keyLen, len;

    if (mp_init(&tmp) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(&tmp, (byte*)in, inLen) != MP_OKAY)
        ERROR_OUT(MP_READ_E);

    if (type == RSA_PRIVATE_DECRYPT || type == RSA_PRIVATE_ENCRYPT) {
        #ifdef RSA_LOW_MEM      /* half as much memory but twice as slow */
            if (mp_exptmod(&tmp, &key->d, &key->n, &tmp) != MP_OKAY)
                ERROR_OUT(MP_EXPTMOD_E);
        #else
            #define INNER_ERROR_OUT(x) { ret = (x); goto inner_done; }

            mp_int tmpa, tmpb;

            if (mp_init(&tmpa) != MP_OKAY)
                ERROR_OUT(MP_INIT_E);

            if (mp_init(&tmpb) != MP_OKAY) {
                mp_clear(&tmpa);
                ERROR_OUT(MP_INIT_E);
            }

            /* tmpa = tmp^dP mod p */
            if (mp_exptmod(&tmp, &key->dP, &key->p, &tmpa) != MP_OKAY)
                INNER_ERROR_OUT(MP_EXPTMOD_E);

            /* tmpb = tmp^dQ mod q */
            if (mp_exptmod(&tmp, &key->dQ, &key->q, &tmpb) != MP_OKAY)
                INNER_ERROR_OUT(MP_EXPTMOD_E);

            /* tmp = (tmpa - tmpb) * qInv (mod p) */
            if (mp_sub(&tmpa, &tmpb, &tmp) != MP_OKAY)
                INNER_ERROR_OUT(MP_SUB_E);

            if (mp_mulmod(&tmp, &key->u, &key->p, &tmp) != MP_OKAY)
                INNER_ERROR_OUT(MP_MULMOD_E);

            /* tmp = tmpb + q * tmp */
            if (mp_mul(&tmp, &key->q, &tmp) != MP_OKAY)
                INNER_ERROR_OUT(MP_MUL_E);

            if (mp_add(&tmp, &tmpb, &tmp) != MP_OKAY)
                INNER_ERROR_OUT(MP_ADD_E);

        inner_done:
            mp_clear(&tmpa);
            mp_clear(&tmpb);

            if (ret != 0) return ret;

        #endif   /* RSA_LOW_MEM */
    }
    else if (type == RSA_PUBLIC_ENCRYPT || type == RSA_PUBLIC_DECRYPT) {
        if (mp_exptmod(&tmp, &key->e, &key->n, &tmp) != MP_OKAY)
            ERROR_OUT(MP_EXPTMOD_E);
    }
    else
        ERROR_OUT(RSA_WRONG_TYPE_E);

    keyLen = mp_unsigned_bin_size(&key->n);
    if (keyLen > *outLen)
        ERROR_OUT(RSA_BUFFER_E);

    len = mp_unsigned_bin_size(&tmp);

    /* pad front w/ zeros to match key length */
    while (len < keyLen) {
        *out++ = 0x00;
        len++;
    }

    *outLen = keyLen;

    /* convert */
    if (mp_to_unsigned_bin(&tmp, out) != MP_OKAY)
        ERROR_OUT(MP_TO_E);
   
done: 
    mp_clear(&tmp);
    return ret;
}


int RsaPublicEncrypt(const byte* in, word32 inLen, byte* out, word32 outLen,
                     RsaKey* key, RNG* rng)
{
    int sz, ret;

#ifdef HAVE_CAVIUM
    if (key->magic == CYASSL_RSA_CAVIUM_MAGIC)
        return CaviumRsaPublicEncrypt(in, inLen, out, outLen, key);
#endif

    sz = mp_unsigned_bin_size(&key->n);
    if (sz > (int)outLen)
        return RSA_BUFFER_E;

    if (inLen > (word32)(sz - RSA_MIN_PAD_SZ))
        return RSA_BUFFER_E;

    ret = RsaPad(in, inLen, out, sz, RSA_BLOCK_TYPE_2, rng);
    if (ret != 0)
        return ret;

    if ((ret = RsaFunction(out, sz, out, &outLen, RSA_PUBLIC_ENCRYPT, key)) < 0)
        sz = ret;

    return sz;
}


int RsaPrivateDecryptInline(byte* in, word32 inLen, byte** out, RsaKey* key)
{
    int ret;

#ifdef HAVE_CAVIUM
    if (key->magic == CYASSL_RSA_CAVIUM_MAGIC) {
        ret = CaviumRsaPrivateDecrypt(in, inLen, in, inLen, key);
        if (ret > 0)
            *out = in;
        return ret;
    }
#endif

    if ((ret = RsaFunction(in, inLen, in, &inLen, RSA_PRIVATE_DECRYPT, key))
            < 0) {
        return ret;
    }
 
    return RsaUnPad(in, inLen, out, RSA_BLOCK_TYPE_2);
}


int RsaPrivateDecrypt(const byte* in, word32 inLen, byte* out, word32 outLen,
                     RsaKey* key)
{
    int plainLen;
    byte*  tmp;
    byte*  pad = 0;

#ifdef HAVE_CAVIUM
    if (key->magic == CYASSL_RSA_CAVIUM_MAGIC)
        return CaviumRsaPrivateDecrypt(in, inLen, out, outLen, key);
#endif

    tmp = (byte*)XMALLOC(inLen, key->heap, DYNAMIC_TYPE_RSA);
    if (tmp == NULL) {
        return MEMORY_E;
    }

    XMEMCPY(tmp, in, inLen);

    if ( (plainLen = RsaPrivateDecryptInline(tmp, inLen, &pad, key) ) < 0) {
        XFREE(tmp, key->heap, DYNAMIC_TYPE_RSA);
        return plainLen;
    }
    if (plainLen > (int)outLen)
        plainLen = BAD_FUNC_ARG;
    else
        XMEMCPY(out, pad, plainLen);
    XMEMSET(tmp, 0x00, inLen); 

    XFREE(tmp, key->heap, DYNAMIC_TYPE_RSA);
    return plainLen;
}


/* for Rsa Verify */
int RsaSSL_VerifyInline(byte* in, word32 inLen, byte** out, RsaKey* key)
{
    int ret;

#ifdef HAVE_CAVIUM
    if (key->magic == CYASSL_RSA_CAVIUM_MAGIC) {
        ret = CaviumRsaSSL_Verify(in, inLen, in, inLen, key);
        if (ret > 0)
            *out = in;
        return ret;
    }
#endif

    if ((ret = RsaFunction(in, inLen, in, &inLen, RSA_PUBLIC_DECRYPT, key))
            < 0) {
        return ret;
    }
  
    return RsaUnPad(in, inLen, out, RSA_BLOCK_TYPE_1);
}


int RsaSSL_Verify(const byte* in, word32 inLen, byte* out, word32 outLen,
                     RsaKey* key)
{
    int plainLen;
    byte*  tmp;
    byte*  pad = 0;

#ifdef HAVE_CAVIUM
    if (key->magic == CYASSL_RSA_CAVIUM_MAGIC)
        return CaviumRsaSSL_Verify(in, inLen, out, outLen, key);
#endif

    tmp = (byte*)XMALLOC(inLen, key->heap, DYNAMIC_TYPE_RSA);
    if (tmp == NULL) {
        return MEMORY_E;
    }

    XMEMCPY(tmp, in, inLen);

    if ( (plainLen = RsaSSL_VerifyInline(tmp, inLen, &pad, key) ) < 0) {
        XFREE(tmp, key->heap, DYNAMIC_TYPE_RSA);
        return plainLen;
    }

    if (plainLen > (int)outLen)
        plainLen = BAD_FUNC_ARG;
    else 
        XMEMCPY(out, pad, plainLen);
    XMEMSET(tmp, 0x00, inLen); 

    XFREE(tmp, key->heap, DYNAMIC_TYPE_RSA);
    return plainLen;
}


/* for Rsa Sign */
int RsaSSL_Sign(const byte* in, word32 inLen, byte* out, word32 outLen,
                      RsaKey* key, RNG* rng)
{
    int sz, ret;

#ifdef HAVE_CAVIUM
    if (key->magic == CYASSL_RSA_CAVIUM_MAGIC)
        return CaviumRsaSSL_Sign(in, inLen, out, outLen, key);
#endif

    sz = mp_unsigned_bin_size(&key->n);
    if (sz > (int)outLen)
        return RSA_BUFFER_E;

    if (inLen > (word32)(sz - RSA_MIN_PAD_SZ))
        return RSA_BUFFER_E;

    ret = RsaPad(in, inLen, out, sz, RSA_BLOCK_TYPE_1, rng);
    if (ret != 0)
        return ret;

    if ((ret = RsaFunction(out, sz, out, &outLen, RSA_PRIVATE_ENCRYPT,key)) < 0)
        sz = ret;
    
    return sz;
}


int RsaEncryptSize(RsaKey* key)
{
#ifdef HAVE_CAVIUM
    if (key->magic == CYASSL_RSA_CAVIUM_MAGIC)
        return key->c_nSz;
#endif
    return mp_unsigned_bin_size(&key->n);
}


int RsaFlattenPublicKey(RsaKey* key, byte* e, word32* eSz, byte* n, word32* nSz)
{
    int sz, ret;

    if (key == NULL || e == NULL || eSz == NULL || n == NULL || nSz == NULL)
       return BAD_FUNC_ARG;

    sz = mp_unsigned_bin_size(&key->e);
    if ((word32)sz > *nSz)
        return RSA_BUFFER_E;
    ret = mp_to_unsigned_bin(&key->e, e);
    if (ret != MP_OKAY)
        return ret;
    *eSz = (word32)sz;

    sz = mp_unsigned_bin_size(&key->n);
    if ((word32)sz > *nSz)
        return RSA_BUFFER_E;
    ret = mp_to_unsigned_bin(&key->n, n);
    if (ret != MP_OKAY)
        return ret;
    *nSz = (word32)sz;

    return 0;
}


static int RsaGetValue(mp_int* in, byte* out, word32* outSz)
{
    word32 sz;
    int ret = 0;

    sz = (word32)mp_unsigned_bin_size(in);
    if (sz > *outSz)
        ret = RSA_BUFFER_E;

    if (ret == 0)
        ret = mp_to_unsigned_bin(in, out);

    if (ret == MP_OKAY)
        *outSz = sz;

    return ret;
}


int RsaExportKey(RsaKey* key,
                 byte* e, word32* eSz, byte* n, word32* nSz,
                 byte* d, word32* dSz, byte* p, word32* pSz,
                 byte* q, word32* qSz)
{
    int ret = BAD_FUNC_ARG;

    if (key && e && eSz && n && nSz && d && dSz && p && pSz && q && qSz)
        ret = 0;

    if (ret == 0)
        ret = RsaGetValue(&key->e, e, eSz);
    if (ret == 0)
        ret = RsaGetValue(&key->n, n, nSz);
    if (ret == 0)
        ret = RsaGetValue(&key->d, d, dSz);
    if (ret == 0)
        ret = RsaGetValue(&key->p, p, pSz);
    if (ret == 0)
        ret = RsaGetValue(&key->q, q, qSz);

    return ret;
}


#ifdef CYASSL_KEY_GEN

/* Check that |p-q| > 2^((size/2)-100) */
static int CompareDiffPQ(mp_int* p, mp_int* q, int size)
{
    mp_int c, d;
    int ret;

    if (p == NULL || q == NULL)
        return BAD_FUNC_ARG;

    ret = mp_init_multi(&c, &d, NULL, NULL, NULL, NULL);

    /* c = 2^((size/2)-100) */
    if (ret == 0)
        ret = mp_2expt(&c, (size/2)-100);

    /* d = |p-q| */
    if (ret == 0)
        ret = mp_sub(p, q, &d);

    if (ret == 0)
        ret = mp_abs(&d, &d);

    /* compare */
    if (ret == 0)
        ret = mp_cmp(&d, &c);

    if (ret == MP_GT)
        ret = MP_OKAY;

    mp_clear(&d);
    mp_clear(&c);

    return ret;
}


/* The lower_bound value is floor(2^(0.5) * 2^((nlen/2)-1)) where nlen is 4096.
 * This number was calculated using a small test tool written with a common
 * large number math library. Other values of nlen may be checked with a subset
 * of lower_bound. */
static const byte lower_bound[] = {
    0xB5, 0x04, 0xF3, 0x33, 0xF9, 0xDE, 0x64, 0x84,
    0x59, 0x7D, 0x89, 0xB3, 0x75, 0x4A, 0xBE, 0x9F,
    0x1D, 0x6F, 0x60, 0xBA, 0x89, 0x3B, 0xA8, 0x4C,
    0xED, 0x17, 0xAC, 0x85, 0x83, 0x33, 0x99, 0x15,
/* 512 */
    0x4A, 0xFC, 0x83, 0x04, 0x3A, 0xB8, 0xA2, 0xC3,
    0xA8, 0xB1, 0xFE, 0x6F, 0xDC, 0x83, 0xDB, 0x39,
    0x0F, 0x74, 0xA8, 0x5E, 0x43, 0x9C, 0x7B, 0x4A,
    0x78, 0x04, 0x87, 0x36, 0x3D, 0xFA, 0x27, 0x68,
/* 1024 */
    0xD2, 0x20, 0x2E, 0x87, 0x42, 0xAF, 0x1F, 0x4E,
    0x53, 0x05, 0x9C, 0x60, 0x11, 0xBC, 0x33, 0x7B,
    0xCA, 0xB1, 0xBC, 0x91, 0x16, 0x88, 0x45, 0x8A,
    0x46, 0x0A, 0xBC, 0x72, 0x2F, 0x7C, 0x4E, 0x33,
    0xC6, 0xD5, 0xA8, 0xA3, 0x8B, 0xB7, 0xE9, 0xDC,
    0xCB, 0x2A, 0x63, 0x43, 0x31, 0xF3, 0xC8, 0x4D,
    0xF5, 0x2F, 0x12, 0x0F, 0x83, 0x6E, 0x58, 0x2E,
    0xEA, 0xA4, 0xA0, 0x89, 0x90, 0x40, 0xCA, 0x4A,
/* 2048 */
    0x81, 0x39, 0x4A, 0xB6, 0xD8, 0xFD, 0x0E, 0xFD,
    0xF4, 0xD3, 0xA0, 0x2C, 0xEB, 0xC9, 0x3E, 0x0C,
    0x42, 0x64, 0xDA, 0xBC, 0xD5, 0x28, 0xB6, 0x51,
    0xB8, 0xCF, 0x34, 0x1B, 0x6F, 0x82, 0x36, 0xC7,
    0x01, 0x04, 0xDC, 0x01, 0xFE, 0x32, 0x35, 0x2F,
    0x33, 0x2A, 0x5E, 0x9F, 0x7B, 0xDA, 0x1E, 0xBF,
    0xF6, 0xA1, 0xBE, 0x3F, 0xCA, 0x22, 0x13, 0x07,
    0xDE, 0xA0, 0x62, 0x41, 0xF7, 0xAA, 0x81, 0xC2,
/* 3072 */
    0xC1, 0xFC, 0xBD, 0xDE, 0xA2, 0xF7, 0xDC, 0x33,
    0x18, 0x83, 0x8A, 0x2E, 0xAF, 0xF5, 0xF3, 0xB2,
    0xD2, 0x4F, 0x4A, 0x76, 0x3F, 0xAC, 0xB8, 0x82,
    0xFD, 0xFE, 0x17, 0x0F, 0xD3, 0xB1, 0xF7, 0x80,
    0xF9, 0xAC, 0xCE, 0x41, 0x79, 0x7F, 0x28, 0x05,
    0xC2, 0x46, 0x78, 0x5E, 0x92, 0x95, 0x70, 0x23,
    0x5F, 0xCF, 0x8F, 0x7B, 0xCA, 0x3E, 0xA3, 0x3B,
    0x4D, 0x7C, 0x60, 0xA5, 0xE6, 0x33, 0xE3, 0xE1
/* 4096 */
};


static INLINE int RsaSizeCheck(int size)
{
    switch (size) {
#ifndef HAVE_FIPS
        case 1024:
#endif
        case 2048:
        case 3072:
        case 4096:
            return 1;
    }
    return 0;
}


static int CheckProbablePrime_ex(mp_int* p, mp_int* q, mp_int* e, int nlen,
                                    int* isPrime)
{
    int ret;
    mp_int tmp1, tmp2;
    mp_int* prime;

    if (p == NULL || e == NULL || isPrime == NULL)
        return BAD_FUNC_ARG;

    if (!RsaSizeCheck(nlen))
        return BAD_FUNC_ARG;

    *isPrime = MP_NO;

    if (q != NULL) {
        /* 5.4 - check that |p-q| <= (2^(1/2))(2^((nlen/2)-1)) */
        ret = CompareDiffPQ(p, q, nlen);
        if (ret != MP_OKAY) goto notOkay;
        prime = q;
    }
    else
        prime = p;

    ret = mp_init_multi(&tmp1, &tmp2, NULL, NULL, NULL, NULL);
    if (ret != MP_OKAY) goto notOkay;

    /* 4.4,5.5 - Check that prime >= (2^(1/2))(2^((nlen/2)-1))
     *           This is a comparison against lowerBound */
    ret = mp_read_unsigned_bin(&tmp1, lower_bound, nlen/16);
    if (ret != MP_OKAY) goto notOkay;
    ret = mp_cmp(prime, &tmp1);
    if (ret == MP_LT) goto exit;

    /* 4.5,5.6 - Check that GCD(p-1, e) == 1 */
    ret = mp_sub_d(prime, 1, &tmp1);  /* tmp1 = prime-1 */
    if (ret != MP_OKAY) goto notOkay;
    ret = mp_gcd(&tmp1, e, &tmp2);  /* tmp2 = gcd(prime-1, e) */
    if (ret != MP_OKAY) goto notOkay;
    ret = mp_cmp_d(&tmp2, 1);
    if (ret != MP_EQ) goto exit; /* e divides p-1 */

    /* 4.5.1,5.6.1 - Check primality of p with 8 iterations */
    ret = mp_prime_is_prime(prime, 8, isPrime);
        /* Performs some divides by a table of primes, and then does M-R,
         * it sets isPrime as a side-effect. */
    if (ret != MP_OKAY) goto notOkay;

exit:
    ret = MP_OKAY;
notOkay:
    mp_clear(&tmp1);
    mp_clear(&tmp2);
    return ret;
}



int CheckProbablePrime(const byte* pRaw, word32 pRawSz,
                       const byte* qRaw, word32 qRawSz,
                       const byte* eRaw, word32 eRawSz,
                       int nlen, int* isPrime)
{
    mp_int p, q, e;
    mp_int* Q = NULL;
    int ret;

    if (pRaw == NULL || pRawSz == 0 ||
        eRaw == NULL || eRawSz == 0 ||
        isPrime == NULL) {

        return BAD_FUNC_ARG;
    }

    if ((qRaw != NULL && qRawSz == 0) || (qRaw == NULL && qRawSz != 0))
        return BAD_FUNC_ARG;

    ret = mp_init_multi(&p, &q, &e, NULL, NULL, NULL);

    if (ret == MP_OKAY)
        ret = mp_read_unsigned_bin(&p, pRaw, pRawSz);

    if (ret == MP_OKAY) {
        if (qRaw != NULL) {
            if (ret == MP_OKAY)
                ret = mp_read_unsigned_bin(&q, qRaw, qRawSz);
            if (ret == MP_OKAY)
                Q = &q;
        }
    }

    if (ret == MP_OKAY)
        ret = mp_read_unsigned_bin(&e, eRaw, eRawSz);

    if (ret == MP_OKAY)
        ret = CheckProbablePrime_ex(&p, Q, &e, nlen, isPrime);

    ret = (ret == MP_OKAY) ? 0 : PRIME_GEN_E;

    mp_clear(&p);
    mp_clear(&q);
    mp_clear(&e);

    return ret;
}


/* Make an RSA key for size bits, with e specified, 65537 is a good e */
int MakeRsaKey(RsaKey* key, int size, long e, RNG* rng)
{
    mp_int p, q, tmp1, tmp2, tmp3;
    int err, i, failCount, primeSz, isPrime;
    byte* buf = NULL;

    if (key == NULL || rng == NULL)
        return BAD_FUNC_ARG;

    if (!RsaSizeCheck(size))
        return BAD_FUNC_ARG;

    if (e < 3 || (e & 1) == 0)
        return BAD_FUNC_ARG;

    err = mp_init_multi(&p, &q, &tmp1, &tmp2, &tmp3, NULL);

    if (err == MP_OKAY)
        err = mp_set_int(&tmp3, e);

    failCount = 5 * (size / 2);
    primeSz = size / 16; /* size is the size of n in bits.
                            primeSz is in bytes. */

    /* allocate buffer to work with */
    if (err == MP_OKAY) {
        buf = (byte*)XMALLOC(primeSz, key->heap, DYNAMIC_TYPE_RSA);
        if (buf == NULL)
            err = MEMORY_E;
    }

    /* make p */
    if (err == MP_OKAY) {
        isPrime = 0;
        i = 0;
        do {
#ifdef SHOW_GEN
            printf(".");
            fflush(stdout);
#endif
            /* generate value */
            err = RNG_GenerateBlock(rng, buf, primeSz);

            if (err == 0) {
                /* prime lower bound has the MSB set, set it in candidate */
                buf[0] |= 0x80;
                /* make candidate odd */
                buf[primeSz-1] |= 0x01;
                /* load value */
                err = mp_read_unsigned_bin(&p, buf, primeSz);
            }

            if (err == MP_OKAY)
                err = CheckProbablePrime_ex(&p, NULL, &tmp3, size, &isPrime);

            i++;
        } while (err == MP_OKAY && !isPrime && i < failCount);
    }

    if (err == MP_OKAY && !isPrime)
        err = PRIME_GEN_E;

    /* make q */
    if (err == MP_OKAY) {
        isPrime = 0;
        i = 0;
        do {
#ifdef SHOW_GEN
            printf(".");
            fflush(stdout);
#endif
            /* generate value */
            err = RNG_GenerateBlock(rng, buf, primeSz);

            if (err == 0) {
                /* prime lower bound has the MSB set, set it in candidate */
                buf[0] |= 0x80;
                /* make candidate odd */
                buf[primeSz-1] |= 0x01;
                /* load value */
                err = mp_read_unsigned_bin(&q, buf, primeSz);
            }

            if (err == MP_OKAY)
                err = CheckProbablePrime_ex(&p, &q, &tmp3, size, &isPrime);

            i++;
        } while (err == MP_OKAY && !isPrime && i < failCount);
    }

    if (err == MP_OKAY && !isPrime)
        err = PRIME_GEN_E;

    if (buf) {
        ForceZero(buf, primeSz);
        XFREE(buf, key->heap, DYNAMIC_TYPE_RSA);
    }

    if (err == MP_OKAY)
        err = mp_init_multi(&key->n, &key->e, &key->d, &key->p, &key->q, NULL);

    if (err == MP_OKAY)
        err = mp_init_multi(&key->dP, &key->dQ, &key->u, NULL, NULL, NULL);

    if (err == MP_OKAY)
        err = mp_sub_d(&p, 1, &tmp1);  /* tmp1 = p-1 */

    if (err == MP_OKAY)
        err = mp_sub_d(&q, 1, &tmp2);  /* tmp2 = q-1 */

    if (err == MP_OKAY)
        err = mp_lcm(&tmp1, &tmp2, &tmp3);  /* tmp3 = lcm(p-1, q-1),last loop */

    /* make key */
    if (err == MP_OKAY)
        err = mp_set_int(&key->e, (mp_digit)e);  /* key->e = e */

    if (err == MP_OKAY)                /* key->d = 1/e mod lcm(p-1, q-1) */
        err = mp_invmod(&key->e, &tmp3, &key->d);

    if (err == MP_OKAY)
        err = mp_mul(&p, &q, &key->n);  /* key->n = pq */

    if (err == MP_OKAY)
        err = mp_mod(&key->d, &tmp1, &key->dP); /* key->dP = d mod(p-1) */

    if (err == MP_OKAY)
        err = mp_mod(&key->d, &tmp2, &key->dQ); /* key->dQ = d mod(q-1) */

    if (err == MP_OKAY)
        err = mp_invmod(&q, &p, &key->u); /* key->u = 1/q mod p */

    if (err == MP_OKAY)
        err = mp_copy(&p, &key->p);

    if (err == MP_OKAY)
        err = mp_copy(&q, &key->q);

    if (err == MP_OKAY)
        key->type = RSA_PRIVATE;

    mp_clear(&tmp1);
    mp_clear(&tmp2);
    mp_clear(&tmp3);
    mp_clear(&p);
    mp_clear(&q);

    if (err != MP_OKAY) {
        FreeRsaKey(key);
        return err;
    }

    return 0;
}

#endif /* CYASSL_KEY_GEN */


#ifdef HAVE_CAVIUM

#include <cyassl/ctaocrypt/logging.h>
#include "cavium_common.h"

/* Initiliaze RSA for use with Nitrox device */
int RsaInitCavium(RsaKey* rsa, int devId)
{
    if (rsa == NULL)
        return -1;

    if (CspAllocContext(CONTEXT_SSL, &rsa->contextHandle, devId) != 0)
        return -1;

    rsa->devId = devId;
    rsa->magic = CYASSL_RSA_CAVIUM_MAGIC;
   
    return 0;
}


/* Free RSA from use with Nitrox device */
void RsaFreeCavium(RsaKey* rsa)
{
    if (rsa == NULL)
        return;

    CspFreeContext(CONTEXT_SSL, rsa->contextHandle, rsa->devId);
    rsa->magic = 0;
}


/* Initialize cavium RSA key */
static int InitCaviumRsaKey(RsaKey* key, void* heap)
{
    if (key == NULL)
        return BAD_FUNC_ARG;

    key->heap = heap;
    key->type = -1;   /* don't know yet */

    key->c_n  = NULL;
    key->c_e  = NULL;
    key->c_d  = NULL;
    key->c_p  = NULL;
    key->c_q  = NULL;
    key->c_dP = NULL;
    key->c_dQ = NULL;
    key->c_u  = NULL;

    key->c_nSz   = 0;
    key->c_eSz   = 0;
    key->c_dSz   = 0;
    key->c_pSz   = 0;
    key->c_qSz   = 0;
    key->c_dP_Sz = 0;
    key->c_dQ_Sz = 0;
    key->c_uSz   = 0;
    
    return 0;
}


/* Free cavium RSA key */
static int FreeCaviumRsaKey(RsaKey* key)
{
    if (key == NULL)
        return BAD_FUNC_ARG;

    XFREE(key->c_n,  key->heap, DYNAMIC_TYPE_CAVIUM_TMP);
    XFREE(key->c_e,  key->heap, DYNAMIC_TYPE_CAVIUM_TMP);
    XFREE(key->c_d,  key->heap, DYNAMIC_TYPE_CAVIUM_TMP);
    XFREE(key->c_p,  key->heap, DYNAMIC_TYPE_CAVIUM_TMP);
    XFREE(key->c_q,  key->heap, DYNAMIC_TYPE_CAVIUM_TMP);
    XFREE(key->c_dP, key->heap, DYNAMIC_TYPE_CAVIUM_TMP);
    XFREE(key->c_dQ, key->heap, DYNAMIC_TYPE_CAVIUM_TMP);
    XFREE(key->c_u,  key->heap, DYNAMIC_TYPE_CAVIUM_TMP);

    return InitCaviumRsaKey(key, key->heap);  /* reset pointers */
}


static int CaviumRsaPublicEncrypt(const byte* in, word32 inLen, byte* out,
                                   word32 outLen, RsaKey* key)
{
    word32 requestId;
    word32 ret;

    if (key == NULL || in == NULL || out == NULL || outLen < (word32)key->c_nSz)
        return -1;

    ret = CspPkcs1v15Enc(CAVIUM_BLOCKING, BT2, key->c_nSz, key->c_eSz,
                         (word16)inLen, key->c_n, key->c_e, (byte*)in, out,
                         &requestId, key->devId);
    if (ret != 0) {
        CYASSL_MSG("Cavium Enc BT2 failed");
        return -1;
    }
    return key->c_nSz;
}


static INLINE void ato16(const byte* c, word16* u16)
{
    *u16 = (c[0] << 8) | (c[1]);
}


static int CaviumRsaPrivateDecrypt(const byte* in, word32 inLen, byte* out,
                                    word32 outLen, RsaKey* key)
{
    word32 requestId;
    word32 ret;
    word16 outSz = (word16)outLen;

    if (key == NULL || in == NULL || out == NULL || inLen != (word32)key->c_nSz)
        return -1;

    ret = CspPkcs1v15CrtDec(CAVIUM_BLOCKING, BT2, key->c_nSz, key->c_q,
                            key->c_dQ, key->c_p, key->c_dP, key->c_u,
                            (byte*)in, &outSz, out, &requestId, key->devId);
    if (ret != 0) {
        CYASSL_MSG("Cavium CRT Dec BT2 failed");
        return -1;
    }
    ato16((const byte*)&outSz, &outSz); 

    return outSz;
}


static int CaviumRsaSSL_Sign(const byte* in, word32 inLen, byte* out,
                             word32 outLen, RsaKey* key)
{
    word32 requestId;
    word32 ret;

    if (key == NULL || in == NULL || out == NULL || inLen == 0 || outLen <
                                                             (word32)key->c_nSz)
        return -1;

    ret = CspPkcs1v15CrtEnc(CAVIUM_BLOCKING, BT1, key->c_nSz, (word16)inLen,
                            key->c_q, key->c_dQ, key->c_p, key->c_dP, key->c_u,
                            (byte*)in, out, &requestId, key->devId);
    if (ret != 0) {
        CYASSL_MSG("Cavium CRT Enc BT1 failed");
        return -1;
    }
    return key->c_nSz;
}


static int CaviumRsaSSL_Verify(const byte* in, word32 inLen, byte* out,
                               word32 outLen, RsaKey* key)
{
    word32 requestId;
    word32 ret;
    word16 outSz = (word16)outLen;

    if (key == NULL || in == NULL || out == NULL || inLen != (word32)key->c_nSz)
        return -1;

    ret = CspPkcs1v15Dec(CAVIUM_BLOCKING, BT1, key->c_nSz, key->c_eSz,
                         key->c_n, key->c_e, (byte*)in, &outSz, out,
                         &requestId, key->devId);
    if (ret != 0) {
        CYASSL_MSG("Cavium Dec BT1 failed");
        return -1;
    }
    outSz = ntohs(outSz);

    return outSz;
}


#endif /* HAVE_CAVIUM */

#endif /* NO_RSA */
