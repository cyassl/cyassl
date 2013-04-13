/* sha512.c
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <cyassl/ctaocrypt/settings.h>

#ifdef CYASSL_SHA512

#include <cyassl/ctaocrypt/sha512.h>
#ifdef NO_INLINE
    #include <cyassl/ctaocrypt/misc.h>
#else
    #include <ctaocrypt/src/misc.c>
#endif


#ifndef min

    static INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }

#endif /* min */


void InitSha512(Sha512* sha512)
{
    sha512->digest[0] = W64LIT(0x6a09e667f3bcc908);
    sha512->digest[1] = W64LIT(0xbb67ae8584caa73b);
    sha512->digest[2] = W64LIT(0x3c6ef372fe94f82b);
    sha512->digest[3] = W64LIT(0xa54ff53a5f1d36f1);
    sha512->digest[4] = W64LIT(0x510e527fade682d1);
    sha512->digest[5] = W64LIT(0x9b05688c2b3e6c1f);
    sha512->digest[6] = W64LIT(0x1f83d9abfb41bd6b);
    sha512->digest[7] = W64LIT(0x5be0cd19137e2179);

    sha512->buffLen = 0;
    sha512->loLen   = 0;
    sha512->hiLen   = 0;
}


static const word64 K512[80] = {
	W64LIT(0x428a2f98d728ae22), W64LIT(0x7137449123ef65cd),
	W64LIT(0xb5c0fbcfec4d3b2f), W64LIT(0xe9b5dba58189dbbc),
	W64LIT(0x3956c25bf348b538), W64LIT(0x59f111f1b605d019),
	W64LIT(0x923f82a4af194f9b), W64LIT(0xab1c5ed5da6d8118),
	W64LIT(0xd807aa98a3030242), W64LIT(0x12835b0145706fbe),
	W64LIT(0x243185be4ee4b28c), W64LIT(0x550c7dc3d5ffb4e2),
	W64LIT(0x72be5d74f27b896f), W64LIT(0x80deb1fe3b1696b1),
	W64LIT(0x9bdc06a725c71235), W64LIT(0xc19bf174cf692694),
	W64LIT(0xe49b69c19ef14ad2), W64LIT(0xefbe4786384f25e3),
	W64LIT(0x0fc19dc68b8cd5b5), W64LIT(0x240ca1cc77ac9c65),
	W64LIT(0x2de92c6f592b0275), W64LIT(0x4a7484aa6ea6e483),
	W64LIT(0x5cb0a9dcbd41fbd4), W64LIT(0x76f988da831153b5),
	W64LIT(0x983e5152ee66dfab), W64LIT(0xa831c66d2db43210),
	W64LIT(0xb00327c898fb213f), W64LIT(0xbf597fc7beef0ee4),
	W64LIT(0xc6e00bf33da88fc2), W64LIT(0xd5a79147930aa725),
	W64LIT(0x06ca6351e003826f), W64LIT(0x142929670a0e6e70),
	W64LIT(0x27b70a8546d22ffc), W64LIT(0x2e1b21385c26c926),
	W64LIT(0x4d2c6dfc5ac42aed), W64LIT(0x53380d139d95b3df),
	W64LIT(0x650a73548baf63de), W64LIT(0x766a0abb3c77b2a8),
	W64LIT(0x81c2c92e47edaee6), W64LIT(0x92722c851482353b),
	W64LIT(0xa2bfe8a14cf10364), W64LIT(0xa81a664bbc423001),
	W64LIT(0xc24b8b70d0f89791), W64LIT(0xc76c51a30654be30),
	W64LIT(0xd192e819d6ef5218), W64LIT(0xd69906245565a910),
	W64LIT(0xf40e35855771202a), W64LIT(0x106aa07032bbd1b8),
	W64LIT(0x19a4c116b8d2d0c8), W64LIT(0x1e376c085141ab53),
	W64LIT(0x2748774cdf8eeb99), W64LIT(0x34b0bcb5e19b48a8),
	W64LIT(0x391c0cb3c5c95a63), W64LIT(0x4ed8aa4ae3418acb),
	W64LIT(0x5b9cca4f7763e373), W64LIT(0x682e6ff3d6b2b8a3),
	W64LIT(0x748f82ee5defb2fc), W64LIT(0x78a5636f43172f60),
	W64LIT(0x84c87814a1f0ab72), W64LIT(0x8cc702081a6439ec),
	W64LIT(0x90befffa23631e28), W64LIT(0xa4506cebde82bde9),
	W64LIT(0xbef9a3f7b2c67915), W64LIT(0xc67178f2e372532b),
	W64LIT(0xca273eceea26619c), W64LIT(0xd186b8c721c0c207),
	W64LIT(0xeada7dd6cde0eb1e), W64LIT(0xf57d4f7fee6ed178),
	W64LIT(0x06f067aa72176fba), W64LIT(0x0a637dc5a2c898a6),
	W64LIT(0x113f9804bef90dae), W64LIT(0x1b710b35131c471b),
	W64LIT(0x28db77f523047d84), W64LIT(0x32caab7b40c72493),
	W64LIT(0x3c9ebe0a15c9bebc), W64LIT(0x431d67c49c100d4c),
	W64LIT(0x4cc5d4becb3e42b6), W64LIT(0x597f299cfc657e2a),
	W64LIT(0x5fcb6fab3ad6faec), W64LIT(0x6c44198c4a475817)
};


#define blk0(i) (W[i] = sha512->buffer[i])
#define blk2(i) (W[i&15]+=s1(W[(i-2)&15])+W[(i-7)&15]+s0(W[(i-15)&15]))

#define Ch(x,y,z) (z^(x&(y^z)))
#define Maj(x,y,z) ((x&y)|(z&(x|y)))

#define a(i) T[(0-i)&7]
#define b(i) T[(1-i)&7]
#define c(i) T[(2-i)&7]
#define d(i) T[(3-i)&7]
#define e(i) T[(4-i)&7]
#define f(i) T[(5-i)&7]
#define g(i) T[(6-i)&7]
#define h(i) T[(7-i)&7]

#define S0(x) (rotrFixed64(x,28)^rotrFixed64(x,34)^rotrFixed64(x,39))
#define S1(x) (rotrFixed64(x,14)^rotrFixed64(x,18)^rotrFixed64(x,41))
#define s0(x) (rotrFixed64(x,1)^rotrFixed64(x,8)^(x>>7))
#define s1(x) (rotrFixed64(x,19)^rotrFixed64(x,61)^(x>>6))

#define R(i) h(i)+=S1(e(i))+Ch(e(i),f(i),g(i))+K[i+j]+(j?blk2(i):blk0(i));\
	d(i)+=h(i);h(i)+=S0(a(i))+Maj(a(i),b(i),c(i))

#define blk384(i) (W[i] = sha384->buffer[i])

#define R2(i) h(i)+=S1(e(i))+Ch(e(i),f(i),g(i))+K[i+j]+(j?blk2(i):blk384(i));\
	d(i)+=h(i);h(i)+=S0(a(i))+Maj(a(i),b(i),c(i))


static void Transform(Sha512* sha512)
{
    const word64* K = K512;

    word32 j;
    word64 W[16];
    word64 T[8];

    /* Copy digest to working vars */
    XMEMCPY(T, sha512->digest, sizeof(T));

    /* 64 operations, partially loop unrolled */
    for (j = 0; j < 80; j += 16) {
        R( 0); R( 1); R( 2); R( 3);
        R( 4); R( 5); R( 6); R( 7);
        R( 8); R( 9); R(10); R(11);
        R(12); R(13); R(14); R(15);
    }

    /* Add the working vars back into digest */

    sha512->digest[0] += a(0);
    sha512->digest[1] += b(0);
    sha512->digest[2] += c(0);
    sha512->digest[3] += d(0);
    sha512->digest[4] += e(0);
    sha512->digest[5] += f(0);
    sha512->digest[6] += g(0);
    sha512->digest[7] += h(0);

    /* Wipe variables */
    XMEMSET(W, 0, sizeof(W));
    XMEMSET(T, 0, sizeof(T));
}


static INLINE void AddLength(Sha512* sha512, word32 len)
{
    word32 tmp = sha512->loLen;
    if ( (sha512->loLen += len) < tmp)
        sha512->hiLen++;                       /* carry low to high */
}


void Sha512Update(Sha512* sha512, const byte* data, word32 len)
{
    /* do block size increments */
    byte* local = (byte*)sha512->buffer;

    while (len) {
        word32 add = min(len, SHA512_BLOCK_SIZE - sha512->buffLen);
        XMEMCPY(&local[sha512->buffLen], data, add);

        sha512->buffLen += add;
        data         += add;
        len          -= add;

        if (sha512->buffLen == SHA512_BLOCK_SIZE) {
            #ifdef LITTLE_ENDIAN_ORDER
                ByteReverseWords64(sha512->buffer, sha512->buffer,
                                   SHA512_BLOCK_SIZE);
            #endif
            Transform(sha512);
            AddLength(sha512, SHA512_BLOCK_SIZE);
            sha512->buffLen = 0;
        }
    }
}


void Sha512Final(Sha512* sha512, byte* hash)
{
    byte* local = (byte*)sha512->buffer;

    AddLength(sha512, sha512->buffLen);               /* before adding pads */

    local[sha512->buffLen++] = 0x80;  /* add 1 */

    /* pad with zeros */
    if (sha512->buffLen > SHA512_PAD_SIZE) {
        XMEMSET(&local[sha512->buffLen], 0, SHA512_BLOCK_SIZE -sha512->buffLen);
        sha512->buffLen += SHA512_BLOCK_SIZE - sha512->buffLen;

        #ifdef LITTLE_ENDIAN_ORDER
            ByteReverseWords64(sha512->buffer,sha512->buffer,SHA512_BLOCK_SIZE);
        #endif
        Transform(sha512);
        sha512->buffLen = 0;
    }
    XMEMSET(&local[sha512->buffLen], 0, SHA512_PAD_SIZE - sha512->buffLen);
   
    /* put lengths in bits */
    sha512->hiLen = (sha512->loLen >> (8*sizeof(sha512->loLen) - 3)) + 
                 (sha512->hiLen << 3);
    sha512->loLen = sha512->loLen << 3;

    /* store lengths */
    #ifdef LITTLE_ENDIAN_ORDER
        ByteReverseWords64(sha512->buffer, sha512->buffer, SHA512_PAD_SIZE);
    #endif
    /* ! length ordering dependent on digest endian type ! */
    sha512->buffer[SHA512_BLOCK_SIZE / sizeof(word64) - 2] = sha512->hiLen;
    sha512->buffer[SHA512_BLOCK_SIZE / sizeof(word64) - 1] = sha512->loLen;

    Transform(sha512);
    #ifdef LITTLE_ENDIAN_ORDER
        ByteReverseWords64(sha512->digest, sha512->digest, SHA512_DIGEST_SIZE);
    #endif
    XMEMCPY(hash, sha512->digest, SHA512_DIGEST_SIZE);

    InitSha512(sha512);  /* reset state */
}



#ifdef CYASSL_SHA384

void InitSha384(Sha384* sha384)
{
    sha384->digest[0] = W64LIT(0xcbbb9d5dc1059ed8);
    sha384->digest[1] = W64LIT(0x629a292a367cd507);
    sha384->digest[2] = W64LIT(0x9159015a3070dd17);
    sha384->digest[3] = W64LIT(0x152fecd8f70e5939);
    sha384->digest[4] = W64LIT(0x67332667ffc00b31);
    sha384->digest[5] = W64LIT(0x8eb44a8768581511);
    sha384->digest[6] = W64LIT(0xdb0c2e0d64f98fa7);
    sha384->digest[7] = W64LIT(0x47b5481dbefa4fa4);

    sha384->buffLen = 0;
    sha384->loLen   = 0;
    sha384->hiLen   = 0;
}


static void Transform384(Sha384* sha384)
{
    const word64* K = K512;

    word32 j;
    word64 W[16];
    word64 T[8];

    /* Copy digest to working vars */
    XMEMCPY(T, sha384->digest, sizeof(T));

    /* 64 operations, partially loop unrolled */
    for (j = 0; j < 80; j += 16) {
        R2( 0); R2( 1); R2( 2); R2( 3);
        R2( 4); R2( 5); R2( 6); R2( 7);
        R2( 8); R2( 9); R2(10); R2(11);
        R2(12); R2(13); R2(14); R2(15);
    }

    /* Add the working vars back into digest */

    sha384->digest[0] += a(0);
    sha384->digest[1] += b(0);
    sha384->digest[2] += c(0);
    sha384->digest[3] += d(0);
    sha384->digest[4] += e(0);
    sha384->digest[5] += f(0);
    sha384->digest[6] += g(0);
    sha384->digest[7] += h(0);

    /* Wipe variables */
    XMEMSET(W, 0, sizeof(W));
    XMEMSET(T, 0, sizeof(T));
}


static INLINE void AddLength384(Sha384* sha384, word32 len)
{
    word32 tmp = sha384->loLen;
    if ( (sha384->loLen += len) < tmp)
        sha384->hiLen++;                       /* carry low to high */
}


void Sha384Update(Sha384* sha384, const byte* data, word32 len)
{
    /* do block size increments */
    byte* local = (byte*)sha384->buffer;

    while (len) {
        word32 add = min(len, SHA384_BLOCK_SIZE - sha384->buffLen);
        XMEMCPY(&local[sha384->buffLen], data, add);

        sha384->buffLen += add;
        data         += add;
        len          -= add;

        if (sha384->buffLen == SHA384_BLOCK_SIZE) {
            #ifdef LITTLE_ENDIAN_ORDER
                ByteReverseWords64(sha384->buffer, sha384->buffer,
                                   SHA384_BLOCK_SIZE);
            #endif
            Transform384(sha384);
            AddLength384(sha384, SHA384_BLOCK_SIZE);
            sha384->buffLen = 0;
        }
    }
}


void Sha384Final(Sha384* sha384, byte* hash)
{
    byte* local = (byte*)sha384->buffer;

    AddLength384(sha384, sha384->buffLen);              /* before adding pads */

    local[sha384->buffLen++] = 0x80;  /* add 1 */

    /* pad with zeros */
    if (sha384->buffLen > SHA384_PAD_SIZE) {
        XMEMSET(&local[sha384->buffLen], 0, SHA384_BLOCK_SIZE -sha384->buffLen);
        sha384->buffLen += SHA384_BLOCK_SIZE - sha384->buffLen;

        #ifdef LITTLE_ENDIAN_ORDER
            ByteReverseWords64(sha384->buffer,sha384->buffer,SHA384_BLOCK_SIZE);
        #endif
        Transform384(sha384);
        sha384->buffLen = 0;
    }
    XMEMSET(&local[sha384->buffLen], 0, SHA384_PAD_SIZE - sha384->buffLen);
   
    /* put lengths in bits */
    sha384->hiLen = (sha384->loLen >> (8*sizeof(sha384->loLen) - 3)) + 
                 (sha384->hiLen << 3);
    sha384->loLen = sha384->loLen << 3;

    /* store lengths */
    #ifdef LITTLE_ENDIAN_ORDER
        ByteReverseWords64(sha384->buffer, sha384->buffer, SHA384_PAD_SIZE);
    #endif
    /* ! length ordering dependent on digest endian type ! */
    sha384->buffer[SHA384_BLOCK_SIZE / sizeof(word64) - 2] = sha384->hiLen;
    sha384->buffer[SHA384_BLOCK_SIZE / sizeof(word64) - 1] = sha384->loLen;

    Transform384(sha384);
    #ifdef LITTLE_ENDIAN_ORDER
        ByteReverseWords64(sha384->digest, sha384->digest, SHA384_DIGEST_SIZE);
    #endif
    XMEMCPY(hash, sha384->digest, SHA384_DIGEST_SIZE);

    InitSha384(sha384);  /* reset state */
}

#endif /* CYASSL_SHA384 */

#endif /* CYASSL_SHA512 */
