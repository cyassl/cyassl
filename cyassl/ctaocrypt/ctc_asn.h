/* ctc_asn.h
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


#ifndef CTAO_CRYPT_ASN_H
#define CTAO_CRYPT_ASN_H

#include "ctc_types.h"
#include "ctc_rsa.h"
#include "ctc_dh.h"
#include "ctc_dsa.h"
#include "ctc_sha.h"
#include "ctc_asn_public.h"   /* public interface */
#ifdef HAVE_ECC
    #include "ctc_ecc.h"
#endif

#ifdef __cplusplus
    extern "C" {
#endif


enum {
    ISSUER  = 0,
    SUBJECT = 1,

    EXTERNAL_SERIAL_SIZE = 32,

    BEFORE  = 0,
    AFTER   = 1
};

/* ASN Tags   */
enum ASN_Tags {        
    ASN_INTEGER           = 0x02,
    ASN_BIT_STRING        = 0x03,
    ASN_OCTET_STRING      = 0x04,
    ASN_TAG_NULL          = 0x05,
    ASN_OBJECT_ID         = 0x06,
    ASN_SEQUENCE          = 0x10,
    ASN_SET               = 0x11,
    ASN_UTC_TIME          = 0x17,
    ASN_GENERALIZED_TIME  = 0x18,
    ASN_LONG_LENGTH       = 0x80
};


enum  ASN_Flags{
    ASN_CONSTRUCTED       = 0x20,
    ASN_CONTEXT_SPECIFIC  = 0x80
};

enum DN_Tags {
    ASN_COMMON_NAME   = 0x03,   /* CN */
    ASN_SUR_NAME      = 0x04,   /* SN */
    ASN_COUNTRY_NAME  = 0x06,   /* C  */
    ASN_LOCALITY_NAME = 0x07,   /* L  */
    ASN_STATE_NAME    = 0x08,   /* ST */
    ASN_ORG_NAME      = 0x0a,   /* O  */
    ASN_ORGUNIT_NAME  = 0x0b    /* OU */
};

enum PBES {
    PBE_MD5_DES      = 0,
    PBE_SHA1_DES     = 1,
    PBE_SHA1_DES3    = 2,
    PBE_SHA1_RC4_128 = 3,
    PBES2            = 13       /* algo ID */
};

enum ENCRYPTION_TYPES {
    DES_TYPE  = 0,
    DES3_TYPE = 1,
    RC4_TYPE  = 2
};

enum Misc_ASN { 
    ASN_NAME_MAX        = 256,
    MAX_SALT_SIZE       =  64,     /* MAX PKCS Salt length */
    MAX_IV_SIZE         =  64,     /* MAX PKCS Iv length */
    MAX_KEY_SIZE        =  64,     /* MAX PKCS Key  length */
    PKCS5               =   5,     /* PKCS oid tag */
    PKCS5v2             =   6,     /* PKCS #5 v2.0 */
    PKCS12              =  12,     /* PKCS #12 */
    MAX_UNICODE_SZ      = 256,
    SHA_SIZE            =  20,
    RSA_INTS            =   8,     /* RSA ints in private key */
    MIN_DATE_SIZE       =  13,
    MAX_DATE_SIZE       =  32,
    ASN_GEN_TIME_SZ     =  15,     /* 7 numbers * 2 + Zulu tag */
    MAX_ENCODED_SIG_SZ  = 512,
    MAX_SIG_SZ          = 256,
    MAX_ALGO_SZ         =  20,
    MAX_SEQ_SZ          =   5,     /* enum(seq | con) + length(4) */  
    MAX_SET_SZ          =   5,     /* enum(set | con) + length(4) */  
    MAX_VERSION_SZ      =   5,     /* enum + id + version(byte) + (header(2))*/
    MAX_ENCODED_DIG_SZ  =  73,     /* sha512 + enum(bit or octet) + legnth(4) */
    MAX_RSA_INT_SZ      = 517,     /* RSA raw sz 4096 for bits + tag + len(4) */
    MAX_NTRU_KEY_SZ     = 610,     /* NTRU 112 bit public key */
    MAX_NTRU_ENC_SZ     = 628,     /* NTRU 112 bit DER public encoding */
    MAX_RSA_E_SZ        =  16,     /* Max RSA public e size */
    MAX_PUBLIC_KEY_SZ   = MAX_NTRU_ENC_SZ + MAX_ALGO_SZ + MAX_SEQ_SZ * 2, 
                                   /* use bigger NTRU size */
    MAX_LENGTH_SZ       =   4 
};


enum Oid_Types {
    hashType = 0,
    sigType  = 1,
    keyType  = 2
};


enum Sig_Sum  {
    SHAwDSA    = 517,
    MD2wRSA    = 646,
    MD5wRSA    = 648,
    SHAwRSA    = 649,
    SHAwECDSA  = 520,
    SHA256wRSA   = 655,
    SHA256wECDSA = 524
};

enum Hash_Sum  {
    MD2h    = 646,
    MD5h    = 649,
    SHAh    =  88,
    SHA256h = 414
};

enum Key_Sum {
    DSAk   = 515,
    RSAk   = 645,
    NTRUk  = 364,
    ECDSAk = 518
};

enum Ecc_Sum {
    ECC_256R1 = 526,
    ECC_384R1 = 210,
    ECC_521R1 = 211,
    ECC_160R1 = 184,
    ECC_192R1 = 520,
    ECC_224R1 = 209
};


enum KDF_Sum {
    PBKDF2_OID = 660
};


enum VerifyType {
    NO_VERIFY = 0,
    VERIFY    = 1
};


typedef struct DecodedCert DecodedCert;
typedef struct Signer      Signer;


struct DecodedCert {
    byte*   publicKey;
    word32  pubKeySize;
    int     pubKeyStored;
    word32  certBegin;               /* offset to start of cert          */
    word32  sigIndex;                /* offset to start of signature     */
    word32  sigLength;               /* length of signature              */
    word32  signatureOID;            /* sum of algorithm object id       */
    word32  keyOID;                  /* sum of key algo  object id       */
    byte    subjectHash[SHA_SIZE];   /* hash of all Names                */
    byte    issuerHash[SHA_SIZE];    /* hash of all Names                */
    byte*   signature;               /* not owned, points into raw cert  */
    char*   subjectCN;               /* CommonName                       */
    int     subjectCNLen;
    char    issuer[ASN_NAME_MAX];    /* full name including common name  */
    char    subject[ASN_NAME_MAX];   /* full name including common name  */
    int     verify;                  /* Default to yes, but could be off */
    byte*   source;                  /* byte buffer holder cert, NOT owner */
    word32  srcIdx;                  /* current offset into buffer       */
    word32  maxIdx;                  /* max offset based on init size    */
    void*   heap;                    /* for user memory overrides        */
    byte    serial[EXTERNAL_SERIAL_SIZE];  /* raw serial number          */
    int     serialSz;                /* raw serial bytes stored */
#ifdef CYASSL_CERT_GEN
    /* easy access to sujbect info for other sign */
    char*   subjectSN;
    int     subjectSNLen;
    char*   subjectC;
    int     subjectCLen;
    char*   subjectL;
    int     subjectLLen;
    char*   subjectST;
    int     subjectSTLen;
    char*   subjectO;
    int     subjectOLen;
    char*   subjectOU;
    int     subjectOULen;
    char*   subjectEmail;
    int     subjectEmailLen;
#endif /* CYASSL_CERT_GEN */
};


/* CA Signers */
struct Signer {
    byte*   publicKey;
    word32  pubKeySize;
    word32  keyOID;                  /* key type */
    char*   name;                    /* common name */
    byte    hash[SHA_DIGEST_SIZE];   /* sha hash of names in certificate */
    Signer* next;
};


/* not for public consumption but may use for testing sometimes */
#ifdef CYASSL_TEST_CERT
    #define CYASSL_TEST_API CYASSL_API
#else
    #define CYASSL_TEST_API CYASSL_LOCAL
#endif

CYASSL_TEST_API void InitDecodedCert(DecodedCert*, byte*, word32, void*);
CYASSL_TEST_API void FreeDecodedCert(DecodedCert*);
CYASSL_TEST_API int  ParseCert(DecodedCert*, int type, int verify,
                               Signer* signer);

CYASSL_LOCAL int ParseCertRelative(DecodedCert*, int type, int verify,
                                   Signer* signer);

CYASSL_LOCAL word32 EncodeSignature(byte* out, const byte* digest, word32 digSz,
                                    int hashOID);

CYASSL_LOCAL Signer* MakeSigner(void*);
CYASSL_LOCAL void    FreeSigners(Signer*, void*);


CYASSL_LOCAL int ToTraditional(byte* buffer, word32 length);
CYASSL_LOCAL int ToTraditionalEnc(byte* buffer, word32 length,const char*, int);


#ifdef HAVE_ECC
    /* ASN sig helpers */
    CYASSL_LOCAL int StoreECC_DSA_Sig(byte* out, word32* outLen, mp_int* r,
                                      mp_int* s);
    CYASSL_LOCAL int DecodeECC_DSA_Sig(const byte* sig, word32 sigLen,
                                       mp_int* r, mp_int* s);
    /* private key helpers */
    CYASSL_LOCAL int EccPrivateKeyDecode(const byte* input,word32* inOutIdx,
                                         ecc_key*,word32);
#endif

#ifdef CYASSL_CERT_GEN

enum cert_enums {
    NAME_ENTRIES    =  8,
    JOINT_LEN       =  2,
    EMAIL_JOINT_LEN =  9,
    RSA_KEY         = 10,
    NTRU_KEY        = 11
};


#endif /* CYASSL_CERT_GEN */


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* CTAO_CRYPT_ASN_H */

