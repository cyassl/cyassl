/* ctc_rabbit.h
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


#ifndef NO_RABBIT

#ifndef CTAO_CRYPT_RABBIT_H
#define CTAO_CRYPT_RABBIT_H

#include "ctc_types.h"

#ifdef __cplusplus
    extern "C" {
#endif


/* Rabbit Context */
typedef struct RabbitCtx {
    word32 x[8];
    word32 c[8];
    word32 carry;
} RabbitCtx;
    

/* Rabbit stream cipher */
typedef struct Rabbit {
    RabbitCtx masterCtx;
    RabbitCtx workCtx;
} Rabbit;


CYASSL_API void RabbitProcess(Rabbit*, byte*, const byte*, word32);
CYASSL_API void RabbitSetKey(Rabbit*, const byte* key, const byte* iv);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* CTAO_CRYPT_RABBIT_H */

#endif /* NO_RABBIT */
