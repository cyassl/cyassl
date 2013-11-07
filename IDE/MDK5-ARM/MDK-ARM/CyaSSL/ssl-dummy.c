/* ssl-dummy.c
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

#include <cyassl/ssl.h>
#include <cyassl/internal.h>

Signer* GetCA(void* vp, byte* hash) 
{ 
    return NULL  ;
}

int CyaSSL_dtls(CYASSL* ssl)
{
    return NULL ;
}

int CyaSSL_get_using_nonblock(CYASSL* ssl)
{
    return NULL ;
}

Signer* GetCAByName(void* vp, byte* hash)
{
    return NULL ;
}

int CyaSSL_PemCertToDer(const char* fileName, unsigned char* derBuf, int derSz) 
{
        return NULL ;
}
