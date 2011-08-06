/* echoserver.c
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

#include <config.h>

#include <openssl/ssl.h>
#include <openssl/cyassl_test.h>

#ifndef NO_MAIN_DRIVER
    #define ECHO_OUT
#endif


#ifdef SESSION_STATS
    void PrintSessionStats(void);
#endif


static void SignalReady(void* args)
{
#if defined(_POSIX_THREADS) && defined(NO_MAIN_DRIVER)
    /* signal ready to tcp_accept */
    func_args* server_args = (func_args*)args;
    tcp_ready* ready = server_args->signal;
    pthread_mutex_lock(&ready->mutex);
    ready->ready = 1;
    pthread_cond_signal(&ready->cond);
    pthread_mutex_unlock(&ready->mutex);
#endif
}


THREAD_RETURN CYASSL_THREAD echoserver_test(void* args)
{
    SOCKET_T    sockfd = 0;
    SSL_METHOD* method = 0;
    SSL_CTX*    ctx    = 0;

    int    outCreated = 0;
    int    shutdown = 0;
    int    argc = ((func_args*)args)->argc;
    char** argv = ((func_args*)args)->argv;

#ifdef ECHO_OUT
    FILE* fout = stdout;
    if (argc >= 2) {
        fout = fopen(argv[1], "w");
        outCreated = 1;
    }
    if (!fout) err_sys("can't open output file");
#endif

    ((func_args*)args)->return_code = -1; /* error state */

    tcp_listen(&sockfd);

#if defined(CYASSL_DTLS)
    method  = DTLSv1_server_method();
#elif  !defined(NO_TLS)
    method = SSLv23_server_method();
#else
    method = SSLv3_server_method();
#endif
    ctx    = SSL_CTX_new(method);
    /* SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF); */

#ifdef OPENSSL_EXTRA
    SSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
#endif

#ifndef NO_FILESYSTEM
    #ifdef HAVE_NTRU
        /* ntru */
        if (SSL_CTX_use_certificate_file(ctx, ntruCert, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
            err_sys("can't load ntru cert file");

        if (CyaSSL_CTX_use_NTRUPrivateKey_file(ctx, ntruKey)
                != SSL_SUCCESS)
            err_sys("can't load ntru key file");
    #elif HAVE_ECC
        /* ecc */
        if (SSL_CTX_use_certificate_file(ctx, eccCert, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
            err_sys("can't load server cert file");

        if (SSL_CTX_use_PrivateKey_file(ctx, eccKey, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
            err_sys("can't load server key file");
    #else
        /* normal */
        if (SSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
            err_sys("can't load server cert file");

        if (SSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
            err_sys("can't load server key file");
    #endif
#else
    load_buffer(ctx, svrCert, CYASSL_CERT);
    load_buffer(ctx, svrKey,  CYASSL_KEY);
#endif

    SignalReady(args);

    while (!shutdown) {
        SSL* ssl = 0;
        char command[1024];
        int  echoSz = 0;
        int  clientfd;
                
#ifndef CYASSL_DTLS 
        SOCKADDR_IN_T client;
        socklen_t     client_len = sizeof(client);
        clientfd = accept(sockfd, (struct sockaddr*)&client,
                         (ACCEPT_THIRD_T)&client_len);
#else
        clientfd = udp_read_connect(sockfd);
#endif
        if (clientfd == -1) err_sys("tcp accept failed");

        ssl = SSL_new(ctx);
        if (ssl == NULL) err_sys("SSL_new failed");
        SSL_set_fd(ssl, clientfd);
        SetDH(ssl);
        if (SSL_accept(ssl) != SSL_SUCCESS) {
            printf("SSL_accept failed\n");
            SSL_free(ssl);
            CloseSocket(clientfd);
            continue;
        }
#if defined(PEER_INFO)
        showPeer(ssl);
#endif

        while ( (echoSz = SSL_read(ssl, command, sizeof(command))) > 0) {
           
            if ( strncmp(command, "quit", 4) == 0) {
                printf("client sent quit command: shutting down!\n");
                shutdown = 1;
                break;
            }
            if ( strncmp(command, "break", 5) == 0) {
                printf("client sent break command: closing session!\n");
                break;
            }
#ifdef SESSION_STATS
            if ( strncmp(command, "printstats", 10) == 0) {
                PrintSessionStats();
                break;
            }
#endif
            if ( strncmp(command, "GET", 3) == 0) {
                char type[]   = "HTTP/1.0 200 ok\r\nContent-type:"
                                " text/html\r\n\r\n";
                char header[] = "<html><body BGCOLOR=\"#ffffff\">\n<pre>\n";
                char body[]   = "greetings from CyaSSL\n";
                char footer[] = "</body></html>\r\n\r\n";
            
                strncpy(command, type, sizeof(type));
                echoSz = sizeof(type) - 1;

                strncpy(&command[echoSz], header, sizeof(header));
                echoSz += sizeof(header) - 1;
                strncpy(&command[echoSz], body, sizeof(body));
                echoSz += sizeof(body) - 1;
                strncpy(&command[echoSz], footer, sizeof(footer));
                echoSz += sizeof(footer);

                if (SSL_write(ssl, command, echoSz) != echoSz)
                    err_sys("SSL_write failed");
                break;
            }
            command[echoSz] = 0;

            #ifdef ECHO_OUT
                fputs(command, fout);
            #endif

            if (SSL_write(ssl, command, echoSz) != echoSz)
                err_sys("SSL_write failed");
        }
#ifndef CYASSL_DTLS
        SSL_shutdown(ssl);
#endif
        SSL_free(ssl);
        CloseSocket(clientfd);
#ifdef CYASSL_DTLS
        tcp_listen(&sockfd);
        SignalReady(args);
#endif
    }

    CloseSocket(sockfd);
    SSL_CTX_free(ctx);

#ifdef ECHO_OUT
    if (outCreated)
        fclose(fout);
#endif

    ((func_args*)args)->return_code = 0;
    return 0;
}


/* so overall tests can pull in test function */
#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        func_args args;

        StartTCP();

        args.argc = argc;
        args.argv = argv;

        CyaSSL_Init();
#ifdef DEBUG_CYASSL
        CyaSSL_Debugging_ON();
#endif
        echoserver_test(&args);
        CyaSSL_Cleanup();

        return args.return_code;
    }

#endif /* NO_MAIN_DRIVER */



