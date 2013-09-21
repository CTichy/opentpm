/********************************************************************************/
/*										*/
/*			     	TPM Utility Functions				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpmutil_tty.c 4073 2010-04-30 14:44:14Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2006, 2010.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/


/* These are platform specific.  This version uses a character device interface.

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <windows.h>
#include <unistd.h>     

#ifdef TPM_POSIX
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#include <windows.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef USE_SERIAL_PORT
#include <termios.h>
#endif

#include <openssl/rand.h>
#include <openssl/sha.h>

#include "tpm.h"
#include "tpmfunc.h"
#include "tpm_types.h"
#include "tpm_constants.h"
#include "tpmutil.h"
#include "tpm_lowlevel.h"

/* local prototypes */
static uint32_t TPM_OpenClientCharDev(int *sock_fd);
static uint32_t TPM_CloseClientCharDev(int sock_fd);
static uint32_t TPM_ReceiveCharDev(int sock_fd, struct tpm_buffer *tb);
static uint32_t TPM_TransmitCharDev(int sock_fd, struct tpm_buffer *tb,
                                    const char *mgs);
#ifdef USE_PARTIAL_READ
static uint32_t TPM_ReceiveBytes(int sock_fd,
                                 unsigned char *buffer,
                                 size_t nbytes);
#endif
#ifdef USE_SERIAL_PORT
   static struct termios saved_terminos;
   static enum { RAW, RESET } tty_state = RESET;

   static uint32_t set_tty(int fd) ;
   static uint32_t reset_tty(int fd) ;
#endif
/* local variables */
#define DEFAULT_TPM_DEVICE "\\\\.\\OPENTPM"
#define VTPM_SOCKET "/var/vtpm/vtpm.socket"

static struct tpm_transport char_transport = {
    .open = TPM_OpenClientCharDev,
    .close = TPM_CloseClientCharDev,
    .send = TPM_TransmitCharDev,
    .recv  = TPM_ReceiveCharDev,
};

void TPM_LowLevel_TransportCharDev_Set(void)
{
    TPM_LowLevel_Transport_Set(&char_transport);
}


/****************************************************************************/
/*                                                                          */
/* Open the socket to the TPM Host emulation                                */
/*                                                                          */
/****************************************************************************/

static uint32_t 
TPM_OpenClientSocket_UnixIO(int *sock_fd)
{
    struct stat         _stat;
    if (0 == stat(VTPM_SOCKET, &_stat)) {
        if (S_ISSOCK(_stat.st_mode)) {
            *sock_fd = socket(PF_UNIX, SOCK_STREAM, 0);
            if (*sock_fd > 0) {
                struct sockaddr_un addr;
                addr.sun_family = AF_UNIX;
                strcpy(addr.sun_path, VTPM_SOCKET);
                if (connect(*sock_fd,
                            (struct sockaddr *)&addr,
                            sizeof(addr)) == 0) {
                    return 0;
                } else {
                    close(*sock_fd);
                    *sock_fd = 0;
                }
            }
        }
    }
    return ERR_IO;
}

static uint32_t TPM_OpenClientCharDev(int *sock_fd)
{
printf("corey: TPM_OpenClientCharDev called and set sock_fd to 1\n");
*sock_fd = 1;
    return 0;
}
/****************************************************************************/
/*                                                                          */
/* Close the socket to the TPM Host emulation                               */
/*                                                                          */
/****************************************************************************/

static uint32_t TPM_CloseClientCharDev(int sock_fd)
{
    return 0;
}

/* write buffer to socket sock_fd */

static uint32_t TPM_TransmitCharDev(int sock_fd, struct tpm_buffer *tb,
                                    const char *msg)
{
    HANDLE hFile;
    unsigned int nbytes = 0;
    unsigned int nwritten = 0;
    unsigned int nleft = 0;
    unsigned int offset = 0;
    unsigned int ret;
  
    printf("TPM_TransmitCharDev called\n");
    ret = tpm_buffer_load32(tb, TPM_PARAMSIZE_OFFSET, &nbytes);
    
    //size = ntohl(*(unsigned int *)&tb->buffer[2]);
    //printf("transmit size: %d\n", size);
    sleep(1);
    hFile = CreateFile("\\\\.\\OPENTPM", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (!hFile)
    {
    	printf("corey: TPM_TransmitCharDev CreateFile failed\n");
    	return 0;
    }
    nleft = nbytes;
    while (nleft > 0)
    {
    	WriteFile(hFile, &tb->buffer[offset], nleft, &nwritten, NULL);
    	nleft -= nwritten;
    	offset += nwritten;
    	printf("TransmitCharDev: nwritten: %d nleft: %x\n", nwritten, nleft);
    } 
    //WriteFile(hFile, tb->buffer, size, &ret, NULL);
    CloseHandle(&hFile);
    //printf("WriteFile  ret: %d\n", ret);
    printf("TPM_TransmitCharDev returning\n");
    return 0;
}

/* read a TPM packet from socket sock_fd */

static uint32_t
TPM_ReceiveCharDev(int sock_fd, struct tpm_buffer *tb)
{
    HANDLE hFile;
    unsigned int size;
    unsigned int ret;
    unsigned int i;
    unsigned int paramSize;
    unsigned int rc;
    sleep(1);
    hFile = CreateFile("\\\\.\\OPENTPM", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    printf("TPM_ReceiveCharDev called\n");
    if (!hFile)
    {
    	printf("corey: TPM_ReceiveCharDev CreateFile failed\n");
    	return 0;
    }
    memset(tb->buffer, 0x00, 4096);
    ReadFile(hFile, tb->buffer, 4096, &ret, NULL);
    CloseHandle(&hFile); 
    printf("readFile ret: %d\n", ret);
    for (i=0;i<ret;i++)
    {
     printf("%02x ", tb->buffer[i]);
    }
    
    printf("\n");
    paramSize = LOAD32(tb->buffer, TPM_PARAMSIZE_OFFSET);
    tb->used = paramSize;
    tpm_buffer_load32(tb,TPM_RETURN_OFFSET,&rc);
    printf("TPM_ReceiveCharDev returning\n");
    return rc;
}    

