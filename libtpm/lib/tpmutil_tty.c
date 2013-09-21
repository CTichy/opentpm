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
    return ERR_IO;
}

static uint32_t TPM_OpenClientCharDev(int *sock_fd)
{
//corey - do nothing
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
//corey - do nothing
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
	unsigned int i;

    ret = tpm_buffer_load32(tb, TPM_PARAMSIZE_OFFSET, &nbytes);
    
    hFile = CreateFile("\\\\.\\OPENTPM", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (!hFile)
    {
    	printf("TPM_TransmitCharDev CreateFile failed\n");
    	return 0;
    }
    nleft = nbytes;
    while (nleft > 0)
    {
    	WriteFile(hFile, &tb->buffer[offset], nleft, &nwritten, NULL);
    	nleft -= nwritten;
    	offset += nwritten;
    }
	#ifdef SNIFF_TPM
	printf("sniffing send data\n");
	for (i=0;i<nbytes;i++)
	{
		if (i!=0 && i%16 == 0)
			printf("\n");
		printf("%02x ", tb->buffer[i]);
	}
	printf("\n");
	#endif
    CloseHandle(&hFile);
    return 0;
}

/* read a TPM packet from socket sock_fd */

static uint32_t
TPM_ReceiveCharDev(int sock_fd, struct tpm_buffer *tb)
{
    HANDLE hFile;
    unsigned int ret;
    unsigned int paramSize;
    unsigned int rc;
	unsigned int i;
	
    hFile = CreateFile("\\\\.\\OPENTPM", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (!hFile)
    {
    	printf("TPM_ReceiveCharDev CreateFile failed\n");
    	return 0;
    }
    
    memset(tb->buffer, 0x00, 4096);
    ReadFile(hFile, tb->buffer, 4096, &ret, NULL);
    CloseHandle(&hFile); 
    
    paramSize = LOAD32(tb->buffer, TPM_PARAMSIZE_OFFSET);
    tb->used = paramSize;
    tpm_buffer_load32(tb,TPM_RETURN_OFFSET,&rc);
	#ifdef SNIFF_TPM
	printf("sniffing recv data\n");
	for (i=0;i<tb->used;i++)
	{
		if (i!=0 && i%16 == 0)
			printf("\n");
		printf("%02x ", tb->buffer[i]);
	}
	printf("\n");
	#endif
	return rc;
}    

