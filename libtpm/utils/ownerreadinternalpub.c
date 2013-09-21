/********************************************************************************/
/*										*/
/*			     	TPM OwnerReadInternalPub			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: ownerreadinternalpub.c 4073 2010-04-30 14:44:14Z kgoldman $	*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include "tpm.h"
#include "tpmutil.h"
#include <tpmfunc.h>

static void printUsage() {
    printf("Usage: ownerreadinternalpub [Options] -hk <keyhandle> -of <filename> -pwdo <owner password>\n"
	       "\n"
	       "Reads the internally held public key protion of either the endorsement\n"
	       "key or the storage root key. The handle of the endorsement key is 0x40000006\n"
	       "and the one of the SRK is 0x40000000.\n"
	       "\n"
	       "Possible Options are:\n"
	       "-v    : to enable verbose output\n"
	       "\n"
	       "Examples:\n"
	   "ownerreadinternalpub -hk 40000000 -of srk.pub -pwdo ooo\n");
	exit(-1);
}


int main(int argc, char *argv[])
{
	unsigned char passhash1[20];
	char * ownpass = NULL;
	int ret;
	char * filename = NULL;
	uint32_t keyhandle = 0;
	STACK_TPM_BUFFER(keybuf);
	keydata k;
	
	int i = 1;
	memset(&k, 0x0, sizeof(k));
	
	TPM_setlog(0);
	
	for (i=1 ; i<argc ; i++) {
	    if (!strcmp(argv[i], "-pwdo")) {
		i++;
		if (i < argc) {
		    ownpass = argv[i];
		}
		else {
		    printf("Missing parameter to -pwdo\n");
		    printUsage();
		}
	    }
	    else if (strcmp(argv[i],"-hk") == 0) {
		i++;
		if (i < argc) {
		    /* convert key handle from hex */
		    if (1 != sscanf(argv[i], "%x", &keyhandle)) {
			printf("Invalid -hk argument '%s'\n",argv[i]);
			exit(2);
		    }
		}
		else {
		    printf("-hk option needs a value\n");
		    printUsage();
		}
	    }
	    else if (strcmp(argv[i],"-of") == 0) {
		i++;
		if (i < argc) {
		    filename = argv[i];
		}
		else {
		    printf("-of option needs a value\n");
		    printUsage();
		}
	    }
	    else if (!strcmp(argv[i], "-h")) {
		printUsage();
	    }
	    else if (!strcmp(argv[i], "-v")) {
		TPM_setlog(1);
	    }
	    else {
		printf("\n%s is not a valid option\n", argv[i]);
		printUsage();
	    }
	}
	if ((ownpass == NULL) ||
	    (keyhandle == 0) ||
	    (filename == NULL)) {
	    printf("Missing argument\n");
	    printUsage();
	    exit(2);
	}
	TSS_sha1(ownpass,strlen(ownpass),passhash1);
	ret = TPM_OwnerReadInternalPub(keyhandle,
	                               passhash1,
	                               &k.pub);
	if (0 != ret) {
		printf("OwnerReadInternalPub returned error '%s' (0x%x).\n",
		       TPM_GetErrMsg(ret),
		       ret);
	} else {
		uint32_t ret;
		FILE * f = fopen(filename, "wb");
		ret = TPM_WriteKeyPub(&keybuf, &k);
		if (NULL != f) {
			fwrite(keybuf.buffer,keybuf.used,1,f);
			fclose(f);
		}
	}
	exit(ret);
}

