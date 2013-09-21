/********************************************************************************/
/*										*/
/*			     	TPM Enable audit				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: enableaudit.c 4073 2010-04-30 14:44:14Z kgoldman $		*/
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

static void usage() {
	printf("Usage: enableaudit -o <ordinal> -p <owner password> [-d] [-v]\n"
	       "\n"
	       "-o    : option to pass the ordinal for the audit\n"
	       "-p    : the owner password\n"
	       "-d    : to disable the audit; default is enabling\n"
	       "-v    : turns on verbose mode\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	uint32_t ordinal = -1;
	int ret;
	int verbose = FALSE;
	int i = 1;
	unsigned char ownerAuth[TPM_DIGEST_SIZE];
	char * ownerpass = NULL;
	TPM_BOOL auditState = TRUE;
	
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-o",argv[i])) {
			i++;
			if (i < argc) {
				sscanf(argv[i],"%d",&ordinal);
			} else {
				printf("Missing parameter for -o.\n");
				usage();
				exit(-1);
			}
		}
		else if (!strcmp("-p",argv[i])) {
			i++;
			if (i < argc) {
				ownerpass = argv[i];
			} else {
				printf("Missing parameter for -p.\n");
				usage();
				exit(-1);
			}
		}
		else if (!strcmp("-d",argv[i])) {
			auditState = FALSE;
		}
		else if (!strcmp("-v",argv[i])) {
			verbose = TRUE;
			TPM_setlog(1);
		}
		else if (!strcmp("-h",argv[i])) {
		    usage();
		    exit(-1);
		}
		else {
		    printf("\n%s is not a valid option\n",argv[i]);
		    usage();
		    exit(-1);
		}
		i++;
	}
	
	if (-1 == (int)ordinal ||
	    NULL == ownerpass) {
		printf("Missing mandatory parameter.\n");
		usage();
		exit(-1);
	}
	
	TSS_sha1(ownerpass,strlen(ownerpass),ownerAuth);

	ret = TPM_SetOrdinalAuditStatus(ordinal,
	                                auditState,
	                                ownerAuth);
	if (ret != 0) {
		printf("SetOrdinalAuditStatus returned error %s.\n",
		        TPM_GetErrMsg(ret));
	}

	exit(ret);
}
