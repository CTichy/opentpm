/********************************************************************************/
/*										*/
/*			    TCPA Release a counter				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: counter_release.c 4073 2010-04-30 14:44:14Z kgoldman $	*/
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
#include <unistd.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include "tpm.h"
#include "tpmutil.h"
#include "tpmfunc.h"
#include "tpm_constants.h"
#include "tpm_structures.h"


static void usage() {
	printf("Usage: counter_release -pwdo <owner password> -ix id -pwdc cntrpwd[-v]\n");
	printf("\n");
	printf(" -pwdo ownerpass : the TPM owner password; not necessary if -pwdc is provided\n");
	printf(" -ix id          : The id of the counter.\n");
	printf(" -pwdc cntrpwd   : The counter password; not necessary if -pwdo is provided \n");
	printf(" -v              : Enable verbose output.\n");
	printf("\n");
	printf("Examples:\n");
	printf("counter_release -pwdo aaa -ix 5\n"
	       "counter_release -ix 5 -pwdc ctr1\n");
	exit(-1);
}

int main(int argc, char * argv[]) {
	char * ownerpass = NULL;
	char * counterpass = NULL;
	unsigned char * passptr1 = NULL;
	unsigned char * passptr2 = NULL;
	unsigned char passhash1[20];
	unsigned char passhash2[20];	
	uint32_t ret;
	int i =	0;
	uint32_t id = -1;
	
	i = 1;
	
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-ix",argv[i])) {
			i++;
			if (i < argc) {
				id = atoi(argv[i]);
			} else {
				printf("Missing mandatory parameter for -ix.\n");
				usage();
			}
		} else
		if (!strcmp("-pwdc",argv[i])) {
			i++;
			if (i < argc) {
				counterpass = argv[i];
			} else {
				printf("Missing parameter for -pwdc.\n");
				usage();
			}
		} else
		if (!strcmp("-pwdo",argv[i])) {
			i++;
			if (i < argc) {
				ownerpass = argv[i];
			} else {
				printf("Missing parameter for -pwdo.\n");
				usage();
			}
		} else
		if (!strcmp("-v",argv[i])) {
			TPM_setlog(1);
		} else
		if (!strcmp("-h",argv[i])) {
			usage();
		} else {
			printf("\n%s is not a valid option\n",argv[i]);
			usage();
		}
		i++;
	}

	if ((NULL == counterpass && NULL == ownerpass) || (int)id < 0) {
		printf("Input parameter missing!\n");
		usage();
	}
	
	
	if (NULL != ownerpass) {
		TSS_sha1(ownerpass,strlen(ownerpass),passhash1);
		passptr1 = passhash1;
	} else {
		passptr1 = NULL;
	}

	if (NULL != counterpass) {
		TSS_sha1(counterpass,strlen(counterpass),passhash2);
		passptr2 = passhash2;
	} else {
		passptr2 = NULL;
	}


	if (counterpass != NULL) {
		ret= TPM_ReleaseCounter(id,
		                        passptr2);
		if (0 != ret) {
			printf("Got error '%s' (0x%x) from TPM_ReleaseCounter.\n",
			       TPM_GetErrMsg(ret),
			       ret);
		}
	} else {
		ret = TPM_ReleaseCounterOwner(id,
		                              passptr1);
		if (0 != ret) {
			printf("Got error '%s' (0x%x) from TPM_ReleaseCounterOwner.\n",
			       TPM_GetErrMsg(ret),
			       ret);
		}
	}

	if (0 == ret) {
		printf("Successfully released the counter.\n");
	}

	return ret;
}
