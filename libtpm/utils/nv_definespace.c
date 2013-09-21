/********************************************************************************/
/*										*/
/*			    TCPA Define NV Storage Space			*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: nv_definespace.c 4073 2010-04-30 14:44:14Z kgoldman $	*/
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
	printf("Usage: nv_definespace [-pwdo <owner password>] -ix index -sz size [-per permission] [-pwdd <area password>] [-v]\n"
	       "\n"
	       " -pwdo pwd    : The TPM owner password, if TPM has an owner\n"
	       " -ix index    : Index of the memory to define in hex\n"
	       " -sz size      : Size of the memory in bytes\n"
	       " -per permission: A hex number that defines the permissions for the area of memory\n"
	       "                E.g. -per 40004 to set permissions to TPM_NV_PER_AUTHREAD|TPM_NV_PER_AUTHWRITE\n"
	       "                E.g. -per 20002 to set permissions to TPM_NV_PER_OWNERREAD|TPM_NV_PER_OWNERWRITE\n"
	       "                Default permissions 20000 allows reading only by the owner\n"
	       " -pwdd password  : The password for the memory area to protect.  If not specified, an\n"
               "                all zero value is used\n"
	       " -v           : Enable verbose output\n"
	       "\n"
	       "Examples:\n"
	       "nv_definespace -pwdo aaa -ix 1 -sz 10\n"
	       "nv_definespace -pwdo aaa -ix 2 -per 40004 -pwdd MyPWD\n");
	exit(-1);
}

int main(int argc, char * argv[]) {
	char * ownerpass = NULL;
	char * areapass = NULL;
	unsigned char * passptr1 = NULL;
	unsigned char * passptr2 = NULL;
	unsigned char passhash1[20];
	unsigned char passhash2[20];	
	uint32_t ret;
	int i =	0;
	TPM_NV_INDEX index = 0;
	TPM_BOOL index_set = FALSE;
	uint32_t size = 0xffffffff;
	uint32_t permissions = TPM_NV_PER_OWNERREAD;
	int verbose = FALSE;
	
	i = 1;
	
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-pwdo",argv[i])) {
			i++;
			if (i < argc) {
				ownerpass = argv[i];
			} else {
				printf("Missing mandatory parameter for -pwdo.\n");
				usage();
			}
		} else
		if (!strcmp("-ix",argv[i])) {
			i++;
			if (i < argc) {
				if (1 == sscanf(argv[i], "%x", &index)) {
				    index_set = TRUE;
				} else {
				    printf("Could not read index.\n");
				    exit(-1);
				}
			} else {
				printf("Missing mandatory parameter for -ix.\n");
				usage();
			}
		} else
		if (!strcmp("-sz",argv[i])) {
			i++;
			if (i < argc) {
				size = atoi(argv[i]);
				if ((int)size < 0) {
					printf("Negative size not allowed!\n");
					exit(-1);
				}
			} else {
				printf("Missing mandatory parameter for -ix.\n");
				usage();
			}
		} else
		if (!strcmp("-per",argv[i])) {
			i++;
			if (i < argc) {
				sscanf(argv[i],"%x",&permissions);
			} else {
				printf("Missing parameter for -x.\n");
				usage();
			}
		} else
		if (!strcmp("-pwdd",argv[i])) {
			i++;
			if (i < argc) {
				areapass = argv[i];
			} else {
				printf("Missing parameter for -pwdd.\n");
				usage();
			}
		} else
		if (!strcmp("-v",argv[i])) {
			verbose = TRUE;
			TPM_setlog(1);
		} else
		if (!strcmp("-h",argv[i])) {
			usage();
		} else {
			printf("\n%s is not a valid option\n", argv[i]);
			usage();
		}
		i++;
	}

	if ((FALSE == index_set) || (size == 0xffffffff)) {
		printf("Input parameters wrong or missing!\n");
		usage();
	}
	
	if (NULL != ownerpass) {
		TSS_sha1(ownerpass,strlen(ownerpass),passhash1);
		passptr1 = passhash1;
	} else {
		passptr1 = NULL;
	}

	if (NULL != areapass) {
		TSS_sha1(areapass,strlen(areapass),passhash2);
		passptr2 = passhash2;
	} else {
		passptr2 = NULL;
	}

	if (TRUE == verbose) {
		printf("index = %d = 0x%x\n",(int)index,(int)index);
	}

	/*
	 * Define a space in NV ram,
	 */

	ret = TPM_NV_DefineSpace2(passptr1,                // Sha(HMAC key)
	                          index,
	                          size,
	                          permissions,
	                          passptr2                 // NV auth   - used to create  encAuth
	                         );

	if (0 != ret) {
		printf("Got error '%s' from TPM_NV_DefineSpace2().\n",
		       TPM_GetErrMsg(ret));
	}

	exit(ret);
}
