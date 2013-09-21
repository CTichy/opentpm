/********************************************************************************/
/*										*/
/*			    TCPA Write to NV Storage				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: nv_writevalue.c 4073 2010-04-30 14:44:14Z kgoldman $		*/
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


/* local functions */


static void usage() {
	printf("Usage: nv_writevalue [-pwdo <owner password>] -ix index -ic data [-off offset] [-pwdd <area password>]\n");
	printf("\n");
	printf(" -pwdo pwd    : The TPM owner password.\n");
	printf(" -ix index    : The index of the memory to use in hex.\n");
	printf(" -ic data      : The data to write into the memory (default data length 0.\n");
	printf(" -off offset    : The offset where to start writing (default 0).\n");
	printf(" -pwdd password  : The password for the memory area.\n");
	printf(" -ee num      : Expected error\n");
	printf("\n");
        printf("With -pwdo, does TPM_WriteValue\n");
        printf("With -pwdd, does TPM_WriteValueAuth\n");
        printf("With neither, does TPM_WriteValue with no authorization\n");
        printf("\n");
	printf("Examples:\n");
	printf("nv_writevalue -pwdo ooo -ix 1 -ic Hello\n");
	printf("nv_writevalue -pwdd aaa -ix 2 -ic Hello -off 5\n");
	exit(-1);
}


int main(int argc, char * argv[]) {
	char * ownerpass = NULL;
	char * areapass = NULL;
	unsigned char * passptr1 = NULL;
	unsigned char * passptr2 = NULL;
	unsigned char passhash1[20];
	unsigned char passhash2[20];	
	uint32_t ret = 0;
	uint32_t offset = 0;
	int i =	0;
	TPM_NV_INDEX index = 0xffffffff;
	unsigned char * data = NULL;
	unsigned int datalen = 0;
	uint32_t expectederror = 0;
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
		if (!strcmp("-ic",argv[i])) {
			i++;
			if (i < argc) {
				data = (unsigned char*)argv[i];
			} else {
				printf("Missing mandatory parameter for -ic.\n");
				usage();
			}
		} else
		if (!strcmp("-ix",argv[i])) {
			i++;
			if (i < argc) {
			    if (1 != sscanf(argv[i], "%x", &index)) {
				printf("Could not parse index '%s'.\n", argv[i]);
				exit(-1);
			    }
			} else {
			    printf("Missing mandatory parameter for -ix (NV space index).\n");
			    usage();
			}
		} else
		if (!strcmp("-off",argv[i])) {
			i++;
			if (i < argc) {
				offset = atoi(argv[i]);
			} else {
				printf("Missing optional parameter for -off.\n");
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
		if (!strcmp("-ee",argv[i])) {
			i++;
			if (i < argc) {
				expectederror = atoi(argv[i]);
			} else {
				printf("Missing parameter for -ee.\n");
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

	if (NULL == data) {
	    datalen = 0;
	}
	else {
	    datalen = strlen((char *)data);
	}
	if (index == 0xffffffff) {
	    printf("\nInput index parameter wrong or missing!\n");
	    usage();
	}
	if (TRUE == verbose) {
		printf("Using ownerpass : %s\n",ownerpass);
		printf("Using areapass: %s\n",areapass);
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

        /* if no area password specified, do owner read (either auth-1 or no auth) */
	if (NULL == areapass) {
		ret = TPM_NV_WriteValue(index,
		                        offset,
		                        data, datalen,
		                        passptr1 );
		if (0 != ret) {
			if (ret == expectederror) {
				printf("Success.\n");
			} else {
				printf("Error %s from NV_WriteValue\n",
				       TPM_GetErrMsg(ret));
			}
		}
	}
        /* if area password specified, and no owner password */
        else if (NULL == ownerpass) {
		ret = TPM_NV_WriteValueAuth(index,
		                            offset,
		                            data, datalen,
		                            passptr2 );
		if (0 != ret) {
			if (ret == expectederror) {
				printf("Success.\n");
			} else {
				printf("Error %s from NV_WriteValueAuth\n",
				       TPM_GetErrMsg(ret));
			}
		}
	}
        /* if both area and owner password specified */
        else {
            printf("Owner and area password cannot both be specified\n");
            usage();
        }
	
	exit(ret);
}
