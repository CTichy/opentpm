/********************************************************************************/
/*										*/
/*		    Key control for control over attributes of key              */
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: keycontrol.c 4073 2010-04-30 14:44:14Z kgoldman $		*/
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
#include "tpmfunc.h"

/* local prototypes */

static void printUsage()
{
	printf("Usage: keycontrol -pwdk <keypassword> -hk <key handle> -bn <bit name>\n" 
               "                  -bv <bit value> -pwdo <owner password>\n" 
               "\n" 
               "-hk key handle       : handle of a loaded key; pass hex number\n"
               "-bn bit name         : name of the bit to change; use hex number\n"
               "-bv bit value        : 0 for false, 1 for true\n"
               "-pwdo owner password : the owner password\n"
               "\n");
	exit(-1);
}

int main(int argc, char *argv[])
{
	int ret = 0;
	uint32_t keyhandle = -1;
	char *keypass = NULL;
	char *ownerpass = NULL;
	unsigned char *keypassptr = NULL;
	unsigned char ownerhash[TPM_HASH_SIZE];
	unsigned char keypasshash[TPM_HASH_SIZE];
	uint32_t bitname = -1;
	uint32_t bitvalue = -1;
	keydata key;
	int i = 1;
	TPM_setlog(0);
	
	for (i=1 ; i<argc ; i++) {
	    if (!strcmp(argv[i], "-pwdk")) {
		i++;
		if (i < argc) {
		    keypass = argv[i];
		}
		else {
		    printf("Missing parameter to -pwdk\n");
		    printUsage();
		}
	    }
	    else if (!strcmp(argv[i], "-pwdo")) {
		i++;
		if (i < argc) {
		    ownerpass = argv[i];
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
	    else if (strcmp(argv[i],"-bn") == 0) {
		i++;
		if (i < argc) {
		    /* convert key handle from hex */
		    if (1 != sscanf(argv[i], "%x", &bitname)) {
			printf("Invalid -bn argument '%s'\n",argv[i]);
			exit(2);
		    }
		}
		else {
		    printf("-bn option needs a value\n");
		    printUsage();
		}
	    }
	    else if (strcmp(argv[i],"-bv") == 0) {
		i++;
		if (i < argc) {
		    /* convert key handle from hex */
		    if (1 != sscanf(argv[i], "%d", &bitvalue)) {
			printf("Invalid -bv argument '%s'\n",argv[i]);
			exit(2);
		    }
		}
		else {
		    printf("-bv option needs a value\n");
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

	if ((NULL == ownerpass) ||
	    (-1 == (int)keyhandle) ||
	    (-1 == (int)bitname)) {
	    printf("Missing or wrong parameter.\n");
	    printUsage();
	}

	if (bitvalue > 1) {
		bitvalue = 1;
	}

	if (NULL != keypass) {
		TSS_sha1(keypass, strlen(keypass), keypasshash);
		keypassptr = keypasshash;
	}

	ret = TPM_GetPubKey(keyhandle, keypassptr, &key.pub);
	if (ret != 0) {
		printf("Could not read the public key: '%s'.\n",
		       TPM_GetErrMsg(ret));
		exit(-1);
	}

	TSS_sha1(ownerpass, strlen(ownerpass), ownerhash);
	ret = TPM_KeyControlOwner(ownerhash,
				  keyhandle, 
				  &key,
				  bitname, 
				  (TPM_BOOL) bitvalue);

	if (0 != ret) {
		printf("Error %s from TPM_KeyControlOwner\n",
		       TPM_GetErrMsg(ret));
	} else {
		printf("Successfully changed flag on the key.\n");
	}

	exit(ret);
}
