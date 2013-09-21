/********************************************************************************/
/*										*/
/*			     	TPM Test of TPM Take Ownership			*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: takeown.c 4073 2010-04-30 14:44:14Z kgoldman $		*/
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
#include <string.h>
#include "tpmfunc.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

static void printUsage(void)
{
    printf("Usage: takeown [-v12] [-sz keylen] -pwdo <owner password> \n"
	   "   [-pwds <storage root key password>]\n");
}

int main(int argc, char *argv[])
{
	int ret;
	unsigned char pass1hash[20];
	unsigned char pass2hash[20];
	keydata srk;
	RSA *rsa = NULL;       	/* OpenSSL format Public Key */
	FILE *keyfile;    	/* output file for public key */
	EVP_PKEY *pkey = NULL;  /* OpenSSL public key */
	int keylen = 2048;
	int i;

	TPM_setlog(0);		/* turn off verbose output */
	TPM_BOOL v12 = FALSE;
	const char *ownerAuth = NULL;
	const char *srkAuth = NULL;
	
	for (i=1 ; (i<argc)  ; i++) {
	    if (!strcmp(argv[i], "-v12")) {
		v12 = TRUE;
	    }
	    else if (!strcmp(argv[i], "-sz")) {
		i++;
		if (i < argc) {
		    if (1 != sscanf(argv[i], "%d", &keylen)) {
			printf("Could not parse keylen.\n");
			exit(-1);
		    }
		}
		else {
		    printf("Missing parameter for '-sz'.\n");
		    printUsage();
		    exit(-1);
		}
		if (keylen < 512) {
		    printf("Unacceptable key length of %d\n",keylen);
		    exit(-1);
		}
	    }
	    else if (strcmp(argv[i],"-pwdo") == 0) {
		i++;
		if (i < argc) {
		    ownerAuth = argv[i];
		}
		else {
		    printf("pwdo option needs a value\n");
		    printUsage();
		    exit(2);
		}

	    }
	    else if (strcmp(argv[i],"-pwds") == 0) {
		i++;
		if (i < argc) {
		    srkAuth = argv[i];
		}
		else {
		    printf("-pwds option needs a value\n");
		    printUsage();
		    exit(2);
		}

	    }
	    else if (strcmp(argv[i],"-v") == 0) {
		TPM_setlog(1);
	    }
	    else if (strcmp(argv[i],"-h") == 0) {
		printUsage();
		exit(2);
	    }
	    else {
		printf("\n%s is not a valid option\n",argv[i]);
		printUsage();
		exit(2);
	    }
	}
	if (ownerAuth == NULL) {
	    printf("\nMissing -pwdo argument\n");
	    printUsage();
	    exit(2);
	}
	    
	
	/*
	** use the SHA1 hash of the password string as the Owner Authorization Data
	*/
	TSS_sha1((unsigned char *)ownerAuth,
	         strlen(ownerAuth),
	         pass1hash);
	/*
	** use the SHA1 hash of the password string as the SRK Authorization Data
	*/
	if (srkAuth != NULL) {
	    TSS_sha1((unsigned char *)srkAuth,
		     strlen(srkAuth),
		     pass2hash);
	    ret = TPM_TakeOwnership(pass1hash,pass2hash,keylen,&srk, v12);
	} else {
	    ret = TPM_TakeOwnership(pass1hash,NULL,keylen,&srk, v12);
	}
	if (ret != 0) {
		printf("Error %s from TPM_TakeOwnership\n",TPM_GetErrMsg(ret));
		exit(ret);
	}
	
	if (v12 == TRUE) {
	    if (srk.v.tag != TPM_TAG_KEY12) {
		printf("SRK should be a TPM_KEY12.\n");
		exit(-1);
	    }
	}
	/*
	** convert the returned public key to OpenSSL format and
	** export it to a file
	*/
	rsa = TSS_convpubkey(&(srk.pub));
	if (rsa == NULL) {
		printf("Error from TSS_convpubkey\n");
		exit(-3);
	}
	OpenSSL_add_all_algorithms();
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
	    printf("Unable to create EVP_PKEY\n");
	    exit(-4);
	}
	ret = EVP_PKEY_assign_RSA(pkey,rsa);
	if (ret == 0) {
	    printf("Unable to assign public key to EVP_PKEY\n");
	    exit(-5);
	}
	keyfile = fopen("srk.pem","wb");
	if (keyfile == NULL) {
		printf("Unable to create public key file\n");
		exit(-6);
	}
	ret = PEM_write_PUBKEY(keyfile,pkey);
	if (ret == 0) {
		printf("Unable to write public key file\n");
		exit(-7);
	}
	fclose(keyfile);
	EVP_PKEY_free(pkey);
	exit(0);
}
