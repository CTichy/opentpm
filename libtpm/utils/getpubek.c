/********************************************************************************/
/*										*/
/*			     	TPM Read Endorsement Public Key			*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: getpubek.c 4073 2010-04-30 14:44:14Z kgoldman $		*/
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

/* local prototypes */
void printUsage(void);

int main(int argc, char *argv[])
   {
   int ret = 0;
   int i;
   unsigned char pass1hash[20];
   pubkeydata pubek;
   RSA *rsa;                       /* OpenSSL format Public Key */
   FILE *keyfile;                  /* output file for public key */
   EVP_PKEY *pkey = NULL;          /* OpenSSL public key */
   const char *ownpass = NULL;
   
   TPM_setlog(0); /* turn off verbose output */

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
   if (ownpass != NULL)  /* if password is specified, use OwnerReadKey */
      {
      TSS_sha1((unsigned char *)ownpass ,strlen(ownpass),pass1hash);
      ret = TPM_OwnerReadPubek(pass1hash,&pubek);
      if (ret != 0)
         {
         printf("Error %s from TPM_OwnerReadPubek\n",TPM_GetErrMsg(ret));
         exit(-2);
         }
      }
   else           /* if no password specified, use ReadEKey */
      {
      ret = TPM_ReadPubek(&pubek);
      if (ret != 0)
         {
         printf("Error %s from TPM_ReadPubek.\n",TPM_GetErrMsg(ret));
         exit(ret);
         }
      }
   /*
   ** convert the returned public key to OpenSSL format and
   ** export it to a file
   */
   rsa = TSS_convpubkey(&pubek);
   if (rsa == NULL)
      {
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
   keyfile = fopen("pubek.pem","wb");
   if (keyfile == NULL)
      {
      printf("Unable to create public key file\n");
      exit(-5);
      }
   ret = PEM_write_PUBKEY(keyfile,pkey);
   if (ret == 0)
      {
      printf("Unable to write public key file\n");
      exit(-6);
      }
   printf("pubek.pem successfully written\n");
   printf("Pubek keylength %d\nModulus:",pubek.pubKey.keyLength);
   for(i=0;i<(int)pubek.pubKey.keyLength;i++){
       if(!(i%16))
           printf("\n");
       printf("%02X ",pubek.pubKey.modulus[i]);
   }
   printf("\n");

   fclose(keyfile);
   EVP_PKEY_free(pkey);
   exit(0);
   }

void printUsage(void)
{
    printf("\n");
    printf("getpubek [-pwdo owner password]\n");
    printf("\n");
    printf("With owner password - runs TPM_OwnerReadPubek\n");
    printf("Without owner password - runs TPM_ReadPubek\n");
    printf("\n");
    exit(1);
}
