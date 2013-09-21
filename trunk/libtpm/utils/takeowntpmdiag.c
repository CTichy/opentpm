/********************************************************************************/
/*										*/
/*			     	TPM Test of TPM Take Ownership			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: takeowntpmdiag.c 4073 2010-04-30 14:44:14Z kgoldman $	*/
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


/* modified for tpmdiag SRK password SRK PWD (8 characters with space and null) */

#include <stdio.h>
#include <string.h>
#include "tpmfunc.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

int main(int argc, char *argv[])
   {
   int ret;
   unsigned char pass1hash[20];
   unsigned char pass2hash[20];
   keydata srk;
   RSA *rsa;                       /* OpenSSL format Public Key */
   FILE *keyfile;                  /* output file for public key */
   EVP_PKEY *pkey = NULL;          /* OpenSSL public key */
   
   if (argc < 2)
      {
      printf("Usage: takeown <owner password> [<storage root key password>]\n");
      exit(1);
      }
   TPM_setlog(0);      /* turn off verbose output */
   /*
   ** use the SHA1 hash of the password string as the Owner Authorization Data
   */
   TSS_sha1((unsigned char*)argv[1],strlen(argv[1]),pass1hash);
   /*
   ** use the SHA1 hash of the password string as the SRK Authorization Data
   */
   if (argc > 2)
      {
      TSS_sha1((unsigned char *)argv[2],strlen(argv[2]),pass2hash);
      ret = TPM_TakeOwnership12(pass1hash,pass2hash,&srk);
      }
   else
      {
      TSS_sha1((unsigned char *)"SRK PWD",8,pass2hash);	/* hard code for tpmdiag */
      ret = TPM_TakeOwnership12(pass1hash,pass2hash,&srk);
      }
   if (ret != 0)
      {
      printf("Error %s from TPM_TakeOwnership\n",TPM_GetErrMsg(ret));
      exit(2);
      }
   /*
   ** convert the returned public key to OpenSSL format and
   ** export it to a file
   */
   rsa = TSS_convpubkey(&(srk.pub));
   if (rsa == NULL)
      {
      printf("Error from TSS_convpubkey\n");
      exit(3);
      }
   OpenSSL_add_all_algorithms();
   pkey = EVP_PKEY_new();
   if (pkey == NULL) {
       printf("Unable to create EVP_PKEY\n");
       exit(4);
   }
   ret = EVP_PKEY_assign_RSA(pkey,rsa);
   keyfile = fopen("srk.pem","wb");
   if (keyfile == NULL)
      {
      printf("Unable to create public key file\n");
      exit(5);
      }
   ret = PEM_write_PUBKEY(keyfile,pkey);
   if (ret == 0)
      {
      printf("Unable to write public key file\n");
      exit(6);
      }
   fclose(keyfile);
   EVP_PKEY_free(pkey);
   exit(0);
   }
