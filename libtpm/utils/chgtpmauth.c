/********************************************************************************/
/*										*/
/*			     	TPM Change TPM Auth				*/
/*			     Written by J. Kravitz 				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: chgtpmauth.c 4073 2010-04-30 14:44:14Z kgoldman $		*/
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
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include "tpmfunc.h"

static void printUsage(void);

static int ownflag  = 0;


int main(int argc, char *argv[])
   {
   int ret;
   char *ownpass = NULL;
   char *newpass = NULL;
   unsigned char  ownphash[TPM_HASH_SIZE];
   unsigned char  newphash[TPM_HASH_SIZE];
   int 	i;
   
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
       else if (!strcmp(argv[i], "-pwdn")) {
	   i++;
	   if (i < argc) {
	       newpass = argv[i];
	   }
	   else {
	       printf("Missing parameter to -pwdn\n");
	       printUsage();
	   }
       }
       else if (strcmp(argv[i],"-own") == 0) {
	   ownflag = 1;
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
       (newpass == NULL)) {
       printf("Missing password argument\n");
       exit(2);
   }
   /*
   ** use the SHA1 hash of the password string as the TPM Owner Password
   */
   TSS_sha1((unsigned char*)ownpass,strlen(ownpass),ownphash);
   /*
   ** use the SHA1 hash of the password string as the New Authorization Data
   */
   TSS_sha1((unsigned char*)newpass,strlen(newpass),newphash);
   if (ownflag)
      {
      ret = TPM_ChangeOwnAuth(ownphash,newphash);
      if (ret != 0)
         {
         printf("Error %s from TPM_ChangeOwnAuth\n",TPM_GetErrMsg(ret));
         exit(1);
         }
      }
   else
      {
      ret = TPM_ChangeSRKAuth(ownphash,newphash);
      if (ret != 0)
         {
         printf("Error %s from TPM_ChangeSRKAuth\n",TPM_GetErrMsg(ret));
         exit(1);
         }
      }
   exit(0);
   }
   
static void printUsage()
   {
   printf("Usage: chgtpmauth [-own] -pwdo <TPM owner password> -pwdn <new SRK or Owner password>\n");
   printf("Runs TPM_ChangeAuthOwner\n");
   printf("\n");
   printf("    -own to specify the TPM Owner password is to be changed\n");
   printf("    -h print usage information (this message)\n");
   exit(1);
   }
