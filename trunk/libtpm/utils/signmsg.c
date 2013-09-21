/********************************************************************************/
/*										*/
/*			     	TPM Sign a Message				*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: signmsg.c 4073 2010-04-30 14:44:14Z kgoldman $		*/
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
#include <unistd.h>
#include "tpmfunc.h"
#include <openssl/sha.h>

#define	VALID_ARGS	"k:?"
   
static int ParseArgs(int argc, char *argv[]);
static void usage(void);

static char *keypass = NULL;

int main(int argc, char *argv[])
   {
   int ret;
   uint32_t parhandle;             /* handle of parent key */
   unsigned char passhash[TPM_HASH_SIZE];     /* hash of parent key password */
   unsigned char datahash[TPM_HASH_SIZE];     /* hash of data file */
   unsigned char sig[4096];        /* resulting signature */
   uint32_t  siglen;           /* signature length */
   unsigned char *passptr;
   char *indata;
   FILE *sigfile;
   
   int nxtarg;
   
   nxtarg = ParseArgs(argc, argv);
   if (argc < (nxtarg + 3) ) usage();
   TPM_setlog(0);                  /* turn off verbose output */
   /*
   ** convert parent key handle from hex
   */
   ret = sscanf(argv[nxtarg+0],"%x",&parhandle);
   if (ret != 1)
      {
      printf("Invalid argument '%s'\n",argv[nxtarg+0]);
      exit(2);
      }
   /*
   ** use the SHA1 hash of the password string as the Key Authorization Data
   */
   if (keypass != NULL)
      {
      TSS_sha1(keypass,strlen(keypass),passhash);
      passptr = passhash;
      }
   else passptr = NULL;
   /*
   ** read and hash the message
   */
   indata = argv[nxtarg+1];
   if (indata == NULL)
      {
      printf("Unable to get input data'\n");
      exit(-2);
      }
   TSS_sha1(indata,strlen(indata),datahash);

   ret = TPM_Sign(parhandle,              /* Key Handle */
                  passptr,                /* key Password */
                  datahash,sizeof (datahash),     /* data to be signed, length */
                  sig,&siglen);           /* buffer to receive sig, int to receive sig length */
   if (ret != 0)
      {
      printf("Error %s from TPM_Sign\n",TPM_GetErrMsg(ret));
      exit(1);
      }
   sigfile = fopen(argv[nxtarg+2],"wb");
   if (sigfile == NULL)
      {
      printf("Unable to open output file '%s'\n",argv[nxtarg+2]);
      exit(4);
      }
   ret = fwrite(sig,1,siglen,sigfile);
   if (ret != (int)siglen)
      {
      printf("I/O Error while writing output file '%s'\n",argv[nxtarg+2]);
      exit(5);
      }
   fclose(sigfile);
   exit(0);
   }
   
/**************************************************************************/
/*                                                                        */
/*  Parse Arguments                                                       */
/*                                                                        */
/**************************************************************************/
static int ParseArgs(int argc, char *argv[])
   {
   int opt;

   if (argc == 2 && *argv[1] == '?') usage();
   /*
    * Loop over the command line looking for arguments.
    */
   while ((opt = getopt (argc, argv, VALID_ARGS)) != -1)
      {
      switch (opt)
         {
      case 'k':
         if (*optarg == '-')
            {
            printf("option -k missing an argument\n");
            usage();
            }
         keypass = optarg;
         break;
      case '?':
      default :
         usage();
         }
      }
   return optind;
   }

static void usage()
   {
   printf("Usage: signfile [options] <key handle in hex> <input data> <output file>\n");
   printf("\n");
   printf("   Where the arguments are...\n");
   printf("    <keyhandle>   is the key handle in hex\n");
   printf("    <input data>  arbitrary data that will be SHA1 hashed and then signed\n");
   printf("    <output file> is the file to contain the signed data\n");
   printf("\n");
   printf("   Where the <options> are...\n");
   printf("    -k <keypass>      to specify the key use password\n");
   printf("    -?                print usage information (this message)\n");
   exit(1);
   }
