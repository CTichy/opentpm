/********************************************************************************/
/*										*/
/*			     	TPM Update Verification				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: updateverification.c 4073 2010-04-30 14:44:14Z kgoldman $	*/
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
                     
#include "tpm.h"
#include "tpmutil.h"
#include <tpmfunc.h>

static void usage() {
	printf("Usage: updateverification [-v] [-o owner password>] input-file output-file\n"
	       "\n"
	       "-o <owner password> : password of the TPM owner\n"
	       "\n");
}


int main(int argc, char *argv[])
{
	uint32_t ret = 0;
	int verbose = FALSE;
	char * filename = NULL;
	char *out_filename = NULL;
	int i = 1;
	char *ownerpass = NULL;
	unsigned char ownerpasshash[TPM_HASH_SIZE];
	unsigned char *ownerHashPtr = NULL;
	struct stat _stat;

	TPM_setlog(0);

	while (i < argc) {
		if (!strcmp("-o",argv[i])) {
			i++;
			if (i < argc) {
				ownerpass = argv[i];
			} else {
				printf("Missing parameter for -o.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-v",argv[i])) {
			verbose = TRUE;
			TPM_setlog(1);
		} else
		if (!strcmp("-?",argv[i])) {
			usage();
			exit(0);
		} else {
			break;
		}
		i++;
	}

	if (i + 1 < argc) {
		filename = argv[i];
		i++;
		out_filename = argv[i+1];
	} else {
		printf("Missing parameter: filename(s)\n");
		usage();
		exit(-1);
	}

	if (NULL != ownerpass) {
		TSS_sha1(ownerpass, strlen(ownerpass), ownerpasshash);
		ownerHashPtr = ownerpasshash;
	}

	if (0 == stat(filename, &_stat)) {
		unsigned char *blob = malloc(_stat.st_size);
		uint32_t blobSize = _stat.st_size;
		unsigned char outBlob[1024];
		uint32_t outBlobSize = sizeof(outBlob);
		FILE *f;
		if (NULL == blob) {
			printf("Could not allocate memory!\n");
			exit(-1);
		}
		
		f = fopen(filename, "rb");
		if (NULL == f) {
			printf("Could not open file for reading.\n");
			exit(-1);
		}
		
		if (blobSize != fread(blob, 1, blobSize, f)) {
			printf("Could not read the file.\n");
			fclose(f);
			exit(-1);
		}
		fclose(f);
		ret = TPM_Delegate_UpdateVerification(blob, blobSize,
		                                      ownerHashPtr,
		                                      outBlob,&outBlobSize);

		if ( ret  != 0) {
			printf("Error '%s' from Delegate_UpdateVerification.\n",
			       TPM_GetErrMsg(ret));
			exit(-1);
		} else {
			printf("Successfully loaded the blob.\n");
			f = fopen(out_filename, "wb");
			if (NULL != f) {
				if (outBlobSize != fwrite(outBlob,
				                          1,
				                          outBlobSize,
				                          f)) {
					fclose(f);
					printf("Error, could not write to file!\n");
					exit(-1);
				} else {
					printf("Successfully wrote blob to file.\n");
				}
				fclose(f);
			}
		}
	
	} else {
		printf("Error, file %s not accessible.\n",filename);
	}

	exit(ret);
}
