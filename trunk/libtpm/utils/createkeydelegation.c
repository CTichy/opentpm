/********************************************************************************/
/*										*/
/*			     	TPM Create key delegation			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: createkeydelegation.c 4073 2010-04-30 14:44:14Z kgoldman $	*/
/*										*/
/*			       IBM Confidential					*/
/*			     OCO Source Materials				*/
/*			 (c) Copyright IBM Corp. 2010				*/
/*			      All Rights Reserved			        */
/*										*/
/*	   The source code for this program is not published or otherwise	*/
/*	   divested of its trade secrets, irrespective of what has been		*/
/*	   deposited with the U.S. Copyright Office.				*/
/*										*/
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
#include <tpmfunc.h>

static void usage() {
	printf("Usage: createkeydelegation  Parameters <key handle> <new key password> <filename>\n"
	       "\n"
	       "Valid parameters are:\n"
	       "-label <label>      : the label for the public parameters\n"
	       "-id <familiyID>     : to set the familyD\n"
	       "-per1 <permissions> : to set the permission1 parameter (hex)\n"
	       "-per2 <permissions> : to set the permission2 parameter (hex)\n"
	       "-v                  : turns on verbose mode\n"
	       "-p <key password>   : Key password\n"
	       "\n"
	       "Example:\n"
	       "createkeydelegation -label 1 -id 1 -per1 0x2 -p key 0x05abcde key2 keydel.bin\n "
	       "\n");
}

int main(int argc, char *argv[])
{
	int ret = 0;
	int verbose = FALSE;
	STACK_TPM_BUFFER(buffer)
	char *keyPass = NULL;
	unsigned char keyPassHash[TPM_HASH_SIZE];
	unsigned char *keyHashPtr = NULL;
	uint32_t keyhandle = 0;
	
	unsigned char delhash[TPM_HASH_SIZE];
	unsigned char *delAuthHashPtr = NULL;
	int i = 1;
	TPM_FAMILY_ID familyID;
	uint32_t pcrs;

	unsigned char retbuffer[1024];
	uint32_t retbufferlen = sizeof(retbuffer);

	TPM_DELEGATE_PUBLIC tdp;
	unsigned char label;
	unsigned int per1 = 0, per2 = 0;
	char *filename = NULL;
#if 0
	BOOL bool;
#endif
	unsigned int verificationCount = 0;

	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-label", argv[i])) {
			i++;
			if (i < argc) {
				if (1 != sscanf(argv[i], "%c", &label)) {
					printf("Error while reading option parameter.\n");
					usage();
					exit(-1);
				}
			} else {
				printf("Missing parameter for '-label'.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-id", argv[i])) {
			i++;
			if (i < argc) {
				if (1 != sscanf(argv[i], "%d", &familyID)) {
					printf("Error while reading option parameter.\n");
					usage();
					exit(-1);
				}
			} else {
				printf("Missing parameter for '-id'.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-per1", argv[i])) {
			i++;
			if (i < argc) {
				if (1 != sscanf(argv[i], "%x", &per1)) {
					printf("Error while reading option parameter.\n");
					usage();
					exit(-1);
				}
			} else {
				printf("Missing parameter for '-per1'.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-per2", argv[i])) {
			i++;
			if (i < argc) {
				if (1 != sscanf(argv[i], "%x", &per2)) {
					printf("Error while reading option parameter.\n");
					usage();
					exit(-1);
				}
			} else {
				printf("Missing parameter for '-per2'.\n");
				usage();
				exit(-1);
			}
		} else
#if 0
		if (!strcmp("-admin",argv[i])) {
			i++;
			if (i < argc) {
				unsigned int x;
				mode = TPM_FAMILY_ADMIN;
				if (1 != sscanf(argv[i], "%x", &x)) {
					printf("Error while reading option parameter.\n");
					usage();
					exit(-1);
				}
				if (x == 0) {
					bool = 0;
				} else 
					bool = 1;
			} else {
				printf("Missing parameter for -admin.\n");
				usage();
				exit(-1);
			}
			
		} else
#endif
		if (!strcmp("-p",argv[i])) {
			i++;
			if (i < argc) {
				keyPass = argv[i];
			} else {
				printf("Missing parameter for -p.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-v",argv[i])) {
			verbose = TRUE;
			TPM_setlog(1);
		} else
		if (!strcmp("-h",argv[i])) {
			usage();
			exit(0);
		} else {
			break;
		}
		i++;
	}

#if 0
	if (-1 == mode) {
		printf("Missing mandatory option.\n");
		usage();
		exit(-1);
	}
#endif
	
	if (i + 2 < argc) {
		if (1 != sscanf(argv[i],"%x",&keyhandle)) {
			printf("Error while reading the key handle!\n");
			exit(-1);
		}
		i++;
		TSS_sha1(argv[i], strlen(argv[i]), delhash);
		delAuthHashPtr = delhash;
		i++;
		filename = argv[i];
	} else {
		printf("Missing mandatory parameters: keyhandle, password and filename\n");
		usage();
		exit(-1);
	}

	if (NULL != keyPass) {
		TSS_sha1(keyPass, strlen(keyPass), keyPassHash);
		keyHashPtr = keyPassHash;
	}
	

	ret = TPM_GetNumPCRRegisters(&pcrs);
	if (ret != 0) {
		printf("Error reading number of PCR registers.\n");
		exit(-1);
	}
	if (pcrs > TPM_NUM_PCR) {
		printf("Library does not support that many PCRs.\n");
		exit(-1);
	}

	tdp.tag = TPM_TAG_DELEGATE_PUBLIC;
	tdp.rowLabel = label;
	tdp.pcrInfo.pcrSelection.sizeOfSelect = pcrs / 8;
	memset(&tdp.pcrInfo.pcrSelection.pcrSelect,
	       0x0,
	       sizeof(tdp.pcrInfo.pcrSelection.pcrSelect));
	tdp.pcrInfo.localityAtRelease = TPM_LOC_ZERO;
	tdp.permissions.tag = TPM_TAG_DELEGATIONS;
	tdp.permissions.delegateType = TPM_DEL_KEY_BITS;
	tdp.permissions.per1 = per1;
	tdp.permissions.per2 = per2;
	tdp.familyID = familyID;
	tdp.verificationCount = verificationCount;

	ret = TPM_Delegate_CreateKeyDelegation(keyhandle,
	                                       &tdp,
	                                       delAuthHashPtr,
	                                       keyHashPtr,
	                                       retbuffer, &retbufferlen);

	if (0 != ret) {
		printf("Error %s from TPM_Delegate_CreateKeyDelegation.\n",
		       TPM_GetErrMsg(ret));
	} else {
		FILE *f = fopen(filename,"wb");
		if (NULL != f) {
			fwrite(retbuffer, retbufferlen, 1, f);
			fclose(f);
			printf("Ok.\n");
		} else {
			printf("Could not write data to file!\n");
		}
	}
	exit(ret);
}
