/********************************************************************************/
/*										*/
/*			     	TPM Delegate Manage				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: delegatemanage.c 3990 2010-04-14 20:51:04Z kgoldman $	*/
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
	printf("Usage: delegate_manage [Option] [<owner password>]\n"
	       "\n"
	       "Valid options are:\n"
	       "\n"
	       "-create <label>  : create a family (0 <= label <= 255)\n"
	       "-invalidate      : invalidate the familyID\n"
	       "-enable BOOL     : enable or disable\n"
	       "-admin BOOL      : administrate\n"
	       "-id <familyID>   : the ID of the family this command is for\n"
	       "-v               : turns on verbose mode\n"
	       "\n"
	       "The familiyID must be an integer in the range of 0..255.\n"
	       "The last parameter indicates the familyID to be managed.\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	int ret = 0;
	int verbose = FALSE;
	TPM_BOOL bool = TRUE;
	int mode = -1;
	STACK_TPM_BUFFER(buffer)
	uint32_t len;
	TPM_FAMILY_LABEL tfl = 0; /* = BYTE */
	char * ownerPass;
	unsigned char ownerhash[TPM_HASH_SIZE];
	unsigned char * ownerHashPtr = NULL;
	int i = 1;
	TPM_FAMILY_ID familyID = 0x0; /* = UINT32 */
	unsigned char retbuffer[256];
	uint32_t retbufferlen = sizeof(retbuffer);
	
	
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-id",argv[i])) {
			i++;
			if (i < argc) {
				if (1 != sscanf(argv[i],"%d", &familyID)) {
					printf("Error while getting option parameter\n");
					usage();
					exit(-1);
				}
			}
		} else
		if (!strcmp("-create",argv[i])) {
			i++;
			if (i < argc) {
				int x;
				mode = TPM_FAMILY_CREATE;
				if (1 != sscanf(argv[i],"%d", &x)) {
					printf("Error while getting option parameter\n");
					usage();
					exit(-1);
				}
				if (x > 255) {
					printf("Error: Label out of range!\n");
					usage();
					exit(-1);
				}
				tfl = (TPM_FAMILY_LABEL)x;
			} else {
				printf("Missing parameter for -create.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-invalidate",argv[i])) {
			mode = TPM_FAMILY_INVALIDATE;
		} else
		if (!strcmp("-enable",argv[i])) {
			i++;
			if (i < argc) {
				int x;
				mode = TPM_FAMILY_ENABLE;
				if (1 != sscanf(argv[i],"%d", &x)) {
					printf("Error while getting option parameter\n");
					usage();
					exit(-1);
				}
				if (x == 0) {
					bool = 0;
				} else
					bool = 1;
			} else {
				printf("Missing parameter for -enable.\n");
				usage();
				exit(-1);
			}
			
		} else
		if (!strcmp("-admin",argv[i])) {
			i++;
			if (i < argc) {
				int x;
				mode = TPM_FAMILY_ADMIN;
				if (1 != sscanf(argv[i],"%d", &x)) {
					printf("Error while getting option parameter\n");
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
		if (!strcmp("-h", argv[i])) {
		    usage();
		    exit(-1);
		} else
		if (!strcmp("-v",argv[i])) {
			verbose = TRUE;
			TPM_setlog(1);
		} else {
			break;
		}
		i++;
	}

	if (-1 == mode) {
		printf("Missing mandatory option.\n");
		usage();
		exit(-1);
	}
	
	if (i < argc ) {
		ownerPass = argv[i];
		TSS_sha1(ownerPass, strlen(ownerPass), ownerhash);
		ownerHashPtr = ownerhash;
		i++;
	}
	
	switch (mode) {
		case TPM_FAMILY_CREATE:
			len = TPM_WriteTPMFamilyLabel(&buffer,
			                              tfl);
			ret = TPM_Delegate_Manage(familyID,
			                          mode,
			                          buffer.buffer, len,
			                          ownerHashPtr,
			                          retbuffer, &retbufferlen);
			if (0 == ret) {
				if (4 == retbufferlen) {
					uint32_t id = htonl(*(unsigned int*)&retbuffer[0]);
					printf("Family ID that was created: %d\n",id);
				}
			}
		break;

		case TPM_FAMILY_INVALIDATE:
			ret = TPM_Delegate_Manage(familyID,
			                          mode,
			                          NULL, 0,
			                          ownerHashPtr,
			                          retbuffer, &retbufferlen);
		break;

		case TPM_FAMILY_ENABLE:
		case TPM_FAMILY_ADMIN:
			ret = TPM_Delegate_Manage(familyID,
			                          mode,
			                          &bool, sizeof(TPM_BOOL),
			                          ownerHashPtr,
			                          retbuffer, &retbufferlen);
		break;
	}

	if (0 != ret) {
		printf("Error %s from TPM_Delegate_manage.\n",
		       TPM_GetErrMsg(ret));
	} else {
		printf("Ok.\n");
	}

	exit(ret);
}
