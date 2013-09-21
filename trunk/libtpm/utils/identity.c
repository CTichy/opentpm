/********************************************************************************/
/*										*/
/*			    TCPA Identity    					*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: identity.c 4073 2010-04-30 14:44:14Z kgoldman $		*/
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

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "tpm.h"
#include "tpmutil.h"
#include "tpmfunc.h"
#include "tpm_constants.h"
#include "tpm_structures.h"
#include "tpm_error.h"

/* local prototypes */
static RSA * getpubek(unsigned char * passhash) ;
static uint32_t do_ca_contents(unsigned char * passptr1,
                               keydata * idkey,
                               uint32_t  newhandle,
                               unsigned char * usageptr);
uint32_t do_ek_blob(unsigned char * passptr1,
                    keydata * idkey,
                    uint32_t newhandle,
                    unsigned char * usageptr);
static uint32_t do_activateIdentity(unsigned char * passptr1,
                               unsigned char * usageptr,
                               unsigned char * blobbuf, uint32_t blobbufsize,
                               uint32_t newhandle);

static void usage() {
	printf("Usage: identity -pwdo <owner password> -la <label> [options]\n");
	printf("\n");
	printf(" -pwdo pwd    : The TPM owner password.\n");
	printf(" -la label    : Some label for the identity.\n");
	printf(" -pwdk idpwd  : A password for the identity.\n");
	printf(" -pwds srkpwd : The password for the storage root key.\n");
	printf(" -ac          : To activate the identity after generating it.\n");
	printf(" -ekb         : Use a TPM_EK_BLOB for activation instead of TPM_ASYM_CA_CONTENTS.\n");
	printf(" -v12         : Use version 1.2 key structure\n");
	printf("\n");
	printf("Examples:\n");
	exit(-1);
}

int main(int argc, char * argv[]) {
	char * ownerpass = NULL;
	char * usagepass = NULL;
	char * label = NULL;
	char * srkpass = NULL;  
	uint32_t parhandle;             /* handle of parent key */
	unsigned char * passptr1 = NULL;
	unsigned char * usageptr = NULL;
	unsigned char * srkhashptr = NULL;
	unsigned char passhash1[20];
	unsigned char srkhash[20];
	unsigned char labelhash[20];	
	unsigned char usagehash[20];	
	uint32_t ret;
	char filename[256];
	int i =	0;
	uint32_t idbindingbuffersize = 1024;
	unsigned char idbindingbuffer[idbindingbuffersize];    	
	keydata keyparms;
	keydata idkey;
	RSA *rsa;
	char *keyname = NULL;
	FILE *keyfile;
	FILE *blbfile;
	unsigned char keyblob[4096];
	unsigned int keybloblen;
	EVP_PKEY *pkey = NULL;
	int activate = FALSE;
	int use_ca = TRUE;
	TPM_BOOL v12 = FALSE;

	memset(&keyparms, 0x0, sizeof(keyparms));
	memset(&idkey   , 0x0, sizeof(idkey));
	
	i = 1;
	
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-pwdo",argv[i])) {
			i++;
			if (i < argc) {
				ownerpass = argv[i];
			} else {
				printf("Missing parameter for -pwdo.\n");
				usage();
			}
		} else
		if (!strcmp("-pwdk",argv[i])) {
			i++;
			if (i < argc) {
				usagepass = argv[i];
			} else {
				printf("Missing parameter for -pwdk.\n");
				usage();
			}
		} else
		if (!strcmp("-pwds",argv[i])) {
			i++;
			if (i < argc) {
				srkpass = argv[i];
			} else {
				printf("Missing parameter for -pwds.\n");
				usage();
			}
		} else
		if (!strcmp("-la",argv[i])) {
			i++;
			if (i < argc) {
				label = argv[i];
			} else {
				printf("Missing parameter for -la.\n");
				usage();
			}
		} else
		if (!strcmp("-ac",argv[i])) {
			activate = TRUE;
		} else
		if (!strcmp("-ekb",argv[i])) {
			use_ca = FALSE;
		} else
		if (!strcmp("-v12",argv[i])) {
			v12 = TRUE;
		} else
		if (!strcmp("-v",argv[i])) {
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

	if (NULL == ownerpass || NULL == label) {
		printf("Missing or wrong parameter.\n");
		usage();
	}

	parhandle = 0x00000000;
	
	if (NULL != ownerpass) {
		TSS_sha1(ownerpass,strlen(ownerpass),passhash1);
		passptr1 = passhash1;
	} else {
		passptr1 = NULL;
	}

	if (NULL != srkpass) {
		TSS_sha1(srkpass,strlen(srkpass),srkhash);
		srkhashptr = srkhash;
	} else {
		srkhashptr = NULL;
	}

	if (NULL != usagepass) {
		TSS_sha1(usagepass,strlen(usagepass),usagehash);
		usageptr = usagehash;
	} else {
		usageptr = NULL;
	}

	
	if (NULL != label) {
		TSS_sha1(label,strlen(label),labelhash);
	}

	if (FALSE == v12) {
		keyparms.v.ver.major = 1;
		keyparms.v.ver.minor = 1;
	} else {
		keyparms.v.tag = TPM_TAG_KEY12;
	}
	keyparms.keyUsage      = TPM_KEY_IDENTITY;
	keyparms.pub.algorithmParms.algorithmID = TPM_ALG_RSA;
	keyparms.pub.algorithmParms.u.rsaKeyParms.keyLength = 2048;
	keyparms.pub.algorithmParms.u.rsaKeyParms.numPrimes = 2;
	keyparms.pub.algorithmParms.encScheme = TPM_ES_NONE;
	keyparms.pub.algorithmParms.sigScheme = TPM_SS_RSASSAPKCS1v15_SHA1;
	if (usagepass) {
		keyparms.authDataUsage = TPM_AUTH_ALWAYS;
	} else {
		keyparms.authDataUsage = TPM_AUTH_NEVER;
	}
	
	memset(keyblob,0x00,4096);
	keybloblen = 0;
	ret = TPM_MakeIdentity(usageptr,
	                       labelhash,
	                       &keyparms,
	                       &idkey,
	                       srkhashptr,
	                       passptr1,
	                       idbindingbuffer,
	                       &idbindingbuffersize,
	                       &keyblob,
			       &keybloblen);
	printf("TPM_MakeIdentity returned keyblob len=%d\n", keybloblen);
	if (0 != ret) {
		printf("MakeIdentity returned error '%s' (%d).\n",
		       TPM_GetErrMsg(ret),
		       ret);
		exit(ret);
	}

	if (TRUE == v12) {
		if (idkey.v.tag != TPM_TAG_KEY12) {
			printf("MakeIdentity returned a wrong key structure! Expected TPM_KEY12\n");
			exit(-1);
		}
	}
//START COREY ADDITIONS
	sprintf(filename,"identity.key");
	blbfile = fopen(filename,"wb");
	if (blbfile == NULL)
	{
	    printf("Unable to create key file %s.\n",filename);
	    exit(-1);
	}
	ret = fwrite(keyblob,1,keybloblen,blbfile);
	if (ret != keybloblen)
	{
	    printf("I/O Error writing key file\n");
	    exit(-1);
	}
	fclose(blbfile);

	rsa = TSS_convpubkey(&(idkey.pub));
	if (rsa == NULL)
	{
	    printf("Error from TSS_convpubkey\n");
	    exit(-1);
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
	sprintf(filename,"identity.pem");
	keyfile = fopen(filename,"wb");
	if (keyfile == NULL)
	{
	    printf("Unable to create public key file\n");
	    exit(-6);
	}
	ret = PEM_write_PUBKEY(keyfile,pkey);
	if (ret == 0)
	{
	    printf("I/O Error writing public key file\n");
	    exit(-7);
	}
	fclose(keyfile);
	
	EVP_PKEY_free(pkey);


//END COREY ADDITIONS


	if (TRUE == activate) {
		uint32_t newhandle = 0;
		char *version = getenv("TPM_VERSION");
		/*
		 * Activate the identity.
		 */
		if (version == NULL || !strcmp("11",version)) {
			ret = TPM_LoadKey(0x40000000, // must be SRK in this case!
			                  srkhashptr,
			                  &idkey,
		        	          &newhandle);
			if (ret == TPM_BAD_ORDINAL) {
				ret = TPM_LoadKey2(0x40000000, // must be SRK in this case!
				                  srkhashptr,
				                  &idkey,
			        	          &newhandle);
			}
		} else {
			ret = TPM_LoadKey2(0x40000000, // must be SRK in this case!
			                  srkhashptr,
			                  &idkey,
		        	          &newhandle);
		}
		if (0 != ret) {
			printf("LoadKey returned error '%s' (%d).\n",
			       TPM_GetErrMsg(ret),
			       ret);
		} else {
			printf("Identity key handle %08X\n",newhandle);
			if (TRUE == use_ca) {
				ret = do_ca_contents(passptr1,
				                     &idkey,
				                     newhandle,
				                     usageptr);
			} else {
				ret = do_ek_blob(passptr1,
				                 &idkey,
				                 newhandle,
				                 usageptr);
			}
		}
	}

	return ret;
}


uint32_t do_ek_blob(unsigned char * passptr1,
                    keydata * idkey,
                    uint32_t newhandle,
                    unsigned char * usageptr) {
	TPM_EK_BLOB ekblob;
	TPM_EK_BLOB_ACTIVATE activate;
	TPM_SYMMETRIC_KEY tpm_symkey;
	unsigned char symkey[] = {0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
	                          0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
	STACK_TPM_BUFFER( ser_symkey_buf )
	uint32_t      ser_symkey_len = 0;
	uint32_t serkeylen;
	STACK_TPM_BUFFER( buffer )
	STACK_TPM_BUFFER( ek_actblob )
	uint32_t ek_actblobsize = 0;
	STACK_TPM_BUFFER(ek_blobbuf)
	uint32_t ek_blobbufsize = 0;

	uint32_t ret = 0;
	uint32_t pcrs;

	memset(&activate, 0x0, sizeof(activate));

	/*
	 * Need to build the symmetric key structure,
	 * serialize it and attach it to data.buffer of 'data'.
	 */
	tpm_symkey.algId       = TPM_ALG_AES128;
	tpm_symkey.encScheme   = TPM_ES_SYM_CTR;
	tpm_symkey.size        = sizeof(symkey);
	tpm_symkey.data        = symkey;

	ser_symkey_len = TPM_WriteSymmetricKey(&ser_symkey_buf, &tpm_symkey);


	activate.tag  = TPM_TAG_EK_BLOB_ACTIVATE;
	activate.sessionKey = tpm_symkey;

	ret = TPM_WriteKeyPub(&buffer,idkey);
	if (ret & ERR_MASK) {
		return ret;
	}
	serkeylen = ret;
	TSS_sha1(buffer.buffer,serkeylen,activate.idDigest);

	
	ret = TPM_GetNumPCRRegisters(&pcrs);
	if (ret != 0) {
		printf("Error reading number of PCR registers.\n");
		exit(-1);
	}
	if (pcrs > TPM_NUM_PCR) {
		printf("Library does not support that many PCRs.\n");
		exit(-1);
	}

	activate.pcrInfo.pcrSelection.sizeOfSelect = pcrs / 8;
	activate.pcrInfo.localityAtRelease = TPM_LOC_ZERO;

	ret = TPM_WriteEkBlobActivate(&ek_actblob,&activate);

	if (ret & ERR_MASK) {
		return ret;
	}
	
	ek_actblobsize = ret;

	ekblob.tag    = TPM_TAG_EK_BLOB;
	ekblob.ekType = TPM_EK_TYPE_ACTIVATE;
	ekblob.blob.size   = ek_actblobsize;
	ekblob.blob.buffer = ek_actblob.buffer;

	ret = TPM_WriteEkBlob(&ek_blobbuf, &ekblob);
	if (ret & ERR_MASK) {
		return ret;
	}
	
	ek_blobbufsize = ret;

	return do_activateIdentity(passptr1,
	                           usageptr,
	                           ek_blobbuf.buffer, ek_blobbufsize,
	                           newhandle);
}

static 
uint32_t   do_activateIdentity(unsigned char * passptr1,
                               unsigned char * usageptr,
                               unsigned char * blobbuf, uint32_t blobbufsize,
                               uint32_t newhandle) {
	uint32_t ret = 0;
	RSA * rsa;
	rsa = getpubek(passptr1);
	if (NULL != rsa) {
		unsigned char out_blob[2048];
		uint32_t blobsize;
		unsigned char * blob;
		STACK_TPM_BUFFER(returnbuffer)
		unsigned char tpm_oaep_pad_str[] = { 'T' , 'C' , 'P' , 'A' };

		blobsize = RSA_size(rsa);
		blob = malloc(blobsize);

		/*
		 * Add some padding to the data that need to
		 * be encrypted.
		 */
		ret = RSA_padding_add_PKCS1_OAEP(blob,
		                                 blobsize,
		                                 blobbuf,
		                                 blobbufsize,
		                                 tpm_oaep_pad_str,
		                                 sizeof(tpm_oaep_pad_str));

		if (0 == ret) {
			printf("Error while adding padding.\n");
			exit(-1);
		}

		ret = RSA_public_encrypt(blobsize, 
		                         blob,
		                         out_blob, 
		                         rsa,
		                         RSA_NO_PADDING);

		if (ret != blobsize) {
			printf("Something went wrong while encoding with public key!!! ret(%d)!=blobsize(%d)\n",
			       ret,
			       blobsize);
			exit(-1);
		}


		ret = TPM_ActivateIdentity(newhandle,
		                           out_blob, blobsize,
		                           usageptr,
		                           passptr1,
		                           &returnbuffer);

		if (0 != ret) {
			printf("ActivateIdentity returned error '%s' (0x%x).\n",
			       TPM_GetErrMsg(ret),
			       ret);
			exit(-1);
		} else {
			TPM_SYMMETRIC_KEY retkey;
			printf("Successfully activated the identity.\n");
			ret = TPM_ReadSymmetricKey(&returnbuffer,
			                           0,
			                           &retkey);
			if (ret > 0) {
				uint32_t j = 0;
				printf("Received the following symmetric key:\n");
				printf("algId     : 0x%x\n",(uint32_t)retkey.algId);
				printf("encScheme : 0x%x\n",(uint32_t)retkey.encScheme);
				printf("data      : ");
				while (j < retkey.size) {
					printf("%02X ",retkey.data[j]);
					j++;
				}
				printf("\n");
				ret = 0;
			}
		}
	} else {
		exit(-1);
	}

	return ret;
}


/*
 * Call the ActivateIdentity function with a TPM_ASYM_CA_CONTENTS
 * structure.
 */
uint32_t do_ca_contents(unsigned char * passptr1,
                        keydata * idkey,
                        uint32_t  newhandle,
                        unsigned char * usageptr) {
	/*
	 * An arbitrary symmetric key
	 */
	unsigned char symkey[] = {0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
	                          0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
	                          0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
	                          0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
	STACK_TPM_BUFFER(buffer)
	uint32_t serkeylen;
	uint32_t sercacontlen;
	TPM_ASYM_CA_CONTENTS data;
	TPM_SYMMETRIC_KEY tpm_symkey;
	STACK_TPM_BUFFER(ser_symkey_buf)
	uint32_t      ser_symkey_len = 0;
	uint32_t ret = 0;

	/*
	 * Need to build the symmetric key structure,
	 * serialize it and attach it to data.buffer of 'data'.
	 */
	tpm_symkey.algId       = TPM_ALG_AES256;
	tpm_symkey.encScheme   = TPM_ES_SYM_CTR;
	tpm_symkey.size        = sizeof(symkey);
	tpm_symkey.data        = symkey;
	
	ser_symkey_len = TPM_WriteSymmetricKey(&ser_symkey_buf, &tpm_symkey);	

	memset(&data,0x0,sizeof(data));
	// symmetric key
	data.sessionKey =  tpm_symkey;
	/*
	 * Need to calculate the digest of the public key part in 
	 * idKey as returned by MakeIdentity
	 * First serialize the key, then sha it
	 */
	ret = TPM_WriteKeyPub(&buffer,idkey);
	if (ret & ERR_MASK) {
		printf("Error while serializing key!\n");
		return ret;
	}
	
	serkeylen = ret;
	
	TSS_sha1(buffer.buffer,serkeylen,data.idDigest);
	
	/*
	 * Need to serialize the 'data' structure
	 * and encrypt it using the public EK.
	 */
	RESET_TPM_BUFFER(&buffer);
	ret = TPM_WriteCAContents(&buffer, &data);
	if (ret & ERR_MASK) {
		printf("Error while serializing CA Contents.\n");
		return ret;
	}
	sercacontlen = ret;

	return do_activateIdentity(passptr1,
	                           usageptr,
	                           buffer.buffer, sercacontlen,
	                           newhandle);

}

/*
 * Get the public endorsement key needed for encryption
 */
static RSA * getpubek(unsigned char * passhash) 
{
	RSA *rsa;                       /* OpenSSL format Public Key */
	pubkeydata pubek;
	uint32_t ret;
	memset(&pubek,0x0,sizeof(pubek));

	/*
	 * Get the public endorsement key from the TPM.
	 */
	ret = TPM_OwnerReadPubek(passhash,&pubek);
	if (ret == TPM_BAD_ORDINAL) {
		ret = TPM_OwnerReadInternalPub(TPM_KH_EK,
		                               passhash,
		                               &pubek);
		if (ret != 0) {
			printf("Error '%s' from OwnerReadInternalPub.\n",
			        TPM_GetErrMsg(ret));
			return NULL;
		}
	}
	if (ret != 0) {
		printf("Error %s from TPM_OwnerReadPubek\n",TPM_GetErrMsg(ret));
		return NULL;
	}
	/*
	 ** convert the returned public key to OpenSSL format 
	 */
	rsa = TSS_convpubkey(&pubek);

	return rsa;
}
