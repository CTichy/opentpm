/********************************************************************************/
/*										*/
/*			        TCPA Migration   				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: migrate.c 4073 2010-04-30 14:44:14Z kgoldman $		*/
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
#include <sys/types.h>
#include <sys/stat.h>

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

/* local prototypes */


static void usage() {
	printf("Usage: migrate -hp <parent key handle> -pwdp <parent key password>\n"
	       "       -pwdo <owner password>\n"
	       "       -hm <handle of the migration key> -im <file of the migration key> -pwdk <migration key password>\n"
	       "       -pwdm <migration password> [-ok <filename for key>] -ik keyfile\n"
	       "       [-rewrap] [-v]\n"
	       "-hp    : parent key handle\n"
	       "-pwdp  : parent key password used for encryption\n"
	       "-pwdo  : TPM owner password\n"
	       "-pwdm  : migration password\n"
	       "-im    : file containing the migration key or\n"
	       "-hm    : handle of the migration key\n"
	       "-pwdk  : the password of the migration key\n"
	       "-ok    : filename to write the migrated key into. If not given, the key\n"
	       "         will be loaded back into the TPM.\n"
	       "-ik    : file with the key to be migrated\n"
	       "-rewrap: Use migration scheme 'rewrap'\n"
	       "-v     : enable verbose output\n"
	       "\n"
	       "This program migrates a key.  The key may come from a file or be already loaded\n");
	printf("\n");
	printf("\n");
	printf("Examples:\n");
}

int main(int argc, char * argv[]) {
	char * ownerpass = NULL;
	char * migpass = NULL;
	char * parpass = NULL;
	char * filename = NULL;
	char * migkeypass = NULL;
	char * keyfile = NULL;
	char * migkeyfilename = NULL;
	uint32_t parhandle = -1;             /* handle of parent key */
	unsigned char * passptr1 = NULL;
	unsigned char passhash1[20];
	unsigned char hashpass1[20];    /* hash of new key password */
	unsigned char hashpass3[20];    /* hash of parent key password */
	unsigned char hashpass4[20];    /* hash of migration key pwd */
	uint32_t ret;
	int i =	0;
	keydata keyparms;
	keydata idkey;
	unsigned char *aptr1 = NULL;
	unsigned char *aptr3 = NULL;
	unsigned char *aptr4 = NULL;
	keydata q;
	keydata migkey;
	uint16_t migscheme = TPM_MS_MIGRATE;
	uint32_t migkeyhandle = 0;
	
	
	
	memset(&keyparms, 0x0, sizeof(keyparms));
	memset(&idkey   , 0x0, sizeof(idkey));
	
	i = 1;
	
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-hp",argv[i])) {
			i++;
			if (i  < argc) {
				sscanf(argv[i],"%x",&parhandle);
			} else {
				printf("Missing parameter for -hp.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-pwdp",argv[i])) {
			i++;
			if (i < argc) {
				parpass = argv[i];
			} else {
				printf("Missing parameter for -pwdp.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-ok",argv[i])) {
			i++;
			if (i < argc) {
				filename = argv[i];
			} else {
				printf("Missing parameter for -ok.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-pwdo",argv[i])) {
			i++;
			if (i < argc) {
				ownerpass = argv[i];
			} else {
				printf("Missing parameter for -pwdo.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-pwdm",argv[i])) {
			i++;
			if (i < argc) {
				migpass = argv[i];
			} else {
				printf("Missing parameter for -pwdm.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-hm",argv[i])) {
			i++;
			if (i < argc) {
				sscanf(argv[i],"%x",&migkeyhandle);
			} else {
				printf("Missing parameter for -hm.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-im",argv[i])) {
			i++;
			if (i < argc) {
				migkeyfilename = argv[i];
			} else {
				printf("Missing parameter for -im.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-pwdk",argv[i])) {
			i++;
			if (i < argc) {
				migkeypass = argv[i];
			} else {
				printf("Missing parameter for -pwdk.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-ik",argv[i])) {
			i++;
			if (i < argc) {
				keyfile = argv[i];
			} else {
				printf("Missing parameter for -ik.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-v",argv[i])) {
			TPM_setlog(1);
		} else
		if (!strcmp("-h",argv[i])) {
		    usage();
		    exit(-1);
		} else
		if (!strcmp("-rewrap",argv[i])) {
			migscheme = TPM_MS_REWRAP;
		} else {
		    printf("Unknown parameter %s\n", argv[i]);
		    usage();
		    exit(-1);
		}
		i++;
	}


	if (NULL == keyfile  ||
	    NULL == ownerpass || 
	    -1 == (int)parhandle   || 
	    ( 0 == migkeyhandle && NULL == migkeyfilename)) {
		printf("Missing or wrong parameter.\n");
		usage();
		exit(-1);
	}

	if (NULL != ownerpass) {
		TSS_sha1(ownerpass,strlen(ownerpass),passhash1);
		passptr1 = passhash1;
	} else {
		passptr1 = NULL;
	}
	

	/*
	** use the SHA1 hash of the password string as the Parent Key Authorization Data
	*/
	if (parpass != NULL) { TSS_sha1(parpass,strlen(parpass),hashpass1); aptr1 = hashpass1; }
	/*
	** use the SHA1 hash of the password string as the Key Migration Authorization Data
	*/
	if (migpass != NULL) { TSS_sha1(migpass,strlen(migpass),hashpass3); aptr3 = hashpass3; }
	/*
	** use the SHA1 hash of the password string as the Key Migration Authorization Data
	*/
	if (migkeypass != NULL) { TSS_sha1(migkeypass,strlen(migkeypass),hashpass4); aptr4 = hashpass4; }
	
	ret = TPM_ReadKeyfile(keyfile, &q);
	
	if (0 == ret) {
		STACK_TPM_BUFFER(migkeybuffer);
		
		if (0 != migkeyhandle) {
			keydata kd;
			ret = TPM_GetPubKey(migkeyhandle, 
			                    aptr4, 
			                    &kd.pub);
			if (ret != 0) {
				printf("Error '%s' from GetPubKey.\n",
				       TPM_GetErrMsg(ret));
				exit(ret);
			}
			ret = TPM_WriteKeyPub(&migkeybuffer, &kd);
			if ((ret & ERR_MASK)) {
				printf("Error '%s' (%08X) serializing the public key.\n",
				       TPM_GetErrMsg(ret),ret);
				exit(ret);
			}
			ret = 0;
		} else {
			ret = TPM_ReadKeyfile(migkeyfilename,
			                      &migkey);
			if ( (ret & ERR_MASK) != 0) {
				printf("Could not read key from file.\n");
				exit(-1);
			}
			
		}
		if (0 == ret) {

			STACK_TPM_BUFFER(keyblob)
			keydata keyd;

			memset(&keyd, 0x0, sizeof(keyd));

			if (0 != migkeyhandle) {
				SET_TPM_BUFFER(&keyblob,
				               migkeybuffer.buffer,
				               migkeybuffer.used);

			} else {
				ret = TPM_WriteKeyPub(&keyblob,
				                      &migkey);
				if ( ( ret & ERR_MASK ) != 0 ) {
					printf("Could not serialize key.\n");
					exit(-1);
				}
			}

			ret = TPM_AuthorizeMigrationKey(passptr1,
			                                migscheme,         // migration scheme
			                                &keyblob,          // public key to be authorized
			                                &migkeybuffer);
			if (0 == ret) {
				unsigned char * rndblob = NULL;
				uint32_t rndblen;
				unsigned char * outblob = NULL;
				uint32_t outblen;
				unsigned char * encblob = NULL;
				uint32_t encblen;

				encblob = malloc(q.encData.size);
				if (NULL == encblob) {
					printf("Could not allocated %d bytes of memory.\n",
					       q.encData.size);
					exit(-1);
				}
				encblen = q.encData.size;
				outblob = malloc(q.encData.size);
				if (NULL == outblob) {
					printf("Could not allocated %d bytes of memory.\n",
					       q.encData.size);
					free(encblob);
					exit(-1);
				}
				outblen = q.encData.size;
				
				rndblob = malloc(q.encData.size);
				if (NULL == rndblob) {
					printf("Could not allocated %d bytes of memory.\n",
					       q.encData.size);
					free(encblob);
					free(outblob);
					exit(-1);
				}
				rndblen = q.encData.size;

				memcpy(encblob,
				       q.encData.buffer,
				       q.encData.size);
				encblen = q.encData.size;
				/*
				 * Now call the TPM_CreateMigrationBlob function.
				 */
				ret = TPM_CreateMigrationBlob(parhandle,         // handle of a key that can decrypt the encblob below
				                              aptr1,             // password for that parent key
				                              aptr3,             // migration password
				                              migscheme,         // migration type
				                              migkeybuffer.buffer, migkeybuffer.used,  // migration public key: key to use for migration
				                              encblob, encblen,  // encrypted private key that will show up re-encrypted in outblob
				                              rndblob, &rndblen, // output: used for xor encryption
				                              outblob, &outblen);// output: re-encrypted private key
				if (0 == ret) {
					if (NULL != filename) {
						STACK_TPM_BUFFER(keybuf)
						/*
						 * serialize the key in 'q'
						 * I have to fix the size of that key, though,
						 * since it might be different now that it has
						 * been re-encrypted.
						 */
						q.encData.size = outblen;
						ret = TPM_WriteKey(&keybuf,&q);
						if (ret > 0) {
							unsigned int keybuflen = ret;
							FILE * f = fopen(filename,"wb");
							if (NULL != f) {
								struct tpm_buffer *filebuf = TSS_AllocTPMBuffer(10240);
								if (NULL != filebuf) {
									int l;
									l = TSS_buildbuff("@ @ @", filebuf,
									                   rndblen, rndblob,
									                     outblen, outblob,
									                       keybuflen, keybuf.buffer);
									fwrite(filebuf->buffer,
									       l,
									       1,
									       f);
									fclose(f);
									printf("Wrote migration blob and associated data to file.\n");
									ret = 0;
									TSS_FreeTPMBuffer(filebuf);
								} else {
									printf("Error. Could not allocate memory.\n");
									ret = -1;
									
								}
							} else {
								printf("Error. Could not write blob to file.\n");
								ret = -1;
							}
						} else {
							printf("Error while serializing key!\n");
						}
					} else {
						ret = 0;
						if (0 == ret) {
							uint32_t newesthandle = 0;
							if (TPM_MS_REWRAP == migscheme) {
								memcpy(q.encData.buffer,
								       outblob,
								       outblen);
							} else {
								unsigned char * newencblob = NULL;
								uint32_t newencblen;
								newencblob = malloc(q.encData.size);
								if (NULL == newencblob) {
									printf("Could not allocated %d bytes.\n",
									       q.encData.size);
									exit(-1);
								}
								newencblen = q.encData.size;
								ret = TPM_ConvertMigrationBlob(migkeyhandle,  // handle of a loaded key that can decrypt keys
								                               aptr4,         // key password
								                               rndblob, rndblen, // used for xor encryption/decrpytion
								                               outblob, outblen, // re-encrypted private key (here input)
							        	                       newencblob, &newencblen); // 
								if (0 == ret) {
									if (0 != newencblen) {
										memcpy(q.encData.buffer,
										       newencblob,
										       newencblen);
									}
								} else {
									printf("ConvertMigrationBlob returned '%s' (0x%x).\n",
									        TPM_GetErrMsg(ret),
									        ret);
								}
							}
							if (0 == ret) {
								printf("Trying to load encryted key back into TPM.\n");
//								if (NULL == aptr1) {
//									ret = TPM_LoadKey(migkeyhandle,
//									                  NULL,
//									                  &q,
//									                  &newesthandle);
//								} else {
									ret = TPM_LoadKey(migkeyhandle,
									                  aptr4,
									                  &q,
									                  &newesthandle);
//								}
								if (0 == ret) {
									printf("Loading the migrated key back into the tpm was successful.\n");
									printf("The handle for the key is 0x%X\n",newesthandle);
								} else {
									printf("LoadKey returned '%s' (%d).\n",
									       TPM_GetErrMsg(ret),
									       ret);
								}
							}
						} else {
							printf("LoadKey returned '%s' (0x%x).\n",
							       TPM_GetErrMsg(ret),
							       ret);
						}
					}
				} else {
					printf("CreateMigrationBlob returned '%s' (%d).\n",
					       TPM_GetErrMsg(ret),
					       ret);
				}

				free(encblob);
				free(outblob);
				free(rndblob);
			} else {
				printf("AuthorizeMigrationKey returned '%s' (0x%x).\n",
				       TPM_GetErrMsg(ret),
				       ret);
			}

		} else {
			printf("Error %s while loading key.\n",
			       TPM_GetErrMsg(ret));
			ret = -1;
		}
	} else {
		printf("Error %s while loading key.\n",
		       TPM_GetErrMsg(ret));
		ret = -1;
	}
	exit(ret);
}
