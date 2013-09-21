#################################################################################
#										#	
#			Windows MinGW TPM Utilities Makefile			#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	      $Id: makefile.mak 4073 2010-04-30 14:44:14Z kgoldman $		#
#										#
# (c) Copyright IBM Corporation 2006, 2010.					#
# 										#
# All rights reserved.								#
# 										#
# Redistribution and use in source and binary forms, with or without		#
# modification, are permitted provided that the following conditions are	#
# met:										#
# 										#
# Redistributions of source code must retain the above copyright notice,	#
# this list of conditions and the following disclaimer.				#
# 										#
# Redistributions in binary form must reproduce the above copyright		#
# notice, this list of conditions and the following disclaimer in the		#
# documentation and/or other materials provided with the distribution.		#
# 										#
# Neither the names of the IBM Corporation nor the names of its			#
# contributors may be used to endorse or promote products derived from		#
# this software without specific prior written permission.			#
# 										#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR		#
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		#
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,		#
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY		#
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE		#
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		#
#										#
#################################################################################

CC = c:/mingw/bin/gcc.exe

CCFLAGS = -Wall 			\
	-Wnested-externs -ggdb -O0 -c 	\
	-DTPM_WINDOWS 			\
	-DTPM_NV_DISK			\
	-DTPM_AES			\
	-DTPM_V12			\
	-DTPM_USE_TAG_IN_STRUCTURE	\
	-Ic:/MinGW/include	\
	-Ic:/openssl-win32/include	\
	-I../lib			\
	-I.

LNFLAGS = -ggdb 			\
	-DTPM_WINDOWS 			\
	-DTPM_NV_DISK			\
	-DTPM_AES			\
	-DTPM_USE_TAG_IN_STRUCTURE	\
	-D_MT				\
	-DTPM_V12			\
	-Ic:/MinGW/include		\
	-I../lib			\
	-Ic:/openssl-win32/include	\
	-I.

LNLIBS = 	c:/openssl-win32/lib/mingw/libeay32.a \
		c:/openssl-win32/lib/mingw/ssleay32.a \
		c:/MinGW/lib/libws2_32.a

LNDLLS = ../lib/libtpm.dll

.PHONY:		clean
.PRECIOUS:	%.o

all:				\
	pcrread.exe		\
	tpmtakeown.exe		\
	createkey.exe		\
	listkeys.exe		\
	loadkey.exe		\
	identity.exe \
	evictkey.exe \
	pcrreset.exe \
	sealfile.exe \
	unsealfile.exe \
	signfile.exe \
	nv_readvalue.exe \
	nv_writevalue.exe \
	nv.exe \
	quote.exe \
	quote2.exe \
	extend.exe \
	bindfile.exe

applink.o:
		$(CC) -c applink.c

clean:		
		rm *.o *.exe 

pcrread.exe:	applink.o
		$(CC) $(LNFLAGS) applink.o pcrread.c -o $@ $(LNLIBS) $(LNDLLS)

tpmtakeown.exe:	applink.o
		$(CC) $(LNFLAGS) applink.o takeown.c -o $@ $(LNLIBS) $(LNDLLS)

identity.exe:	applink.o
		$(CC) $(LNFLAGS) applink.o identity.c -o $@ $(LNLIBS) $(LNDLLS)

createkey.exe:	applink.o
		$(CC) $(LNFLAGS) applink.o createkey.c -o $@ $(LNLIBS) $(LNDLLS)

loadkey.exe:	applink.o
		$(CC) $(LNFLAGS) applink.o loadkey.c -o $@ $(LNLIBS) $(LNDLLS)

listkeys.exe:	applink.o
		$(CC) $(LNFLAGS) applink.o listkeys.c -o $@ $(LNLIBS) $(LNDLLS)

evictkey.exe:	applink.o
		$(CC) $(LNFLAGS) applink.o evictkey.c -o $@ $(LNLIBS) $(LNDLLS)
		
pcrreset.exe: 	applink.o
		$(CC) $(LNFLAGS) applink.o pcrreset.c -o $@ $(LNLIBS) $(LNDLLS)

sealfile.exe: 	applink.o
		$(CC) $(LNFLAGS) applink.o sealfile.c -o $@ $(LNLIBS) $(LNDLLS)

unsealfile.exe: 	applink.o
		$(CC) $(LNFLAGS) applink.o unsealfile.c -o $@ $(LNLIBS) $(LNDLLS)

signfile.exe: 	applink.o
		$(CC) $(LNFLAGS) applink.o signfile.c -o $@ $(LNLIBS) $(LNDLLS)

nv_readvalue.exe: 	applink.o
		$(CC) $(LNFLAGS) applink.o nv_readvalue.c -o $@ $(LNLIBS) $(LNDLLS)

nv_writevalue.exe: 	applink.o
		$(CC) $(LNFLAGS) applink.o nv_writevalue.c -o $@ $(LNLIBS) $(LNDLLS)

nv.exe: 	applink.o
		$(CC) $(LNFLAGS) applink.o nv.c -o $@ $(LNLIBS) $(LNDLLS)

quote.exe: 	applink.o
		$(CC) $(LNFLAGS) applink.o quote.c -o $@ $(LNLIBS) $(LNDLLS)

quote2.exe: 	applink.o
		$(CC) $(LNFLAGS) applink.o quote2.c -o $@ $(LNLIBS) $(LNDLLS)
		
		
extend.exe: 	applink.o
		$(CC) $(LNFLAGS) applink.o extend.c -o $@ $(LNLIBS) $(LNDLLS)

bindfile.exe: 	applink.o
		$(CC) $(LNFLAGS) applink.o bindfile.c -o $@ $(LNLIBS) $(LNDLLS)
		




