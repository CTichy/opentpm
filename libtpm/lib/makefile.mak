#################################################################################
#										#
#			Windows MinGW TPM Library Makefile			#
#			     Written by S. Berger				#
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
	-DTPM_USE_CHARDEV		\
	-DTPM_NV_DISK			\
	-DTPM_V12			\
	-DTPM_AES			\
	-DTPM_USE_TAG_IN_STRUCTURE	\
	-DSNIFF_TPM					\
	-Ic:/openssl-win32/include/	\
	-I.


LNFLAGS = -ggdb 			\
	-DTPM_WINDOWS			\
	-DTPM_USE_CHARDEV		\
	-DTPM_NV_DISK			\
	-DTPM_V12			\
	-DTPM_AES			\
	-DTPM_USE_TAG_IN_STRUCTURE	\
	-DSNIFF_TPM					\
	-D_MT				\
	-Ic:/openssl-win32/openssl	\
	-I.

LNLIBS = 	c:/openssl-win32/lib/mingw/libeay32.a \
		c:/openssl-win32/lib/mingw/ssleay32.a \
		c:/MinGW/lib/libws2_32.a

OBJS = 	auditing.o 	\
	bind.o		\
	chgauth.o	\
	context.o	\
	counter.o	\
	daa.o		\
	debug.o		\
	delegation.o	\
	dir.o		\
	eviction.o	\
	hmac.o		\
	identity.o	\
	keys.o		\
	keyswap.o	\
	maintenance.o	\
	management.o	\
	migrate.o	\
	miscfunc.o	\
	nv.o		\
	oiaposap.o	\
	optin.o		\
	owner.o		\
	ownertpmdiag.o	\
	pcrs.o		\
	raw.o		\
	rng.o		\
	seal.o		\
	serialize.o	\
	session.o	\
	sha.o		\
	signature.o	\
	startup.o	\
	testing.o	\
	ticks.o		\
	tpmutil.o	\
	tpmutil_tty.o   \
	transport.o	\
	tpmutil_sock.o	

.PHONY:		clean
.PRECIOUS:	%.o

all:		libtpm.dll

clean:		
		rm *.o *.exe *~ *.dll *.a

%.o:		%.c
		$(CC) $(CCFLAGS) -DBUILD_DLL $< -o $@

libtpm.dll:	$(OBJS)
		$(CC) $(LNFLAGS) -shared -o libtpm.dll $(OBJS) -Wl,--out-implib,libtpm.a $(LNLIBS)

