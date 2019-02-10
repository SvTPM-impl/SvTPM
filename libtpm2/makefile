#################################################################################
#										#
#			Linux gcc TPM2 Makefile					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	      $Id: makefile 809 2016-11-16 18:31:54Z kgoldman $			#
#										#
# (c) Copyright IBM Corporation 2015, 2016					#
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


CC = /usr/bin/gcc

CFLAGS = -shared -fPIC -I. -I../utils
CCFLAGS = -c -ggdb -O0 			\
	-DTPM_POSIX			\
	-D_POSIX_			\
	-I../utils			\
	-I. -shared -fPIC

LNFLAGS = -ggdb 			\
	-DTPM_POSIX			\
	-lcrypto			\
	-L.				\
	-I.	

###############
Signed_Enclave_Name := libtpm2.signed.so
Enclave_Name := libtpm2.so

all:	$(Enclave_Name)

CRYPTO_SUBSYSTEM = openssl

include makefile-common


.PHONY:		clean
.PRECIOUS:	%.o

tpm_server:	$(OBJFILES)
		$(CC) $(OBJFILES) $(LNFLAGS) -o tpm_server

TPM_SOURCE := $(shell find ./ -name "*.c")


SGXSSL_TRUSTED_LIB_PATH := $(SGX_SSL)/lib64
# SGXSSL_INCLUDE_PATH := $(SGX_SSL)/include
SGXSSL_Link_Flags := -Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive -lsgx_tsgxssl_crypto
Enclave_Include_Paths := $(SGX_SDK)/include
SGX_TPROTECTED_FS := sgx_tprotected_fs 

######## Enclave Objects ########
Enclave_C_Files := $(wildcard *.c)
Enclave_C_Objects := $(Enclave_C_Files:.c=.o)


%.o: %.c
	@echo '----------------COMPILE-----------------'	
	$(CC) -c -g -DTPM_POSIX -D_POSIX_ $(Enclave_C_Flags) -I. -I$(SGXSSL_INCLUDE_PATH) -I$(Enclave_Include_Paths) $< -o $@
	@echo "CC  <=  %.c"

$(Enclave_Name): Enclave_t.o $(OBJFILES)
	@echo '-----------------LINK-------------------'
	$(CC) $^ -o $@ $(SGXSSL_Link_Flags) -L$(SGXSSL_TRUSTED_LIB_PATH) -l$(SGX_TPROTECTED_FS) $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	$(SGX_ENCLAVE_SIGNER) sign -key Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"



######## Enclave Objects ########


# $(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects)
# 	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
# 	@echo "LINK =>  $@"

	
install:	
		@install libtpm2.so $(RPM_INSTALL_ROOT)/usr/lib64
clean:		
		rm -f *.o *.so tpm_server *~

# %.o:		%.c
# 		$(CC) $(CCFLAGS) $< -o $@

