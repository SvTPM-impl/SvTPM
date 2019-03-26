######## SGX SDK Settings ########

export SGX_SDK ?= /opt/intel/sgxsdk
export SGX_SSL ?= /opt/intel/sgxssl
SGX_MODE ?= SIM
SGX_ARCH ?= x64


##############

App := qemu
App_Name := x86_64-softmmu/qemu-system-x86_64
Enclave := libtpm2
Enclave_Name := libtpm2.so
Signed_Enclave_Name := libtpm2.signed.so
Enclave_Config_File := Enclave.config.xml

export Qemu_C_Flags := -I$(SGX_SDK)/include
export SGXSSL_INCLUDE_PATH := $(SGX_SSL)/include

SGX_TPROTECTED_FS := sgx_tprotected_fs
SGX_UPROTECTED_FS := sgx_uprotected_fs

##############

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	export SGX_COMMON_CFLAGS := -m32
	export SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	export SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	export SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	export SGX_COMMON_CFLAGS := -m64
	export SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	export SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	export SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	export Urts_Library_Name := sgx_urts_sim
else
	export Urts_Library_Name := sgx_urts
endif

App_Cpp_Files := App/App.cpp $(wildcard App/Edger8rSyntax/*.cpp) $(wildcard App/TrustedLibrary/*.cpp)
QEMU_SGX_PATH=/home/project/qemu-sgx/qemu
QEMU_SGX_PATH=`pwd`/qemu
#export QEMU_SGX_PATH
export App_Include_Paths := -I$(SGX_SDK)/include -I$(QEMU_SGX_PATH)$(QEMU_PATH)/ -I$(QEMU_SGX_PATH)$(QEMU_PATH)/include


App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths) 

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11
export App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -l$(SGX_UPROTECTED_FS) -lpthread 

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

#App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)


######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

# Enclave_Cpp_Files := Enclave/1.cpp $(wildcard Enclave/Edger8rSyntax/*.cpp) $(wildcard Enclave/TrustedLibrary/*.cpp)
Enclave_C_Files := $(wildcard libtpm2/*.c)
Enclave_Cpp_Files := $(wildcard libtpm2/*.cpp) $(wildcard libtpm2/Edger8rSyntax/*.cpp) $(wildcard libtpm2/TrustedLibrary/*.cpp)

Enclave_Include_Paths := -IInclude -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

export Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
# export Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++
export Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tstdcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=Enclave.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Enclave_C_Objects := $(Enclave_C_Files:.c=.o)


ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool. See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(App) $(Signed_Enclave_Name)

endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

install:
	@cd $(App) && make install


######## App Objects ########
.PHONY: $(App)

$(App)/Enclave_u.c: $(SGX_EDGER8R) libtpm2/Enclave.edl
	@cd $(App) && $(SGX_EDGER8R) --untrusted ../libtpm2/Enclave.edl --search-path ../libtpm2 --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(App)/Enclave_u.o: $(App)/Enclave_u.c
	@echo $(App_C_Flags)
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

#$(App)/$(App_Name): $(App)/Enclave_u.o
#	cd $(App) && make
$(App)/$(App_Name): 
	cd $(App) && make

$(App): $(App)/Enclave_u.o $(App)/$(App_Name)
	cd $(App) && make
	


######## Enclave Objects ########

$(Enclave)/Enclave_t.c: $(SGX_EDGER8R) $(Enclave)/Enclave.edl
	@cd $(Enclave) && $(SGX_EDGER8R) --trusted Enclave.edl --search-path ./ --search-path $(SGX_SDK)/include --search-path $(SGXSSL_INCLUDE_PATH) --search-path /usr/include
	@echo "GEN  =>  $@"

$(Enclave)/Enclave_t.o: $(Enclave)/Enclave_t.c
	$(CC) $(Enclave_C_Flags) -Ilibtpm2/ -c -g $< -o $@
	@echo "CC   <=  Enclave_t.c"

$(Signed_Enclave_Name): $(Enclave)/Enclave_t.o
	cd $(Enclave) && make
	cd $(Enclave) && $(SGX_ENCLAVE_SIGNER) sign -key Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"
	@cp $(Enclave)/$(Signed_Enclave_Name) /usr/lib/
	@echo "INSTALL =>  $@"



.PHONY: clean
clean:
	@cd $(App) && (make clean) && (rm -f Enclave_u.*)
	@cd $(Enclave) && (make clean) && (rm -f Enclave_t.*)
