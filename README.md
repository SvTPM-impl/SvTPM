# SvTPM
vTPM with SGX protection
## Introduction
SvTPM is a secure and efficient software-based vTPM implementation based on hardwarerooted Trusted Execution Environment (TEE), providing a whole life cycle protection of vTPMs in the cloud. SvTPM offers strong isolation protection, so that cloud tenants or even cloud administrators cannot get vTPM’s private keys or any other sensitive data.  
This repository mainly includes two parts: QEMU and libtpm2. In the QEMU section, we implemented the backend interface of the TPM and were responsible for creating and destroying the enclave. In the libtpm2 section, we solved some security challenges, such as NVRAM rollback issues, security entropy sources, etc., which will eventually be compiled into enclave files.


## Platform Support
Ubuntu 18.04

## Prerequisites
* [linux-sgx](https://github.com/intel/linux-sgx) : 2.3
* [intel-sgx-ssl](https://github.com/intel/intel-sgx-ssl) : 2.2

## Installing
```shell
cd SvTPM/qemu
./configure --prefix=/usr --enable-debug --enable-tpm --enable-kvm --enable-sdl --target-list=x86_64-softmmu
cd SvTPM
make SGX_MODE=HW SGX_DEBUG=1
make install
```

## Usage
```shell
qemu-system-x86_64 -enable-kvm -m 2048 -hda ubuntu.qcow2 -device tpm-tis,tpmdev=tpm-tpm0,id=tpm0 -tpmdev libtpms,id=tpm-tpm0,nvram=drive-nvram0-0-0,startup=clear -drive file=nvram.qcow2,if=none,id=drive-nvram0-0-0  -nographic -sdl -bios bios.bin -boot menu=on -d unimp -D /tmp/kvm.log
```
