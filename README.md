# SvTPM
vTPM with SGX protection

## Platform Support
Ubuntu 18.04

## Prerequisites
* [linux-sgx](https://github.com/intel/linux-sgx) : 2.3
* [intel-sgx-ssl](https://github.com/intel/intel-sgx-ssl) : 2.2

## Build
```shell
cd SvTPM/qemu
./configure --prefix=/usr --enable-debug --enable-tpm --enable-kvm --enable-sdl --target-list=x86_64-softmmu
cd SvTPM
make SGX_MODE=HW SGX_DEBUG=1
make install
```

## Ｕsage
```shell
qemu-system-x86_64 -enable-kvm -m 2048 -hda ubuntu.qcow2 -device tpm-tis,tpmdev=tpm-tpm0,id=tpm0 -tpmdev libtpms,id=tpm-tpm0,nvram=drive-nvram0-0-0,startup=clear -drive file=nvram.qcow2,if=none,id=drive-nvram0-0-0  -nographic -sdl -bios bios.bin -boot menu=on -d unimp -D /tmp/kvm.log
```
