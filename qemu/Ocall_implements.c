#include "Ocall_implements.h"
#include "Enclave_u.h"


int ocall_rand (void){
	return rand();
}

void ocall_getTime (void){
	struct timeval tval;
    uint64_t tpmtime;

    gettimeofday(&tval, NULL);
    tpmtime = ((uint64_t)tval.tv_sec * 1000 *1000) + ((uint64_t)tval.tv_usec);
    printf("[*] seal time : %lld\n", tpmtime);
}

void ocall_gettimeofday(struct timeval*tv, struct timezone *tz){
	gettimeofday(tv, tz);
}

int ocall_tpm_ltpms_nvram_init(void){
	return tpm_ltpms_nvram_init();
}

int ocall_tpm_ltpms_nvram_storedata(const unsigned char *data, uint32_t length, uint32_t tpm_number, const char *name){
	return tpm_ltpms_nvram_storedata(data, length, tpm_number, name);
}

int ocall_tpm_ltpms_nvram_loaddata(unsigned char *data, uint32_t *length, uint32_t tpm_number, const char *name){
	return tpm_ltpms_nvram_loaddata(data, length, tpm_number, name);
}
