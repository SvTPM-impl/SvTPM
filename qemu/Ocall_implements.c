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



/*FILE * ocall_fopen(const char * path, const char * mode){
	return fopen(path, mode);
}

size_t ocall_fread (void *buffer, size_t size, size_t count, FILE *stream){
	return fread(buffer, size, count, stream);
}

size_t ocall_fwrite(const void* buffer, size_t size, size_t count, FILE* stream){
	return fwrite(buffer, size, count, stream);
}*/


// int ocall_sgx_read(int fd, [out, size=n]void *buf, int n);
// int ocall_sgx_write(int fd, [in, size=n]const void *buf, int n);
// int ocall_sgx_close(int fd);

/*FILE * ocall_fopen(const char * path, const char * mode){
	return fopen(path, mode);
}

int ocall_fseek(FILE *stream, long offset, int fromwhere){
	return fseek(stream, offset, fromwhere);
}

long ocall_ftell(FILE *stream){
	return ftell(stream);
}

size_t ocall_fwrite(const void* buffer, size_t size, size_t count, FILE* stream){
	return fwrite(buffer, size, count, stream);
}

int ocall_rand (void){
	return rand();
}

void ocall_fclose(FILE *stream){
	fclose(stream);
}

void ocall_gettimeofday(struct timeval*tv, struct timezone *tz){
	gettimeofday(tv, tz);
}



long ocall_clock(void)
{
	struct timespec tstart={0,0}, tend={0,0};
    clock_gettime(CLOCK_MONOTONIC, &tstart);
	return tstart.tv_sec * 1000000 + tstart.tv_nsec/1000; // Return micro seconds
}

time_t ocall_time(time_t *timep, int t_len)
{
	return 	time(timep);
}

struct tm *ocall_localtime(const time_t *timep, int t_len)
{
	return localtime(timep);
}

struct tm *ocall_gmtime_r(const time_t *timep, int t_len, struct tm *tmp, int tmp_len)
{
	return gmtime_r(timep, tmp);
}

int ocall_gettimeofday(void *tv, int tv_size)
{
	return gettimeofday((struct timeval *)tv, NULL);
}

int ocall_getsockopt(int s, int level, int optname, char *optval, int optval_len, int* optlen)
{
    return getsockopt(s, level, optname, optval, (socklen_t *)optlen);
}

int ocall_setsockopt(int s, int level, int optname, const void *optval, int optlen)
{
	return setsockopt(s, level, optname, optval, optlen);
}

int ocall_socket(int af, int type, int protocol)
{
	int retv;
	retv = socket(af, type, protocol);
	return retv;
}

int ocall_bind(int s, const void *addr, int addr_size)
{
	return bind(s, (struct sockaddr *)addr, addr_size);
}

int ocall_listen(int s, int backlog)
{
	return listen(s, backlog);
}

int ocall_connect(int s, const void *addr, int addrlen)
{
	int retv = connect(s, (struct sockaddr *)addr, addrlen);
	return retv;
}

int ocall_accept(int s, void *addr, int addr_size, int *addrlen)
{
	return accept(s, (struct sockaddr *)addr, (socklen_t *)addrlen);
}

int ocall_shutdown(int fd, int how)
{
	return shutdown(fd, how);
}

int ocall_read(int fd, void *buf, int n)
{
	return read(fd, buf, n);
}

int ocall_write(int fd, const void *buf, int n)
{
	return write(fd, buf, n);
}

int ocall_close(int fd)
{
	return close(fd);
}

int ocall_getenv(const char *env, int envlen, char *ret_str,int ret_len)
{
	const char *env_val = getenv(env);
	if(env_val == NULL){
		return -1;
	}
	memcpy(ret_str, env_val, strlen(env_val)+1);
	return 0;
}

void ocall_print_string(const char *str)
{
    printf("%s", str);
}

void ocall_exit(int e)
{
	exit(e);
}

void ocall_free(void *ptr)
{
	free(ptr);
}*/