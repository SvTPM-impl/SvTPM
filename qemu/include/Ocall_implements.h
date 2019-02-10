#ifndef _OCALL_IMPLEMENTS_H_
#define _OCALL_IMPLEMENTS_H_

#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#if defined(__cplusplus)
extern "C" {
#endif

/*FILE * ocall_fopen(const char * path, const char * mode);
int ocall_fseek(FILE *stream, long offset, int fromwhere);
long ocall_ftell(FILE *stream);
size_t ocall_fwrite(const void* buffer, size_t size, size_t count, FILE* stream);
int ocall_rand (void);
int ocall_fclose(FILE *stream);
int ocaxll_gettimeofday(struct timeval*tv, struct timezone *tz);
*/

long ocall_clock(void); /* For Performance evaluation */
time_t ocall_time(time_t *timep, int t_len);
struct tm *ocall_localtime(const time_t *timep, int t_len);
struct tm *ocall_gmtime_r(const time_t *timep, int t_len, struct tm *tmp, int tmp_len);
/*int ocall_gettimeofday(void *tv, int tv_size);*/
int ocall_getsockopt(int s, int level, int optname, char *optval, int optval_len, int* optlen);
int ocall_setsockopt(int s, int level, int optname, const void *optval, int optlen);
int ocall_socket(int af, int type, int protocol);
int ocall_bind(int s, const void *addr, int addr_size);
int ocall_connect(int s, const void *addr, int addrlen);
int ocall_accept(int s, void *addr, int addr_size, int *addrlen);
int ocall_shutdown(int fd, int how);
int ocall_read(int fd, void *buf, int n);
int ocall_write(int fd, const void *buf, int n);
int ocall_close(int fd);
int ocall_getenv(const char *env, int envlen, char *ret_str,int ret_len);
void ocall_print_string(const char *str);

void ocall_getTime(void);

#if defined(__cplusplus)
}
#endif

#endif /* !_OCALL_IMPLEMENTS_H_ */