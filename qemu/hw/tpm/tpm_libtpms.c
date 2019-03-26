#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "qemu/sockets.h"
#include "hw/hw.h"
#include "hw/i386/pc.h"
#include "tpm_tis.h"
#include "tpm_util.h"
#include <stdbool.h>
#include <stdint.h>
#include "qapi/error.h"

#include "sysemu/tpm_backend.h"
#include "tpm_int.h"
#include "tpm_nvram.h"
#include "qapi/qmp/qerror.h"
#include "migration/migration.h"
#include "sysemu/tpm_backend_int.h"
#include "block/block_int.h"

#include<libtpms2/Platform.h>
#include<libtpms2/Manufacture_fp.h>
#include<libtpms2/TPMLib.h>
#include<libtpms2/tpm_store.h>

#include <sys/time.h>



  
  /* #define DEBUG_TPM */
  
typedef uint32_t  TPM_RESULT;		/* The return code from a function  */
#define TPM_SUCCESS 0x0
typedef uint32_t  TPM_MODIFIER_INDICATOR; /* The locality modifier  */
typedef unsigned char  TPM_BOOL; 
  
#define TPM_PERMANENT_ALL_NAME	"permall"
#define TPM_SAVESTATE_NAME      "savestate"
#define TPM_VOLATILESTATE_NAME      "volatilestate"
#define TPM_RETRY  0x00000800

#define MAX_RESPONSE_SIZE	4096


#ifdef DEBUG_TPM
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)
#define DPRINTF_BUFFER(buffer, len) \
          do { tpm_ltpms_dump_buffer(stderr, buffer, len); } while (0)
#else
#define DPRINTF(fmt, ...) \
                   do { } while (0)
#define DPRINTF_BUFFER(buffer, len) \
                               do { } while (0)
#endif
  
#define NVRAM_BLOB_OFFSET_FROM_ENTRY(entry_offset) \
                                              (entry_offset + sizeof(uint32_t))
  
#define TYPE_TPM_LIBTPMS "tpm-libtpms"
#define TPM_LIBTPMS(obj) \
                      OBJECT_CHECK(TPMLTPMsState, (obj), TYPE_TPM_LIBTPMS)
  
static const TPMDriverOps tpm_ltpms_driver;
  
  
/* data structures */
typedef struct TPMLTPMsThreadParams {
	TPMState *tpm_state;
  
	TPMRecvDataCB *recv_data_callback;
	TPMBackend *tb;
} TPMLTPMsThreadParams;
  
struct NVRAMEntry {
	uint32_t cur_size;
	uint8_t *buffer;
};
  
typedef struct NVRAMEntry NVRAMEntry;
  
struct TPMLTPMsState {
	TPMBackend parent;
  
	TPMBackendThread tbt;
  
	TPMLTPMsThreadParams tpm_thread_params;
  
	bool tpm_initialized;
	bool had_fatal_error;
  
	BlockDriverState *bdrv;
  
	NVRAMEntry *perm_state_entry;
  
	uint32_t perm_state_entry_offset;
  
	uint32_t perm_state_max_size;
  
	QemuMutex tpm_initialized_mutex;
  
	uint8_t locty; /* locality of command being executed by libtpms */
	
	TPMVersion tpm_version;
};
  
typedef struct TPMLTPMsState TPMLTPMsState;
static TPMBackend *tpm_backend;
  
/* functions */
static void tpm_ltpms_nv_init(char *path);
static void tpm_ltpms_tpm_init(char *path);


// SGX
#include "sgx_urts.h"
#include "Enclave_u.h"

#include <sys/types.h>
#include <pwd.h>

#define ENCLAVE_FILENAME "/usr/lib/libtpm2.signed.so"
#define TOKEN_FILENAME   "enclave.token"
#define MAX_PATH FILENAME_MAX
#define MAX_BUF_LEN 100


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

extern uint8_t qemu_uuid[16];

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
        NULL
    },
};


#ifdef DEBUG_TPM

static inline void tpm_ltpms_dump_buffer(FILE *stream,
	unsigned char *buffer,
	unsigned int len)
{
	int i;
  
	for (i = 0; i < len; i++) {
		if (i && !(i % 16)) {
			fprintf(stream, "\n");
		}
		fprintf(stream, "%.2X ", buffer[i]);
	}
	fprintf(stream, "\n");
}
#endif
  
static inline void tpm_ltpms_free_nvram_buffer(NVRAMEntry *entry)
{
	if (entry && entry->buffer) {
		TPM_Free(entry->buffer);
		entry->buffer = NULL;
		entry->cur_size = 0;
	}
 
}
  
/*
 * Generates the drive offsets where NVRAM blobs are stored.  Each offset
 * allows for enough room to store the current blob size plus a blob of
 * the maximum size.
 */
static void tpm_ltpms_get_nvram_offsets(TPMLTPMsState *tpm_ltpms)
{
	tpm_ltpms->perm_state_entry_offset = 0;
	// tpm_ltpms->perm_state_max_size = 16 * 1024;
    tpm_ltpms->perm_state_max_size = 18 * 1024;
  
}
  
/*
 * Writes an NVRAM entry and it's blob to the specified drive offset
 */
static int tpm_ltpms_write_to_nvram(TPMLTPMsState *tpm_ltpms,
	uint32_t offset,
	NVRAMEntry *entry,
	uint32_t max_size)
{
	int rc;
	uint8_t *buffer = entry->buffer;
	uint32_t size = entry->cur_size;
	BlockDriverState *bdrv = tpm_ltpms->bdrv;
  
	DPRINTF("tpm_libtpms: Writing NVRAM entry to offset %"PRIu32"\n", offset);
  
	if (tpm_ltpms->had_fatal_error) {
		return TPM_FAIL;
	}
  
	if (size > max_size) {
		error_report(ERROR_CLASS_GENERIC_ERROR, "TPM NVRAM blob size too big");
		return TPM_FAIL;
	}
  
	DPRINTF("tpm_libtpms: current blob size = %"PRIu32"\n", size);
  
	// Write the blob
	if (size > 0) {
		DPRINTF_BUFFER(buffer, size);
  
		rc = tpm_nvram_bdrv_write(bdrv,
			NVRAM_BLOB_OFFSET_FROM_ENTRY(offset),
			buffer,
			size);
		if (rc != size) {
			error_report(ERROR_CLASS_GENERIC_ERROR, "TPM NVRAM write failed");
			return rc;
		}
	}
  
	// Blob size is stored on disk in big-endian 
	size = cpu_to_be32(size);
  
	// Write the blob size 
	rc = tpm_nvram_bdrv_write(bdrv, offset, (uint8_t *)&size, sizeof(size));
	if (rc != sizeof(size)) {
		error_report(ERROR_CLASS_GENERIC_ERROR, "TPM NVRAM write failed");
		return rc;
	}
  
	return TPM_SUCCESS;
}

//////////////////////////////////////////////////
/*extern char nvram_key[256];

void get_nvram_key(char* nv_key)
{
	int len = strlen(nv_key);
	nvram_key[len] = '\0';
}*/
/////////////////////////////////////////////////
  
/*
 * Reads an NVRAM entry and it's blob from the specified drive offset
 */
static int tpm_ltpms_read_from_nvram(TPMLTPMsState *tpm_ltpms,
	uint32_t offset,
	NVRAMEntry **entry,
	uint32_t max_size)
{
  
	int rc;
	uint8_t *buffer = NULL;
	uint32_t *size = NULL;
	BlockDriverState *bdrv = tpm_ltpms->bdrv;
	BlockDriver *drv = bdrv->drv;
  
	DPRINTF("tpm_libtpms: Reading NVRAM entry from offset %"PRIu32"\n", offset);
  
	if (tpm_ltpms->had_fatal_error) {
		return TPM_FAIL;
	}
  
	// Allocate the in-memory blob entry 
	if (!(*entry))
	{
		rc = TPM_Malloc((unsigned char **)entry, sizeof(**entry));
		if (rc != TPM_SUCCESS) {
			error_report(ERROR_CLASS_GENERIC_ERROR,
				"TPM memory allocation failed");
			abort();
		}

	}

  
	// Read the blob size
	rc = tpm_nvram_bdrv_read(bdrv, offset, (uint8_t **)&size, sizeof(*size));
	if (rc != sizeof(*size)) {
		error_report(ERROR_CLASS_GENERIC_ERROR, "TPM NVRAM read failed");
		goto err_exit;
	}
  
	// Blob size is stored on disk in big-endian
	*size = be32_to_cpu(*size);
  
	if (*size > max_size) {
		error_report(ERROR_CLASS_GENERIC_ERROR, "TPM NVRAM blob size too big");
		rc = TPM_FAIL;
		goto err_exit;
	}
  
	DPRINTF("tpm_libtpms: current blob size = %"PRIu32"\n", *size);
  
	(*entry)->cur_size = *size;
	(*entry)->buffer = NULL;
  
	// Read the blob
	if (*size > 0) {
		rc = tpm_nvram_bdrv_read(bdrv,
			NVRAM_BLOB_OFFSET_FROM_ENTRY(offset),
			&buffer,
			*size);
		if (rc != *size) {
			error_report(ERROR_CLASS_GENERIC_ERROR, "TPM NVRAM read failed");
			goto err_exit;
		}
  
		(*entry)->buffer = buffer;
  
		DPRINTF_BUFFER(buffer, *size);
	}
  
	rc = TPM_SUCCESS;
  
err_exit:
	if (size) {
		TPM_Free((uint8_t *)size);
	}
	return rc;
}
  
/*
 * Loads the TPM's NVRAM state from NVRAM drive into memory
 */
static int tpm_ltpms_load_tpm_state_from_nvram(TPMLTPMsState *tpm_ltpms)
{
	int rc;
  
	rc = tpm_ltpms_read_from_nvram(tpm_ltpms,
		tpm_ltpms->perm_state_entry_offset,
		&tpm_ltpms->perm_state_entry,
		tpm_ltpms->perm_state_max_size);
	if (rc) {
		goto err_exit;
	}
  
	return 0;
  
err_exit:
	tpm_ltpms->had_fatal_error = true;
  
	return rc;
}
  
/*
 * Processes a command request by calling into libtpms, and returns
 * result to front end
 */
static void tpm_ltpms_process_request(TPMLTPMsState *tpm_ltpms,
	TPMLTPMsThreadParams *thr_parms)
{
	uint32_t in_len, out_len;
	uint8_t *in, *out;
	TPMLocality *locty_data;
	bool selftest_done = false;
  
	DPRINTF("tpm_libtpms: processing command\n");
  
	tpm_ltpms->locty = thr_parms->tpm_state->locty_number;
  
	locty_data = thr_parms->tpm_state->locty_data;
  
	in      = locty_data->w_buffer.buffer;
	in_len  = locty_data->w_offset;
	out     = locty_data->r_buffer.buffer;
	out_len = locty_data->r_buffer.size;
  
	if (tpm_ltpms->tpm_initialized) {
		DPRINTF("tpm_libtpms: received %d bytes from VM in locality %d\n",
			in_len,
			tpm_ltpms->locty);
		DPRINTF_BUFFER(in, in_len);
        
        // SGX  
		ecall_plat__LocalitySet(global_eid, 3);
		ecall_ExecuteCommand(global_eid, in_len, in, &out_len, &out);
            
		TPMState *s = thr_parms->tpm_state;
		TPMTISEmuState *tis = &s->s.tis;
		tis->loc[0].r_buffer.buffer = out;
  
		goto send_response;
		error_report(ERROR_CLASS_GENERIC_ERROR,
			"TPM libtpms command processing failed");
	}
	else {
		error_report(ERROR_CLASS_GENERIC_ERROR,
			"TPM libtpms not initialized");
	}
  
send_response:
  
	thr_parms->recv_data_callback(thr_parms->tpm_state, tpm_ltpms->locty, selftest_done);
      
	return;
}


/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}


int qemu_create_enclave()
{
	char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL){
			fclose(fp);   	
        } 
		qemu_log("[*] failed to create enclave.\n");
		printf("[*] failed to create enclave.\n");
		abort();
        // return -1;
    }else{
		qemu_log("[*]  successed to create enclave.\n");
		printf("[*]  successed to create enclave.\n");    	
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
} 

int qemu_destroy_enclave()
{
	if(global_eid){
		if(SGX_SUCCESS != sgx_destroy_enclave(global_eid)){
			qemu_log("[*] failed to destory enclave.\n");
			printf("[*] failed to destory enclave.\n");
		}else{
			qemu_log("[*] successed to destory enclave.\n");
			printf("[*] successed to destory enclave.\n");
		}
	}

	return 0;
} 
  
static void tpm_ltpms_worker_thread(gpointer data, gpointer user_data)
{
	TPMLTPMsThreadParams *thr_parms = user_data;
	TPMLTPMsState *tpm_ltpms = TPM_LIBTPMS(thr_parms->tb);
	TPMBackendCmd cmd = (TPMBackendCmd)data;
  
	tpm_backend = thr_parms->tb;
  
	DPRINTF("tpm_libtpms: processing command type %d\n", cmd);
  
	switch (cmd) {
	case TPM_BACKEND_CMD_TPM_RESET:
		if (tpm_ltpms->tpm_initialized) {
			qemu_mutex_lock(&tpm_ltpms->tpm_initialized_mutex);
			tpm_ltpms->tpm_initialized = false;
			qemu_mutex_unlock(&tpm_ltpms->tpm_initialized_mutex);
  
			ecall_plat__Signal_PowerOff(global_eid);

		}
		/* fall through */
	case TPM_BACKEND_CMD_INIT:
		{
			
			tpm_ltpms->bdrv = bdrv_find(tpm_backend->nvram_id); 
			BlockDriverState *bd = tpm_ltpms->bdrv;
			char *path = (char *)bd->filename;

			// qemu_create_enclave();

			
			tpm_ltpms_nv_init(path);
			tpm_ltpms_tpm_init(path);
			//ecall_plat__TPM_Init(global_eid, path);

			// SGX
			ecall_plat__LocalitySet(global_eid, 3);

			// add enclave

                  
			unsigned char *respbuffer = NULL;
			respbuffer = (unsigned char *)malloc(MAX_RESPONSE_SIZE);
			if (respbuffer == NULL)
			{
				error_report(ERROR_CLASS_GENERIC_ERROR, "TPM malloc failed");
			}
			uint32_t resp_size = MAX_RESPONSE_SIZE;
			int i;
			unsigned char TPM_Startup[] = {
				0x80,
				0x01,
				0x00,
				0x00,
				0x00,
				0x0C,
				0x00,
				0x00,
				0x01,
				0x44,
				0x00,
				0x00
			};
			uint32_t command_size = sizeof(TPM_Startup);
			unsigned char *command = TPM_Startup;
			ecall_ExecuteCommand(global_eid, command_size, command, &resp_size, &respbuffer);
			for (i = 0;i < resp_size;i++)
				qemu_log("... %02x ...\n", respbuffer[i]);
 
 			free(respbuffer);
			qemu_mutex_lock(&tpm_ltpms->tpm_initialized_mutex);
			tpm_ltpms->tpm_initialized = true;
			qemu_mutex_unlock(&tpm_ltpms->tpm_initialized_mutex);
		}
		break;
  
	case TPM_BACKEND_CMD_PROCESS_CMD:
		{
			struct timeval tval1;
			uint64_t tpmtime1;
			struct timeval tval2;
			uint64_t tpmtime2;

			gettimeofday(&tval1, NULL);
			tpmtime1 = ((uint64_t)tval1.tv_sec * 1000 * 1000) + ((uint64_t)tval1.tv_usec);
			//qemu_log("[*] tpmtime1 : %qu\n", tpmtime1);
			//printf("[*] tpmtime1 : %qu\n", tpmtime1);

			tpm_ltpms_process_request(tpm_ltpms, thr_parms);


			gettimeofday(&tval2, NULL);
			tpmtime2 = ((uint64_t)tval2.tv_sec * 1000 * 1000) + ((uint64_t)tval2.tv_usec);
			//qemu_log("[*] tpmtime2 : %qu\n", tpmtime2);
			//printf("[*] tpmtime2 : %qu\n", tpmtime2);
			//qemu_log("[*] time interval : %qu\n", tpmtime2-tpmtime1);
			//printf("[*] time interval : %qu\n", tpmtime2-tpmtime1);
		}
		break;
	case TPM_BACKEND_CMD_END:
		if (tpm_ltpms->tpm_initialized) {
			qemu_mutex_lock(&tpm_ltpms->tpm_initialized_mutex);
			tpm_ltpms->tpm_initialized = false;
			qemu_mutex_unlock(&tpm_ltpms->tpm_initialized_mutex);
  
			ecall_plat__Signal_PowerOff(global_eid);

			// qemu_destroy_enclave();
		}
		break;
	}
}
  
/*
 * tpm_ltpms_nv_init()
 * initialize NVRAM and Load NVRAM to TPM state
 * if TPM is first used,initialize TPM by call TPM_Manufacture()
 */
static void tpm_ltpms_nv_init(char *path) {

    int rc;
	qemu_log("path:%s\n", path);
	//ecall_plat__NVEnable_Path(global_eid, &rc, NULL, path);
  
	// initialize NVRAM
	ecall_plat__NvInit(global_eid, &rc, qemu_uuid);
  
	// load NVRAM to TPM internal state
	struct timeval tval1;
	uint64_t tpmtime1;
	struct timeval tval2;
	uint64_t tpmtime2;

	gettimeofday(&tval1, NULL);
	tpmtime1 = ((uint64_t)tval1.tv_sec * 1000 * 1000) + ((uint64_t)tval1.tv_usec);

	//printf("[*] nvload time1 : %qu\n", tpmtime1);
	ecall_plat__NvLoad(global_eid, &rc, qemu_uuid);
	gettimeofday(&tval2, NULL);
	tpmtime2 = ((uint64_t)tval2.tv_sec * 1000 * 1000) + ((uint64_t)tval2.tv_usec);
	//qemu_log("[*] tpmtime2 : %qu\n", tpmtime2);
	//printf("[*] nvload time2 : %qu\n", tpmtime2);
	//qemu_log("[*] time interval : %qu\n", tpmtime2-tpmtime1);
	//printf("[*] nvload interval : %qu\n", tpmtime2-tpmtime1);  
	
	uint32_t *size = NULL;
	TPMLTPMsState *tpm_ltpms = TPM_LIBTPMS(tpm_backend);
	BlockDriverState *bdrv = tpm_ltpms->bdrv;
	rc = tpm_nvram_bdrv_read(bdrv, tpm_ltpms->perm_state_entry_offset, (uint8_t **)&size, sizeof(*size));
	if (rc != sizeof(*size)) {
		error_report(ERROR_CLASS_GENERIC_ERROR, "TPM NVRAM read failed");
	}
  
	// Blob size is stored on disk in big-endian 
	*size = be32_to_cpu(*size);
  
	// if TPM is first used (NVRAM size is 0),initialize TPM
	if (*size <= 0)
		ecall_TPM_Manufacture(global_eid, &rc, 1);
}
  
  
/*
 * tpm_ltpms_tpm_init()
 * initialize TPM
 */
static void tpm_ltpms_tpm_init(char *path) {    
    int rc;
	// ecall_plat__Signal_PowerOn_Path(global_eid);
    ecall_plat__Signal_PowerOn(global_eid, &rc);
	ecall_TPM_Init(global_eid);
}
  

/* TPM_Malloc() is a general purpose wrapper around malloc()
 */

TPM_RESULT TPM_Malloc(unsigned char **buffer, uint32_t size)
{
    int          rc = 0;
    
    /* assertion test.  The coding style requires that all allocated pointers are initialized to
       NULL.  A non-NULL value indicates either a missing initialization or a pointer reuse (a
       memory leak). */
    if (rc == 0) {
        if (*buffer != NULL) {
            // printf("TPM_Malloc: Error (fatal), *buffer %p should be NULL before malloc\n", *buffer);
            rc = TPM_RC_PCR;
        }
    }
    /* verify that the size is not "too large" */
    if (rc == 0) {
        if (size > TPM_ALLOC_MAX) {
            // printf("TPM_Malloc: Error, size %u greater than maximum allowed\n", size);
            rc = TPM_RC_PCR;
        }       
    }
    /* verify that the size is not 0, this would be implementation defined and should never occur */
    if (rc == 0) {
        if (size == 0) {
            // printf("TPM_Malloc: Error (fatal), size is zero\n");
            rc = TPM_RC_PCR;
        }       
    }
    if (rc == 0) {
        *buffer = malloc(size);
        if (*buffer == NULL) {
            // printf("TPM_Malloc: Error allocating %u bytes\n", size);
            rc = TPM_RC_PCR;
        }
    }
    return rc;
}

void TPM_Free(unsigned char *buffer)
{
    free(buffer);
    return;
}

/* TPM_Realloc() is a general purpose wrapper around realloc()

 */

TPM_RESULT TPM_Realloc(unsigned char **buffer,
                       uint32_t size)
{
    int                 rc = 0;
    unsigned char       *tmpptr = NULL;

    /* verify that the size is not "too large" */
    if (rc == 0) {
        if (size > TPM_ALLOC_MAX) {
            // printf("TPM_Realloc: Error, size %u greater than maximum allowed\n", size);
            rc = TPM_RC_PCR;
        }       
    }
    if (rc == 0) {
        tmpptr = realloc(*buffer, size);
        if (tmpptr == NULL) {
            // printf("TPM_Realloc: Error reallocating %u bytes\n", size);
            rc = TPM_RC_PCR;
        }
    }
    if (rc == 0) {
        *buffer = tmpptr;
    }
    return rc;

}

  
/*****************************************************************
 * libtpms TPM library callbacks
 ****************************************************************/
  
/*
 * Called by libtpms before any access to persistent storage is done
 */
TPM_RESULT tpm_ltpms_nvram_init(void)
{
  
	int rc;
	TPMLTPMsState *tpm_ltpms = TPM_LIBTPMS(tpm_backend);
  
	tpm_ltpms->bdrv = bdrv_find(tpm_backend->nvram_id);
	if (!tpm_ltpms->bdrv) {
		error_report(ERROR_CLASS_GENERIC_ERROR, "TPM 'nvram' drive not found");
		abort();
	}
	rc = tpm_nvram_bdrv_init(tpm_ltpms->bdrv);
	if (rc) {
		error_report(ERROR_CLASS_GENERIC_ERROR, "TPM NVRAM drive init failed");
		abort();
	}
  
	tpm_ltpms_get_nvram_offsets(tpm_ltpms);
  
	rc = tpm_ltpms_load_tpm_state_from_nvram(tpm_ltpms);
	if (rc) {
		error_report(ERROR_CLASS_GENERIC_ERROR, "TPM NVRAM load state failed");
		abort();
	}
  
	return TPM_SUCCESS;
}
  
/*
 * Called by libtpms when the TPM wants to load state from persistent
 * storage
 */
TPM_RESULT tpm_ltpms_nvram_loaddata(unsigned char *data,
	uint32_t *length,
	uint32_t tpm_number,
	const char *name)
{
	TPM_RESULT rc = TPM_SUCCESS;
	TPMLTPMsState *tpm_ltpms = TPM_LIBTPMS(tpm_backend);
	NVRAMEntry **entry = NULL;
  
	DPRINTF("tpm_libtpms: Loading NVRAM state '%s' from storage\n", name);
  
	if (tpm_ltpms->had_fatal_error) {
		return TPM_FAIL;
	}
  
	*length = 0;
  
	if (!strcmp(name, TPM_PERMANENT_ALL_NAME)) {
		entry = &tpm_ltpms->perm_state_entry;
	}
	else if (!strcmp(name, TPM_SAVESTATE_NAME)) {
	}
	else if (!strcmp(name, TPM_VOLATILESTATE_NAME)) {
	}
  
	// In-memory entries are allocated for the life of the backend
	assert(entry != NULL);
  
	*length = (*entry)->cur_size;
	if (*length > 0) {
/*		rc = TPM_Malloc(data, *length);
		if (rc == TPM_SUCCESS) {
			memcpy(*data, (*entry)->buffer, *length);
		}*/
        memcpy(data, (*entry)->buffer, *length);
/*		else {
			error_report(ERROR_CLASS_GENERIC_ERROR,
				"TPM memory allocation failed");
			abort();
		}*/
	}
  
	if (*length == 0) {
		rc = TPM_RETRY;
	}
  
	DPRINTF("tpm_libtpms: Read %"PRIu32" bytes from storage\n", *length);
  
	return rc;
}
  
/*
 * Called by libtpms when the TPM wants to store state to persistent
 * storage
 */
TPM_RESULT tpm_ltpms_nvram_storedata(const unsigned char *data,
	uint32_t length,
	uint32_t tpm_number,
	const char *name)
{
	TPM_RESULT rc = TPM_SUCCESS;
	TPMLTPMsState *tpm_ltpms = TPM_LIBTPMS(tpm_backend);
	NVRAMEntry *entry = NULL;
	uint32_t offset = 0, max_size = 0;
  
	DPRINTF("tpm_libtpms: Storing NVRAM state '%s' to storage\n", name);
  
	if (tpm_ltpms->had_fatal_error) {
		return TPM_FAIL;
	}
  
	if (!strcmp(name, TPM_PERMANENT_ALL_NAME)) {
		entry = tpm_ltpms->perm_state_entry;
		offset = tpm_ltpms->perm_state_entry_offset;
		max_size = tpm_ltpms->perm_state_max_size;
	}
	else if (!strcmp(name, TPM_SAVESTATE_NAME)) {
  
	}
	else if (!strcmp(name, TPM_VOLATILESTATE_NAME)) {
          
	}
  
	// In-memory entries are allocated for the life of the backend
	assert(entry != NULL);
  
	if (length > 0) {
		rc = TPM_Realloc(&entry->buffer, length);
		if (rc != TPM_SUCCESS) {
			error_report(ERROR_CLASS_GENERIC_ERROR,
				"TPM memory allocation failed");
			abort();
		}
		memcpy(entry->buffer, data, length);
		entry->cur_size = length;
	}
	else {
		tpm_ltpms_free_nvram_buffer(entry);
	}
  
	if (tpm_ltpms_write_to_nvram(tpm_ltpms, offset, entry, max_size)) {
		goto err_exit;
	}
  
	DPRINTF("tpm_libtpms: Wrote %"PRIu32" bytes to storage\n", length);
  
	return rc;
  
err_exit:
	tpm_ltpms->had_fatal_error = true;
  
	return TPM_FAIL;
}
  
/*
 * Called by libtpms when the TPM wants to delete state from persistent
 * storage
 */
static TPM_RESULT tpm_ltpms_nvram_deletename(uint32_t tpm_number,
	const char *name,
	TPM_BOOL mustExist)
{
  
	return TPM_SUCCESS;
  
}
  
/*
 * Called by libtpms to initialize the I/O subsystem of the TPM
 */
static TPM_RESULT tpm_ltpms_io_init(void)
{
	return TPM_SUCCESS;
}
  
/*
 * Called by libtpms when the TPM needs to determine the locality under
 * which a command is supposed to be executed
 */
static TPM_RESULT tpm_ltpms_io_getlocality(TPM_MODIFIER_INDICATOR *
                                           localityModifier,
	uint32_t tpm_number)
{
  
	return TPM_SUCCESS;
}
  
/*
 * Called by libtpms when the TPM needs to determine whether physical
 * presence has been asserted
 */
static TPM_RESULT tpm_ltpms_io_getphysicalpresence(TPM_BOOL *physicalPresence,
	uint32_t tpm_number)
{
	return TPM_SUCCESS;
}
  
  
struct libtpms_callbacks callbacks = {
	.sizeOfStruct = sizeof(struct libtpms_callbacks),
	.tpm_nvram_init = tpm_ltpms_nvram_init,
	.tpm_nvram_loaddata = tpm_ltpms_nvram_loaddata,
	.tpm_nvram_storedata = tpm_ltpms_nvram_storedata,
	.tpm_nvram_deletename = tpm_ltpms_nvram_deletename,
	.tpm_io_init = tpm_ltpms_io_init,
	.tpm_io_getlocality = tpm_ltpms_io_getlocality,
	.tpm_io_getphysicalpresence = tpm_ltpms_io_getphysicalpresence,
};
 
/*****************************************************************/
  
/*
 * Start the TPM (thread).  If it had been started before, then terminate
 * and start it again.
 */
static int tpm_ltpms_startup_tpm(TPMBackend *tb)
{
	struct TPMLTPMsState *tpm_ltpms = TPM_LIBTPMS(tb);
  
	/* 'power-reset' a running TPM; if none is running start one */
	tpm_backend_thread_tpm_reset(&tpm_ltpms->tbt,
		tpm_ltpms_worker_thread,
		&tpm_ltpms->tpm_thread_params);
  
	return 0;
}
  
static void tpm_ltpms_terminate_tpm_thread(TPMBackend *tb)
{
	struct TPMLTPMsState *tpm_ltpms = TPM_LIBTPMS(tb);
  
	tpm_backend_thread_end(&tpm_ltpms->tbt);
}
  
static void tpm_ltpms_reset(TPMBackend *tb)
{
	TPMLTPMsState *tpm_ltpms = TPM_LIBTPMS(tb);
  
	DPRINTF("tpm_libtpms: Resetting TPM libtpms backend\n");
  
	tpm_ltpms_terminate_tpm_thread(tb);
  
	tpm_ltpms->had_fatal_error = false;
}
  
static int tpm_ltpms_init(TPMBackend *tb,
	TPMState *s,
	TPMRecvDataCB *recv_data_cb)
{
    int rt;
	TPMLTPMsState *tpm_ltpms = TPM_LIBTPMS(tb);

    //qemu_create_enclave();

/*    ecall_TPMLIB_RegisterCallbacks(global_eid, &rt, (void *)&callbacks);
	if (rt != TPM_SUCCESS) {
		error_report(ERROR_CLASS_GENERIC_ERROR,
			"TPM libtpms callback registration failed");
		return -1;
	}*/
  
	tpm_ltpms->tpm_thread_params.tpm_state = s;
	tpm_ltpms->tpm_thread_params.recv_data_callback = recv_data_cb;
	tpm_ltpms->tpm_thread_params.tb = tb;
  
	qemu_mutex_init(&tpm_ltpms->tpm_initialized_mutex);
  
	return 0;
}
  
static bool tpm_ltpms_get_tpm_established_flag(TPMBackend *tb)
{
	TPMLTPMsState *tpm_ltpms = TPM_LIBTPMS(tb);
	bool tpmEstablished = false;
  
	qemu_mutex_lock(&tpm_ltpms->tpm_initialized_mutex);
	if (tpm_ltpms->tpm_initialized) {
		tpmEstablished = false;
	}
	qemu_mutex_unlock(&tpm_ltpms->tpm_initialized_mutex);
  
	return tpmEstablished;
}
  
static int tpm_ltpms_reset_tpm_established_flag(TPMBackend *tb,
	uint8_t locty)
{
	/* only a TPM 2.0 will support this */
	return 0;
}
  
static bool tpm_ltpms_get_startup_error(TPMBackend *tb)
{
	return false;
}
  
static size_t tpm_ltpms_realloc_buffer(TPMSizedBuffer *sb)
{
	size_t wanted_size = 4096;
	unsigned char       *res;
	if (sb->size != wanted_size) {
		res = realloc(sb->buffer, wanted_size);
		sb->buffer = res;
		sb->size = wanted_size;
	}
	//qemu_log("%c", *res); 出错原因在于如果不走上面的判断，则res是个随机地址
	return sb->size;
}
  
static void tpm_ltpms_deliver_request(TPMBackend *tb)
{
	TPMLTPMsState *tpm_ltpms = TPM_LIBTPMS(tb);
  
	tpm_backend_thread_deliver_request(&tpm_ltpms->tbt);
}
  
static void tpm_ltpms_cancel_cmd(TPMBackend *be)
{
}
  
static const char *tpm_ltpms_create_desc(void)
{
	return "libtpms TPM backend driver";
}
  
static TPMVersion tpm_ltpms_get_tpm_version(TPMBackend *tb)
{
	TPMLTPMsState *tpm_ltpms = TPM_LIBTPMS(tb);
  
	return tpm_ltpms->tpm_version;
}
  
/*
static int tpm_ltpms_handle_device_opts(QemuOpts *opts, TPMBackend *tb)
{
	TPMLTPMsState *tpm_ltpms = TPM_LIBTPMS(tb);
	tpm_ltpms->tpm_version = 2;
	
	return 0;
}
*/

static TPMBackend *tpm_ltpms_create(QemuOpts *opts, const char *id)
{

    qemu_create_enclave();

	Object *obj = object_new(TYPE_TPM_LIBTPMS);
	TPMBackend *tb = TPM_BACKEND(obj);
	const char *value;
	TPMLTPMsState *tpm_ltpms = TPM_LIBTPMS(tb);	
	tpm_ltpms->tpm_version = 2;
  
	tb->id = g_strdup(id);
	tb->fe_model = -1;
	tb->ops = &tpm_ltpms_driver;
	
	/*if (tpm_ltpms_handle_device_opts(opts, tb))
	{
		goto err_exit;
	}*/
  
	value = qemu_opt_get(opts, "nvram");
	if (!value) {
		error_report(QERR_MISSING_PARAMETER, "nvram");
		goto err_exit;
	}
	tb->nvram_id = g_strdup(value);
      
	/*add startup*/
	value = qemu_opt_get(opts, "startup");
	if (!value) {
		tb->startup_type = TPM_Startup_ST_STATE;
	}
      
	if (strcmp(value, "clear") == 0) {
		tb->startup_type = TPM_Startup_ST_CLEAR;
	}
	else if (strcmp(value, "state") == 0) {
		tb->startup_type = TPM_Startup_ST_STATE;
	}
	else if (strcmp(value, "deactivated") == 0) {
		tb->startup_type = TPM_Startup_ST_DEACTIVATED;
	}
          
	return tb;
  
err_exit:
	g_free(tb->id);
  
	return NULL;
}


  
static void tpm_ltpms_destroy(TPMBackend *tb)
{

	tpm_ltpms_terminate_tpm_thread(tb);
  
	g_free(tb->id);
	g_free(tb->nvram_id);

    qemu_destroy_enclave();
}
  
static const QemuOptDesc tpm_ltpms_cmdline_opts[] = {
	TPM_STANDARD_CMDLINE_OPTS,
{
	.name = "nvram",
	.type = QEMU_OPT_STRING,
	.help = "NVRAM drive id",
},
      
{
	.name = "startup",
	.type = QEMU_OPT_STRING,
	.help = "Startup type",
},
      
	{ /* end of list */ },
};
  
static const TPMDriverOps tpm_ltpms_driver = {
	.type = TPM_TYPE_LIBTPMS,
	.opts = tpm_ltpms_cmdline_opts,
	.desc = tpm_ltpms_create_desc,
	.create = tpm_ltpms_create,
	.destroy = tpm_ltpms_destroy,
	.init = tpm_ltpms_init,
	.startup_tpm = tpm_ltpms_startup_tpm,
	.realloc_buffer = tpm_ltpms_realloc_buffer,
	.reset = tpm_ltpms_reset,
	.had_startup_error = tpm_ltpms_get_startup_error,
	.deliver_request = tpm_ltpms_deliver_request,
	.cancel_cmd = tpm_ltpms_cancel_cmd,
	.get_tpm_established_flag = tpm_ltpms_get_tpm_established_flag,
	.reset_tpm_established_flag = tpm_ltpms_reset_tpm_established_flag,
	.get_tpm_version = tpm_ltpms_get_tpm_version,
};
  
  
static void tpm_ltpms_inst_init(Object *obj)
{
}
  
static void tpm_ltpms_inst_finalize(Object *obj)
{
}
  
static void tpm_ltpms_class_init(ObjectClass *klass, void *data)
{
	TPMBackendClass *tbc = TPM_BACKEND_CLASS(klass);
  
	tbc->ops = &tpm_ltpms_driver;
}
  
static const TypeInfo tpm_ltpms_info = {
	.name = TYPE_TPM_LIBTPMS,
	.parent = TYPE_TPM_BACKEND,
	.instance_size = sizeof(TPMLTPMsState),
	.class_init = tpm_ltpms_class_init,
	.instance_init = tpm_ltpms_inst_init,
	.instance_finalize = tpm_ltpms_inst_finalize,
};
  
static void tpm_libtpms_register(void)
{
	type_register_static(&tpm_ltpms_info);
	tpm_register_driver(&tpm_ltpms_driver);
}
  
type_init(tpm_libtpms_register);
  
