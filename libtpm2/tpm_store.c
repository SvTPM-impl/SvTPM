//** Description

// This file contains functions that migrate state of the TPM.

//** Includes and Data Definitions
#define PCR_C
#define OBJECT_C
#define SESSION_C
#define SESSION_PROCESS_C

#include <stdio.h>
#include <stdlib.h>
/*#include <memory.h>*/
#include <string.h>
//#include "InternalRoutines.h"
#include "Tpm.h"
//#include <Platform.h>
#include <Platform_fp.h>

#include "sgx_tseal.h"
#include "ssl_enclave_types.h"
#include "sgx_attributes.h"
//#include "tseal_migration_attr.h"

#define FLAGS_NON_SECURITY_BITS     (0xFFFFFFFFFFFFC0ULL | SGX_FLAGS_MODE64BIT | SGX_FLAGS_PROVISION_KEY| SGX_FLAGS_EINITTOKEN_KEY)
#define TSEAL_DEFAULT_FLAGSMASK     (~FLAGS_NON_SECURITY_BITS)

#define MISC_NON_SECURITY_BITS      0x0FFFFFFF  /* bit[27:0]: have no security implications */
#define TSEAL_DEFAULT_MISCMASK (~MISC_NON_SECURITY_BITS)


/* This tag defines the global variable s_pcrs in Global.c*/
#define PCR_START       0x0001
/* This tag defines the global variable s_objects in Global.c*/
#define OBJECT_START      0x0002
/* This tag defines the global variable gc in Global.c*/
#define STATE_CLEAR_DATA_START  0x0003
/* This tag defines the global variable gr in Global.c*/
#define STATE_RESET_DATA_START  0x0004
/* This tag defines the global variable s_sessions in Global.c*/
#define SESSION_SLOT_START        0x0005
/* This tag defines the global variable s_sessionHandles in Global.c*/
#define S_SESSION_HANDLES_START 0x0006
/* This tag defines the global variable s_attributes in Global.c*/
#define S_ATTRIBUTES_START    0x0007
/* This tag defines the global variable s_associatedHandles in Global.c*/
#define S_ASSOCIATEDHANDLES_START 0x0008
/* This tag defines the global variable s_nonceCaller in Global.c*/
#define S_NONCECALLER_START   0x0009
/* This tag defines the global variable s_inputAuthValues in Global.c*/
#define S_INPUTAUTHVALUES_START 0x000A

#define FAILED_TRIES_START 0x000B


sgx_sealed_data_t *volatile_sealed;
uint32_t volatile_sealed_len;
uint32_t global_failedTries;

int libtpms_seal_volatile(unsigned char *data, uint32_t data_len, unsigned char *volatile_sealed)
{
    uint32_t ret = 0;
    //uint32_t data_len = NV_MEMORY_SIZE;
    //volatile_sealed_len = 16944;
    volatile_sealed_len = sgx_calc_sealed_data_size(0, data_len);
    if (0xFFFFFFFF == volatile_sealed_len) {
        return ret;
    }
    /*if(s_NV_sealed == NULL){
        s_NV_sealed = (sgx_sealed_data_t *)malloc(volatile_sealed_len * sizeof(uint8_t));
    }*/


    sgx_attributes_t attribute_mask;
    attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
    attribute_mask.xfrm = 0x0;  
   
    if (SGX_SUCCESS != sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE, attribute_mask, TSEAL_DEFAULT_MISCMASK, 0, NULL, data_len, data, volatile_sealed_len, volatile_sealed)) {
        abort();
        //return ret;
    }
    //free(s_NV_sealed);
    return ret;
}

int libtpms_unseal_volatile(unsigned char *volatile_sealed, uint32_t volatile_sealed_len,
                     unsigned char *stream, uint32_t stream_size)
{
    uint32_t ret = 0;
    //len = sgx_calc_sealed_data_size(add_len, txt_len);
    //uint32_t s_NV_unsealed_len = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)data);
    //uint32_t s_NV_unsealed_len = NV_MEMORY_SIZE;

/*    if(s_NV_unsealed == NULL){
      s_NV_unsealed = (uint8_t *)malloc(s_NV_unsealed_len * sizeof(uint8_t));
    }*/
    //sgx_status_t rc = sgx_unseal_data((sgx_sealed_data_t *)data, NULL, 0, s_NV_unsealed, &s_NV_unsealed_len);
    sgx_status_t rc = sgx_unseal_data((sgx_sealed_data_t *)volatile_sealed, NULL, 0, stream, &stream_size);
    if (SGX_SUCCESS != rc) {
        abort();
    }
    //free(s_NV_unsealed);
    return ret;
}


/* TPM_Sbuffer_Init() sets up a new serialize buffer.  It should be called before the first use. */
void TPM_Sbuffer_Init(TPM_STORE_BUFFER *sbuffer)
{
    sbuffer->buffer = NULL;
    sbuffer->buffer_current = NULL;
    sbuffer->buffer_end = NULL;
}

/* TPM_Sbuffer_Get() gets the resulting byte buffer and its size. */

void TPM_Sbuffer_Get(TPM_STORE_BUFFER *sbuffer,
                     const unsigned char *buffer)
{
    uint32_t length = sbuffer->buffer_current - sbuffer->buffer;

    libtpms_seal_volatile(sbuffer->buffer, length, buffer);
    //*buffer = sbuffer->buffer;

    return;
}

/* TPM_Sbuffer_Delete() frees an existing buffer and reinitializes it.  It must be called when a
   TPM_STORE_BUFFER is no longer required, to avoid a memory leak.  The buffer can be reused, but in
   that case TPM_Sbuffer_Clear would be a better choice. */
void TPM_Sbuffer_Delete(TPM_STORE_BUFFER *sbuffer)
{

    free(sbuffer->buffer);

    TPM_Sbuffer_Init(sbuffer);

}

/* TPM_VolatileAll_Store() stores the TPM state to a stream that can be restored through
   TPM_VolatileAll_Load().

   The two functions must be kept in sync.
*/
// TPM_RESULT TPM_VolatileAll_Store(unsigned char **buffer,uint32_t *length,unsigned char tpm_volatile[])
TPM_RESULT TPM_VolatileAll_Store(unsigned char *buffer)
{

    TPM_RESULT rc = 0;
    TPM_STORE_BUFFER  sbuffer;   /* safe buffer for storing binary data */
  
//  printf(" TPM_VolatileAll_Store:\n");

    TPM_Sbuffer_Init(&sbuffer);     /* freed @1 */

    /* store the global variable s_pcrs */
    if (rc == 0) {
        rc = TPM_PCRs_Store(&sbuffer);
    }

    /* store the global variable s_objects */
    if (rc == 0) {
      rc = TPM_OBJECT_SLOT_Store(&sbuffer);
    }

    /* store the global variable gc */
    if (rc == 0) {
        rc = TPM_STATE_CLEAR_DATA_Store(&sbuffer);
    }

    /* store the global variable gr */
    if (rc == 0) {
        rc = TPM_STATE_RESET_DATA_Store(&sbuffer);
    }

    /* store the global variable s_sessions */
    if (rc == 0) {
        rc = TPM_SESSION_SLOT_Store(&sbuffer);
    }

    /* store several relevant global variables */
    if (rc == 0) {
        rc = TPM_SESSION_ABOUT_Store(&sbuffer);
    }
  
    if(rc == 0) {
        rc = TPM_FAILED_TRIES_Store(&sbuffer);

    }

    if (rc == 0) {
    /* get the serialized buffer and its length */
        TPM_Sbuffer_Get(&sbuffer, buffer);
  
    // printf("length:%d\n",*length);
    // memcpy(tpm_volatile,sbuffer.buffer,*length);
    }

    TPM_Sbuffer_Delete(&sbuffer); /* @1 */
    return rc;
}



/* TPM_VolatileAll_Load() restores the TPM state from a stream created by TPM_VolatileAll_Store()
   The two functions must be kept in sync.
*/
TPM_RESULT TPM_VolatileAll_Load(unsigned char *volatile_sealed,
                uint32_t volatile_sealed_len)
{
    TPM_RESULT     rc = 0;

    uint32_t stream_size = 12366;
    unsigned char *stream = malloc(stream_size);
    if(stream == NULL) {
        abort();
    }

    libtpms_unseal_volatile(volatile_sealed, volatile_sealed_len, stream, stream_size);

    /* load the global variable s_pcrs */
    if (rc == 0) {
        rc = TPM_PCRs_Load(&stream, &stream_size);
    }

    /* load the global variable s_objects */
    if (rc == 0) {
        rc = TPM_OBJECT_SLOT_Load(&stream, &stream_size);
    }

    /* load /* store the global variable gc */
    if (rc == 0) {
        rc = TPM_STATE_CLEAR_DATA_Load(&stream, &stream_size);
    }

    /* load /* store the global variable gr */
    if (rc == 0) {
        rc = TPM_STATE_RESET_DATA_Load(&stream, &stream_size);
    }

    /* load the global variable s_sessions */
    if (rc == 0) {
        rc = TPM_SESSION_SLOT_Load(&stream, &stream_size);
    }

    /* load several relevant global variables */
    if (rc == 0) {
        rc = TPM_SESSION_ABOUT_Load(&stream, &stream_size);
    }

    if (rc == 0) {
        rc = TPM_FAILED_TRIES_Load(&stream, &stream_size);
    }

    return rc;
}


TPM_RESULT TPM_FAILED_TRIES_Store(TPM_STORE_BUFFER *sbuffer)
{
    TPM_RESULT  rc = 0;
    size_t  i;

    //printf(" TPM_PCRs_Store:\n");
    
    if (rc == 0) {
        TPM_Sbuffer_Append16(sbuffer, FAILED_TRIES_START);
    }

    if (rc == 0) {
        rc = TPM_Sbuffer_Append(sbuffer, &gp.failedTries, sizeof(gp.failedTries));
        global_failedTries = gp.failedTries;
    }
    return rc;
}

TPM_RESULT TPM_FAILED_TRIES_Load( unsigned char **stream,
                 uint32_t *stream_size)
{
    TPM_RESULT  rc = 0;

    // printf("TPM_FAILED_TRIES_Load:\n");
    if (rc == 0) {
        rc = TPM_CheckTag(FAILED_TRIES_START, stream, stream_size);
    }

    if (rc == 0) {
        rc = TPM_Loadn(&gp.failedTries, sizeof(gp.failedTries), stream, stream_size);
        gp.failedTries = global_failedTries;
        //rc = TPM_Loadn(&gc, (sizeof(gp.failedTries)), stream, stream_size);
    }

    return rc;
}


/* TPM_PCRs_Store()
   
   serialize the global variable s_pcrs in Global.c to a stream contained in 'sbuffer'
   returns 0 or error codes
*/

TPM_RESULT TPM_PCRs_Store(TPM_STORE_BUFFER *sbuffer)
{
    TPM_RESULT  rc = 0;
    size_t  i;

    //printf(" TPM_PCRs_Store:\n");
    
    if (rc == 0) {
        TPM_Sbuffer_Append16(sbuffer, PCR_START);
    }

    if (rc == 0) {
        rc = TPM_Sbuffer_Append(sbuffer, s_pcrs, sizeof(s_pcrs));
    }
    return rc;
}

/* TPM_OBJECT_SLOT_Store()
   
   serialize the global variable s_objects in Global.c to a stream contained in 'sbuffer'
   returns 0 or error codes
*/

TPM_RESULT TPM_OBJECT_SLOT_Store(TPM_STORE_BUFFER *sbuffer)
{
    TPM_RESULT  rc = 0;

    //  printf(" TPM_OBJECT_SLOT_Store:\n");
    if (rc == 0) {
        rc = TPM_Sbuffer_Append16(sbuffer, OBJECT_START);
    }

    if (rc == 0) {
        rc = TPM_Sbuffer_Append(sbuffer, s_objects, sizeof(s_objects));
    }
  
    return rc;
}

/* TPM_STATE_CLEAR_DATA_Store()
   
   serialize the global variable gc in Global.c to a stream contained in 'sbuffer'
   returns 0 or error codes
*/

TPM_RESULT TPM_STATE_CLEAR_DATA_Store(TPM_STORE_BUFFER *sbuffer)
{
    TPM_RESULT  rc = 0;

//  printf(" TPM_STATE_CLEAR_DATA_Store:\n");
    if (rc == 0) {
        rc = TPM_Sbuffer_Append16(sbuffer, STATE_CLEAR_DATA_START);
    }
  
    if (rc == 0) {
        rc = TPM_Sbuffer_Append(sbuffer, &gc,sizeof(gc));
    }

    return rc;
}

/* TPM_STATE_RESET_DATA_Store()
   
   serialize the global variable gr in Global.c to a stream contained in 'sbuffer'
   returns 0 or error codes
*/

TPM_RESULT TPM_STATE_RESET_DATA_Store(TPM_STORE_BUFFER *sbuffer)

{
  TPM_RESULT  rc = 0;

  size_t  i;

//  printf(" TPM_STATE_RESET_DATA_Store:\n");

  if (rc == 0) {

    rc=TPM_Sbuffer_Append16(sbuffer, STATE_RESET_DATA_START);

  }

  if (rc == 0) {

    rc=TPM_Sbuffer_Append(sbuffer, &gr,sizeof(gr));

  }
  
    return rc;

}

/* TPM_SESSION_SLOT_Store()
   
   serialize the global variable s_sessions in Global.c to a stream contained in 'sbuffer'
   returns 0 or error codes
*/

TPM_RESULT TPM_SESSION_SLOT_Store(TPM_STORE_BUFFER *sbuffer)
{
  TPM_RESULT  rc = 0;

//  printf(" TPM_SESSION_SLOT_Store:\n");

  if (rc == 0) {
    rc=TPM_Sbuffer_Append16(sbuffer, SESSION_SLOT_START);
  }

  if (rc == 0) {
    rc=TPM_Sbuffer_Append(sbuffer, s_sessions,sizeof(s_sessions));
  }
  
    return rc;
}

/* TPM_SESSION_ABOUT_Store()
   
   serialize several relevant global variables to a stream contained in 'sbuffer'
   returns 0 or error codes
*/

TPM_RESULT TPM_SESSION_ABOUT_Store(TPM_STORE_BUFFER *sbuffer)
{
  TPM_RESULT  rc = 0;

//  printf(" TPM_SESSION_ABOUT_Store:\n");
  if (rc == 0) {
    rc=TPM_Sbuffer_Append16(sbuffer, S_SESSION_HANDLES_START);
  }

  if (rc == 0) {
    rc=TPM_Sbuffer_Append(sbuffer, s_sessionHandles,sizeof(s_sessionHandles));
  }
  
  if (rc == 0) {
    rc=TPM_Sbuffer_Append16(sbuffer, S_ATTRIBUTES_START);
  }

  if (rc == 0) {
    rc=TPM_Sbuffer_Append(sbuffer, s_attributes,sizeof(s_attributes));
  }
  if (rc == 0) {
    rc=TPM_Sbuffer_Append16(sbuffer, S_ASSOCIATEDHANDLES_START);
  }

  if (rc == 0) {
    rc=TPM_Sbuffer_Append(sbuffer, s_associatedHandles,sizeof(s_associatedHandles));
  }
  
  if (rc == 0) {
    rc=TPM_Sbuffer_Append16(sbuffer, S_NONCECALLER_START);
  }

  if (rc == 0) {
    rc=TPM_Sbuffer_Append(sbuffer, s_nonceCaller,sizeof(s_nonceCaller));
  }

  if (rc == 0) {
    rc=TPM_Sbuffer_Append16(sbuffer, S_INPUTAUTHVALUES_START);
  }

  if (rc == 0) {
    rc=TPM_Sbuffer_Append(sbuffer, s_inputAuthValues,sizeof(s_inputAuthValues));
  }
    return rc;
}

/* TPM_Sbuffer_Append() is the basic function to append 'data' of size 'data_length' to the
   TPM_STORE_BUFFER

   Returns 0 if success, TPM_SIZE if the buffer cannot be allocated.
*/

TPM_RESULT TPM_Sbuffer_Append(TPM_STORE_BUFFER *sbuffer,
                              const void *data,
                              size_t data_length)
{

    TPM_RESULT  rc = 0;

    size_t free_length;         /* length of free bytes in current buffer */
    size_t current_size;        /* size of current buffer */
    size_t current_length;      /* bytes in current buffer */
    size_t new_size;            /* size of new buffer */
    
    /* can data fit? */
    if (rc == 0) {
        /* cast safe as end is always greater than current */
        free_length = (size_t)(sbuffer->buffer_end - sbuffer->buffer_current);
        /* if data cannot fit in buffer as sized */
        if (free_length < data_length) {
            /* This test will fail long before the add uint32_t overflow */
            if (rc == 0) {
                /* cast safe as current is always greater than start */
                current_length = (size_t)(sbuffer->buffer_current - sbuffer->buffer);
                if ((current_length + data_length) > TPM_ALLOC_MAX) {
                    /*printf("TPM_Sbuffer_Append: "
                           "Error, size %lu + %lu greater than maximum allowed\n",
                           (unsigned long)current_length, (unsigned long)data_length);*/
                    rc = TPM_RC_PCR;
                }
            }
            if (rc == 0) {
                /* cast safe as end is always greater than start */
                current_size = (size_t)(sbuffer->buffer_end - sbuffer->buffer);
                /* optimize realloc's by rounding up data_length to the next increment */
                new_size = current_size +       /* currently used */
                           ((((data_length - 1)/TPM_STORE_BUFFER_INCREMENT) + 1) *
                            TPM_STORE_BUFFER_INCREMENT);

                /* but not greater than maximum buffer size */
                if (new_size > TPM_ALLOC_MAX) {
                    new_size = TPM_ALLOC_MAX;
                }
                /*printf("   TPM_Sbuffer_Append: data_length %lu, growing from %lu to %lu\n",
                       (unsigned long)data_length,
                       (unsigned long)current_size,
                       (unsigned long)new_size);*/

                rc = TPM_Realloc(&(sbuffer->buffer), new_size);
            }
            if (rc == 0) {

                sbuffer->buffer_end = sbuffer->buffer + new_size;       /* end */
                sbuffer->buffer_current = sbuffer->buffer + current_length; /* new empty position */

            }
        }
    }
    /* append the data */
    if (rc == 0) {

        memcpy(sbuffer->buffer_current, data, data_length);
        sbuffer->buffer_current += data_length;

    }

    return rc;
}


/* TPM_Sbuffer_Append16() is a special append that converts a uint16_t to big endian (network byte

   order) and appends. */

TPM_RESULT TPM_Sbuffer_Append16(TPM_STORE_BUFFER *sbuffer, uint16_t data)
{

    TPM_RESULT  rc = 0;

//  printf("data:%x\n",data);
    uint16_t ndata = htons(data);

//  printf("ndata:%x\n",ndata);
    rc = TPM_Sbuffer_Append(sbuffer, (const unsigned char *)(&ndata), sizeof(uint16_t));

    return rc;
}

/* TPM_Malloc() is a general purpose wrapper around malloc()
 */

TPM_RESULT TPM_Malloc(unsigned char **buffer, uint32_t size)
{
    TPM_RESULT          rc = 0;
    
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

/* TPM_Free() is the companion to the TPM allocation functions.  It is not used internally.  The
   intent is for use by an application that links directly to a TPM and wants to free memory
   allocated by the TPM.

   It avoids a potential problem if the application uses a different allocation library, perhaps one
   that wraps the functions to detect overflows or memory leaks.
*/

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

    TPM_RESULT          rc = 0;
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

/* TPM_PCRs_Load()

   deserialize the global variable s_pcrs in Global.c from a 'stream'
   'stream_size' is checked for sufficient data
   returns 0 or error codes
*/
TPM_RESULT TPM_PCRs_Load( unsigned char **stream,
                 uint32_t *stream_size)
{
    TPM_RESULT  rc = 0;

//    printf(" TPM_PCRs_Load:\n");
  if (rc == 0) {
      rc = TPM_CheckTag(PCR_START, stream, stream_size);
    }

  if (rc == 0) {
      rc = TPM_Loadn(s_pcrs, (sizeof(PCR)*IMPLEMENTATION_PCR), stream, stream_size);
  }

    return rc;
}

/* TPM_OBJECT_SLOT_Load()

   deserialize the global variable s_objects in Global.c from a 'stream'
   'stream_size' is checked for sufficient data
   returns 0 or error codes
*/
TPM_RESULT TPM_OBJECT_SLOT_Load(  unsigned char **stream,
                 uint32_t *stream_size)
{
    TPM_RESULT  rc = 0;

//  printf(" TPM_OBJECT_SLOT_Load:\n");
    if (rc == 0) {
        rc = TPM_CheckTag(OBJECT_START, stream, stream_size);
    }

    if (rc == 0) {
        //rc = TPM_Loadn(s_objects, (sizeof(OBJECT_SLOT)*MAX_LOADED_OBJECTS), stream, stream_size);
        rc = TPM_Loadn(s_objects, (sizeof(OBJECT)*MAX_LOADED_OBJECTS), stream, stream_size);
    }

    return rc;
}

/* TPM_STATE_CLEAR_DATA_Load()

   deserialize the global variable gc in Global.c from a 'stream'
   'stream_size' is checked for sufficient data
   returns 0 or error codes
*/

TPM_RESULT TPM_STATE_CLEAR_DATA_Load( unsigned char **stream,
                 uint32_t *stream_size)
{
    TPM_RESULT  rc = 0;

    //  printf(" TPM_STATE_CLEAR_DATA_Load:\n");
    if (rc == 0) {
        rc = TPM_CheckTag(STATE_CLEAR_DATA_START, stream, stream_size);
    }

    if (rc == 0) {
        rc = TPM_Loadn(&gc, (sizeof(gc)), stream, stream_size);
    }

    return rc;

}

/* TPM_STATE_RESET_DATA_Load()

   deserialize the global variable gr in Global.c from a 'stream'
   'stream_size' is checked for sufficient data
   returns 0 or error codes
*/
TPM_RESULT TPM_STATE_RESET_DATA_Load( unsigned char **stream,
                 uint32_t *stream_size)
{
    TPM_RESULT  rc = 0;



    //  printf(" TPM_STATE_RESET_DATA_Load:\n");
    if (rc == 0) {
        rc = TPM_CheckTag(STATE_RESET_DATA_START, stream, stream_size);
    }

    if (rc == 0) {
        rc = TPM_Loadn(&gr, (sizeof(gr)), stream, stream_size);
    }

    return rc;
}

/* TPM_SESSION_SLOT_Load()

   deserialize the global variable s_sessions in Global.c from a 'stream'
   'stream_size' is checked for sufficient data
   returns 0 or error codes
*/
TPM_RESULT TPM_SESSION_SLOT_Load( unsigned char **stream,
                 uint32_t *stream_size)
{
    TPM_RESULT  rc = 0;

    //  printf(" TPM_SESSION_SLOT_Load:\n");

    if (rc == 0) {
        rc = TPM_CheckTag(SESSION_SLOT_START, stream, stream_size);
    }

    if (rc == 0) {
        rc = TPM_Loadn(s_sessions, (sizeof(s_sessions)), stream, stream_size);
    }

    return rc;

}

/* TPM_SESSION_ABOUT_Load()

   deserialize several relevant global variables in Global.c from a 'stream'
   'stream_size' is checked for sufficient data
   returns 0 or error codes
*/

TPM_RESULT TPM_SESSION_ABOUT_Load(  unsigned char **stream,
                 uint32_t *stream_size)
{
    TPM_RESULT  rc = 0;

//  printf(" TPM_SESSION_ABOUT_Load:\n");

    if (rc == 0) {
        rc = TPM_CheckTag(S_SESSION_HANDLES_START, stream, stream_size);
    }

    if (rc == 0) {
        rc = TPM_Loadn(s_sessionHandles, (sizeof(s_sessionHandles)), stream, stream_size);
    }
    if (rc == 0) {
        rc = TPM_CheckTag(S_ATTRIBUTES_START, stream, stream_size);
    }

    if (rc == 0) {
        rc = TPM_Loadn(s_attributes, (sizeof(s_attributes)), stream, stream_size);
    }
    if (rc == 0) {
        rc = TPM_CheckTag(S_ASSOCIATEDHANDLES_START, stream, stream_size);
    }

    if (rc == 0) {
        rc = TPM_Loadn(s_associatedHandles, (sizeof(s_associatedHandles)), stream, stream_size);
    }
    if (rc == 0) {
        rc = TPM_CheckTag(S_NONCECALLER_START, stream, stream_size);
    }

    if (rc == 0) {
        rc = TPM_Loadn(s_nonceCaller, (sizeof(s_nonceCaller)), stream, stream_size);
    }
    if (rc == 0) {
        rc = TPM_CheckTag(S_INPUTAUTHVALUES_START, stream, stream_size);
    }

    if (rc == 0) {
        rc = TPM_Loadn(s_inputAuthValues, (sizeof(s_inputAuthValues)), stream, stream_size);
    }
    return rc;
}

/* TPM_CheckTag() loads a TPM_STRUCTURE_TAG from 'stream'.  It check that the value is 'expectedTag'
   and returns TPM_INVALID_STRUCTURE on error.

*/

TPM_RESULT TPM_CheckTag(uint16_t expectedTag,
      unsigned char **stream,
      uint32_t   *stream_size)
{
    TPM_RESULT          rc = 0;
    uint16_t   tag;

    if (rc == 0) {      
        rc = TPM_Load16(&tag, stream, stream_size);
    }

    if (rc == 0) {
        if (tag != expectedTag) {
            // printf("TPM_CheckTag: Error, tag expected %04x found %04hx\n", expectedTag, tag);
            rc = TPM_RC_PCR;
            abort();
        }
    }

    return rc;
}


/* TPM_Load16() loads 'tpm_uint16' from the stream.

   It checks that the stream has sufficient data, and adjusts 'stream'

   and 'stream_size' past the data.

*/
TPM_RESULT TPM_Load16(uint16_t *tpm_uint16,
                      unsigned char **stream,
                      uint32_t *stream_size)
{
    TPM_RESULT  rc = 0;

    /* check stream_size */
    if (rc == 0) {

        if (*stream_size < sizeof(uint16_t)) {
            /*printf("TPM_Load16: Error, stream_size %u less than %lu\n",
                   *stream_size, (unsigned long)sizeof(uint16_t));*/
            rc = TPM_RC_PCR;
        }
    }

    /* load the parameter */
    if (rc == 0) {
        *tpm_uint16 = LOAD16(*stream, 0);
        *stream += sizeof (uint16_t);
        *stream_size -= sizeof (uint16_t);
    }
    return rc;

}


/* TPM_Loadn() copies 'data_length' bytes from 'stream' to 'data' with
   no endian adjustments. */
TPM_RESULT TPM_Loadn(void *data,
                     size_t data_length,
                     unsigned char **stream,
                     uint32_t *stream_size)
{

    TPM_RESULT  rc = 0;
    /* check stream_size */
    if (rc == 0) {
        if (*stream_size < data_length) {
            /*printf("TPM_Loadn: Error, stream_size %u less than %lu\n",
                   *stream_size, (unsigned long)data_length);*/
            rc = TPM_RC_PCR;
        }
    }

    /* load the parameter */
    if (rc == 0) {
        memcpy(data, *stream, data_length);
        *stream += data_length;
        *stream_size -= data_length;
    }
    return rc;
}

/* TPM_Load8() loads 'tpm_uint8' from the stream.
   It checks that the stream has sufficient data, and adjusts 'stream'
   and 'stream_size' past the data.
*/
TPM_RESULT TPM_Load8(uint8_t *tpm_uint8,
                     unsigned char **stream,
                     uint32_t *stream_size)
{

    TPM_RESULT  rc = 0;
    /* check stream_size */
    if (rc == 0) {
        if (*stream_size < sizeof(uint8_t)) {
            /*printf("TPM_Load8: Error, stream_size %u less than %lu\n",
                   *stream_size, (unsigned long)sizeof(uint8_t));*/
            rc = TPM_RC_PCR;
        }
    }

    /* load the parameter */
    if (rc == 0) {
        *tpm_uint8 = LOAD8(*stream, 0);
        *stream += sizeof (uint8_t);
        *stream_size -= sizeof (uint8_t);
    }

    return rc;
}


/* The LOADn() functions convert a big endian stream to integer types */
uint16_t LOAD16(const unsigned char *buffer, uint32_t offset)
{

    uint32_t i;
    uint16_t result = 0;

    for (i = 0 ; i < 2 ; i++) {
        result <<= 8;
        result |= buffer[offset + i];
    }

    return result;
}

uint8_t LOAD8(const unsigned char *buffer, uint32_t offset)
{

    uint8_t result = 0;
    result |= buffer[offset];
    return result;

}


