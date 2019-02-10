#include "BaseTypes.h"


/* This structure implements a safe storage buffer, used throughout the code when serializing

   structures to a stream.

*/

#define TPM_ALLOC_MAX  0x10000  /* 64k bytes */

#define TPM_STORE_BUFFER_INCREMENT (TPM_ALLOC_MAX / 64)

typedef uint32_t  TPM_RESULT;		/* The return code from a function  */

typedef struct tdTPM_STORE_BUFFER {

    unsigned char *buffer;              /* beginning of buffer */

    unsigned char *buffer_current;      /* first empty position in buffer */

    unsigned char *buffer_end;          /* one past last valid position in buffer */

} TPM_STORE_BUFFER;



void       TPM_Sbuffer_Init(TPM_STORE_BUFFER *sbuffer);

void       TPM_Sbuffer_Delete(TPM_STORE_BUFFER *sbuffer);

/*void       TPM_Sbuffer_Get(TPM_STORE_BUFFER *sbuffer,
                           const unsigned char **buffer,
                           uint32_t *length);*/
void       TPM_Sbuffer_Get(TPM_STORE_BUFFER *sbuffer,
                           const unsigned char *buffer);


// TPM_RESULT TPM_VolatileAll_Store(unsigned char **buffer,uint32_t *length,unsigned char tpm_volatile[]);
TPM_RESULT TPM_VolatileAll_Store(unsigned char *buffer);

TPM_RESULT TPM_FAILED_TRIES_Store(TPM_STORE_BUFFER *sbuffer);

TPM_RESULT TPM_PCRs_Store(TPM_STORE_BUFFER *sbuffer);


TPM_RESULT TPM_OBJECT_SLOT_Store(TPM_STORE_BUFFER *sbuffer);

TPM_RESULT TPM_STATE_CLEAR_DATA_Store(TPM_STORE_BUFFER *sbuffer);

TPM_RESULT TPM_STATE_RESET_DATA_Store(TPM_STORE_BUFFER *sbuffer);

TPM_RESULT TPM_SESSION_SLOT_Store(TPM_STORE_BUFFER *sbuffer);

TPM_RESULT TPM_SESSION_ABOUT_Store(TPM_STORE_BUFFER *sbuffer);

TPM_RESULT TPM_Sbuffer_Append(TPM_STORE_BUFFER *sbuffer,
														const void *data,
														size_t data_length);

TPM_RESULT TPM_Sbuffer_Append16(TPM_STORE_BUFFER *sbuffer, uint16_t data);

TPM_RESULT TPM_Malloc(unsigned char **buffer, uint32_t size);

void TPM_Free(unsigned char *buffer);

TPM_RESULT TPM_Realloc(unsigned char **buffer, uint32_t size);

//TPM_RESULT TPM_VolatileAll_Load(unsigned char **stream,uint32_t *stream_size);
TPM_RESULT TPM_VolatileAll_Load(unsigned char *stream, uint32_t stream_size);

TPM_RESULT TPM_FAILED_TRIES_Load( unsigned char **stream,
                 uint32_t *stream_size);

TPM_RESULT TPM_PCRs_Load(	unsigned char **stream,
								 uint32_t *stream_size);


TPM_RESULT TPM_OBJECT_SLOT_Load(	unsigned char **stream,
								 uint32_t *stream_size);


TPM_RESULT TPM_STATE_CLEAR_DATA_Load(	unsigned char **stream,
								 uint32_t *stream_size);


TPM_RESULT TPM_STATE_RESET_DATA_Load(	unsigned char **stream,
								 uint32_t *stream_size);

TPM_RESULT TPM_SESSION_SLOT_Load(	unsigned char **stream,
								 uint32_t *stream_size);

TPM_RESULT TPM_SESSION_ABOUT_Load(	unsigned char **stream,
							   uint32_t *stream_size);

TPM_RESULT TPM_CheckTag(uint16_t expectedTag,
			unsigned char **stream,
			uint32_t   *stream_size);


TPM_RESULT TPM_Load16(uint16_t *tpm_uint16,
                      unsigned char **stream,
                      uint32_t *stream_size);

uint16_t LOAD16(const unsigned char *buffer, unsigned int offset);

TPM_RESULT TPM_Loadn(void *data,
                     size_t data_length,
                     unsigned char **stream,
                     uint32_t *stream_size);

TPM_RESULT TPM_Load8(uint8_t *tpm_uint8,
                     unsigned char **stream,
                     uint32_t *stream_size);

uint8_t LOAD8(const unsigned char *buffer, unsigned int offset);


