/*(Copyright)

        Microsoft Copyright 2009, 2010, 2011, 2012, 2013
        Confidential Information

*/

#include <stdint.h>

#ifndef    TPM_LIB_H
#define    TPM_LIB_H

typedef uint32_t  TPM_RESULT;		/* The return code from a function  */
#define TPM_SUCCESS  0x0
typedef unsigned char  TPM_BOOL;        /* TRUE/FALSE field. TRUE = 0x01, FALSE = 0x00 Use TPM_BOOL
                                           because MS VC++ defines BOOL on Windows */
typedef uint32_t  TPM_MODIFIER_INDICATOR;

//****************************************************************************
//** Manufacture and Tear down
//****************************************************************************

// TPM initialization
// return type: int
//      0       if success
//      non 0   if fails
/*int
TPM_Manufacture();*/

// TPM tear down
// return type: int
//      0        if success
//      non 0    if fails
int
TPM_TearDown();

//****************************************************************************
//** Command Execution
//****************************************************************************

//***ExecuteCommand()
// Execute a TPM command
// return type: void
void
ExecuteCommand(
    unsigned int         requestSize,       // IN: command buffer size
    unsigned char       *request,           // IN: command buffer
    unsigned int        *responseSize,      // OUT: response buffer size
    unsigned char      **response           // OUT: response buffer
);

//****************************************************************************
//** Power Events
//****************************************************************************

//***_TPM_Init()
// Signal a power on event.
void
_TPM_Init();

//****************************************************************************
//** DRTM Events
//****************************************************************************

// _TPM_Hash_Start signal
void
Signal_Hash_Start();

void
Signal_Hash_Data(
    unsigned int        size,
    unsigned char       *buffer
);

void
Signal_Hash_End();

/*struct libtpms_callbacks
	used for callback
*/
struct libtpms_callbacks {
    int sizeOfStruct;
    TPM_RESULT (*tpm_nvram_init)(void);
    TPM_RESULT (*tpm_nvram_loaddata)(unsigned char **data,
                                     uint32_t *length,
                                     uint32_t tpm_number,
                                     const char *name);
    TPM_RESULT (*tpm_nvram_storedata)(const unsigned char *data,
                                      uint32_t length,
                                      uint32_t tpm_number,
                                      const char *name);
    TPM_RESULT (*tpm_nvram_deletename)(uint32_t tpm_number,
                                       const char *name,
                                       TPM_BOOL mustExist);
    TPM_RESULT (*tpm_io_init)(void);
    TPM_RESULT (*tpm_io_getlocality)(TPM_MODIFIER_INDICATOR *localityModifer,
				     uint32_t tpm_number);
    TPM_RESULT (*tpm_io_getphysicalpresence)(TPM_BOOL *physicalPresence,
					     uint32_t tpm_number);
};

/*Register callback functions*/
TPM_RESULT ecall_TPMLIB_RegisterCallbacks(void *);
TPM_RESULT TPMLIB_RegisterCallbacks(struct libtpms_callbacks *);


/* need to restrict the maximum size of keys to cap the below blobs */
#define TPM_RSA_KEY_LENGTH_MAX     2048

/* maximum size of the IO buffer used for requests and responses */
#define TPM_BUFFER_MAX             4096

/*
 * Below the following acronyms are used to identify what
 * #define influences which one of the state blobs the TPM
 * produces.
 *
 * PA : permanentall
 * SS : savestate
 * VA : volatileall
 *
 * BAL: contributes to the ballooning of the state blob
 */

/*
 * Do not touch these #define's anymore. They are fixed forever
 * and define the properties of the TPM library and have a
 * direct influence on the size requirements of the TPM's block
 * store and the organization of data inside that block store.
 */
/*
 * Every 2048 bit key in volatile space accounts for an
 * increase of maximum of 559 bytes (PCR_INFO_LONG, tied to PCRs).
 */
#define TPM_KEY_HANDLES                  20            /* SS, VA,  BAL */

/*
 * Every 2048 bit key on which the owner evict key flag is set
 * accounts for an increase of 559 bytes of the permanentall
 * blob.
 */
#define TPM_OWNER_EVICT_KEY_HANDLES      10            /* PA, BAL */

/*
 * The largets auth session is DSAP; each such session consumes 119 bytes
 */
#define TPM_MIN_AUTH_SESSIONS            16            /* SS, VA, BAL */

/*
 * Every transport session accounts for an increase of 78 bytes
 */
#define TPM_MIN_TRANS_SESSIONS           16            /* SS, VA, BAL */
/*
 * Every DAA session accounts for an increase of 844 bytes.
 */
#define TPM_MIN_DAA_SESSIONS              2            /* SS, VA, BAL */

#define TPM_MIN_SESSION_LIST            128            /* SS, VA */
#define TPM_MIN_COUNTERS                  8            /* PA */
#define TPM_NUM_FAMILY_TABLE_ENTRY_MIN   16            /* PA */
#define TPM_NUM_DELEGATE_TABLE_ENTRY_MIN  4            /* PA */

/*
 * NB: above #defines directly influence the largest size of the
 * 'permanentall', 'savestate' and 'volatileall' data. If these
 * #define's allow the below space requirements to be exceeded, the
 * TPM may go into shutdown mode, something we would definitely
 * like to prevent. We are mostly concerned about the size of
 * the 'permanentall' blob, which is capped by TPM_MAX_NV_SPACE,
 * and that of the 'savestate' blob, which is capped by
 * TPM_MAX_SAVESTATE_SPACE.
 */

#define TPM_SPACE_SAFETY_MARGIN      (4 * 1024)

/*
 * As of V0.5.1 (may have increased since then):
 *     permanent space + 10 keys = 7920  bytes
 * full volatile space           = 17223 bytes
 * full savestate space          = 16992 bytes
 */

/*
 * For the TPM_MAX_NV_SPACE we cannot provide a safety margin here
 * since the TPM will allow NVRAM spaces to allocate everything.
 * So, we tell the user in TPMLIB_GetTPMProperty that it's 20kb. This
 * gives us some safety margin for the future.
 */
#define TPM_PERMANENT_ALL_BASE_SIZE  (2334 /* incl. SRK, EK */ + \
                                      2048 /* extra space */)

#define TPM_MAX_NV_DEFINED_SIZE      (2048    /* min.  NVRAM spaces */ + \
                                      26*1024 /* extra NVRAM space */ )

#define TPM_MAX_NV_SPACE             (TPM_PERMANENT_ALL_BASE_SIZE +       \
                                      TPM_OWNER_EVICT_KEY_HANDLES * 559 + \
                                      TPM_MAX_NV_DEFINED_SIZE)

#define TPM_MAX_SAVESTATE_SPACE      (972 + /* base size */         \
                                      TPM_KEY_HANDLES * 559 +       \
                                      TPM_MIN_TRANS_SESSIONS * 78 + \
                                      TPM_MIN_DAA_SESSIONS * 844 +  \
                                      TPM_MIN_AUTH_SESSIONS * 119 + \
                                      TPM_SPACE_SAFETY_MARGIN)

#define TPM_MAX_VOLATILESTATE_SPACE  (1203  + /* base size */       \
                                      TPM_KEY_HANDLES * 559 +       \
                                      TPM_MIN_TRANS_SESSIONS * 78 + \
                                      TPM_MIN_DAA_SESSIONS * 844 +  \
                                      TPM_MIN_AUTH_SESSIONS * 119 + \
                                      TPM_SPACE_SAFETY_MARGIN)

/*
 * The timeouts in microseconds.
 *
 * The problem with the timeouts is that on a heavily utilized
 * virtualized platform, the processing of the TPM's commands will
 * take much longer than on a system that's not very busy. So, we
 * now choose values that are very high so that we don't hit timeouts
 * in TPM drivers just because the system is busy. However, hitting
 * timeouts on a very busy system may be inevitable...
 */

#define TPM_SMALL_DURATION    ( 50 * 1000 * 1000)
#define TPM_MEDIUM_DURATION   (100 * 1000 * 1000)
#define TPM_LONG_DURATION     (300 * 1000 * 1000)


#define ROUNDUP(VAL, SIZE) \
  ( ( (VAL) + (SIZE) - 1 ) / (SIZE) ) * (SIZE)

#endif
