/**************************************************************
 *
 * Copyright 2014, Andreas Fuchs @ Fraunhofer SIT
 *
 **************************************************************/

#ifndef TSS2_COMMON_H
#define TSS2_COMMON_H


/**
 * API version negotiation
 */

#define TSS2_CREATOR 0x1    /* TCG TSS-WG */
#define TSS2_FAMILY 0x1                     //TBD
#define TSS2_LEVEL 0x1                      //TBD
#define TSS2_REVISION 0x1                   //TBD

/* TSS2_VERSION_<CREATOR>_<FAMILY>_<LEVEL>_<REVISION> */
#define TSS2_API_VERSION_1_1_1_1                //TBD



/**
 * Type definitions
 */

#include <stdint.h>

typedef uint8_t     UINT8;      /* unsigned, 8-bit integer */
typedef uint8_t     BYTE;       /* unsigned 8-bit integer */
typedef int8_t      INT8;       /* signed, 8-bit integer */
typedef int         BOOL;       /* a bit in an int  */
typedef uint16_t    UINT16;     /* unsigned, 16-bit integer */
typedef int16_t     INT16;      /* signed, 16-bit integer */
typedef uint32_t    UINT32;     /* unsigned, 32-bit integer */
typedef int32_t     INT32;      /* signed, 32-bit integer */
typedef uint64_t    UINT64;     /* unsigned, 64-bit integer */
typedef int64_t     INT64;      /* signed, 64-bit integer */

typedef UINT32 TSS2_RC; 


/**
 * ABI runetime negotiation structure.
 */
typedef struct {
    UINT32 tssCreator;  /* If == 1, this equals TSSWG-Interop
                   If == 2..9, this is reserved
                   If > TCG_VENDOR_ID_FIRST, this equals Vendor-ID */
    UINT32 tssFamily;   /* Free-to-use for creator > TCG_VENDOR_FIRST */
    UINT32 tssLevel;    /* Free-to-use for creator > TCG_VENDOR_FIRST */
    UINT32 tssVersion;      /* Free-to-use for creator > TCG_VENDOR_FIRST */
} TSS2_ABI_VERSION;


/**
 * Error Levels
 *
 *
 */

// This macro is used to indicate the level of the error:  use 5 and 6th
// nibble for error level.

#define TSS2_RC_LEVEL_SHIFT   16

#define TSS2_ERROR_LEVEL( level )     ( level << TSS2_RC_LEVEL_SHIFT )


//
// Error code levels.   These indicate what level in the software stack
// the error codes are coming from.
//
#define TSS2_APP_ERROR_LEVEL             TSS2_ERROR_LEVEL(5)
#define TSS2_FEATURE_ERROR_LEVEL         TSS2_ERROR_LEVEL(6)
#define TSS2_ESAPI_ERROR_LEVEL           TSS2_ERROR_LEVEL(7)
#define TSS2_SYS_ERROR_LEVEL             TSS2_ERROR_LEVEL(8)
#define TSS2_SYS_PART2_ERROR_LEVEL       TSS2_ERROR_LEVEL(9)
#define TSS2_TCTI_ERROR_LEVEL            TSS2_ERROR_LEVEL(10)
#define TSS2_RESMGR_ERROR_LEVEL          TSS2_ERROR_LEVEL(11)
#define TSS2_DRIVER_ERROR_LEVEL          TSS2_ERROR_LEVEL(12)

/**
 * Error Codes
 */

//
// Base error codes
// These are not returned directly, but are combined with an ERROR_LEVEL to
// produce the error codes for each layer.
//
#define TSS2_BASE_RC_GENERAL_FAILURE            1
#define TSS2_BASE_RC_NOT_IMPLEMENTED            2
#define TSS2_BASE_RC_BAD_CONTEXT                3
#define TSS2_BASE_RC_ABI_MISMATCH               5
#define TSS2_BASE_RC_BAD_PARAMETER              6
#define TSS2_BASE_RC_INSUFFICIENT_BUFFER        7
#define TSS2_BASE_RC_BAD_SEQUENCE               8
#define TSS2_BASE_RC_NO_CONNECTION              9
#define TSS2_BASE_RC_TRY_AGAIN                 10
#define TSS2_BASE_RC_NO_RESPONSE_RECEIVED      11
#define TSS2_BASE_RC_DRIVER_NOT_FOUND          12
#define TSS2_BASE_RC_DRIVERINFO_NOT_FOUND      13
#define TSS2_BASE_RC_BAD_VALUE                 14
#define TSS2_BASE_RC_NOT_PERMITTED             15
#define TSS2_BASE_RC_INVALID_SESSIONS          16
#define TSS2_BASE_RC_NO_DECRYPT_PARAM          17
#define TSS2_BASE_RC_NO_ENCRYPT_PARAM          18
#define TSS2_BASE_RC_BAD_SIZE                  19
#define TSS2_BASE_RC_MALFORMED_RESPONSE        20
#define TSS2_BASE_RC_INSUFFICIENT_CONTEXT      21
#define TSS2_BASE_RC_INSUFFICIENT_RESPONSE     22
#define TSS2_BASE_RC_INCOMPATIBLE_TCTI         23
#define TSS2_BASE_RC_BAD_TCTI_STRUCTURE        24

//added by fjyu@whu.edu.cn
#define TSS2_BASE_RC_BAD_ENCDEC_TYPE           25
#define TSS2_BASE_RC_SEND_LDKEYMSG_FAIL        26
#define TSS2_BASE_RC_BAD_PARENTKEY_ID          27
#define TSS2_BASE_RC_SEND_LDKEYID_FAIL         28
#define TSS2_BASE_RC_RCV_LDKEYLEN_FAIL         29
#define TSS2_BASE_RC_RCV_LDKEYBLOB_FAIL        30
#define TSS2_BASE_RC_KEY_FLUSHED               31



#define TSS2_RC_SUCCESS                         ((TSS2_RC)0)


// TCTI error codes

#define TSS2_TCTI_RC_GENERAL_FAILURE            ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL + \
                                                    TSS2_BASE_RC_GENERAL_FAILURE))
#define TSS2_TCTI_RC_NOT_IMPLEMENTED            ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL + \
                                                    TSS2_BASE_RC_NOT_IMPLEMENTED))
#define TSS2_TCTI_RC_BAD_CONTEXT                ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_BAD_CONTEXT))
#define TSS2_TCTI_RC_WRONG_ABI_VERSION          ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_ABI_MISMATCH))
#define TSS2_TCTI_RC_BAD_PARAMETER              ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_BAD_PARAMETER))
#define TSS2_TCTI_RC_INSUFFICIENT_BUFFER        ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_INSUFFICIENT_BUFFER))
#define TSS2_TCTI_RC_BAD_SEQUENCE               ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_BAD_SEQUENCE))
#define TSS2_TCTI_RC_NO_CONNECTION              ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_NO_CONNECTION))
#define TSS2_TCTI_RC_TRY_AGAIN                  ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_TRY_AGAIN))
#define TSS2_TCTI_RC_NO_RESPONSE                ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_NO_RESPONSE_RECEIVED)) 
#define TSS2_TCTI_RC_DRIVER_NOT_FOUND           ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_DRIVER_NOT_FOUND))
#define TSS2_TCTI_RC_DRIVERINFO_NOT_FOUND       ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_DRIVERINFO_NOT_FOUND))
#define TSS2_TCTI_RC_BAD_VALUE                  ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_BAD_VALUE))
#define TSS2_TCTI_RC_NOT_PERMITTED              ((TSS2_RC)(TSS2_TCTI_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_NOT_PERMITTED))

//
// SAPI error codes
//
#define TSS2_SYS_RC_ABI_MISMATCH                ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_ABI_MISMATCH))
#define TSS2_SYS_RC_BAD_PARAMETER               ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_BAD_PARAMETER))
#define TSS2_SYS_RC_INSUFFICIENT_BUFFER         ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_INSUFFICIENT_BUFFER))
#define TSS2_SYS_RC_BAD_SEQUENCE                ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_BAD_SEQUENCE))
#define TSS2_SYS_RC_NO_RESPONSE_RECEIVED        ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_NO_RESPONSE_RECEIVED))
#define TSS2_SYS_RC_INVALID_SESSIONS            ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_INVALID_SESSIONS))
#define TSS2_SYS_RC_NO_DECRYPT_PARAM            ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_NO_DECRYPT_PARAM))
#define TSS2_SYS_RC_NO_ENCRYPT_PARAM            ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_NO_ENCRYPT_PARAM))
#define TSS2_SYS_RC_BAD_SIZE                    ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_BAD_SIZE))
#define TSS2_SYS_RC_MALFORMED_RESPONSE          ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_MALFORMED_RESPONSE))
#define TSS2_SYS_RC_INSUFFICIENT_CONTEXT        ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_INSUFFICIENT_CONTEXT))
#define TSS2_SYS_RC_INSUFFICIENT_RESPONSE       ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_INSUFFICIENT_RESPONSE))
#define TSS2_SYS_RC_INCOMPATIBLE_TCTI           ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_INCOMPATIBLE_TCTI))
#define TSS2_SYS_RC_BAD_TCTI_STRUCTURE          ((TSS2_RC)(TSS2_SYS_ERROR_LEVEL + \
                                                     TSS2_BASE_RC_BAD_TCTI_STRUCTURE))


// FAPI error codes
// Added by fjyu@whu.edu.cn
#define TSS2_FAPI_RC_BAD_ENCDECTYPE             ((TSS2_RC)(TSS2_FEATURE_ERROR_LEVEL + TSS2_BASE_RC_ABI_MISMATCH))
#define TSS2_FAPI_RC_SENDLDKMSG_FAIL            ((TSS2_RC)(TSS2_FEATURE_ERROR_LEVEL + TSS2_BASE_RC_SEND_LDKEYMSG_FAIL))
#define TSS2_FAPI_RC_BAD_PKEYID                 ((TSS2_RC)(TSS2_FEATURE_ERROR_LEVEL + TSS2_BASE_RC_BAD_PARENTKEY_ID))          
#define TSS2_FAPI_RC_SENDLDKID_FAIL             ((TSS2_RC)(TSS2_FEATURE_ERROR_LEVEL + TSS2_BASE_RC_SEND_LDKEYID_FAIL)) 
#define TSS2_FAPI_RC_RCVLDKLEN_FAIL             ((TSS2_RC)(TSS2_FEATURE_ERROR_LEVEL + TSS2_BASE_RC_RCV_LDKEYLEN_FAIL)) 
#define TSS2_FAPI_RC_RCVLDKBLOB_FAIL            ((TSS2_RC)(TSS2_FEATURE_ERROR_LEVEL + TSS2_BASE_RC_RCV_LDKEYBLOB_FAIL)) 
#define TSS2_FAPI_RC_KEY_FLUSHED                ((TSS2_RC)(TSS2_FEATURE_ERROR_LEVEL + TSS2_BASE_RC_KEY_FLUSHED))  


#endif /* TSS2_COMMON_H */
