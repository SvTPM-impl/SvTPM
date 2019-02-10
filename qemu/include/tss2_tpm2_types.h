/********************************************************************************/
/*                                      */
/*              TPM2 Header                     */
/*               Written by Ken Goldman             */
/*             IBM Thomas J. Watson Research Center         */
/*          Time-stamp: "18 April 2014 16:58:27"            */
/*                                      */
/*           (c) Copyright IBM Corp. 2013-2014          */
/*                                      */
/*                                      */
/********************************************************************************/
#ifndef TPM2_h
#define TPM2_h

#include "tss2_common.h"
#ifndef TSS2_API_VERSION_1_1_1_1
#error Version missmatch among TSS2 header files !
#endif  /* TSS2_API_VERSION_1_1_1_1 */

#pragma pack (push, 1)

/* Current to revision 103 */

/* MACROS */

/*
  The C bit field is non-portable, but the TPM specification reference implementation uses them.

  These two macros attempt to define the TPM specification bit fields for little and big endian
  machines.  There is no guarantee that either will work with a specific compiler or tool chain.  If
  not, the developer must create a custom structure.
  
  TPM_BITFIELD_LE - little endian
  TPM_BITFIELD_BE - big endian

  To access the structures as uint's for marshaling and unmarshaling, each bit field is a union with
  an integral field called 'val'.

  Yes, I know that this uses anonymous structs, but the alternative yields another level of
  deferencing, and will likely break more code.  I hope your compiler supports this recent addition
  to the standard.

  For portable code:
  
  If neither macro is defined, this header defines the structures as uint32_t.  It defines constants
  for the various bits, and can be used as:

  variable & CONSTANT       (test for set)
  !(variable & CONSTANT)    (test for clear)
  variable &= CONSTANT      (to set)
  variable |= ~CONSTANT     (to clear)

  Although the portable structures are all uint32_t, some only use the least significatt 8 bits and
  are marshalled as a uint_8.
*/


typedef struct {
    UINT16        size;
    BYTE          buffer[1];
} TPM2B;

/* Table 205 - Defines for SHA1 Hash Values */

#define SHA1_DIGEST_SIZE    20
#define SHA1_BLOCK_SIZE     64
#define SHA1_DER_SIZE       15
#if 0
#define SHA1_DER    {0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E, 0x03,0x02,0x1A,0x05,0x00,0x04,0x14};
#endif

/* Table 206 - Defines for SHA256 Hash Values */

#define SHA256_DIGEST_SIZE  32
#define SHA256_BLOCK_SIZE   64
#define SHA256_DER_SIZE     19
#if 0
#define SHA256_DER      {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86, 0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05, 0x00,0x04,0x20};
#endif

/* Table 207 - Defines for SHA384 Hash Values */

#define SHA384_DIGEST_SIZE  48
#define SHA384_BLOCK_SIZE   128
#define SHA384_DER_SIZE     19
#if 0
#define SHA384_DER      {0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86, 0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05, 0x00,0x04,0x30};
#endif

/* Table 208 - Defines for SHA512 Hash Values */

#define SHA512_DIGEST_SIZE  64
#define SHA512_BLOCK_SIZE   128
#define SHA512_DER_SIZE     19
#if 0
#define SHA512_DER  {0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86, 0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05, 0x00,0x04,0x40};
#endif

/* Table 209 - Defines for SM3_256 Hash Values */
#define SM3_256_DIGEST_SIZE 32
#define SM3_256_BLOCK_SIZE  64  
#define SM3_256_DER_SIZE    18
#if 0
#define SM3_256_DER {0x30,0x30,0x30,0x0c,0x06,0x08,0x2a,0x81, 0x1c,0x81,0x45,0x01,0x83,0x11,0x05,0x00,  0x04,0x20};
#endif

/* Table 210 - Defines for Architectural Limits Values */

#define MAX_SESSION_NUMBER  3   /*  maximum number of authorization sessions that may be in a command */

/* Table 211 - Defines for Logic Values */

#define YES 1
#define NO  0
#define TRUE    1
#define FALSE   0
#define SET 1
#define CLEAR   0

/* Table 212 - Defines for Processor Values */

#define BIG_ENDIAN_TPM      NO  /*  to YES or NO according to the processor */
#define LITTLE_ENDIAN_TPM   YES /*  to YES or NO according to the processor */
#define NO_AUTO_ALIGN       NO  /*  to YES if the processor does not allow unaligned accesses */

/* Table 213 - Defines for Implemented Algorithms */

#define ALG_RSA         YES
#define ALG_SHA1        YES
#define ALG_HMAC        YES /* REQUIRED, do not change this value */
#define ALG_AES         YES
#define ALG_MGF1        YES
#define ALG_XOR         YES
#define ALG_KEYEDHASH       YES /* REQUIRED, do not change this value */
#define ALG_SHA256      YES
#define ALG_SHA384      NO
#define ALG_SHA512      NO
#define ALG_SM3_256     YES
#define ALG_SM4         YES
#define ALG_RSASSA      (YES * RSA) /* requires RSA */
#define ALG_RSAES       (YES * RSA) /* requires RSA */
#define ALG_RSAPSS      (YES * RSA) /* requires RSA */
#define ALG_OAEP        (YES * RSA) /* requires RSA */
#define ALG_ECC         YES
#define ALG_ECDH        (YES * ECC) /* requires ECC */
#define ALG_ECDSA       (YES * ECC) /* requires ECC */
#define ALG_ECDAA       (YES * ECC) /* requires ECC */
#define ALG_SM2         (YES * ECC) /* requires ECC */
#define ALG_ECSCHNORR       (YES * ECC) /* requires ECC */
#define ALG_ECMQV       (NO * ECC)  /* requires ECC */
#define ALG_SYMCIPHER       YES     /* REQUIRED, at least one symmetric algorithm shall be implemented */
#define ALG_KDF1_SP800_56a  (YES * ECC) /* requires ECC */
#define ALG_KDF2        NO
#define ALG_KDF1_SP800_108  YES
#define ALG_CTR         YES
#define ALG_OFB         YES
#define ALG_CBC         YES
#define ALG_CFB         YES     /* REQUIRED, do not change this value */
#define ALG_ECB         YES

/* Part 4 */
#define HASH_COUNT (ALG_SHA1 + ALG_SHA256 + ALG_SHA384 + ALG_SHA512 + ALG_SM3_256)

/* Table 215 - Defines for RSA Algorithm Constants */

#define RSA_KEY_SIZES_BITS      {1024, 2048}    /* braces because this is a list value */
#define MAX_RSA_KEY_BITS        2048        
#define MAX_RSA_KEY_BYTES       ((MAX_RSA_KEY_BITS + 7) / 8)

/* Table 216 - Defines for ECC Algorithm Constants */

#define ECC_CURVES          {TPM_ECC_NIST_P256, TPM_ECC_BN_P256, TPM_ECC_SM2_P256}
#define ECC_KEY_SIZES_BITS      {256}       /* this is a list value with length of one */
#define MAX_ECC_KEY_BITS        256
#define MAX_ECC_KEY_BYTES       ((MAX_ECC_KEY_BITS + 7) / 8)

/* Table 217 - Defines for AES Algorithm Constants */
#define AES_KEY_SIZES_BITS      {128, 256}
#define MAX_AES_KEY_BITS        256
#define MAX_AES_BLOCK_SIZE_BYTES    16
#define MAX_AES_KEY_BYTES       ((MAX_AES_KEY_BITS + 7) / 8)

/* Table 218 - Defines for SM4 Algorithm Constants */

#define SM4_KEY_SIZES_BITS      {128}
#define MAX_SM4_KEY_BITS        128
#define MAX_SM4_BLOCK_SIZE_BYTES    16
#define MAX_SM4_KEY_BYTES       ((MAX_SM4_KEY_BITS + 7) / 8)

/* Table 219 - Defines for Symmetric Algorithm Constants */

#define MAX_SYM_KEY_BITS    MAX_AES_KEY_BITS
#define MAX_SYM_KEY_BYTES   MAX_AES_KEY_BYTES
#define MAX_SYM_BLOCK_SIZE  MAX_AES_BLOCK_SIZE_BYTES

/* Table 220 - Defines for Implementation Values */

#define FIELD_UPGRADE_IMPLEMENTED   NO  /* temporary define */
#define BSIZE               UINT16  /* size used for internal storage of the size field of a TPM2B */
#define BUFFER_ALIGNMENT        4   /* sets the size granularity for the buffers in a TPM2B structure */
#define IMPLEMENTATION_PCR      24  /* the number of PCR in the TPM */
#define PLATFORM_PCR            24  /* the number of PCR required by the relevant platform specification */
#define DRTM_PCR            17  /* the DRTM PCR */
#define NUM_LOCALITIES          5   /* the number of localities supported by the TPM */
#define MAX_HANDLE_NUM          3   /* the maximum number of handles in the handle area */
#define MAX_ACTIVE_SESSIONS     64  /* the number of simultaneously active sessions that are supported by the TPM implementation */

typedef UINT16              CONTEXT_SLOT;       /* the type of an entry in the array of saved contexts */
typedef UINT64              CONTEXT_COUNTER;    /* the type of the saved session counter */

#define MAX_LOADED_SESSIONS     3   /* the number of sessions that the TPM may have in memory */
#define MAX_SESSION_NUM         3   /* this is the current maximum value */
#define MAX_LOADED_OBJECTS      3   /* the number of simultaneously loaded objects that are supported by the TPM */
#define MIN_EVICT_OBJECTS       2   /* the minimum number of evict objects supported by the TPM */
#define PCR_SELECT_MIN          ((PLATFORM_PCR+7)/8)
#define PCR_SELECT_MAX          ((IMPLEMENTATION_PCR+7)/8)
#define NUM_POLICY_PCR_GROUP        1   /* number of PCR groups that have individual policies */
#define NUM_AUTHVALUE_PCR_GROUP     1   /* number of PCR groups that have individual authorization values */
#define MAX_CONTEXT_SIZE        2048    /* This may be larger than necessary */
#define MAX_DIGEST_BUFFER       1024
#define MAX_NV_INDEX_SIZE       1024    /* maximum data size allowed in an NV Index */
#define MAX_CAP_BUFFER          1024
#define NV_MEMORY_SIZE          16384   /* size of NV memory in octets */
#define NUM_STATIC_PCR  16
#define MAX_ALG_LIST_SIZE       64  /* number of algorithms that can be in a list */
#define TIMER_PRESCALE          100000  /* nominal value for the pre-scale value of Clock */
#define PRIMARY_SEED_SIZE       32  /* size of the Primary Seed in octets */
#define CONTEXT_ENCRYPT_ALG     TPM_ALG_AES         /* context encryption algorithm */
#define CONTEXT_ENCRYPT_KEY_BITS    MAX_SYM_KEY_BITS        /* context encryption key size in bits */
#define CONTEXT_ENCRYPT_KEY_BYTES   ((CONTEXT_ENCRYPT_KEY_BITS+7)/8)
#define CONTEXT_INTEGRITY_HASH_ALG  TPM_ALG_SHA256          /* context integrity hash algorithm */
#define CONTEXT_INTEGRITY_HASH_SIZE SHA256_DIGEST_SIZE      /* number of byes in the context integrity digest */
#define PROOF_SIZE          CONTEXT_INTEGRITY_HASH_SIZE /* size of proof value in octets */
#define NV_CLOCK_UPDATE_INTERVAL    12  /* the update interval expressed as a power of 2 seconds */
#define NUM_POLICY_PCR          1   /* number of PCR that allow policy/auth */
#define MAX_COMMAND_SIZE        4096    /* maximum size of a command */
#define MAX_RESPONSE_SIZE       4096    /* maximum size of a response */
#define ORDERLY_BITS            8   /* number between 1 and 32 inclusive */
#define MAX_ORDERLY_COUNT       ((1 << ORDERLY_BITS) - 1)   /* maximum count of orderly
                                       counter before NV is
                                       updated.  This must be of
                                       the form 2N - 1 where 1 =
                                       N = 32. */
#define ALG_ID_FIRST            TPM_ALG_FIRST   /* used by GetCapability() processing to bound the algorithm search */
#define ALG_ID_LAST         TPM_ALG_LAST    /* used by GetCapability() processing to bound the algorithm search */
#define MAX_SYM_DATA            128     /* this is the maximum number of octets that may be in a sealed blob. */
#define MAX_RNG_ENTROPY_SIZE        64
#define RAM_INDEX_SPACE         512
#define RSA_DEFAULT_PUBLIC_EXPONENT 0x00010001  /* 2^^16 + 1 */
#define ENABLE_PCR_NO_INCREMENT     YES     /* indicates if the TPM_PT_PCR_NO_INCREMENT group is implemented */
#define CRT_FORMAT_RSA          YES
#define PRIVATE_VENDOR_SPECIFIC_BYTES   ((MAX_RSA_KEY_BYTES/2) * (3 + CRT_FORMAT_RSA * 2))

/* Part 4 5.3   Capabilities.h */

#define    MAX_CAP_DATA         (MAX_CAP_BUFFER-sizeof(TPM_CAP)-sizeof(UINT32))
#define    MAX_CAP_ALGS         (MAX_CAP_DATA/sizeof(TPMS_ALG_PROPERTY))
#define    MAX_CAP_HANDLES      (MAX_CAP_DATA/sizeof(TPM_HANDLE))
#define    MAX_CAP_CC           (MAX_CAP_DATA/sizeof(TPM_CC))
#define    MAX_TPM_PROPERTIES   (MAX_CAP_DATA/sizeof(TPMS_TAGGED_PROPERTY))
#define    MAX_PCR_PROPERTIES   (MAX_CAP_DATA/sizeof(TPMS_TAGGED_PCR_SELECT))
#define    MAX_ECC_CURVES       (MAX_CAP_DATA/sizeof(TPM_ECC_CURVE))

/* Table 4 - Definition of Types for Documentation Clarity */

typedef UINT32  TPM_ALGORITHM_ID;   /* this is the 1.2 compatible form of the TPM_ALG_ID */
typedef UINT32  TPM_MODIFIER_INDICATOR;
typedef UINT32  TPM_AUTHORIZATION_SIZE; /* the authorizationSize parameter in a command */
typedef UINT32  TPM_PARAMETER_SIZE;     /* the parameterSizeset parameter in a command */
typedef UINT16  TPM_KEY_SIZE;       /* a key size in octets */
typedef UINT16  TPM_KEY_BITS;       /* a key size in bits */

/* Table 5 - Definition of (UINT32) TPM_SPEC Constants <> */

typedef UINT32 TPM_SPEC;

#define TPM_SPEC_FAMILY     0x322E3000  /* ASCII "2.0" with null terminator */
#define TPM_SPEC_LEVEL      00      /* the level number for the specification */
#define TPM_SPEC_VERSION    103     /* the version number of the spec (01.03 * 100)  */
#define TPM_SPEC_YEAR       2013        /* the year of the version */
#define TPM_SPEC_DAY_OF_YEAR    318     /* the day of the year (March 15, 2013) */


/* Table 6 - Definition of (UINT32) TPM_GENERATED Constants <O> */

typedef UINT32 TPM_GENERATED;

#define TPM_GENERATED_VALUE 0xff544347  /* 0xFF 'TCG' (FF 54 43 47) */

/* Table 7 - Definition of (UINT16) TPM_ALG_ID Constants <IN/OUT, S> */

typedef UINT16 TPM_ALG_ID;

#define TPM_ALG_ERROR       0x0000  /*      should not occur */
#define TPM_ALG_FIRST       0x0001  /* marker value  */
#define TPM_ALG_RSA     0x0001  /* A O      the RSA algorithm */
#define TPM_ALG_SHA     0x0004  /* H        the SHA1 algorithm */
#define TPM_ALG_SHA1        0x0004  /* H        redefinition for documentation consistency */
#define TPM_ALG_HMAC        0x0005  /* H X      the RFC 2104 Hash Message Authentication Code (HMAC) algorithm   */
#define TPM_ALG_AES     0x0006  /* S        the AES algorithm with a key size of 128 bits for TPM 1.2 */
#define TPM_ALG_MGF1        0x0007  /* H M      the mask-generation function defined in IEEE Std 1363-2000   */
#define TPM_ALG_KEYEDHASH   0x0008  /* H E X O  an encryption or signing algorithm using a keyed hash   */
#define TPM_ALG_XOR     0x000A  /* H S      the XOR obfuscation algorithm */
#define TPM_ALG_SHA256      0x000B  /* H        the SHA 256 algorithm*/
#define TPM_ALG_SHA384      0x000C  /* H        the SHA 384 algorithm*/
#define TPM_ALG_SHA512      0x000D  /* H        the SHA 512 algorithm*/
#define TPM_ALG_NULL        0x0010  /* Null algorithm    */
#define TPM_ALG_SM3_256     0x0012  /* H        hash algorithm standardized by OSCCA */
#define TPM_ALG_SM4     0x0013  /* S        symmetric algorithm standardized by OSCCA*/
#define TPM_ALG_RSASSA      0x0014  /* A X  RSA a signature algorithm according to PKCS#1v2.1, 8.2   */
#define TPM_ALG_RSAES       0x0015  /* A E  RSA a padding algorithm according to PKCS#1v2.1, 7.2     */
#define TPM_ALG_RSAPSS      0x0016  /* A X  RSA signature algorithm (RSSASSA-PSS) according to PKCS#1v2.1, 8.1   */
#define TPM_ALG_OAEP        0x0017  /* A E  RSA padding algorithm (RSAES_OAEP) according to PKCS#1v2.1, 7.1  */
#define TPM_ALG_ECDSA       0x0018  /* A X  ECC signature algorithm using elliptic curve cryptography (ECC)  */
#define TPM_ALG_ECDH        0x0019  /* A M  ECC secret sharing using ECC from SP800-56A */
#define TPM_ALG_ECDAA       0x001A  /* A X  ECC elliptic-curve based, anonymous signing scheme   */
#define TPM_ALG_SM2     0x001B  /* A X E    ECC */
#define TPM_ALG_ECSCHNORR   0x001C  /* A X  ECC elliptic-curve-based Schnorr signature   */
#define TPM_ALG_ECMQV       0x001D  /* A E  ECC two-phase elliptic-curve key exchange -- C(2, 2, ECC MQV) from SP800-56A     */
#define TPM_ALG_KDF1_SP800_56a  0x0020  /* H M  ECC key derivation alternative #1 from SP800-56A     */
#define TPM_ALG_KDF2        0x0021  /* H M      key derivation function from IEEE Std 1363a-2004     */
#define TPM_ALG_KDF1_SP800_108  0x0022  /* H M      a key derivation method according to SP 800-108, "5.1 KDF in Counter Mode"   */
#define TPM_ALG_ECC     0x0023  /* A O      prime field ECC  */
#define TPM_ALG_SYMCIPHER   0x0025  /* O        the object type for a symmetric block cipher     */
#define TPM_ALG_CTR     0x0040  /* S E      Counter mode */
#define TPM_ALG_OFB     0x0041  /* S E      Output Feedback mode */
#define TPM_ALG_CBC     0x0042  /* S E      Cipher Block Chaining mode */
#define TPM_ALG_CFB     0x0043  /* S E      Cipher Feedback mode */
#define TPM_ALG_ECB     0x0044  /* S E      Electronic Codebook mode     */
#define TPM_ALG_LAST        0x0044  /* marker value */
    
/* Table 8 - Definition of (UINT16) {ECC} TPM_ECC_CURVE Constants <IN/OUT, S> */

typedef UINT16 TPM_ECC_CURVE;

#define TPM_ECC_NONE        0x0000
#define TPM_ECC_NIST_P192   0x0001
#define TPM_ECC_NIST_P224   0x0002
#define TPM_ECC_NIST_P256   0x0003
#define TPM_ECC_NIST_P384   0x0004
#define TPM_ECC_NIST_P521   0x0005
#define TPM_ECC_BN_P256     0x0010  curve to support ECDAA
#define TPM_ECC_BN_P638     0x0011  curve to support ECDAA
#define TPM_ECC_SM2_P256    0x0020

#if 0
if (
    (x != TPM_ECC_NONE  ) &&
    (x != TPM_ECC_NIST_P19) &&
    (x != TPM_ECC_NIST_P22) &&
    (x != TPM_ECC_NIST_P25) &&
    (x != TPM_ECC_NIST_P38) &&
    (x != TPM_ECC_NIST_P52) &&
    (x != TPM_ECC_BN_P256) &&
    (x != TPM_ECC_BN_P638) &&
    (x != TPM_ECC_SM2_P256)) {
    rc = TPM_RC_CURVE;
}
#endif

/* Table 11 - Definition of (UINT32) TPM_CC Constants (Numeric Order) <IN/OUT, S> */

typedef UINT32 TPM_CC;

#define TPM_CC_FIRST            0x0000011F
#define TPM_CC_PP_FIRST         0x0000011F
#define TPM_CC_NV_UndefineSpaceSpecial  0x0000011F
#define TPM_CC_EvictControl     0x00000120
#define TPM_CC_HierarchyControl     0x00000121
#define TPM_CC_NV_UndefineSpace     0x00000122
#define TPM_CC_ChangeEPS        0x00000124
#define TPM_CC_ChangePPS        0x00000125
#define TPM_CC_Clear            0x00000126
#define TPM_CC_ClearControl     0x00000127
#define TPM_CC_ClockSet         0x00000128
#define TPM_CC_HierarchyChangeAuth  0x00000129
#define TPM_CC_NV_DefineSpace       0x0000012A
#define TPM_CC_PCR_Allocate     0x0000012B
#define TPM_CC_PCR_SetAuthPolicy    0x0000012C
#define TPM_CC_PP_Commands      0x0000012D
#define TPM_CC_SetPrimaryPolicy     0x0000012E
#define TPM_CC_FieldUpgradeStart    0x0000012F
#define TPM_CC_ClockRateAdjust      0x00000130
#define TPM_CC_CreatePrimary        0x00000131
#define TPM_CC_NV_GlobalWriteLock   0x00000132
#define TPM_CC_PP_LAST          0x00000132
#define TPM_CC_GetCommandAuditDigest    0x00000133
#define TPM_CC_NV_Increment     0x00000134
#define TPM_CC_NV_SetBits       0x00000135
#define TPM_CC_NV_Extend        0x00000136
#define TPM_CC_NV_Write         0x00000137
#define TPM_CC_NV_WriteLock     0x00000138
#define TPM_CC_DictionaryAttackLockReset    0x00000139
#define TPM_CC_DictionaryAttackParameters   0x0000013A
#define TPM_CC_NV_ChangeAuth        0x0000013B
#define TPM_CC_PCR_Event        0x0000013C
#define TPM_CC_PCR_Reset        0x0000013D
#define TPM_CC_SequenceComplete     0x0000013E
#define TPM_CC_SetAlgorithmSet      0x0000013F
#define TPM_CC_SetCommandCodeAuditStatus    0x00000140
#define TPM_CC_FieldUpgradeData     0x00000141
#define TPM_CC_IncrementalSelfTest  0x00000142
#define TPM_CC_SelfTest         0x00000143
#define TPM_CC_Startup          0x00000144
#define TPM_CC_Shutdown         0x00000145
#define TPM_CC_StirRandom       0x00000146
#define TPM_CC_ActivateCredential   0x00000147
#define TPM_CC_Certify          0x00000148
#define TPM_CC_PolicyNV         0x00000149
#define TPM_CC_CertifyCreation      0x0000014A
#define TPM_CC_Duplicate        0x0000014B
#define TPM_CC_GetTime          0x0000014C
#define TPM_CC_GetSessionAuditDigest    0x0000014D
#define TPM_CC_NV_Read          0x0000014E
#define TPM_CC_NV_ReadLock      0x0000014F
#define TPM_CC_ObjectChangeAuth     0x00000150
#define TPM_CC_PolicySecret     0x00000151
#define TPM_CC_Rewrap           0x00000152
#define TPM_CC_Create           0x00000153
#define TPM_CC_ECDH_ZGen        0x00000154
#define TPM_CC_HMAC         0x00000155
#define TPM_CC_Import           0x00000156
#define TPM_CC_Load         0x00000157
#define TPM_CC_Quote            0x00000158
#define TPM_CC_RSA_Decrypt      0x00000159
#define TPM_CC_HMAC_Start       0x0000015B
#define TPM_CC_SequenceUpdate       0x0000015C
#define TPM_CC_Sign         0x0000015D
#define TPM_CC_Unseal           0x0000015E
#define TPM_CC_PolicySigned     0x00000160
#define TPM_CC_ContextLoad      0x00000161
#define TPM_CC_ContextSave      0x00000162
#define TPM_CC_ECDH_KeyGen      0x00000163
#define TPM_CC_EncryptDecrypt       0x00000164
#define TPM_CC_FlushContext     0x00000165
#define TPM_CC_LoadExternal     0x00000167
#define TPM_CC_MakeCredential       0x00000168
#define TPM_CC_NV_ReadPublic        0x00000169
#define TPM_CC_PolicyAuthorize      0x0000016A
#define TPM_CC_PolicyAuthValue      0x0000016B
#define TPM_CC_PolicyCommandCode    0x0000016C
#define TPM_CC_PolicyCounterTimer   0x0000016D
#define TPM_CC_PolicyCpHash     0x0000016E
#define TPM_CC_PolicyLocality       0x0000016F
#define TPM_CC_PolicyNameHash       0x00000170
#define TPM_CC_PolicyOR         0x00000171
#define TPM_CC_PolicyTicket     0x00000172
#define TPM_CC_ReadPublic       0x00000173
#define TPM_CC_RSA_Encrypt      0x00000174
#define TPM_CC_StartAuthSession     0x00000176
#define TPM_CC_VerifySignature      0x00000177
#define TPM_CC_ECC_Parameters       0x00000178
#define TPM_CC_FirmwareRead     0x00000179
#define TPM_CC_GetCapability        0x0000017A
#define TPM_CC_GetRandom        0x0000017B
#define TPM_CC_GetTestResult        0x0000017C
#define TPM_CC_Hash         0x0000017D
#define TPM_CC_PCR_Read         0x0000017E
#define TPM_CC_PolicyPCR        0x0000017F
#define TPM_CC_PolicyRestart        0x00000180
#define TPM_CC_ReadClock        0x00000181
#define TPM_CC_PCR_Extend       0x00000182
#define TPM_CC_PCR_SetAuthValue     0x00000183
#define TPM_CC_NV_Certify       0x00000184
#define TPM_CC_EventSequenceComplete    0x00000185
#define TPM_CC_HashSequenceStart    0x00000186
#define TPM_CC_PolicyPhysicalPresence   0x00000187
#define TPM_CC_PolicyDuplicationSelect  0x00000188
#define TPM_CC_PolicyGetDigest      0x00000189
#define TPM_CC_TestParms        0x0000018A
#define TPM_CC_Commit           0x0000018B
#define TPM_CC_PolicyPassword       0x0000018C
#define TPM_CC_ZGen_2Phase      0x0000018D
#define TPM_CC_EC_Ephemeral     0x0000018E
#define TPM_CC_PolicyNvWritten      0x0000018F
#define TPM_CC_LAST         0x0000018F

#if 0
if (x != y) {
    rc = TPM_RC_COMMAND_CODE;
 }
#endif

/* Table 15 - Definition of (UINT32) TPM_RC Constants (Actions) <OUT> */

typedef UINT32 TPM_RC;

#define TPM_RC_SUCCESS      0x000
#define TPM_RC_BAD_TAG      0x01E           /* defined for compatibility with TPM 1.2 */

#define RC_VER1         0x100           /* set for all format 0 response codes */

#define TPM_RC_INITIALIZE   (RC_VER1 + 0x000)   /* TPM not initialized */
#define TPM_RC_FAILURE      (RC_VER1 + 0x001)   /* commands not being accepted because of a TPM failure */
#define TPM_RC_SEQUENCE     (RC_VER1 + 0x003)   /* improper use of a sequence handle */
#define TPM_RC_PRIVATE      (RC_VER1 + 0x00B)
#define TPM_RC_HMAC     (RC_VER1 + 0x019)
#define TPM_RC_DISABLED     (RC_VER1 + 0x020)
#define TPM_RC_EXCLUSIVE    (RC_VER1 + 0x021)   /* command failed because audit sequence required exclusivity */
#define TPM_RC_AUTH_TYPE    (RC_VER1 + 0x024)   /* authorization handle is not correct for command */
#define TPM_RC_AUTH_MISSING (RC_VER1 + 0x025)   /* command requires an authorization session for handle and it is not present. */
#define TPM_RC_POLICY       (RC_VER1 + 0x026)   /* policy Failure In Math Operation or an invalid authPolicy value */
#define TPM_RC_PCR      (RC_VER1 + 0x027)   /* PCR check fail */
#define TPM_RC_PCR_CHANGED  (RC_VER1 + 0x028)   /* PCR have changed since checked. */
#define TPM_RC_UPGRADE      (RC_VER1 + 0x02D)   /* for all commands other than TPM2_FieldUpgradeData(), this code indicates that the TPM is in field upgrade mode */
#define TPM_RC_TOO_MANY_CONTEXTS (RC_VER1 + 0x02E)  /* context ID counter is at maximum. */
#define TPM_RC_AUTH_UNAVAILABLE (RC_VER1 + 0x02F)   /* authValue or authPolicy is not available for selected entity. */
#define TPM_RC_REBOOT       (RC_VER1 + 0x030)   /* a _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation. */
#define TPM_RC_UNBALANCED   (RC_VER1 + 0x031)   /* the protection algorithms (hash and symmetric) are not reasonably balanced */
#define TPM_RC_COMMAND_SIZE (RC_VER1 + 0x042)   /* command commandSize value is inconsistent with contents of the command buffer */
#define TPM_RC_COMMAND_CODE (RC_VER1 + 0x043)   /* command code not supported */
#define TPM_RC_AUTHSIZE     (RC_VER1 + 0x044)   /* the value of authorizationSize is out of range */
#define TPM_RC_AUTH_CONTEXT (RC_VER1 + 0x045)   /* use of an authorization session with a context command */
#define TPM_RC_NV_RANGE     (RC_VER1 + 0x046)   /* NV offset+size is out of range. */
#define TPM_RC_NV_SIZE      (RC_VER1 + 0x047)   /* Requested allocation size is larger than allowed. */
#define TPM_RC_NV_LOCKED    (RC_VER1 + 0x048)   /* NV access locked. */
#define TPM_RC_NV_AUTHORIZATION (RC_VER1 + 0x049)   /* NV access authorization fails in command actions (this failure does not affect lockout.action) */
#define TPM_RC_NV_UNINITIALIZED (RC_VER1 + 0x04A)   /* an NV Index is used before being initialized or the state saved by TPM2_Shutdown(STATE) could not be restored */
#define TPM_RC_NV_SPACE     (RC_VER1 + 0x04B)   /* insufficient space for NV allocation */
#define TPM_RC_NV_DEFINED   (RC_VER1 + 0x04C)   /* NV Index or persistend object already defined */
#define TPM_RC_BAD_CONTEXT  (RC_VER1 + 0x050)   /* context in TPM2_ContextLoad() is not valid */
#define TPM_RC_CPHASH       (RC_VER1 + 0x051)   /* cpHash value already set or not correct for use */
#define TPM_RC_PARENT       (RC_VER1 + 0x052)   /* handle for parent is not a valid parent */
#define TPM_RC_NEEDS_TEST   (RC_VER1 + 0x053)   /* some function needs testing. */
#define TPM_RC_NO_RESULT    (RC_VER1 + 0x054)   /* returned when an internal function cannot process a request due to an unspecified problem. */
#define TPM_RC_SENSITIVE    (RC_VER1 + 0x055)   /* the sensitive area did not unmarshal correctly after decryption */
#define RC_MAX_FM0      (RC_VER1 + 0x07F)   /* largest version 1 code that is not a warning */

/* The codes in this group may have a value added to them to indicate the handle, session, or parameter to which they apply. */
#define RC_FMT1         0x080           /* This bit is SET in all format 1 response codes */

#define TPM_RC_ASYMMETRIC   (RC_FMT1 + 0x001)   /* asymmetric algorithm not supported or not correct */
#define TPM_RC_ATTRIBUTES   (RC_FMT1 + 0x002)   /* inconsistent attributes */
#define TPM_RC_HASH     (RC_FMT1 + 0x003)   /* hash algorithm not supported or not appropriate */
#define TPM_RC_VALUE        (RC_FMT1 + 0x004)   /* value is out of range or is not correct for the context */
#define TPM_RC_HIERARCHY    (RC_FMT1 + 0x005)   /* hierarchy is not enabled or is not correct for the use */
#define TPM_RC_KEY_SIZE     (RC_FMT1 + 0x007)   /* key size is not supported */
#define TPM_RC_MGF      (RC_FMT1 + 0x008)   /* mask generation function not supported */
#define TPM_RC_MODE     (RC_FMT1 + 0x009)   /* mode of operation not supported */
#define TPM_RC_TYPE     (RC_FMT1 + 0x00A)   /* the type of the value is not appropriate for the use */
#define TPM_RC_HANDLE       (RC_FMT1 + 0x00B)   /* the handle is not correct for the use */
#define TPM_RC_KDF      (RC_FMT1 + 0x00C)   /* unsupported key derivation function or function not appropriate for use */
#define TPM_RC_RANGE        (RC_FMT1 + 0x00D)   /* value was out of allowed range. */
#define TPM_RC_AUTH_FAIL    (RC_FMT1 + 0x00E)   /* the authorization HMAC check failed and DA counter incremented */
#define TPM_RC_NONCE        (RC_FMT1 + 0x00F)   /* invalid nonce size */
#define TPM_RC_PP       (RC_FMT1 + 0x010)   /* authorization requires assertion of PP */
#define TPM_RC_SCHEME       (RC_FMT1 + 0x012)   /* unsupported or incompatible scheme */
#define TPM_RC_SIZE     (RC_FMT1 + 0x015)   /* structure is the wrong size */
#define TPM_RC_SYMMETRIC    (RC_FMT1 + 0x016)   /* unsupported symmetric algorithm or key size, or not appropriate for instance */
#define TPM_RC_TAG      (RC_FMT1 + 0x017)   /* incorrect structure tag */
#define TPM_RC_SELECTOR     (RC_FMT1 + 0x018)   /* union selector is incorrect */
#define TPM_RC_INSUFFICIENT (RC_FMT1 + 0x01A)   /* the TPM was unable to unmarshal a value because there were not enough octets in the input buffer */
#define TPM_RC_SIGNATURE    (RC_FMT1 + 0x01B)   /* the signature is not valid */
#define TPM_RC_KEY      (RC_FMT1 + 0x01C)   /* key fields are not compatible with the selected use */
#define TPM_RC_POLICY_FAIL  (RC_FMT1 + 0x01D)   /* a policy check failed */
#define TPM_RC_INTEGRITY    (RC_FMT1 + 0x01F)   /* integrity check failed */
#define TPM_RC_TICKET       (RC_FMT1 + 0x020)   /* invalid ticket */
#define TPM_RC_RESERVED_BITS    (RC_FMT1 + 0x021)   /* reserved bits not set to zero as required */
#define TPM_RC_BAD_AUTH     (RC_FMT1 + 0x022)   /* authroization failure without DA implications */
#define TPM_RC_EXPIRED      (RC_FMT1 + 0x023)   /* the policy has expired */
#define TPM_RC_POLICY_CC    (RC_FMT1 + 0x024)   /* the commandCode in the policy is not the commandCode of the command ...  */
#define TPM_RC_BINDING      (RC_FMT1 + 0x025)   /* public and sensitive portions of an object are not cryptographically bound    */
#define TPM_RC_CURVE        (RC_FMT1 + 0x026)   /* curve not supported   */
#define TPM_RC_ECC_POINT    (RC_FMT1 + 0x027)   /* point is not on the required curve. */

#define RC_WARN         0x900           /* set for warning response codes */

#define TPM_RC_CONTEXT_GAP  (RC_WARN + 0x001)   /* gap for context ID is too large   */
#define TPM_RC_OBJECT_MEMORY    (RC_WARN + 0x002)   /* out of memory for object contexts */
#define TPM_RC_SESSION_MEMORY   (RC_WARN + 0x003)   /* out of memory for session contexts    */
#define TPM_RC_MEMORY       (RC_WARN + 0x004)   /* out of shared object/session memory or need space for internal operations */
#define TPM_RC_SESSION_HANDLES  (RC_WARN + 0x005)   /* out of session handles - a session must be flushed before a new session may be created    */
#define TPM_RC_OBJECT_HANDLES   (RC_WARN + 0x006)   /* out of object handles - the handle space for objects is depleted and a reboot is required */
#define TPM_RC_LOCALITY     (RC_WARN + 0x007)   /* bad locality */
#define TPM_RC_YIELDED      (RC_WARN + 0x008)   /* the TPM has suspended operation on the command; forward progress was made and the command may be retried. */
#define TPM_RC_CANCELED     (RC_WARN + 0x009)   /* the command was canceled */
#define TPM_RC_CANCELLED    TPM_RC_CANCELED
#define TPM_RC_TESTING      (RC_WARN + 0x00A)   /* TPM is performing self-tests */
#define TPM_RC_REFERENCE_H0 (RC_WARN + 0x010)   /* the 1st handle in the handle area references a transient object or session that is not loaded */
#define TPM_RC_REFERENCE_H1 (RC_WARN + 0x011)   /* the 2nd handle in the handle area references a transient object or session that is not loaded */
#define TPM_RC_REFERENCE_H2 (RC_WARN + 0x012)   /* the 3rd handle in the handle area references a transient object or session that is not loaded */
#define TPM_RC_REFERENCE_H3 (RC_WARN + 0x013)   /* the 4th handle in the handle area references a transient object or session that is not loaded */
#define TPM_RC_REFERENCE_H4 (RC_WARN + 0x014)   /* the 5th handle in the handle area references a transient object or session that is not loaded */
#define TPM_RC_REFERENCE_H5 (RC_WARN + 0x015)   /* the 6th handle in the handle area references a transient object or session that is not loaded */
#define TPM_RC_REFERENCE_H6 (RC_WARN + 0x016)   /* the 7th handle in the handle area references a transient object or session that is not loaded */
#define TPM_RC_REFERENCE_S0 (RC_WARN + 0x018)   /* the 1st authorization session handle references a session that is not loaded */
#define TPM_RC_REFERENCE_S1 (RC_WARN + 0x019)   /* the 2nd authorization session handle references a session that is not loaded */
#define TPM_RC_REFERENCE_S2 (RC_WARN + 0x01A)   /* the 3rd authorization session handle references a session that is not loaded */
#define TPM_RC_REFERENCE_S3 (RC_WARN + 0x01B)   /* the 4th authorization session handle references a session that is not loaded */
#define TPM_RC_REFERENCE_S4 (RC_WARN + 0x01C)   /* the 5th session handle references a session that is not loaded */
#define TPM_RC_REFERENCE_S5 (RC_WARN + 0x01D)   /* the 6th session handle references a session that is not loaded */
#define TPM_RC_REFERENCE_S6 (RC_WARN + 0x01E)   /* the 7th authorization session handle references a session that is not loaded */
#define TPM_RC_NV_RATE      (RC_WARN + 0x020)   /* the TPM is rate-limiting accesses to prevent wearout of NV */
#define TPM_RC_LOCKOUT      (RC_WARN + 0x021)   /* authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode */
#define TPM_RC_RETRY        (RC_WARN + 0x022)   /* the TPM was not able to start the command */
#define TPM_RC_NV_UNAVAILABLE   (RC_WARN + 0x023)   /* the command may require writing of NV and NV is not current accessible */
#define TPM_RC_NOT_USED     (RC_WARN + 0x07F)   /* this value is reserved and shall not be returned by the TPM */

#define TPM_RC_H        0x000           /* add to a handle-related error */
#define TPM_RC_P        0x040           /* add to a parameter-related error */
#define TPM_RC_S        0x800           /* add to a session-related error */
#define TPM_RC_1        0x100           /* add to a parameter-, handle-, or session-related error */
#define TPM_RC_2        0x200           /* add to a parameter-, handle-, or session-related error */
#define TPM_RC_3        0x300           /* add to a parameter-, handle-, or session-related error */
#define TPM_RC_4        0x400           /* add to a parameter-, handle-, or session-related error */
#define TPM_RC_5        0x500           /* add to a parameter-, handle-, or session-related error */
#define TPM_RC_6        0x600           /* add to a parameter-, handle-, or session-related error */
#define TPM_RC_7        0x700           /* add to a parameter-, handle-, or session-related error */
#define TPM_RC_8        0x800           /* add to a parameter-related error */
#define TPM_RC_9        0x900           /* add to a parameter-related error */
#define TPM_RC_A        0xA00           /* add to a parameter-related error */
#define TPM_RC_B        0xB00           /* add to a parameter-related error */
#define TPM_RC_C        0xC00           /* add to a parameter-related error */
#define TPM_RC_D        0xD00           /* add to a parameter-related error */
#define TPM_RC_E        0xE00           /* add to a parameter-related error */
#define TPM_RC_F        0xF00           /* add to a parameter-related error */
#define TPM_RC_N_MASK       0xF00           /* number mask */

/* Table 16 - Definition of (INT8) TPM_CLOCK_ADJUST Constants <IN> */

typedef INT8 TPM_CLOCK_ADJUST;

#define TPM_CLOCK_COARSE_SLOWER     -3  /* Slow the Clock update rate by one coarse adjustment step. */
#define TPM_CLOCK_MEDIUM_SLOWER     -2  /* Slow the Clock update rate by one medium adjustment step. */
#define TPM_CLOCK_FINE_SLOWER       -1  /* Slow the Clock update rate by one fine adjustment step. */
#define TPM_CLOCK_NO_CHANGE     0   /* No change to the Clock update rate. */
#define TPM_CLOCK_FINE_FASTER       1   /* Speed the Clock update rate by one fine adjustment step. */
#define TPM_CLOCK_MEDIUM_FASTER     2   /* Speed the Clock update rate by one medium adjustment step. */
#define TPM_CLOCK_COARSE_FASTER     3   /* Speed the Clock update rate by one coarse adjustment step. */

#if 0
if ((x != TPM_CLOCK_COARSE_SLOWER   ) &&
    (x != TPM_CLOCK_MEDIUM_SLOWER   ) &&
    (x != TPM_CLOCK_FINE_SLOWER     ) &&    
    (x != TPM_CLOCK_NO_CHANGE       ) &&    
    (x != TPM_CLOCK_FINE_FASTER     ) &&
    (x != TPM_CLOCK_MEDIUM_FASTER   ) &&    
    (x != TPM_CLOCK_COARSE_FASTER   )) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 17 - Definition of (UINT16) TPM_EO Constants <IN/OUT> */

typedef UINT16 TPM_EO;

#define TPM_EO_EQ       0x0000  /* A = B */
#define TPM_EO_NEQ      0x0001  /* A ? B */
#define TPM_EO_SIGNED_GT    0x0002  /* A > B signed  */
#define TPM_EO_UNSIGNED_GT  0x0003  /* A > B unsigned    */
#define TPM_EO_SIGNED_LT    0x0004  /* A < B signed  */
#define TPM_EO_UNSIGNED_LT  0x0005  /* A < B unsigned    */
#define TPM_EO_SIGNED_GE    0x0006  /* A = B signed  */
#define TPM_EO_UNSIGNED_GE  0x0007  /* A = B unsigned    */
#define TPM_EO_SIGNED_LE    0x0008  /* A = B signed  */
#define TPM_EO_UNSIGNED_LE  0x0009  /* A = B unsigned    */
#define TPM_EO_BITSET       0x000A  /* All bits SET in B are SET in A. ((A&B)=B)     */
#define TPM_EO_BITCLEAR     0x000B  /* All bits SET in B are CLEAR in A. ((A&B)=0) */

#if 0
if ((x != TPM_EO_EQ     ) &&    
    (x != TPM_EO_NEQ    ) &&        
    (x != TPM_EO_SIGNED_GT      ) &&
    (x != TPM_EO_UNSIGNED_GT    ) &&    
    (x != TPM_EO_SIGNED_LT      ) &&
    (x != TPM_EO_UNSIGNED_LT        ) &&
    (x != TPM_EO_SIGNED_GE      ) &&
    (x != TPM_EO_UNSIGNED_GE        ) &&
    (x != TPM_EO_SIGNED_LE      ) &&
    (x != TPM_EO_UNSIGNED_LE        ) &&
    (x != TPM_EO_BITSET ) &&
    (x != TPM_EO_BITCLEAR   )) {
    rc = TPM_RC_VALUE;
}       
#endif

/* Table 18 - Definition of (UINT16) TPM_ST Constants <IN/OUT, S> */

typedef UINT16 TPM_ST;

#define TPM_ST_RSP_COMMAND      0x00C4  /* tag value for a response */
#define TPM_ST_NULL         0X8000  /*no structure type specified */
#define TPM_ST_NO_SESSIONS      0x8001  /*command/response has no attached sessions*/
#define TPM_ST_SESSIONS         0x8002  /* command/response has one or more attached sessions*/
#define TPM_ST_ATTEST_NV        0x8014  /* tag for an attestation structure  */
#define TPM_ST_ATTEST_COMMAND_AUDIT 0x8015  /* tag for an attestation structure  */
#define TPM_ST_ATTEST_SESSION_AUDIT 0x8016  /* tag for an attestation structure  */
#define TPM_ST_ATTEST_CERTIFY       0x8017  /* tag for an attestation structure  */
#define TPM_ST_ATTEST_QUOTE     0x8018  /* tag for an attestation structure  */
#define TPM_ST_ATTEST_TIME      0x8019  /* tag for an attestation structure  */
#define TPM_ST_ATTEST_CREATION      0x801A  /* tag for an attestation structure */
#define TPM_ST_CREATION         0x8021  /* tag for a ticket type     */
#define TPM_ST_VERIFIED         0x8022  /* tag for a ticket type     */
#define TPM_ST_AUTH_SECRET      0x8023  /* tag for a ticket type     */
#define TPM_ST_HASHCHECK        0x8024  /* tag for a ticket type     */
#define TPM_ST_AUTH_SIGNED      0x8025  /* tag for a ticket type     */
#define TPM_ST_FU_MANIFEST      0x8029  /* tag for a structure describing a Field Upgrade Policy */

/* Table 19 - Definition of (UINT16) TPM_SU Constants <IN> */

typedef UINT16 TPM_SU;

#define TPM_SU_CLEAR    0x0000  /* on TPM2_Startup(), indicates that the TPM should perform TPM Reset or TPM Restart */
#define TPM_SU_STATE    0x0001  /* on TPM2_Startup(), indicates that the TPM should restore the state saved by TPM2_Shutdown(TPM_SU_STATE) */

#if 0
if (
    (x != TPM_SU_CLEAR      ) &&
    (x != TPM_SU_STATE  )) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 20 - Definition of (UINT8) TPM_SE Constants <IN> */

typedef UINT8 TPM_SE;

#define TPM_SE_HMAC 0x00
#define TPM_SE_POLICY   0x01
#define TPM_SE_TRIAL    0x03

#if 0
if (
    (x != TPM_SE_HMAC   ) &&
    (x != TPM_SE_POLICY ) &&
    (x != TPM_SE_TRIAL  )) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 21 - Definition of (UINT32) TPM_CAP Constants  */

typedef UINT32 TPM_CAP;

#define TPM_CAP_FIRST       0x00000000  /*      */
#define TPM_CAP_ALGS        0x00000000  /* TPM_ALG_ID(1)    TPML_ALG_PROPERTY   */
#define TPM_CAP_HANDLES     0x00000001  /* TPM_HANDLE       TPML_HANDLE */
#define TPM_CAP_COMMANDS    0x00000002  /* TPM_CC       TPML_CCA    */
#define TPM_CAP_PP_COMMANDS 0x00000003  /* TPM_CC       TPML_CC     */
#define TPM_CAP_AUDIT_COMMANDS  0x00000004  /* TPM_CC       TPML_CC */
#define TPM_CAP_PCRS        0x00000005  /* reserved     TPML_PCR_SELECTION  */
#define TPM_CAP_TPM_PROPERTIES  0x00000006  /* TPM_PT       TPML_TAGGED_TPM_PROPERTY    */
#define TPM_CAP_PCR_PROPERTIES  0x00000007  /* TPM_PT_PCR       TPML_TAGGED_PCR_PROPERTY    */
#define TPM_CAP_ECC_CURVES  0x00000008  /* TPM_ECC_CURVE(1) TPML_ECC_CURVE  */
#define TPM_CAP_LAST        0x00000008  /* */       
#define TPM_CAP_VENDOR_PROPERTY 0x00000100  /* manufacturer specific    manufacturer-specific values */

#if 0
if (
    (x != TPM_CAP_FIRST         ) &&
    (x != TPM_CAP_ALGS          ) &&
    (x != TPM_CAP_HANDLES       ) &&
    (x != TPM_CAP_COMMANDS      ) &&
    (x != TPM_CAP_PP_COMMANDS       ) &&
    (x != TPM_CAP_AUDIT_COMMANDS    ) &&
    (x != TPM_CAP_PCRS          ) &&
    (x != TPM_CAP_TPM_PROPERTIES    ) &&
    (x != TPM_CAP_PCR_PROPERTIES    ) &&
    (x != TPM_CAP_ECC_CURVES        ) &&
    (x != TPM_CAP_LAST          ) &&
    (x != TPM_CAP_VENDOR_PROPERTY   )) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 22 - Definition of (UINT32) TPM_PT Constants <IN/OUT, S> */

typedef UINT32 TPM_PT;
        
#define TPM_PT_NONE 0x00000000  /* indicates no property type            */
#define PT_GROUP    0x00000100  /* The number of properties in each group. */
#define PT_FIXED    (PT_GROUP * 1)  /* the group of fixed properties returned as TPMS_TAGGED_PROPERTY */

/* The values in this group are only changed due to a firmware change in the TPM.    */

#define TPM_PT_FAMILY_INDICATOR     (PT_FIXED + 0)  /* a 4-octet character string containing the TPM Family value (TPM_SPEC_FAMILY) */
#define TPM_PT_LEVEL            (PT_FIXED + 1)  /* the level of the specification */
#define TPM_PT_REVISION         (PT_FIXED + 2)  /* the specification Revision times 100 */
#define TPM_PT_DAY_OF_YEAR      (PT_FIXED + 3)  /* the specification day of year using TCG calendar */
#define TPM_PT_YEAR         (PT_FIXED + 4)  /* the specification year using the CE */
#define TPM_PT_MANUFACTURER     (PT_FIXED + 5)  /* the vendor ID unique to each TPM manufacturer     */
#define TPM_PT_VENDOR_STRING_1      (PT_FIXED + 6)  /* the first four characters of the vendor ID string */
#define TPM_PT_VENDOR_STRING_2      (PT_FIXED + 7)  /* the second four characters of the vendor ID string    */
#define TPM_PT_VENDOR_STRING_3      (PT_FIXED + 8)  /* the third four characters of the vendor ID string     */
#define TPM_PT_VENDOR_STRING_4      (PT_FIXED + 9)  /* the fourth four characters of the vendor ID sting     */
#define TPM_PT_VENDOR_TPM_TYPE      (PT_FIXED + 10) /* vendor-defined value indicating the TPM model     */
#define TPM_PT_FIRMWARE_VERSION_1   (PT_FIXED + 11) /* the most-significant 32 bits of a vendor-specific value indicating the version of the firmware    */
#define TPM_PT_FIRMWARE_VERSION_2   (PT_FIXED + 12) /* the least-significant 32 bits of a vendor-specific value indicating the version of the firmware   */
#define TPM_PT_INPUT_BUFFER     (PT_FIXED + 13) /* the maximum size of a parameter (typically, a TPM2B_MAX_BUFFER)   */
#define TPM_PT_HR_TRANSIENT_MIN     (PT_FIXED + 14) /* the minimum number of transient objects that can be held in TPM RAM */
#define TPM_PT_HR_PERSISTENT_MIN    (PT_FIXED + 15) /* the minimum number of persistent objects that can be held in TPM NV memory */
#define TPM_PT_HR_LOADED_MIN        (PT_FIXED + 16) /* the minimum number of authorization sessions that can be held in TPM RAM */
#define TPM_PT_ACTIVE_SESSIONS_MAX  (PT_FIXED + 17) /* the number of authorization sessions that may be active at a time */
#define TPM_PT_PCR_COUNT        (PT_FIXED + 18) /* the number of PCR implemented */
#define TPM_PT_PCR_SELECT_MIN       (PT_FIXED + 19) /* the minimum number of octets in a TPMS_PCR_SELECT.sizeOfSelect */
#define TPM_PT_CONTEXT_GAP_MAX      (PT_FIXED + 20) /* the maximum allowed difference (unsigned) between the contextID values of two saved session contexts */
#define TPM_PT_NV_COUNTERS_MAX      (PT_FIXED + 22) /* the maximum number of NV Indexes that are allowed to have the TPMA_NV_COUNTER attribute SET */
#define TPM_PT_NV_INDEX_MAX     (PT_FIXED + 23) /* the maximum size of an NV Index data area     */
#define TPM_PT_MEMORY           (PT_FIXED + 24) /* a TPMA_MEMORY indicating the memory management method for the TPM     */
#define TPM_PT_CLOCK_UPDATE     (PT_FIXED + 25) /* interval, in milliseconds, between updates to the copy of TPMS_CLOCK_INFO.clock in NV     */
#define TPM_PT_CONTEXT_HASH     (PT_FIXED + 26) /* the algorithm used for the integrity HMAC on saved contexts and for hashing the fuData of TPM2_FirmwareRead() */
#define TPM_PT_CONTEXT_SYM      (PT_FIXED + 27) /* the algorithm used for encryption of saved contexts   */
#define TPM_PT_CONTEXT_SYM_SIZE     (PT_FIXED + 28) /* the size of the key used for encryption of saved contexts     */
#define TPM_PT_ORDERLY_COUNT        (PT_FIXED + 29) /* the modulus - 1 of the count for NV update of an orderly counter */
#define TPM_PT_MAX_COMMAND_SIZE     (PT_FIXED + 30) /* the maximum value for commandSize in a command    */
#define TPM_PT_MAX_RESPONSE_SIZE    (PT_FIXED + 31) /* the maximum value for responseSize in a response  */
#define TPM_PT_MAX_DIGEST       (PT_FIXED + 32) /* the maximum size of a digest that can be produced by the TPM  */
#define TPM_PT_MAX_OBJECT_CONTEXT   (PT_FIXED + 33) /* the maximum size of an object context that will be returned by TPM2_ContextSave   */
#define TPM_PT_MAX_SESSION_CONTEXT  (PT_FIXED + 34) /* the maximum size of a session context that will be returned by TPM2_ContextSave   */
#define TPM_PT_PS_FAMILY_INDICATOR  (PT_FIXED + 35) /* platform-specific family (a TPM_PS value)(see Table 24) */
#define TPM_PT_PS_LEVEL         (PT_FIXED + 36) /*  */
#define TPM_PT_PS_REVISION      (PT_FIXED + 37) /* the specification Revision times 100 for the platform-specific specification  */
#define TPM_PT_PS_DAY_OF_YEAR       (PT_FIXED + 38) /* the platform-specific specification day of year using TCG calendar    */
#define TPM_PT_PS_YEAR          (PT_FIXED + 39) /* the platform-specific specification year using the CE     */
#define TPM_PT_SPLIT_MAX        (PT_FIXED + 40) /* the number of split signing operations supported by the TPM   */
#define TPM_PT_TOTAL_COMMANDS       (PT_FIXED + 41) /* total number of commands implemented in the TPM   */
#define TPM_PT_LIBRARY_COMMANDS     (PT_FIXED + 42) /* number of commands from the TPM library that are implemented  */
#define TPM_PT_VENDOR_COMMANDS      (PT_FIXED + 43) /* number of vendor commands that are implemented */
#define TPM_PT_NV_BUFFER_MAX        (PT_FIXED + 44) /* the maximum data size in one NV write command */
#define PT_VAR              (PT_GROUP * 2)  /* the group of variable properties returned as TPMS_TAGGED_PROPERTY */

/* The properties in this group change because of a Protected Capability other than a firmware
   update. The values are not necessarily persistent across all power transitions. */

#define TPM_PT_PERMANENT        (PT_VAR + 0)    /* TPMA_PERMANENT    */
#define TPM_PT_STARTUP_CLEAR        (PT_VAR + 1)    /* TPMA_STARTUP_CLEAR    */
#define TPM_PT_HR_NV_INDEX      (PT_VAR + 2)    /* the number of NV Indexes currently defined    */
#define TPM_PT_HR_LOADED        (PT_VAR + 3)    /* the number of authorization sessions currently loaded into TPM RAM    */
#define TPM_PT_HR_LOADED_AVAIL      (PT_VAR + 4)    /* the number of additional authorization sessions, of any type, that could be loaded into TPM RAM */
#define TPM_PT_HR_ACTIVE        (PT_VAR + 5)    /* the number of active authorization sessions currently being tracked by the TPM */
#define TPM_PT_HR_ACTIVE_AVAIL      (PT_VAR + 6)    /* the number of additional authorization sessions, of any type, that could be created */
#define TPM_PT_HR_TRANSIENT_AVAIL   (PT_VAR + 7)    /* estimate of the number of additional transient objects that could be loaded into TPM RAM */
#define TPM_PT_HR_PERSISTENT        (PT_VAR + 8)    /* the number of persistent objects currently loaded into TPM NV memory  */
#define TPM_PT_HR_PERSISTENT_AVAIL  (PT_VAR + 9)    /* the number of additional persistent objects that could be loaded into NV memory */
#define TPM_PT_NV_COUNTERS      (PT_VAR + 10)   /* the number of defined NV Indexes that have NV TPMA_NV_COUNTER attribute SET   */
#define TPM_PT_NV_COUNTERS_AVAIL    (PT_VAR + 11)   /* the number of additional NV Indexes that can be defined with their TPMA_NV_COUNTER and TPMA_NV_ORDERLY attribute SET */
#define TPM_PT_ALGORITHM_SET        (PT_VAR + 12)   /* code that limits the algorithms that may be used with the TPM     */
#define TPM_PT_LOADED_CURVES        (PT_VAR + 13)   /* the number of loaded ECC curves   */
#define TPM_PT_LOCKOUT_COUNTER      (PT_VAR + 14)   /* the current value of the lockout counter (failedTries)    */
#define TPM_PT_MAX_AUTH_FAIL        (PT_VAR + 15)   /* the number of authorization failures before DA lockout is invoked     */
#define TPM_PT_LOCKOUT_INTERVAL     (PT_VAR + 16)   /* the number of seconds before the value reported by TPM_PT_LOCKOUT_COUNTER is decremented */
#define TPM_PT_LOCKOUT_RECOVERY     (PT_VAR + 17)   /* the number of seconds after a lockoutAuth failure before use of lockoutAuth may be attempted again    */
#define TPM_PT_NV_WRITE_RECOVERY    (PT_VAR + 18)   /* number of milliseconds before the TPM will accept another command that will modify NV */
#define TPM_PT_AUDIT_COUNTER_0      (PT_VAR + 19)   /* the high-order 32 bits of the command audit counter   */
#define TPM_PT_AUDIT_COUNTER_1      (PT_VAR + 20)   /* the low-order 32 bits of the command audit counter */

/* Table 23 - Definition of (UINT32) TPM_PT_PCR Constants <IN/OUT, S> */

typedef UINT32 TPM_PT_PCR;

#define TPM_PT_PCR_FIRST    0x00000000  /* bottom of the range of TPM_PT_PCR properties      */
#define TPM_PT_PCR_SAVE     0x00000000  /* a SET bit in the TPMS_PCR_SELECT indicates that the PCR is saved and restored by TPM_SU_STATE     */
#define TPM_PT_PCR_EXTEND_L0    0x00000001  /* a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from locality 0 */
#define TPM_PT_PCR_RESET_L0 0x00000002  /* a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 0  */
#define TPM_PT_PCR_EXTEND_L1    0x00000003  /* a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from locality 1  */
#define TPM_PT_PCR_RESET_L1 0x00000004  /* a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 1 */
#define TPM_PT_PCR_EXTEND_L2    0x00000005  /* a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from locality 2  */
#define TPM_PT_PCR_RESET_L2 0x00000006  /* a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 2 */
#define TPM_PT_PCR_EXTEND_L3    0x00000007  /* a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from locality 3 */
#define TPM_PT_PCR_RESET_L3 0x00000008  /* a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 3 */
#define TPM_PT_PCR_EXTEND_L4    0x00000009  /* a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from locality 4 */
#define TPM_PT_PCR_RESET_L4 0x0000000A  /* a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 4 */
#define TPM_PT_PCR_NO_INCREMENT 0x00000011  /* a SET bit in the TPMS_PCR_SELECT indicates that modifications to this PCR (reset or Extend) will not increment the pcrUpdateCounter */
#define TPM_PT_PCR_RESET_L4 0x0000000A  /* a SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by TPM2_PCR_Reset() from locality 4 */
#define TPM_PT_PCR_DRTM_RESET   0x00000012  /* a SET bit in the TPMS_PCR_SELECT indicates that the PCR is reset by a DRTM event */
#define TPM_PT_PCR_POLICY   0x00000013  /* a SET bit in the TPMS_PCR_SELECT indicates that the PCR is controlled by policy */
#define TPM_PT_PCR_AUTH     0x00000014  /* a SET bit in the TPMS_PCR_SELECT indicates that the PCR is controlled by an authorization value */
#define TPM_PT_PCR_LAST     0x00000014  /* top of the range of TPM_PT_PCR properties of the implementation */

/* Table 24 - Definition of (UINT32) TPM_PS Constants <OUT> */

typedef UINT32 TPM_PS;

#define TPM_PS_MAIN     0x00000000  /* not platform specific    */
#define TPM_PS_PC       0x00000001  /* PC Client    */
#define TPM_PS_PDA      0x00000002  /* PDA (includes all mobile devices that are not specifically cell phones)  */
#define TPM_PS_CELL_PHONE   0x00000003  /* Cell Phone   */
#define TPM_PS_SERVER       0x00000004  /* Server WG    */
#define TPM_PS_PERIPHERAL   0x00000005  /* Peripheral WG    */
#define TPM_PS_TSS      0x00000006  /* TSS WG   */
#define TPM_PS_STORAGE      0x00000007  /* Storage WG   */
#define TPM_PS_AUTHENTICATION   0x00000008  /* Authentication WG    */
#define TPM_PS_EMBEDDED     0x00000009  /* Embedded WG  */
#define TPM_PS_HARDCOPY     0x0000000A  /* Hardcopy WG  */
#define TPM_PS_INFRASTRUCTURE   0x0000000B  /* Infrastructure WG    */
#define TPM_PS_VIRTUALIZATION   0x0000000C  /* Virtualization WG    */
#define TPM_PS_TNC      0x0000000D  /* Trusted Network Connect WG   */
#define TPM_PS_MULTI_TENANT 0x0000000E  /* Multi-tenant WG  */
#define TPM_PS_TC       0x0000000F  /* Technical Committee*/

/* Table 25 - Definition of Types for Handles */

typedef UINT32  TPM_HANDLE; /* Handles may refer to objects (keys or data blobs), authorization
                   sessions (HMAC and policy), NV Indexes, permanent TPM locations,
                   and PCR. */

/* Table 26 - Definition of (UINT8) TPM_HT Constants <S> */

typedef UINT8 TPM_HT;

#define TPM_HT_PCR      0x00    /* PCR - consecutive numbers, starting at 0, that reference the PCR registers */
#define TPM_HT_NV_INDEX     0x01    /* NV Index - assigned by the caller     */
#define TPM_HT_HMAC_SESSION 0x02    /* HMAC Authorization Session - assigned by the TPM when the session is created  */
#define TPM_HT_LOADED_SESSION   0x02    /* Loaded Authorization Session - used only in the context of TPM2_GetCapability */
#define TPM_HT_POLICY_SESSION   0x03    /* Policy Authorization Session - assigned by the TPM when the session is created    */
#define TPM_HT_ACTIVE_SESSION   0x03    /* Active Authorization Session - used only in the context of TPM2_GetCapability */
#define TPM_HT_PERMANENT    0x40    /* Permanent Values - assigned by this specification in Table 27     */
#define TPM_HT_TRANSIENT    0x80    /* Transient Objects - assigned by the TPM when an object is
                       loaded into transient-object memory or when a persistent
                       object is converted to a transient object */
#define TPM_HT_PERSISTENT   0x81     /*Persistent Objects - assigned by the TPM when a loaded transient object is made persistent    */

/* Table 27 - Definition of (UINT32) TPM_RH Constants <IN, S> */

typedef UINT32 TPM_RH;

#define TPM_RH_FIRST        0x40000000  /* R         */
#define TPM_RH_SRK      0x40000000  /* R    not used1    */
#define TPM_RH_OWNER        0x40000001  /* K, A, P  handle references the Storage Primary Seed (SPS), the ownerAuth, and the ownerPolicy     */
#define TPM_RH_REVOKE       0x40000002  /* R    not used1    */
#define TPM_RH_TRANSPORT    0x40000003  /* R    not used1    */
#define TPM_RH_OPERATOR     0x40000004  /* R    not used1    */
#define TPM_RH_ADMIN        0x40000005  /* R    not used1    */
#define TPM_RH_EK       0x40000006  /* R    not used1    */
#define TPM_RH_NULL     0x40000007  /* K, A, P  a handle associated with the null hierarchy, an EmptyAuth authValue, and an Empty Policy authPolicy.     */
#define TPM_RH_UNASSIGNED   0x40000008  /* R    value reserved to the TPM to indicate a handle location that has not been initialized or assigned    */
#define TPM_RS_PW       0x40000009  /* S    authorization value used to indicate a password authorization session    */
#define TPM_RH_LOCKOUT      0x4000000A  /* A    references the authorization associated with the dictionary attack lockout reset     */
#define TPM_RH_ENDORSEMENT  0x4000000B  /* K, A, P  references the Endorsement Primary Seed (EPS), endorsementAuth, and endorsementPolicy    */
#define TPM_RH_PLATFORM     0x4000000C  /* K, A, P  references the Platform Primary Seed (PPS), platformAuth, and platformPolicy     */
#define TPM_RH_PLATFORM_NV  0x4000000D  /* C    for phEnableNV */
#define TPM_RH_LAST     0x4000000D  /* R    the top of the reserved handle area */

/* Table 28 - Definition of (TPM_HANDLE) TPM_HC Constants <IN, S> */

#define HR_HANDLE_MASK      0x00FFFFFF              /* to mask off the HR    */
#define HR_RANGE_MASK       0xFF000000              /* to mask off the variable part     */
#define HR_SHIFT        24      
#define HR_PCR          (TPM_HT_PCR << HR_SHIFT)        
#define HR_HMAC_SESSION     (TPM_HT_HMAC_SESSION << HR_SHIFT)       
#define HR_POLICY_SESSION   (TPM_HT_POLICY_SESSION << HR_SHIFT)     
#define HR_TRANSIENT        (TPM_HT_TRANSIENT << HR_SHIFT)      
#define HR_PERSISTENT       (TPM_HT_PERSISTENT << HR_SHIFT)     
#define HR_NV_INDEX     (TPM_HT_NV_INDEX << HR_SHIFT)       
#define HR_PERMANENT        (TPM_HT_PERMANENT << HR_SHIFT)      
#define PCR_FIRST       (HR_PCR + 0)                /* first PCR     */
#define PCR_LAST        (PCR_FIRST + IMPLEMENTATION_PCR-1)  /* last PCR  */
#define HMAC_SESSION_FIRST  (HR_HMAC_SESSION + 0)           /* first HMAC session    */
#define HMAC_SESSION_LAST   (HMAC_SESSION_FIRST+MAX_ACTIVE_SESSIONS-1)  /* last HMAC session     */
#define LOADED_SESSION_FIRST    HMAC_SESSION_FIRST          /* used in GetCapability     */
#define LOADED_SESSION_LAST HMAC_SESSION_LAST           /* used in GetCapability         */
#define POLICY_SESSION_FIRST    (HR_POLICY_SESSION + 0)         /* first policy session  */
#define POLICY_SESSION_LAST (POLICY_SESSION_FIRST + MAX_ACTIVE_SESSIONS-1)  /* last policy session   */
#define TRANSIENT_FIRST     (HR_TRANSIENT + 0)          /* first transient object    */
#define ACTIVE_SESSION_FIRST    POLICY_SESSION_FIRST            /* used in GetCapability         */
#define ACTIVE_SESSION_LAST POLICY_SESSION_LAST         /*  used in GetCapability    */
#define TRANSIENT_LAST      (TRANSIENT_FIRST+MAX_LOADED_OBJECTS-1)  /* last transient object     */
#define PERSISTENT_FIRST    (HR_PERSISTENT + 0)         /* first persistent object       */
#define PERSISTENT_LAST     (PERSISTENT_FIRST + 0x00FFFFFF)     /* last persistent object    */
#define PLATFORM_PERSISTENT (PERSISTENT_FIRST + 0x00800000)     /* first platform persistent object  */
#define NV_INDEX_FIRST      (HR_NV_INDEX + 0)           /* first allowed NV Index    */
#define NV_INDEX_LAST       (NV_INDEX_FIRST + 0x00FFFFFF)       /* last allowed NV Index     */
#define PERMANENT_FIRST     TPM_RH_FIRST        
#define PERMANENT_LAST      TPM_RH_LAST

/* Table 29 - Definition of (UINT32) TPMA_ALGORITHM Bits */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
    int asymmetric  : 1;    /* 0 an asymmetric algorithm with public and private portions */
    int symmetric   : 1;    /* 1 a symmetric block cipher */
    int hash    : 1;    /* a hash algorithm */
    int object  : 1;    /* an algorithm that may be used as an object type */
    int Reserved1   : 4;    /* 7:4 */
    int signing : 1;    /* 8 a signing algorithm */
    int encrypting  : 1;    /* 9 an encryption/decryption algorithm */
    int method  : 1;    /* 10 a method such as a key derivative function (KDF) */
    int Reserved2   : 21;   /* 31:11 */
    };
    UINT32 val;
} TPMA_ALGORITHM;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
    int Reserved2   : 21;   /* 31:11 */
    int method  : 1;    /* 10 a method such as a key derivative function (KDF) */
    int encrypting  : 1;    /* 9 an encryption/decryption algorithm */
    int signing : 1;    /* 8 a signing algorithm */
    int Reserved1   : 4;    /* 7:4 */
    int object  : 1;    /* an algorithm that may be used as an object type */
    int hash    : 1;    /* a hash algorithm */
    int symmetric   : 1;    /* 1 a symmetric block cipher */
    int asymmetric  : 1;    /* 0 an asymmetric algorithm with public and private portions */
    };
    UINT32 val;
} TPMA_ALGORITHM;

#else 

typedef uint32_t TPMA_ALGORITHM;

#define TPMA_ALGORITHM_ASYMMETRIC   0x00000001
#define TPMA_ALGORITHM_SYMMETRIC    0x00000002
#define TPMA_ALGORITHM_HASH     0x00000004
#define TPMA_ALGORITHM_OBJECT       0x00000008
#define TPMA_ALGORITHM_RESERVED1    0x000000f0
#define TPMA_ALGORITHM_SIGNING      0x00000100
#define TPMA_ALGORITHM_ENCRYPTING   0x00000200
#define TPMA_ALGORITHM_METHOD       0x00000400
#define TPMA_ALGORITHM_RESERVED2    0xfffff800

#endif

/* Table 30 - Definition of (UINT32) TPMA_OBJECT Bits */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
    int Reserved1       : 1;    /* 0 shall be zero */
    int fixedTPM        : 1;    /* 1 The hierarchy of the object, as indicated by its Qualified Name, may not change. */
    int stClear         : 1;    /* 2 Previously saved contexts of this object may not be loaded after Startup(CLEAR). */
    int Reserved2       : 1;    /* 3 shall be zero */
    int fixedParent     : 1;    /* 4 The parent of the object may not change. */
    int sensitiveDataOrigin : 1;    /* 5 the TPM generated all of the sensitive data other than the authValue. */
    int userWithAuth    : 1;    /* 6 HMAC session or with a password */ 
    int adminWithPolicy     : 1;    /* 7 policy session. */
    int Reserved3       : 2;    /* 9:8  shall be zero */
    int noDA        : 1;    /* 10   The object is not subject to dictionary attack protections. */
    int encryptedDuplication : 1;   /* 11 */
    int Reserved4       : 4;    /* 15:12    shall be zero */
    int restricted      : 1;    /* 16   Key usage is restricted to manipulate structures of known format */
    int decrypt         : 1;    /* 17   The private portion of the key may be used to decrypt. */
    int sign        : 1;    /* 18   The private portion of the key may be used to sign. */
    int Reserved5       : 13;   /* 31:19    shall be zero */
    };
    UINT32 val;
} TPMA_OBJECT;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
    int Reserved5       : 13;   /* 31:19    shall be zero */
    int sign        : 1;    /* 18   The private portion of the key may be used to sign. */
    int decrypt         : 1;    /* 17   The private portion of the key may be used to decrypt. */
    int restricted      : 1;    /* 16   Key usage is restricted to manipulate structures of known format */
    int Reserved4       : 4;    /* 15:12    shall be zero */
    int encryptedDuplication : 1;   /* 11 */
    int noDA        : 1;    /* 10   The object is not subject to dictionary attack protections. */
    int Reserved3       : 2;    /* 9:8  shall be zero */
    int adminWithPolicy     : 1;    /* 7 policy session. */
    int userWithAuth    : 1;    /* 6 HMAC session or with a password */ 
    int sensitiveDataOrigin : 1;    /* 5 the TPM generated all of the sensitive data other than the authValue. */
    int fixedParent     : 1;    /* 4 The parent of the object may not change. */
    int Reserved2       : 1;    /* 3 shall be zero */
    int stClear         : 1;    /* 2 Previously saved contexts of this object may not be loaded after Startup(CLEAR). */
    int fixedTPM        : 1;    /* 1 The hierarchy of the object, as indicated by its Qualified Name, may not change. */
    int Reserved1       : 1;    /* 0 shall be zero */
    };
    UINT32 val;
} TPMA_OBJECT;

#else 

typedef uint32_t TPMA_OBJECT;
    
#define TPMA_OBJECT_RESERVED1           0x00000001
#define TPMA_OBJECT_FIXEDTPM            0x00000002
#define TPMA_OBJECT_STCLEAR         0x00000004
#define TPMA_OBJECT_RESERVED2           0x00000008
#define TPMA_OBJECT_FIXEDPARENT         0x00000010
#define TPMA_OBJECT_SENSITIVEDATAORIGIN     0x00000020
#define TPMA_OBJECT_USERWITHAUTH        0x00000040
#define TPMA_OBJECT_ADMINWITHPOLICY     0x00000080
#define TPMA_OBJECT_RESERVED3           0x00000300
#define TPMA_OBJECT_NODA            0x00000400
#define TPMA_OBJECT_ENCRYPTEDDUPLICATION    0x00000800
#define TPMA_OBJECT_RESERVED4           0x0000f000
#define TPMA_OBJECT_RESTRICTED          0x00010000
#define TPMA_OBJECT_DECRYPT         0x00020000
#define TPMA_OBJECT_SIGN            0x00040000
#define TPMA_OBJECT_RESERVED5           0xfff80000

#endif

/* Table 31 - Definition of (UINT8) TPMA_SESSION Bits <IN/OUT> */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
    int continueSession     : 1;        /* 0    the session is to remain active after successful completion of the command */
    int auditExclusive  : 1;        /* 1    executed if the session is exclusive at the start of the command */
    int auditReset      : 1;        /* 2    audit digest of the session should be initialized  */
    int Reserved        : 2;        /* 4:3  shall be CLEAR */
    int decrypt         : 1;        /* 5    first parameter in the command is symmetrically encrypted */
    int encrypt         : 1;        /* 6    TPM should use this session to encrypt the first parameter in the response */
    int audit       : 1;        /* 7     session is for audit */
    };
    UINT8 val;
} TPMA_SESSION;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
    int audit       : 1;        /* 7     session is for audit */
    int encrypt         : 1;        /* 6    TPM should use this session to encrypt the first parameter in the response */
    int decrypt         : 1;        /* 5    first parameter in the command is symmetrically encrypted */
    int Reserved        : 2;        /* 4:3  shall be CLEAR */
    int auditReset      : 1;        /* 2    audit digest of the session should be initialized  */
    int auditExclusive  : 1;        /* 1    executed if the session is exclusive at the start of the command */
    int continueSession     : 1;        /* 0    the session is to remain active after successful completion of the command */
    };
    UINT8 val;
} TPMA_SESSION;

#else 

typedef uint32_t TPMA_SESSION;

#define TPMA_SESSION_CONTINUESESSION    0x00000001
#define TPMA_SESSION_AUDITEXCLUSIVE 0x00000002
#define TPMA_SESSION_AUDITRESET     0x00000004
#define TPMA_SESSION_RESERVED       0x00000018
#define TPMA_SESSION_DECRYPT        0x00000020
#define TPMA_SESSION_ENCRYPT        0x00000040
#define TPMA_SESSION_AUDIT      0x00000080

#endif

/* Table 32 - Definition of (UINT8) TPMA_LOCALITY Bits <IN/OUT> */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
    int TPM_LOC_ZERO    : 1;    /* 0 */
    int TPM_LOC_ONE     : 1;    /* 1 */
    int TPM_LOC_TWO     : 1;    /* 2 */
    int TPM_LOC_THREE   : 1;    /* 3 */
    int TPM_LOC_FOUR    : 1;    /* 4 */
    int Extended        : 3;    /* 7:5 */
    };
    UINT8 val;
} TPMA_LOCALITY;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
    int Extended        : 3;    /* 7:5 */
    int TPM_LOC_FOUR    : 1;    /* 4 */
    int TPM_LOC_THREE   : 1;    /* 3 */
    int TPM_LOC_TWO     : 1;    /* 2 */
    int TPM_LOC_ONE     : 1;    /* 1 */
    int TPM_LOC_ZERO    : 1;    /* 0 */
    };
    UINT8 val;
} TPMA_LOCALITY;

#else 

typedef uint32_t TPMA_LOCALITY;

#define TPMA_LOCALITY_ZERO      0x00000001
#define TPMA_LOCALITY_ONE       0x00000002
#define TPMA_LOCALITY_TWO       0x00000004
#define TPMA_LOCALITY_THREE     0x00000008
#define TPMA_LOCALITY_FOUR      0x00000010
#define TPMA_LOCALITY_EXTENDED      0x000000e0

#endif

/* Table 33 - Definition of (UINT32) TPMA_PERMANENT Bits <OUT> */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
    int ownerAuthSet    : 1;    /* 0    TPM2_HierarchyChangeAuth() with ownerAuth has been executed since the last TPM2_Clear(). */
    int endorsementAuthSet  : 1;    /* 1    TPM2_HierarchyChangeAuth() with endorsementAuth has been executed since the last TPM2_Clear(). */
    int lockoutAuthSet  : 1;    /* 2    TPM2_HierarchyChangeAuth() with lockoutAuth has been executed since the last TPM2_Clear(). */
    int Reserved1       : 5;    /* 7:3   */
    int disableClear    : 1;    /* 8    TPM2_Clear() is disabled. */
    int inLockout       : 1;    /* 9    The TPM is in lockout and commands that require authorization with other than Platform Authorization will not succeed. */
    int tpmGeneratedEPS : 1;    /* 10   The EPS was created by the TPM. */
    int Reserved2       : 21;   /* 31:11 */
    };
    UINT32 val;
} TPMA_PERMANENT;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
    int Reserved2       : 21;   /* 31:11 */
    int tpmGeneratedEPS : 1;    /* 10   The EPS was created by the TPM. */
    int inLockout       : 1;    /* 9    The TPM is in lockout and commands that require authorization with other than Platform Authorization will not succeed. */
    int disableClear    : 1;    /* 8    TPM2_Clear() is disabled. */
    int Reserved1       : 5;    /* 7:3   */
    int lockoutAuthSet  : 1;    /* 2    TPM2_HierarchyChangeAuth() with lockoutAuth has been executed since the last TPM2_Clear(). */
    int endorsementAuthSet  : 1;    /* 1    TPM2_HierarchyChangeAuth() with endorsementAuth has been executed since the last TPM2_Clear(). */
    int ownerAuthSet    : 1;    /* 0    TPM2_HierarchyChangeAuth() with ownerAuth has been executed since the last TPM2_Clear(). */
    };
    UINT32 val;
} TPMA_PERMANENT;

#else

typedef uint32_t TPMA_PERMANENT;

#define TPMA_PERMANENT_OWNERAUTHSET     0x00000001
#define TPMA_PERMANENT_ENDORSEMENTAUTHSET   0x00000002
#define TPMA_PERMANENT_LOCKOUTAUTHSET       0x00000004
#define TPMA_PERMANENT_RESERVED1        0x000000f8
#define TPMA_PERMANENT_DISABLECLEAR     0x00000100
#define TPMA_PERMANENT_INLOCKOUT        0x00000200
#define TPMA_PERMANENT_TPMGENERATEDEPS      0x00000400
#define TPMA_PERMANENT_RESERVED2        0xfffff800

#endif

/* Table 34 - Definition of (UINT32) TPMA_STARTUP_CLEAR Bits <OUT> */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
    int phEnable        : 1;    /* 0 The platform hierarchy is enabled and platformAuth or platformPolicy may be used for authorization. */
    int shEnable        : 1;    /* 1 The Storage hierarchy is enabled and ownerAuth or ownerPolicy may be used for authorization. */
    int ehEnable        : 1;    /* 2 The EPS hierarchy is enabled and endorsementAuth may be used to authorize commands. */
    int phEnableNV      : 1;    /* 3 NV indices that have TPMA_PLATFORM_CREATE SET may be read or written.  */
    int Reserved        : 27;   /* 30:4 shall be zero */
    int orderly     : 1;    /* 31 The TPM received a TPM2_Shutdown() and a matching TPM2_Startup(). */
    };
    UINT32 val;
} TPMA_STARTUP_CLEAR;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
    int orderly     : 1;    /* 31 The TPM received a TPM2_Shutdown() and a matching TPM2_Startup(). */
    int Reserved        : 27;   /* 30:4 shall be zero */
    int phEnableNV      : 1;    /* 3 NV indices that have TPMA_PLATFORM_CREATE SET may be read or written.  */
    int ehEnable        : 1;    /* 2 The EPS hierarchy is enabled and endorsementAuth may be used to authorize commands. */
    int shEnable        : 1;    /* 1 The Storage hierarchy is enabled and ownerAuth or ownerPolicy may be used for authorization. */
    int phEnable        : 1;    /* 0 The platform hierarchy is enabled and platformAuth or platformPolicy may be used for authorization. */
    };
    UINT32 val;
} TPMA_STARTUP_CLEAR;

#else 

typedef uint32_t TPMA_STARTUP_CLEAR;

#define TPMA_STARTUP_CLEAR_PHENABLE     0x00000001
#define TPMA_STARTUP_CLEAR_SHENABLE     0x00000002
#define TPMA_STARTUP_CLEAR_EHENABLE     0x00000004
#define TPMA_STARTUP_CLEAR_PHENABLENV       0x00000008
#define TPMA_STARTUP_CLEAR_RESERVED     0x7ffffff0
#define TPMA_STARTUP_CLEAR_ORDERLY      0x80000000

#endif

/* Table 35 - Definition of (UINT32) TPMA_MEMORY Bits <Out> */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
    int sharedRAM       : 1;    /* 0    RAM memory used for authorization session contexts is shared with the memory used for transient objects */
    int sharedNV        : 1;    /* 1    indicates that the NV memory used for persistent objects is shared with the NV memory used for NV Index values */
    int objectCopiedToRam   : 1;    /* 2    indicates that the TPM copies persistent objects to a transient-object slot in RAM */
    int Reserved        : 29;   /* 31:3 shall be zero */
    };
    UINT32 val;
} TPMA_MEMORY;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
    int Reserved        : 29;   /* 31:3 shall be zero */
    int objectCopiedToRam   : 1;    /* 2    indicates that the TPM copies persistent objects to a transient-object slot in RAM */
    int sharedNV        : 1;    /* 1    indicates that the NV memory used for persistent objects is shared with the NV memory used for NV Index values */
    int sharedRAM       : 1;    /* 0    RAM memory used for authorization session contexts is shared with the memory used for transient objects */
    };
    UINT32 val;
} TPMA_MEMORY;

#else 

typedef uint32_t TPMA_MEMORY;

#define TPMA_MEMORY_SHAREDRAM       0x00000001
#define TPMA_MEMORY_SHAREDNV        0x00000002
#define TPMA_MEMORY_OBJECTCOPIEDTORAM   0x00000004
#define TPMA_MEMORY_RESERVED        0xfffffff8

#endif

/* Table 36 - Definition of (TPM_CC) TPMA_CC Bits <OUT> */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
    int commandIndex : 16;  /* 15:0 indicates the command being selected */
    int Reserved    : 6;    /* 21:16 shall be zero */
    int nv      : 1;    /* 22 indicates that the command may write to NV */
    int extensive   : 1;    /* 23 This command could flush any number of loaded contexts. */
    int flushed : 1;    /* 24 The context associated with any transient handle in the command will be flushed when this command completes. */
    int cHandles    : 3;    /* 27:25 indicates the number of the handles in the handle area for this command */
    int rHandle : 1;    /* 28 indicates the presence of the handle area in the input */
    int V       : 1;    /* 29 indicates that the command is vendor-specific */
    int Res     : 2;    /* 31:30    allocated for software; shall be zero */
    };
    UINT32 val;
} TPMA_CC;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
    int Res     : 2;    /* 31:30    allocated for software; shall be zero */
    int V       : 1;    /* 29 indicates that the command is vendor-specific */
    int rHandle : 1;    /* 28 indicates the presence of the handle area in the input */
    int cHandles    : 3;    /* 27:25 indicates the number of the handles in the handle area for this command */
    int flushed : 1;    /* 24 The context associated with any transient handle in the command will be flushed when this command completes. */
    int extensive   : 1;    /* 23 This command could flush any number of loaded contexts. */
    int nv      : 1;    /* 22 indicates that the command may write to NV */
    int Reserved    : 6;    /* 21:16 shall be zero */
    int commandIndex : 16;  /* 15:0 indicates the command being selected */
    };
    UINT32 val;
} TPMA_CC;

#else

typedef uint32_t TPMA_CC;

#define TPMA_CC_COMMANDINDEX    0x0000ffff
#define TPMA_CC_RESERVED    0x003f0000
#define TPMA_CC_NV      0x00400000
#define TPMA_CC_EXTENSIVE   0x00800000
#define TPMA_CC_FLUSHED     0x01000000
#define TPMA_CC_CHANDLES    0x0e000000
#define TPMA_CC_RHANDLE     0x10000000
#define TPMA_CC_V       0x20000000
#define TPMA_CC_RES     0xc0000000

#endif

/* Table 37 - Definition of (BYTE) TPMI_YES_NO Type */

typedef BYTE TPMI_YES_NO;

#define NO  0
#define YES 1   

#if 0
if (
    (x != NO) &&
    (x != YES)
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 38 - Definition of (TPM_HANDLE) TPMI_DH_OBJECT Type */

typedef TPM_HANDLE TPMI_DH_OBJECT;

#if 0
if (
    (x < TRANSIENT_FIRST) || (x > TRANSIENT_LAST) &&
    (x < PERSISTENT_FIRST) || (x > PERSISTENT_LAST) &&
    ((x != TPM_RH_NULL) && allow)
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 39 - Definition of (TPM_HANDLE) TPMI_DH_PERSISTENT Type */

typedef TPM_HANDLE TPMI_DH_PERSISTENT;

#if 0
if (
    (x < PERSISTENT_FIRST) || (x > PERSISTENT_LAST)
    ) {
    rc = TPM_RC_VALUE;
}
#endif

/* Table 40 - Definition of (TPM_HANDLE) TPMI_DH_ENTITY Type <IN> */

typedef TPM_HANDLE TPMI_DH_ENTITY;

#if 0
if (
    (x != TPM_RH_OWNER      ) &&
    (x != TPM_RH_ENDORSEMENT        ) &&
    (x != TPM_RH_PLATFORM       ) &&
    (x != TPM_RH_LOCKOUT        ) &&
    (x < TRANSIENT_FIRST) || (x > TRANSIENT_LAST) &&
    (x < PERSISTENT_FIRST) || (x > PERSISTENT_LAST) &&
    (x < NV_INDEX_FIRST ) || (x > NV_INDEX_LAST) &&
    (x < PCR_FIRST ) || (x > PCR_LAST) &&
    ((x != TPM_RH_NULL) || !allow)
    ) {
    rc = TPM_RC_VALUE;
}
#endif

/* Table 41 - Definition of (TPM_HANDLE) TPMI_DH_PCR Type <IN> */

typedef TPM_HANDLE TPMI_DH_PCR;

#if 0
if (
    (x < PCR_FIRST ) || (x > PCR_LAST) &&
    ((x != TPM_RH_NULL) || !allow)
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 42 - Definition of (TPM_HANDLE) TPMI_SH_AUTH_SESSION Type <IN/OUT> */

typedef TPM_HANDLE TPMI_SH_AUTH_SESSION;

#if 0
if (
    (x < HMAC_SESSION_FIRST ) || (x > HMAC_SESSION_LAST) &&
    (x < POLICY_SESSION_FIRST) || (x > POLICY_SESSION_LAST) &&
    ((x != TPM_RS_PW) || !allow)
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 43 - Definition of (TPM_HANDLE) TPMI_SH_HMAC Type <IN/OUT> */

typedef TPM_HANDLE TPMI_SH_HMAC;

#if 0
if (
    (x < HMAC_SESSION_FIRST ) || (x > HMAC_SESSION_LAST)
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 44 - Definition of (TPM_HANDLE) TPMI_SH_POLICY Type <IN/OUT> */

typedef TPM_HANDLE TPMI_SH_POLICY;

#if 0
if (
    (x < POLICY_SESSION_FIRST) || (x > POLICY_SESSION_LAST)
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 45 - Definition of (TPM_HANDLE) TPMI_DH_CONTEXT Type  */

typedef TPM_HANDLE TPMI_DH_CONTEXT;

#if 0
if (
    (x < HMAC_SESSION_FIRST ) || (x > HMAC_SESSION_LAST) &&
    (x < POLICY_SESSION_FIRST) || (x > POLICY_SESSION_LAST) &&
    (x < TRANSIENT_FIRST) || (x > TRANSIENT_LAST) &&
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 46 - Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY Type  */

typedef TPM_HANDLE TPMI_RH_HIERARCHY;

#if 0
if (
   (x != TPM_RH_OWNER       ) &&
   (x != TPM_RH_PLATFORM    ) &&
   (x != TPM_RH_ENDORSEMENT ) &&
   ((x != TPM_RH_NULL) || !allow)
   ) {
    rc = TPM_RC_VALUE;
}
#endif

/* Table 47 - Definition of (TPM_HANDLE) TPMI_RH_ENABLES Type */

typedef TPM_HANDLE TPMI_RH_ENABLES;

#if 0
if (
    (x != TPM_RH_OWNER      ) &&
    (x != TPM_RH_PLATFORM   ) &&
    (x != TPM_RH_ENDORSEMENT    ) &&
    (x != TPM_RH_PLATFORM_NV    ) &&
    ((x != TPM_RH_NULL) || !allow)
    ) {
    rc = TPM_RC_VALUE;
 }
#endif


/* Table 48 - Definition of (TPM_HANDLE) TPMI_RH_HIERARCHY_AUTH Type <IN> */

typedef TPM_HANDLE TPMI_RH_HIERARCHY_AUTH;

#if 0
if (
   (x != TPM_RH_OWNER       ) &&
   (x != TPM_RH_PLATFORM    ) &&
   (x != TPM_RH_ENDORSEMENT ) &&
   (x != TPM_RH_LOCKOUT     ) &&
   ) {
    rc = TPM_RC_VALUE;
}
#endif

/* Table 49 - Definition of (TPM_HANDLE) TPMI_RH_PLATFORM Type <IN> */

typedef TPM_HANDLE TPMI_RH_PLATFORM;

#if 0
if (
    (x != TPM_RH_PLATFORM       ) 
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 50 - Definition of (TPM_HANDLE) TPMI_RH_OWNER Type <IN> */

typedef TPM_HANDLE TPMI_RH_OWNER;

#if 0
if (
    (x != TPM_RH_OWNER      ) &&
    ((x != TPM_RH_NULL) || !allow)
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 51 - Definition of (TPM_HANDLE) TPMI_RH_ENDORSEMENT Type <IN> */

typedef TPM_HANDLE TPMI_RH_ENDORSEMENT;

#if 0
if (
    (x != TPM_RH_ENDORSEMENT    ) &&
    ((x != TPM_RH_NULL) || !allow)
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 52 - Definition of (TPM_HANDLE) TPMI_RH_PROVISION Type <IN> */

typedef TPM_HANDLE TPMI_RH_PROVISION;

#if 0
if (
    (x != TPM_RH_OWNER      ) &&
    (x != TPM_RH_PLATFORM       )
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 53 - Definition of (TPM_HANDLE) TPMI_RH_CLEAR Type <IN> */

typedef TPM_HANDLE TPMI_RH_CLEAR;

#if 0
if (
    (x != TPM_RH_PLATFORM       ) &&
    (x != TPM_RH_LOCKOUT        )
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 54 - Definition of (TPM_HANDLE) TPMI_RH_NV_AUTH Type <IN> */

typedef TPM_HANDLE TPMI_RH_NV_AUTH;

#if 0
if (
    (x != TPM_RH_PLATFORM       ) &&
    (x != TPM_RH_OWNER  ) &&
    (x < NV_INDEX_FIRST ) || (x > NV_INDEX_LAST)
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 55 - Definition of (TPM_HANDLE) TPMI_RH_LOCKOUT Type <IN> */

typedef TPM_HANDLE TPMI_RH_LOCKOUT;

#if 0
if (
   (x != TPM_RH_LOCKOUT     )
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 56 - Definition of (TPM_HANDLE) TPMI_RH_NV_INDEX Type <IN/OUT> */

typedef TPM_HANDLE TPMI_RH_NV_INDEX;

#if 0
if (
    (x < NV_INDEX_FIRST ) || (x > NV_INDEX_LAST)
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 57 - Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type  */

typedef TPM_ALG_ID TPMI_ALG_HASH;

#if 0
if (
    (x != TPM_ALG_SHA1      ) &&
    (x != TPM_ALG_SHA256    ) &&
    (x != TPM_ALG_SM3_256   ) &&
    (x != TPM_ALG_SHA384    ) &&
    (x != TPM_ALG_SHA512    ) &&
    ((x != TPM_ALG_NULL) || !allow)
    ) {
    rc = TPM_RC_HASH;
 }
#endif

/* Table 58 - Definition of (TPM_ALG_ID) TPMI_ALG_ASYM Type */

typedef TPM_ALG_ID TPMI_ALG_ASYM;

#if 0
if (
    (x != TPM_ALG_RSA       ) &&
    (x != TPM_ALG_ECC       ) &&
    ((x != TPM_ALG_NULL) || !allow)
    ) {
    rc = TPM_RC_ASYMMETRIC;
 }
#endif

/* Table 59 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM Type */

typedef TPM_ALG_ID TPMI_ALG_SYM;

#if 0
if (
    (x != TPM_ALG_AES   ) &&
    (x != TPM_ALG_SM4   ) &&
    (x != TPM_ALG_XOR   ) &&
    ((x != TPM_ALG_NULL) || !allow)
    ) {
    rc = TPM_RC_SYMMETRIC;
 }
#endif

/* Table 60 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_OBJECT Type */

typedef TPM_ALG_ID TPMI_ALG_SYM_OBJECT;

#if 0
if (
    (x != TPM_ALG_AES   ) &&
    (x != TPM_ALG_SM4   ) &&
    ((x != TPM_ALG_NULL) || !allow)
    ) {
    rc = TPM_RC_SYMMETRIC;
}
#endif

/* Table 61 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_MODE Type */

typedef TPM_ALG_ID TPMI_ALG_SYM_MODE;

#if 0
if (
    (x != TPM_ALG_CTR   ) &&
    (x != TPM_ALG_OFB   ) &&
    (x != TPM_ALG_CBC   ) &&
    (x != TPM_ALG_CFB   ) &&
    (x != TPM_ALG_ECB   ) &&
    ((x != TPM_ALG_NULL) || !allow)
    ) {
    rc = TPM_RC_MODE;
}
#endif

/* Table 62 - Definition of (TPM_ALG_ID) TPMI_ALG_KDF Type */

typedef TPM_ALG_ID TPMI_ALG_KDF;

#if 0
if (
    (x != TPM_ALG_MGF1          ) &&
    (x != TPM_ALG_KDF1_SP800_108    ) &&
    (x != TPM_ALG_KDF1_SP800_56a    ) &&
    (x != TPM_ALG_KDF2          ) &&
    ((x != TPM_ALG_NULL) || !allow)
    ) {
    rc = TPM_RC_KDF;
 }
#endif

/* Table 63 - Definition of (TPM_ALG_ID) TPMI_ALG_SIG_SCHEME Type */

typedef TPM_ALG_ID TPMI_ALG_SIG_SCHEME;

#if 0
if (
    (x != TPM_ALG_RSASSA    ) &&
    (x != TPM_ALG_RSAPSS    ) &&
    (x != TPM_ALG_ECDSA     ) &&
    (x != TPM_ALG_ECDAA     ) &&
    (x != TPM_ALG_ECSCHNORR ) &&
    (x != TPM_ALG_SM2       ) &&
    (x != TPM_ALG_HMAC      ) &&
    ((x != TPM_ALG_NULL) || !allow)
    ) {
    rc = TPM_RC_SCHEME;
 }
#endif

/* Table 64 - Definition of (TPM_ALG_ID) TPMI_ECC_KEY_EXCHANGE Type */

typedef TPM_ALG_ID TPMI_ECC_KEY_EXCHANGE;

#if 0
if (
    (x != TPM_ALG_ECDH  ) &&
    (x != TPM_ALG_ECMQV ) &&
    (x != TPM_ALG_SM2   ) &&
    ((x != TPM_ALG_NULL) || !allow)
    ) {
    rc = TPM_RC_SCHEME;
 }
#endif

/* Table 65 - Definition of (TPM_ST) TPMI_ST_COMMAND_TAG Type */

typedef TPM_ST TPMI_ST_COMMAND_TAG;

#if 0
if (
    (x != TPM_ST_NO_SESSIONS    ) &&
    (x != TPM_ST_SESSIONS   ) &&
    ) {
    rc = TPM_RC_BAD_TAG;
 }
#endif

/* Table 67 - Definition of TPMS_ALGORITHM_DESCRIPTION Structure <OUT> */
typedef struct {
    TPM_ALG_ID      alg;        /* an algorithm */
    TPMA_ALGORITHM  attributes; /* the attributes of the algorithm */
} TPMS_ALGORITHM_DESCRIPTION;

/* Table 68 - Definition of TPMU_HA Union <IN/OUT, S> */

typedef union {
    BYTE    sha1 [SHA1_DIGEST_SIZE];    /* TPM_ALG_SHA1 */
    BYTE    sha256 [SHA256_DIGEST_SIZE];    /* TPM_ALG_SHA256 */
    BYTE    sm3_256 [SM3_256_DIGEST_SIZE];  /* TPM_ALG_SM3_256 */
    BYTE    sha384 [SHA384_DIGEST_SIZE];    /* TPM_ALG_SHA384 */
    BYTE    sha512 [SHA512_DIGEST_SIZE];    /* TPM_ALG_SHA512 */
} TPMU_HA;

/* Table 69 - Definition of TPMT_HA Structure <IN/OUT> */

typedef struct {
    TPMI_ALG_HASH   hashAlg;    /* selector of the hash contained in the digest that implies the size of the digest */
    TPMU_HA     digest;     /* the digest data */
} TPMT_HA;

/* Table 70 - Definition of TPM2B_DIGEST Structure */
typedef struct {
    UINT16    size;
    BYTE      buffer[sizeof(TPMU_HA)];
} DIGEST_2B;

typedef union {
    DIGEST_2B    t;
    TPM2B        b;
} TPM2B_DIGEST;

/* Table 71 - Definition of TPM2B_DATA Structure */

typedef struct {
    UINT16  size;               /* size in octets of the buffer field; may be 0 */
    BYTE    buffer[sizeof(TPMT_HA)];    /* the buffer area that contains the algorithm ID and the digest */
} DATA_2B;

typedef union {
    DATA_2B t;
    TPM2B   b;
} TPM2B_DATA;

/* Table 72 - Definition of Types for TPM2B_NONCE */

typedef TPM2B_DIGEST    TPM2B_NONCE;    /* size limited to the same as the digest structure */

/* Table 73 - Definition of Types for TPM2B_AUTH */

typedef TPM2B_DIGEST    TPM2B_AUTH; /* size limited to the same as the digest structure */

/* Table 74 - Definition of Types for TPM2B_OPERAND */

typedef TPM2B_DIGEST    TPM2B_OPERAND;  /* size limited to the same as the digest structure */

/* Table 75 - Definition of TPM2B_EVENT Structure */

typedef struct {
    UINT16  size;           /* size of the operand */
    BYTE    buffer [1024];      /* the operand */
} EVENT_2B;

typedef union {
    EVENT_2B t;
    TPM2B    b;
} TPM2B_EVENT;

/* Table 76 - Definition of TPM2B_MAX_BUFFER Structure */

/* MAX_DIGEST_BUFFER is TPM-dependent but is required to be at least 1,024. */

#define MAX_DIGEST_BUFFER 1024

typedef struct {
    UINT16  size;               /* size of the buffer */
    BYTE    buffer [MAX_DIGEST_BUFFER]; /* the operand  */
} MAX_BUFFER_2B;

typedef union {
    MAX_BUFFER_2B t;
    TPM2B         b;
} TPM2B_MAX_BUFFER;

/* Table 77 - Definition of TPM2B_MAX_NV_BUFFER Structure */

typedef struct {
    UINT16  size;               /* size of the buffer */
    BYTE    buffer [MAX_NV_INDEX_SIZE]; /* the operand  */
} MAX_NV_BUFFER_2B;

typedef union {
    MAX_NV_BUFFER_2B t;
    TPM2B            b;
} TPM2B_MAX_NV_BUFFER;

/* Table 78 - Definition of TPM2B_TIMEOUT Structure <IN/OUT> */

typedef struct {
    UINT16  size;               /* size of the timeout value */
    BYTE    buffer [sizeof(UINT64)];    /* the timeout value */
} TIMEOUT_2B;

typedef union {
    TIMEOUT_2B t;
    TPM2B      b;
} TPM2B_TIMEOUT;

/* Table 79 - Definition of TPM2B_IV Structure <IN/OUT> */

typedef struct {
    UINT16  size;       /* size of the timeout value */
    BYTE    buffer [MAX_SYM_BLOCK_SIZE];    /* the timeout value */
} IV_2B;

typedef union {
    IV_2B t;
    TPM2B b;
} TPM2B_IV;

/* Table 80 - Definition of TPMU_NAME Union <> */

typedef union {
    TPMT_HA digest;     /* when the Name is a digest */
    TPM_HANDLE  handle;     /* when the Name is a handle */
} TPMU_NAME;

/* Table 81 - Definition of TPM2B_NAME Structure */

typedef struct {
    UINT16  size;               /* size of the Name structure */
    BYTE    name[sizeof(TPMU_NAME)];    /* the Name structure */
} NAME_2B;

typedef union {
    NAME_2B t;
    TPM2B   b;
} TPM2B_NAME;

/* Table 82 - Definition of TPMS_PCR_SELECT Structure */

typedef struct {
    UINT8   sizeofSelect;           /* the size in octets of the pcrSelect array */
    BYTE    pcrSelect [PCR_SELECT_MAX]; /* the bit map of selected PCR */
} TPMS_PCR_SELECT;

/* Table 83 - Definition of TPMS_PCR_SELECTION Structure */

typedef struct {
    TPMI_ALG_HASH   hash;               /* the hash algorithm associated with the selection */
    UINT8       sizeofSelect;           /* the size in octets of the pcrSelect array */
    BYTE        pcrSelect [PCR_SELECT_MAX]; /* the bit map of selected PCR */
} TPMS_PCR_SELECTION;

/* Table 86 - Definition of TPMT_TK_CREATION Structure */

typedef struct {
    TPM_ST      tag;        /*  ticket structure tag TPM_ST_CREATION */
    TPMI_RH_HIERARCHY   hierarchy;  /* the hierarchy containing name */
    TPM2B_DIGEST    digest;     /* This shall be the HMAC produced using a proof value of hierarchy. */
} TPMT_TK_CREATION;

/* Table 87 - Definition of TPMT_TK_VERIFIED Structure */

typedef struct {
    TPM_ST      tag;        /* ticket structure tag TPM_ST_VERIFIED*/
    TPMI_RH_HIERARCHY   hierarchy;  /* the hierarchy containing keyName */
    TPM2B_DIGEST    digest;     /* This shall be the HMAC produced using a proof value of hierarchy. */
} TPMT_TK_VERIFIED;

/* Table 88 - Definition of TPMT_TK_AUTH Structure */

typedef struct {
    TPM_ST      tag;        /* ticket structure tag TPM_ST_AUTH_SIGNED, TPM_ST_AUTH_SECRET*/
    TPMI_RH_HIERARCHY   hierarchy;  /* the hierarchy of the object used to produce the ticket */
    TPM2B_DIGEST    digest;     /* This shall be the HMAC produced using a proof value of hierarchy. */
} TPMT_TK_AUTH;

/* Table 89 - Definition of TPMT_TK_HASHCHECK Structure */

typedef struct {
    TPM_ST      tag;        /* ticket structure tag TPM_ST_HASHCHECK */
    TPMI_RH_HIERARCHY   hierarchy;  /* the hierarchy */
    TPM2B_DIGEST    digest;     /* This shall be the HMAC produced using a proof value of hierarchy. */
} TPMT_TK_HASHCHECK;

/* Table 90 - Definition of TPMS_ALG_PROPERTY Structure <OUT> */

typedef struct {
    TPM_ALG_ID      alg;        /* an algorithm identifier */
    TPMA_ALGORITHM  algProperties;  /* the attributes of the algorithm */
} TPMS_ALG_PROPERTY;

/* Table 91 - Definition of TPMS_TAGGED_PROPERTY Structure <OUT> */

typedef struct {
    TPM_PT  property;   /* a property identifier */
    UINT32  value;      /* the value of the property */
} TPMS_TAGGED_PROPERTY;

/* Table 92 - Definition of TPMS_TAGGED_PCR_SELECT Structure <OUT> */

typedef struct {
    TPM_PT  tag;                /* the property identifier */
    UINT8   sizeofSelect;           /* the size in octets of the pcrSelect array */
    BYTE    pcrSelect [PCR_SELECT_MAX]; /* the bit map of PCR with the identified property */
} TPMS_TAGGED_PCR_SELECT;

/* Table 93 - Definition of TPML_CC Structure */

typedef struct {
    UINT32  count;              /* number of commands in the commandCode list; may be 0 */
    TPM_CC  commandCodes[MAX_CAP_CC];   /* a list of command codes */
} TPML_CC;

/* Table 94 - Definition of TPML_CCA Structure <OUT> */

typedef struct {
    UINT32  count;              /* number of values in the commandAttributes list; may be 0 */
    TPMA_CC commandAttributes[MAX_CAP_CC];  /* a list of command codes attributes */
} TPML_CCA;

/* Table 95 - Definition of TPML_ALG Structure */

typedef struct {
    UINT32  count;              /* number of algorithms in the algorithms list; may be 0 */
    TPM_ALG_ID  algorithms[MAX_ALG_LIST_SIZE];  /* a list of algorithm IDs */
} TPML_ALG;

/* Table 96 - Definition of TPML_HANDLE Structure <OUT> */

typedef struct {
    UINT32  count;              /* the number of handles in the list may have a value of 0 */
    TPM_HANDLE  handle[MAX_CAP_HANDLES];    /* an array of handles */
} TPML_HANDLE;


/* Table 97 - Definition of TPML_DIGEST Structure */

typedef struct {
    UINT32      count;      /* number of digests in the list, minimum is two for TPM2_PolicyOR(). */
    TPM2B_DIGEST    digests[8]; /* a list of digests */
} TPML_DIGEST;

/* Table 98 - Definition of TPML_DIGEST_VALUES Structure */

typedef struct {
    UINT32  count;          /* number of digests in the list */
    TPMT_HA digests[HASH_COUNT];    /* a list of tagged digests */
} TPML_DIGEST_VALUES;

/* Table 99 - Definition of TPM2B_DIGEST_VALUES Structure */

typedef struct {
    UINT16  size;                   /* size of the operand buffer */
    BYTE    buffer [sizeof(TPML_DIGEST_VALUES)];    /* the operand */
} TPM2B_DIGEST_VALUES;

/* Table 100 - Definition of TPML_PCR_SELECTION Structure */

typedef struct {
    UINT32      count;              /* number of selection structures A value of zero is allowed. */
    TPMS_PCR_SELECTION  pcrSelections[HASH_COUNT];  /* list of selections */
} TPML_PCR_SELECTION;

/* Table 101 - Definition of TPML_ALG_PROPERTY Structure <OUT> */

typedef struct {
    UINT32      count;              /* number of algorithm properties structures A value of zero is allowed. */
    TPMS_ALG_PROPERTY   algProperties[MAX_CAP_ALGS];    /* list of properties */
} TPML_ALG_PROPERTY;

/* Table 102 - Definition of TPML_TAGGED_TPM_PROPERTY Structure <OUT> */

typedef struct {
    UINT32          count;                  /* number of properties A value of zero is allowed. */
    TPMS_TAGGED_PROPERTY    tpmProperty[MAX_TPM_PROPERTIES];    /* an array of tagged properties */
} TPML_TAGGED_TPM_PROPERTY;

/* Table 103 - Definition of TPML_TAGGED_PCR_PROPERTY Structure <OUT> */

typedef struct {
    UINT32          count;                  /* number of properties A value of zero is allowed. */
    TPMS_TAGGED_PCR_SELECT  pcrProperty[MAX_PCR_PROPERTIES];    /* a tagged PCR selection */
} TPML_TAGGED_PCR_PROPERTY;

/* Table 104 - Definition of {ECC} TPML_ECC_CURVE Structure <OUT> */

typedef struct {
    UINT32      count;              /* number of curves A value of zero is allowed. */
    TPM_ECC_CURVE   eccCurves[MAX_ECC_CURVES];  /* array of ECC curve identifiers */
} TPML_ECC_CURVE ;

/* Table 105 - Definition of TPMU_CAPABILITIES Union <OUT> */

typedef union {
    TPML_ALG_PROPERTY       algorithms; /* TPM_CAP_ALGS */
    TPML_HANDLE         handles;    /* TPM_CAP_HANDLES */
    TPML_CCA            command;    /* TPM_CAP_COMMANDS */
    TPML_CC         ppCommands; /* TPM_CAP_PP_COMMANDS */
    TPML_CC         auditCommands;  /* TPM_CAP_AUDIT_COMMANDS */
    TPML_PCR_SELECTION      assignedPCR;    /* TPM_CAP_PCRS */
    TPML_TAGGED_TPM_PROPERTY    tpmProperties;  /* TPM_CAP_TPM_PROPERTIES */
    TPML_TAGGED_PCR_PROPERTY    pcrProperties;  /* TPM_CAP_PCR_PROPERTIES */
    TPML_ECC_CURVE      eccCurves;  /* TPM_CAP_ECC_CURVES   TPM_ALG_ECC */
} TPMU_CAPABILITIES;
    
/* Table 106 - Definition of TPMS_CAPABILITY_DATA Structure <OUT> */

typedef struct {
    TPM_CAP     capability; /* the capability */
    TPMU_CAPABILITIES   data;       /* the capability data */
} TPMS_CAPABILITY_DATA;

/* Table 107 - Definition of TPMS_CLOCK_INFO Structure */

typedef struct {
    UINT64  clock;      /* time in milliseconds during which the TPM has been powered */
    UINT32  resetCount; /* number of occurrences of TPM Reset since the last TPM2_Clear() */
    UINT32  restartCount;   /* number of times that TPM2_Shutdown() or _TPM_Hash_Start have occurred since the last TPM Reset or TPM2_Clear(). */
    TPMI_YES_NO safe;       /* no value of Clock greater than the current value of Clock has been previously reported by the TPM */
} TPMS_CLOCK_INFO;

/* Table 108 - Definition of TPMS_TIME_INFO Structure */

typedef struct {
    UINT64      time;   /*  time in milliseconds since the last _TPM_Init() or TPM2_Startup() */
    TPMS_CLOCK_INFO clockInfo;  /* a structure containing the clock information */
} TPMS_TIME_INFO;

/* Table 109 - Definition of TPMS_TIME_ATTEST_INFO Structure <OUT> */

typedef struct {
    TPMS_TIME_INFO  time;           /* the Time, clock, resetCount, restartCount, and Safe indicator */
    UINT64      firmwareVersion;    /* a vendor-specific value indicating the version number of the firmware */
} TPMS_TIME_ATTEST_INFO;

/* Table 110 - Definition of TPMS_CERTIFY_INFO Structure <OUT> */

typedef struct {
    TPM2B_NAME  name;       /* Name of the certified object */
    TPM2B_NAME  qualifiedName;  /* Qualified Name of the certified object */
} TPMS_CERTIFY_INFO;

/* Table 111 - Definition of TPMS_QUOTE_INFO Structure <OUT> */

typedef struct {
    TPML_PCR_SELECTION  pcrSelect;  /* information on algID, PCR selected and digest */
    TPM2B_DIGEST    pcrDigest;  /* digest of the selected PCR using the hash of the signing key */
} TPMS_QUOTE_INFO;

/* Table 112 - Definition of TPMS_COMMAND_AUDIT_INFO Structure <OUT> */

typedef struct {
    UINT64      auditCounter;   /* the monotonic audit counter */
    TPM_ALG_ID      digestAlg;  /* hash algorithm used for the command audit */
    TPM2B_DIGEST    auditDigest;    /* the current value of the audit digest */
    TPM2B_DIGEST    commandDigest;  /* digest of the command codes being audited using digestAlg */
} TPMS_COMMAND_AUDIT_INFO;

/* Table 113 - Definition of TPMS_SESSION_AUDIT_INFO Structure <OUT> */

typedef struct {
    TPMI_YES_NO     exclusiveSession;   /* current exclusive status of the session  */
    TPM2B_DIGEST    sessionDigest;      /* the current value of the session audit digest */
} TPMS_SESSION_AUDIT_INFO;

/* Table 114 - Definition of TPMS_CREATION_INFO Structure <OUT> */

typedef struct {
    TPM2B_NAME      objectName; /* Name of the object */
    TPM2B_DIGEST    creationHash;   /* creationHash */
} TPMS_CREATION_INFO;

/* Table 115 - Definition of TPMS_NV_CERTIFY_INFO Structure <OUT> */

typedef struct {
    TPM2B_NAME      indexName;  /* Name of the NV Index */
    UINT16      offset;     /* the offset parameter of TPM2_NV_Certify() */
    TPM2B_MAX_NV_BUFFER nvContents; /* contents of the NV Index */
} TPMS_NV_CERTIFY_INFO;

/* Table 116 - Definition of (TPM_ST) TPMI_ST_ATTEST Type <OUT> */

typedef TPM_ST TPMI_ST_ATTEST;

/*  Table 117 - Definition of TPMU_ATTEST Union <OUT> */

typedef union {
    TPMS_CERTIFY_INFO       certify;    /* TPM_ST_ATTEST_CERTIFY */
    TPMS_CREATION_INFO      creation;   /* TPM_ST_ATTEST_CREATION */
    TPMS_QUOTE_INFO     quote;      /* TPM_ST_ATTEST_QUOTE */
    TPMS_COMMAND_AUDIT_INFO commandAudit;   /* TPM_ST_ATTEST_COMMAND_AUDIT */
    TPMS_SESSION_AUDIT_INFO sessionAudit;   /* TPM_ST_ATTEST_SESSION_AUDIT */
    TPMS_TIME_ATTEST_INFO   time;       /* TPM_ST_ATTEST_TIME */
    TPMS_NV_CERTIFY_INFO    nv;     /* TPM_ST_ATTEST_NV */
} TPMU_ATTEST;

/* Table 118 - Definition of TPMS_ATTEST Structure <OUT> */

typedef struct {
    TPM_GENERATED   magic;          /* the indication that this structure was created by a TPM (always TPM_GENERATED_VALUE) */
    TPMI_ST_ATTEST  type;           /* type of the attestation structure */
    TPM2B_NAME      qualifiedSigner;    /* Qualified Name of the signing key */
    TPM2B_DATA      extraData;      /* external information supplied by caller */
    TPMS_CLOCK_INFO clockInfo;      /* Clock, resetCount, restartCount, and Safe */
    UINT64      firmwareVersion;    /* TPM-vendor-specific field identifying the firmware on the TPM */
    TPMU_ATTEST     attested;       /* the type-specific attestation information */
} TPMS_ATTEST;

/* Table 119 - Definition of TPM2B_ATTEST Structure <OUT> */

typedef struct {
    UINT16  size;                   /* size of the attestationData structure */
    BYTE    attestationData[sizeof(TPMS_ATTEST)];   /* the signed structure */
} ATTEST_2B;

typedef union {
    ATTEST_2B t;
    TPM2B     b;
} TPM2B_ATTEST;

/* Table 120 - Definition of TPMS_AUTH_COMMAND Structure <IN> */

typedef struct {
    TPMI_SH_AUTH_SESSION    sessionHandle;      /* the session handle */
    TPM2B_NONCE         nonce;          /* the session nonce, may be the Empty Buffer */
    TPMA_SESSION        sessionAttributes;  /* the session attributes */
    TPM2B_AUTH          hmac;           /* either an HMAC, a password, or an EmptyAuth */
} TPMS_AUTH_COMMAND;

/* Table 121 - Definition of TPMS_AUTH_RESPONSE Structure <OUT> */

typedef struct {
    TPM2B_NONCE     nonce;          /* the session nonce, may be the Empty Buffer */
    TPMA_SESSION    sessionAttributes;  /* the session attributes */
    TPM2B_AUTH      hmac;           /* either an HMAC, a password, or an EmptyAuth */
} TPMS_AUTH_RESPONSE;

/* Table 122 - Definition of {AES} (TPM_KEY_BITS) TPMI_AES_KEY_BITS Type */

typedef TPM_KEY_BITS TPMI_AES_KEY_BITS;

/* Table 123 - Definition of {SM4} (TPM_KEY_BITS) TPMI_SM4_KEY_BITS Type */

typedef TPM_KEY_BITS TPMI_SM4_KEY_BITS;

/* Table 124 - Definition of TPMU_SYM_KEY_BITS Union */

typedef union {
    TPMI_AES_KEY_BITS   aes;    /* TPM_ALG_AES */
    TPMI_SM4_KEY_BITS   SM4;    /* TPM_ALG_SM4 */
    TPM_KEY_BITS    sym;    /* when selector may be any of the symmetric block ciphers */
    TPMI_ALG_HASH   exclusiveOr;    /* TPM_ALG_XOR  overload for using xor */
} TPMU_SYM_KEY_BITS;

/* Table 125 - Definition of TPMU_SYM_MODE Union */

typedef union {
    TPMI_ALG_SYM_MODE   aes;    /* TPM_ALG_AES  NOTE    TPM_ALG_NULL is not allowed */
    TPMI_ALG_SYM_MODE   SM4;    /* TPM_ALG_SM4  NOTE    TPM_ALG_NULL is not allowed */
    TPMI_ALG_SYM_MODE   sym;    /* when selector may be any of the symmetric block ciphers */
} TPMU_SYM_MODE;

/* Table 126 - xDefinition of TPMU_SYM_DETAILS Union    */

/* Table 127 - Definition of TPMT_SYM_DEF Structure */

typedef struct {
    TPMI_ALG_SYM    algorithm;  /* indicates a symmetric algorithm */
    TPMU_SYM_KEY_BITS   keyBits;    /* a supported key size */
    TPMU_SYM_MODE   mode;       /* the mode for the key */
} TPMT_SYM_DEF;

/* Table 128 - Definition of TPMT_SYM_DEF_OBJECT Structure */

typedef struct {
    TPMI_ALG_SYM_OBJECT algorithm;  /* selects a symmetric block cipher */
    TPMU_SYM_KEY_BITS   keyBits;    /* the key size */
    TPMU_SYM_MODE   mode;       /* default mode */
} TPMT_SYM_DEF_OBJECT;

/* Table 129 - Definition of TPM2B_SYM_KEY Structure */

typedef struct {
    UINT16  size;               /* size, in octets, of the buffer containing the key; may be zero */
    BYTE    buffer [MAX_SYM_KEY_BYTES];     /* the key */
} SYM_KEY_2B;

typedef union {
    SYM_KEY_2B t;
    TPM2B      b;
} TPM2B_SYM_KEY;

/* Table 130 - Definition of TPMS_SYMCIPHER_PARMS Structure */

typedef struct {
    TPMT_SYM_DEF_OBJECT sym;    /* a symmetric block cipher */
} TPMS_SYMCIPHER_PARMS;

/* Table 131 - Definition of TPM2B_SENSITIVE_DATA Structure */

typedef struct {
    UINT16  size;
    BYTE    buffer[MAX_SYM_DATA];   /* the keyed hash private data structure */
} SENSITIVE_DATA_2B;

typedef union {
    SENSITIVE_DATA_2B t;
    TPM2B             b;
} TPM2B_SENSITIVE_DATA;

/* Table 132 - Definition of TPMS_SENSITIVE_CREATE Structure <IN> */

typedef struct {
    TPM2B_AUTH          userAuth;   /* the USER auth secret value */
    TPM2B_SENSITIVE_DATA    data;       /* data to be sealed */
} TPMS_SENSITIVE_CREATE;

/* Table 133 - Definition of TPM2B_SENSITIVE_CREATE Structure <IN, S> */

typedef struct {
    UINT16          size;       /* size of sensitive in octets (may not be zero) */
    TPMS_SENSITIVE_CREATE   sensitive;  /* data to be sealed or a symmetric key value. */
} SENSITIVE_CREATE_2B;

typedef union {
    SENSITIVE_CREATE_2B t;
    TPM2B               b;
} TPM2B_SENSITIVE_CREATE;

/* Table 134 - Definition of TPMS_SCHEME_SIGHASH Structure */

typedef struct {
    TPMI_ALG_HASH   hashAlg;    /* the hash algorithm used to digest the message */
} TPMS_SCHEME_SIGHASH;

/* Table 135 - Definition of (TPM_ALG_ID) TPMI_ALG_KEYEDHASH_SCHEME Type */

typedef TPM_ALG_ID TPMI_ALG_KEYEDHASH_SCHEME;

#if 0
if (
    (x != TPM_ALG_HMAC  ) &&
    (x != TPM_ALG_XOR   ) &&
    ((x != TPM_ALG_NULL     ) && allow)
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 136 - Definition of Types for HMAC_SIG_SCHEME */

typedef TPMS_SCHEME_SIGHASH TPMS_SCHEME_HMAC;

/* Table 137 - Definition of TPMS_SCHEME_XOR Structure */

typedef struct {
    TPMI_ALG_HASH   hashAlg;    /* the hash algorithm used to digest the message */
    TPMI_ALG_KDF    kdf;        /* the key derivation function */
} TPMS_SCHEME_XOR;

/* Table 138 - Definition of TPMU_SCHEME_KEYEDHASH Union <IN/OUT, S> */

typedef union {
    TPMS_SCHEME_HMAC    hmac;   /* TPM_ALG_HMAC the "signing" scheme */
    TPMS_SCHEME_XOR exclusiveOr;    /* TPM_ALG_XOR  the "obfuscation" scheme */
} TPMU_SCHEME_KEYEDHASH;

/* Table 139 - Definition of TPMT_KEYEDHASH_SCHEME Structure */

typedef struct {
    TPMI_ALG_KEYEDHASH_SCHEME   scheme;     /* selects the scheme */
    TPMU_SCHEME_KEYEDHASH   details;    /* the scheme parameters */
} TPMT_KEYEDHASH_SCHEME;

/* Table 140 - Definition of {RSA} Types for RSA_SIG_SCHEMES */

typedef TPMS_SCHEME_SIGHASH TPMS_SCHEME_RSASSA;         
typedef TPMS_SCHEME_SIGHASH TPMS_SCHEME_RSAPSS;

/* Table 141 - Definition of {ECC} Types for ECC_SIG_SCHEMES */

typedef TPMS_SCHEME_SIGHASH     TPMS_SCHEME_ECDSA;          
typedef TPMS_SCHEME_SIGHASH TPMS_SCHEME_SM2;            
typedef TPMS_SCHEME_SIGHASH     TPMS_SCHEME_ECSCHNORR;

/* Table 142 - Definition of {ECC} TPMS_SCHEME_ECDAA Structure */

typedef struct {
    TPMI_ALG_HASH   hashAlg;    /* the hash algorithm used to digest the message */
    UINT16      count;      /* the counter value that is used between TPM2_Commit() and the sign operation */
} TPMS_SCHEME_ECDAA;
    
/* Table 143 - Definition of TPMU_SIG_SCHEME Union <IN/OUT, S> */

typedef union {
    TPMS_SCHEME_RSASSA      rsassa;     /* TPM_ALG_RSASSA   the PKCS#1v1.5 scheme */
    TPMS_SCHEME_RSAPSS      rsapss;     /* TPM_ALG_RSAPSS   the PKCS#1v2.1 PSS scheme */
    TPMS_SCHEME_ECDSA       ecdsa;      /* TPM_ALG_ECDSA    the ECDSA scheme */
    TPMS_SCHEME_SM2     sm2;        /* TPM_ALG_SM2      ECDSA from SM2 */
    TPMS_SCHEME_ECDAA       ecdaa;      /* TPM_ALG_ECDAA    the ECDAA scheme */
    TPMS_SCHEME_ECSCHNORR   ecSchnorr;  /* TPM_ALG_ECSCHNORR    the EC Schnorr */
    TPMS_SCHEME_HMAC        hmac;       /* TPM_ALG_HMAC     the HMAC scheme */
    TPMS_SCHEME_SIGHASH     any;        /* selector that allows access to digest for any signing scheme */

} TPMU_SIG_SCHEME;

/* Table 144 - Definition of TPMT_SIG_SCHEME Structure */

typedef struct {
    TPMI_ALG_SIG_SCHEME scheme;     /* scheme selector */
    TPMU_SIG_SCHEME details;    /* scheme parameters */
} TPMT_SIG_SCHEME;
    
/* Table 145 - Definition of {RSA} TPMS_SCHEME_OAEP Structure */

typedef struct {
    TPMI_ALG_HASH   hashAlg;    /* the hash algorithm used to digest the message */
} TPMS_SCHEME_OAEP;

/* Table 146 - Definition of {ECC} TPMS_SCHEME_ECDH Structure */

typedef struct {
    TPMI_ALG_HASH   hashAlg;    /* the hash algorithm used in the KDF */
} TPMS_SCHEME_ECDH;

/* Table 147 - Definition of TPMS_SCHEME_MGF1 Structure */

typedef struct {
    TPMI_ALG_HASH   hashAlg;    /* the hash algorithm used in the KDF */
} TPMS_SCHEME_MGF1;
 
/* Table 148 - Definition of {ECC} TPMS_SCHEME_KDF1_SP800_56a Structure */

typedef struct {
    TPMI_ALG_HASH   hashAlg;    /* the hash algorithm used in the KDF */
} TPMS_SCHEME_KDF1_SP800_56a ;
    
/* Table 149 - Definition of TPMS_SCHEME_KDF2 Structure */

typedef struct {
    TPMI_ALG_HASH   hashAlg;    /* the hash algorithm used in the KDF */
} TPMS_SCHEME_KDF2;
 
/* Table 150 - Definition of TPMS_SCHEME_KDF1_SP800_108 Structure */

typedef struct {
    TPMI_ALG_HASH   hashAlg;    /* the hash algorithm used in the KDF */
} TPMS_SCHEME_KDF1_SP800_108;
 
/* Table 151 - Definition of TPMU_KDF_SCHEME Union <IN/OUT, S> */

typedef union {
    TPMS_SCHEME_MGF1        mgf1;       /* TPM_ALG_MGF1 */
    TPMS_SCHEME_KDF1_SP800_56a  kdf1_SP800_56a; /* TPM_ALG_KDF1_SP800_56a */
    TPMS_SCHEME_KDF2        kdf2;       /* TPM_ALG_KDF2 */
    TPMS_SCHEME_KDF1_SP800_108  kdf1_sp800_108; /* TPM_ALG_KDF1_SP800_108 */
} TPMU_KDF_SCHEME;

/* Table 152 - Definition of TPMT_KDF_SCHEME Structure */

typedef struct {
    TPMI_ALG_KDF    scheme;     /* scheme selector */
    TPMU_KDF_SCHEME details;    /* scheme parameters */
} TPMT_KDF_SCHEME;
 
/* Table 153 - Definition of (TPM_ALG_ID) TPMI_ALG_ASYM_SCHEME Type <> */

typedef TPM_ALG_ID TPMI_ALG_ASYM_SCHEME;

#if 0
if (
    (x != TPM_ALG_RSASSA) && 
    (x != TPM_ALG_RSAPSS) &&
    (x != TPM_ALG_RSAES) &&
    (x != TPM_ALG_OAEP) &&
    (x != TPM_ALG_ECDSA) &&
    (x != TPM_ALG_SM2) &&
    (x != TPM_ALG_ECDAA) &&
    (x != TPM_ALG_ECDH)
    ((x != TPM_ALG_NULL) || !allow)
    ) {
    rc = TPM_RC_VALUE;
 }    
#endif

/* Table 154 - Definition of TPMU_ASYM_SCHEME Union */

typedef union {
    TPMS_SCHEME_RSASSA      rsassa;     /* TPM_ALG_RSASSA   the PKCS#1v1.5 scheme */
    TPMS_SCHEME_RSAPSS      rsapss;     /* TPM_ALG_RSAPSS   the PKCS#1v2.1 PSS scheme */
    TPMS_SCHEME_OAEP        oaep;       /* TPM_ALG_OAEP     the PKSC#1v2.1 OAEP scheme */
    TPMS_SCHEME_ECDSA       ecdsa;      /* TPM_ALG_ECDSA    an ECDSA scheme */
    TPMS_SCHEME_SM2     sm2;        /* TPM_ALG_SM2      sign or key exchange from SM2 */
    TPMS_SCHEME_ECDAA       ecdaa;      /* TPM_ALG_ECDAA    an ECDAA scheme */
    TPMS_SCHEME_ECSCHNORR   ecSchnorr;  /* TPM_ALG_ECSCHNORR    elliptic curve Schnorr signature */
    TPMS_SCHEME_ECDH        ecdh;       /* TPM_ALG_ECDH     */
    TPMS_SCHEME_SIGHASH     anySig;
} TPMU_ASYM_SCHEME;

/* Table 155 - Definition of TPMT_ASYM_SCHEME Structure <> */

typedef struct {
    TPMI_ALG_ASYM_SCHEME    scheme;     /* scheme selector */
    TPMU_ASYM_SCHEME        details;    /* scheme parameters */
} TPMT_ASYM_SCHEME;

/* Table 156 - Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_SCHEME Type */

typedef TPM_ALG_ID TPMI_ALG_RSA_SCHEME;

#if 0
if (
    (x != TPM_ALG_RSASSA) &&    
    (x != TPM_ALG_RSAPSS) &&        
    (x != TPM_ALG_RSAES) &&     
    (x != TPM_ALG_OAEP) &&      
    ((x != TPM_RH_NULL) && allow)
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 157 - Definition of {RSA} TPMT_RSA_SCHEME Structure */

typedef struct {
    TPMI_ALG_RSA_SCHEME scheme;     /* scheme selector */
    TPMU_ASYM_SCHEME    details;    /* scheme parameters */
} TPMT_RSA_SCHEME;
    
/* Table 158 - Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_DECRYPT Type */

typedef TPM_ALG_ID TPMI_ALG_RSA_DECRYPT;

#if 0
if (
    (x !=TPM_ALG_RSAES  ) &&    
    (x !=TPM_ALG_OAEP   ) &&    
    ((x != TPM_ALG_NULL     ) && allow)
    ) {
    rc = TPM_RC_VALUE;
 }
#endif

/* Table 159 - Definition of {RSA} TPMT_RSA_DECRYPT Structure */

typedef struct {
    TPMI_ALG_RSA_DECRYPT    scheme; /* scheme selector */
    TPMU_ASYM_SCHEME        details;    /* scheme parameters */
} TPMT_RSA_DECRYPT;
    
/* Table 160 - Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure */

typedef struct {
    UINT16  size;               /* size of the buffer */
    BYTE    buffer[MAX_RSA_KEY_BYTES];  /* Value */
} PUBLIC_KEY_RSA_2B;

typedef union {
    PUBLIC_KEY_RSA_2B t;
    TPM2B             b;
} TPM2B_PUBLIC_KEY_RSA;

/* Table 161 - Definition of {RSA} (TPM_KEY_BITS) TPMI_RSA_KEY_BITS Type */

typedef TPM_KEY_BITS TPMI_RSA_KEY_BITS;

/* Table 162 - Definition of {RSA} TPM2B_PRIVATE_KEY_RSA Structure */

typedef struct {
    UINT16  size;
    BYTE    buffer[MAX_RSA_KEY_BYTES/2];    
} PRIVATE_KEY_RSA_2B;

typedef union {
    PRIVATE_KEY_RSA_2B t;
    TPM2B              b;
} TPM2B_PRIVATE_KEY_RSA;

/* Table 163 - Definition of {ECC} TPM2B_ECC_PARAMETER Structure */

typedef struct {
    UINT16  size;               /* size of the buffer */
    BYTE    buffer[MAX_ECC_KEY_BYTES];  /* the parameter data */
} ECC_PARAMETER_2B;

typedef union {
    ECC_PARAMETER_2B t;
    TPM2B        b;
} TPM2B_ECC_PARAMETER;

/* Table 164 - Definition of {ECC} TPMS_ECC_POINT Structure */

typedef struct {
    TPM2B_ECC_PARAMETER x;  /* X coordinate */
    TPM2B_ECC_PARAMETER y;  /* Y coordinate */
} TPMS_ECC_POINT;
    
/* Table 165 - Definition of {ECC} TPM2B_ECC_POINT Structure */

typedef struct {
    UINT16      size;   /* size of the remainder of this structure */
    TPMS_ECC_POINT  point;  /* coordinates */
} ECC_POINT_2B;

typedef union {
    ECC_POINT_2B t;
    TPM2B        b;
} TPM2B_ECC_POINT;

/* Table 166 - Definition of (TPM_ALG_ID) {ECC} TPMI_ALG_ECC_SCHEME Type */

typedef TPM_ALG_ID TPMI_ALG_ECC_SCHEME;

#if 0
if (
    (x != TPM_ALG_ECDSA     ) &&    /* these are the selections allowed for an ECC key   */
    (x != TPM_ALG_SM2       ) &&    
    (x != TPM_ALG_ECDAA     ) &&    
    (x != TPM_ALG_ECSCHNORR ) &&    
    (x != TPM_ALG_ECDH      ) &&    
    ((x != TPM_ALG_NULL ) && allow)
    ) {
     rc = TPM_RC_SCHEME;
 }
#endif

/* Table 167 - Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type */

typedef TPM_ECC_CURVE TPMI_ECC_CURVE;
    
/* Table 168 - Definition of (TPMT_SIG_SCHEME) {ECC} TPMT_ECC_SCHEME Structure */

typedef struct {
    TPMI_ALG_ECC_SCHEME     scheme;     /* scheme selector */
    TPMU_ASYM_SCHEME        details;    /* scheme parameters */
} TPMT_ECC_SCHEME;
   
/* Table 169 - Definition of {ECC} TPMS_ALGORITHM_DETAIL_ECC Structure <OUT> */

typedef struct {
    TPM_ECC_CURVE   curveID;    /* identifier for the curve */
    UINT16      keySize;    /* Size in bits of the key */
    TPMT_KDF_SCHEME kdf;        /* the default KDF and hash algorithm used in secret sharing operations */
    TPMT_ECC_SCHEME sign;       /* If not TPM_ALG_NULL, this is the mandatory signature scheme that is required to be used with this curve. */
    TPM2B_ECC_PARAMETER p;      /* Fp (the modulus) */
    TPM2B_ECC_PARAMETER a;      /* coefficient of the linear term in the curve equation */
    TPM2B_ECC_PARAMETER b;      /* constant term for curve equation */
    TPM2B_ECC_PARAMETER gX;     /* x coordinate of base point G */
    TPM2B_ECC_PARAMETER gY;     /* y coordinate of base point G */
    TPM2B_ECC_PARAMETER n;      /* order of G */
    TPM2B_ECC_PARAMETER h;      /* cofactor (a size of zero indicates a cofactor of 1) */
} TPMS_ALGORITHM_DETAIL_ECC;
    
/* Table 170 - Definition of {RSA} TPMS_SIGNATURE_RSASSA Structure */

typedef struct {
    TPMI_ALG_HASH       hash;   /* the hash algorithm used to digest the message TPM_ALG_NULL is not allowed. */
    TPM2B_PUBLIC_KEY_RSA    sig;    /* The signature is the size of a public key. */
} TPMS_SIGNATURE_RSASSA;
    
/* Table 171 - Definition of {RSA} TPMS_SIGNATURE_RSAPSS Structure */

typedef struct {
    TPMI_ALG_HASH       hash;   /* the hash algorithm used in the signature process TPM_ALG_NULL is not allowed. */
    TPM2B_PUBLIC_KEY_RSA    sig;    /* The signature is the size of a public key. */
} TPMS_SIGNATURE_RSAPSS;
    
/* Table 172 - Definition of {ECC} TPMS_SIGNATURE_ECDSA Structure */

typedef struct {
    TPMI_ALG_HASH   hash;   /* the hash algorithm used in the signature process TPM_ALG_NULL is not allowed. */
    TPM2B_ECC_PARAMETER signatureR;
    TPM2B_ECC_PARAMETER signatureS;
} TPMS_SIGNATURE_ECDSA;
    
/* Table 173 - Definition of TPMU_SIGNATURE Union <IN/OUT, S> */

typedef union {
    TPMS_SIGNATURE_RSASSA   rsassa;         /* TPM_ALG_RSASSA   a PKCS#1v1.5 signature */
    TPMS_SIGNATURE_RSAPSS   rsapss;         /* TPM_ALG_RSAPSS   a PKCS#1v2.1PSS signature */
    TPMS_SIGNATURE_ECDSA    ecdsa;          /* TPM_ALG_ECDSA    an ECDSA signature */
    TPMS_SIGNATURE_ECDSA    sm2;            /* TPM_ALG_SM2  same format as ECDSA */
    TPMS_SIGNATURE_ECDSA    ecdaa;          /* TPM_ALG_ECDAA    same format as ECDSA */
    TPMS_SIGNATURE_ECDSA    ecschnorr;      /* TPM_ALG_ECSCHNORR    same format as ECDSA */
    TPMT_HA         hmac;           /* TPM_ALG_HMAC HMAC signature (required to be supported) */
    TPMS_SCHEME_SIGHASH     any;            /* used to access the hash */
} TPMU_SIGNATURE;


/* Table 174 - Definition of TPMT_SIGNATURE Structure */

typedef struct {
    TPMI_ALG_SIG_SCHEME sigAlg;     /* selector of the algorithm used to construct the signature */
    TPMU_SIGNATURE  signature;  /* This shall be the actual signature information. */
} TPMT_SIGNATURE;
    
/* Table 175 - Definition of TPMU_ENCRYPTED_SECRET Union <S> */

typedef union {
    BYTE    ecc[sizeof(TPMS_ECC_POINT)];        /* TPM_ALG_ECC */
    BYTE    rsa[MAX_RSA_KEY_BYTES];         /* TPM_ALG_RSA */
    BYTE    symmetric[sizeof(TPM2B_DIGEST)];    /* TPM_ALG_SYMCIPHER */
    BYTE    keyedHash[sizeof(TPM2B_DIGEST)];    /* TPM_ALG_KEYEDHASH */
} TPMU_ENCRYPTED_SECRET;

/* Table 176 - Definition of TPM2B_ENCRYPTED_SECRET Structure */

typedef struct {
    UINT16  size;                   /* size of the secret value */
    BYTE    secret[sizeof(TPMU_ENCRYPTED_SECRET)];  /* secret */
} ENCRYPTED_SECRET_2B;

typedef union {
    ENCRYPTED_SECRET_2B t;
    TPM2B               b;
} TPM2B_ENCRYPTED_SECRET;

/* Table 177 - Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type */

typedef TPM_ALG_ID TPMI_ALG_PUBLIC;

#if 0
if (
    (x != TPM_ALG_KEYEDHASH) && /* required of all TPM   */
    (x !=TPM_ALG_SYMCIPHER) &&      /* required of all TPM   */
    (x !=TPM_ALG_RSA) &&        /* At least one asymmetric algorithm shall be implemented. */
    (x !=TPM_ALG_ECC)           /* At least one asymmetric algorithm shall be implemented. */
    ) {
    rc = TPM_RC_TYPE;
}
#endif

/* Table 178 - Definition of TPMU_PUBLIC_ID Union <IN/OUT, S> */

typedef union {
    TPM2B_DIGEST        keyedHash;  /* TPM_ALG_KEYEDHASH */
    TPM2B_DIGEST        sym;        /* TPM_ALG_SYMCIPHER */
    TPM2B_PUBLIC_KEY_RSA    rsa;        /* TPM_ALG_RSA */
    TPMS_ECC_POINT      ecc;        /* TPM_ALG_ECC */
} TPMU_PUBLIC_ID;

/* Table 179 - Definition of TPMS_KEYEDHASH_PARMS Structure */

typedef struct {
    TPMT_KEYEDHASH_SCHEME   scheme; /* Indicates the signing method used for a keyedHash signing object*/
} TPMS_KEYEDHASH_PARMS;
 
/* Table 180 - Definition of TPMS_ASYM_PARMS Structure <> */

typedef struct {
    TPMT_SYM_DEF_OBJECT symmetric;  /* the companion symmetric algorithm for a restricted decryption key */
    TPMT_ASYM_SCHEME    scheme;     /* for a key with the sign attribute SET, a valid signing scheme for the key type */
} TPMS_ASYM_PARMS;
 
/* Table 181 - Definition of {RSA} TPMS_RSA_PARMS Structure */

typedef struct {
    TPMT_SYM_DEF_OBJECT symmetric;  /* for a restricted decryption key, shall be set to a supported symmetric algorithm, key size, and mode. */
    TPMT_RSA_SCHEME scheme;     /* for an unrestricted signing key, shall be either TPM_ALG_RSAPSS TPM_ALG_RSASSA or TPM_ALG_NULL */
    TPMI_RSA_KEY_BITS   keyBits;    /* number of bits in the public modulus */
    UINT32  exponent;       /* the public exponent  */
} TPMS_RSA_PARMS;

/* Table 182 - Definition of {ECC} TPMS_ECC_PARMS Structure */

typedef struct {
    TPMT_SYM_DEF_OBJECT symmetric;  /* for a restricted decryption key, shall be set to a supported symmetric algorithm, key size. and mode. */
    TPMT_ECC_SCHEME scheme;     /* If the sign attribute of the key is SET, then this shall be a valid signing scheme. */
    TPMI_ECC_CURVE  curveID;    /* ECC curve ID */
    TPMT_KDF_SCHEME kdf;        /* an optional key derivation scheme for generating a symmetric key from a Z value */
} TPMS_ECC_PARMS;

/* Table 183 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */

typedef union {
    TPMS_KEYEDHASH_PARMS    keyedHashDetail;    /* TPM_ALG_KEYEDHASH    sign | encrypt | neither */
    TPMS_SYMCIPHER_PARMS    symDetail;      /* TPM_ALG_SYMCIPHER    a symmetric block cipher */
    TPMS_RSA_PARMS      rsaDetail;      /* TPM_ALG_RSA  decrypt + sign(2) */
    TPMS_ECC_PARMS      eccDetail;      /* TPM_ALG_ECC  decrypt + sign(2) */
    TPMS_ASYM_PARMS     asymDetail;     /* common scheme structure for RSA and ECC keys */
} TPMU_PUBLIC_PARMS;

/* Table 184 - Definition of TPMT_PUBLIC_PARMS Structure */

typedef struct {
    TPMI_ALG_PUBLIC type;       /* the algorithm to be tested */
    TPMU_PUBLIC_PARMS   parameters; /* the algorithm details */
} TPMT_PUBLIC_PARMS;
 
/* Table 185 - Definition of TPMT_PUBLIC Structure */

typedef struct {
    TPMI_ALG_PUBLIC type;           /* "algorithm" associated with this object */
    TPMI_ALG_HASH   nameAlg;        /* algorithm used for computing the Name of the object */
    TPMA_OBJECT     objectAttributes;   /* attributes that, along with type, determine the manipulations of this object */
    TPM2B_DIGEST    authPolicy;     /* optional policy for using this key */
    TPMU_PUBLIC_PARMS   parameters;     /* the algorithm or structure details */
    TPMU_PUBLIC_ID  unique;     /* the unique identifier of the structure */
} TPMT_PUBLIC;
 
/* Table 186 - Definition of TPM2B_PUBLIC Structure */

typedef struct {
    UINT16  size;       /* size of publicArea */
    TPMT_PUBLIC publicArea; /* the public area  */
} PUBLIC_2B;

typedef union {
    PUBLIC_2B t;
    TPM2B     b;
} TPM2B_PUBLIC;

/* Table 187 - Definition of {RSA} TPM2B_PRIVATE_VENDOR_SPECIFIC Structure<> */

typedef struct {
    UINT16  size;
    BYTE    buffer[PRIVATE_VENDOR_SPECIFIC_BYTES];  
} PRIVATE_VENDOR_SPECIFIC_2B;

typedef union {
    PRIVATE_VENDOR_SPECIFIC_2B t;
    TPM2B                      b;
} TPM2B_PRIVATE_VENDOR_SPECIFIC;

/* Table 188 - Definition of TPMU_SENSITIVE_COMPOSITE Union <IN/OUT, S> */

typedef union {
    TPM2B_PRIVATE_KEY_RSA       rsa;    /* TPM_ALG_RSA  a prime factor of the public key */
    TPM2B_ECC_PARAMETER         ecc;    /* TPM_ALG_ECC  the integer private key */
    TPM2B_SENSITIVE_DATA        bits;   /* TPM_ALG_KEYEDHASH    the private data */
    TPM2B_SYM_KEY           sym;    /* TPM_ALG_SYMCIPHER    the symmetric key */
    TPM2B_PRIVATE_VENDOR_SPECIFIC   any;    /* vendor-specific size for key storage */
} TPMU_SENSITIVE_COMPOSITE;

/* Table 189 - Definition of TPMT_SENSITIVE Structure */

typedef struct {
    TPMI_ALG_PUBLIC     sensitiveType;  /* identifier for the sensitive area  */
    TPM2B_AUTH          authValue;  /* user authorization data */
    TPM2B_DIGEST        seedValue;  /* for asymmetric key object, the optional protection seed; for other objects, the obfuscation value */
    TPMU_SENSITIVE_COMPOSITE    sensitive;  /* the type-specific private data */
} TPMT_SENSITIVE;
 
/* Table 190 - Definition of TPM2B_SENSITIVE Structure <IN/OUT> */

typedef struct {
    UINT16      size;       /* size of the private structure */
    TPMT_SENSITIVE  sensitiveArea;  /* an unencrypted sensitive area */
} SENSITIVE_2B;

typedef union {
    SENSITIVE_2B t;
    TPM2B        b;
} TPM2B_SENSITIVE;

/* Table 191 - Definition of _PRIVATE Structure <> */

typedef struct {
    TPM2B_DIGEST    integrityOuter;
    TPM2B_DIGEST    integrityInner; /* could also be a TPM2B_IV */
    TPMT_SENSITIVE  sensitive;  /* the sensitive area */
} _PRIVATE;
 
/* Table 192 - Definition of TPM2B_PRIVATE Structure <IN/OUT, S> */

typedef struct {
    UINT16  size;               /* size of the private structure */
    BYTE    buffer[sizeof(_PRIVATE)];   /* an encrypted private area */
} PRIVATE_2B;

typedef union {
    PRIVATE_2B t;
    TPM2B      b;
} TPM2B_PRIVATE;

/* Table 193 - Definition of _ID_OBJECT Structure <> */

typedef struct {
    TPM2B_DIGEST    integrityHMAC;  /* HMAC using the nameAlg of the storage key on the target TPM */
    TPM2B_DIGEST    encIdentity;    /* credential protector information returned if name matches the referenced object */
} _ID_OBJECT;
 
/* Table 194 - Definition of TPM2B_ID_OBJECT Structure <IN/OUT> */

typedef struct {
    UINT16  size;               /* size of the credential structure */
    BYTE    credential[sizeof(_ID_OBJECT)]; /* an encrypted credential area */
} ID_OBJECT_2B;

typedef union {
    ID_OBJECT_2B t;
    TPM2B        b;
} TPM2B_ID_OBJECT;

/* Table 195 - Definition of (UINT32) TPM_NV_INDEX Bits <> */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
    int index : 24;     /* 23:0  The Index of the NV location */
    int RH_NV : 8;      /* 31:24 constant value of TPM_HT_NV_INDEX indicating the NV Index range */
    };
    UINT32 val;
} TPM_NV_INDEX;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
    int RH_NV : 8;      /* 31:24 constant value of TPM_HT_NV_INDEX indicating the NV Index range */
    int index : 24;     /* 23:0  The Index of the NV location */
    };
    UINT32 val;
} TPM_NV_INDEX;

#else 

typedef uint32_t TPM_NV_INDEX;

#define TPM_NV_INDEX_INDEX  0x00ffffff
#define TPM_NV_INDEX_RH_NV  0xff000000

#endif

/* Table 196 - Definition of (UINT32) TPMA_NV Bits */

#if defined TPM_BITFIELD_LE

typedef union {
    struct {
    int TPMA_NV_PPWRITE     : 1;    /* 0    The Index data can be written if Platform Authorization is provided. */
    int TPMA_NV_OWNERWRITE      : 1;    /* 1    The Index data can be written if Owner Authorization is provided. */
    int TPMA_NV_AUTHWRITE       : 1;    /* 2    Authorizations to change the Index contents that require USER role may be provided with an HMAC session or password. */
    int TPMA_NV_POLICYWRITE     : 1;    /* 3    Authorizations to change the Index contents that require USER role may be provided with a policy session. */
    int TPMA_NV_COUNTER     : 1;    /* 4    Index contains an 8-octet value that is to be used as a counter and can only be modified with TPM2_NV_Increment(). */
    int TPMA_NV_BITS        : 1;    /* 5    Index contains an 8-octet value to be used as a bit field and can only be modified with TPM2_NV_SetBits(). */
    int TPMA_NV_EXTEND      : 1;    /* 6    Index contains a digest-sized value used like a PCR. */
    int Reserved1           : 3;    /* 9:7  shall be zero reserved for use in defining additional write controls */
    int TPMA_NV_POLICY_DELETE   : 1;    /* 10   Index may not be deleted unless the authPolicy is satisfied. */
    int TPMA_NV_WRITELOCKED     : 1;    /* 11   Index cannot be written. */
    int TPMA_NV_WRITEALL        : 1;    /* 12   A partial write of the Index data is not allowed. The write size shall match the defined space size. */
    int TPMA_NV_WRITEDEFINE     : 1;    /* 13   TPM2_NV_WriteLock() may be used to prevent further writes to this location. */
    int TPMA_NV_WRITE_STCLEAR   : 1;    /* 14   TPM2_NV_WriteLock() may be used to prevent further writes to this location until the next TPM Reset or TPM Restart. */
    int TPMA_NV_GLOBALLOCK      : 1;    /* 15   If TPM2_NV_GlobalLock() is successful, then further writes are not permitted until the next TPM Reset or TPM Restart. */
    int TPMA_NV_PPREAD      : 1;    /* 16   The Index data can be read if Platform Authorization is provided. */
    int TPMA_NV_OWNERREAD       : 1;    /* 17   The Index data can be read if Owner Authorization is provided. */
    int TPMA_NV_AUTHREAD        : 1;    /* 18   The Index data may be read if the authValue is provided. */
    int TPMA_NV_POLICYREAD      : 1;    /* 19   The Index data may be read if the authPolicy is satisfied. */
    int Reserved2           : 5;    /* 24:20 shall be zero reserved for use in defining additional read controls */
    int TPMA_NV_NO_DA       : 1;    /* 25   Authorization failures of the Index do not affect the DA logic */
    int TPMA_NV_ORDERLY     : 1;    /* 26   NV Index state is only required to be saved when the TPM performs an orderly shutdown */
    int TPMA_NV_CLEAR_STCLEAR   : 1;    /* 27   TPMA_NV_WRITTEN for the Index is CLEAR by TPM Reset or TPM Restart. */
    int TPMA_NV_READLOCKED      : 1;    /* 28   Reads of the Index are blocked until the next TPM Reset or TPM Restart. */
    int TPMA_NV_WRITTEN     : 1;    /* 29   Index has been written. */
    int TPMA_NV_PLATFORMCREATE  : 1;    /* 30   This Index may be undefined with Platform Authorization but not with Owner Authorization. */
    int TPMA_NV_READ_STCLEAR    : 1;    /* 31   TPM2_NV_ReadLock() may be used to SET TPMA_NV_READLOCKED for this Index. */
    };
    UINT32 val;
} TPMA_NV;

#elif defined TPM_BITFIELD_BE

typedef union {
    struct {
    int TPMA_NV_READ_STCLEAR    : 1;    /* 31   TPM2_NV_ReadLock() may be used to SET TPMA_NV_READLOCKED for this Index. */
    int TPMA_NV_PLATFORMCREATE  : 1;    /* 30   This Index may be undefined with Platform Authorization but not with Owner Authorization. */
    int TPMA_NV_WRITTEN     : 1;    /* 29   Index has been written. */
    int TPMA_NV_READLOCKED      : 1;    /* 28   Reads of the Index are blocked until the next TPM Reset or TPM Restart. */
    int TPMA_NV_CLEAR_STCLEAR   : 1;    /* 27   TPMA_NV_WRITTEN for the Index is CLEAR by TPM Reset or TPM Restart. */
    int TPMA_NV_ORDERLY     : 1;    /* 26   NV Index state is only required to be saved when the TPM performs an orderly shutdown */
    int TPMA_NV_NO_DA       : 1;    /* 25   Authorization failures of the Index do not affect the DA logic */
    int Reserved2           : 5;    /* 24:20 shall be zero reserved for use in defining additional read controls */
    int TPMA_NV_POLICYREAD      : 1;    /* 19   The Index data may be read if the authPolicy is satisfied. */
    int TPMA_NV_AUTHREAD        : 1;    /* 18   The Index data may be read if the authValue is provided. */
    int TPMA_NV_OWNERREAD       : 1;    /* 17   The Index data can be read if Owner Authorization is provided. */
    int TPMA_NV_PPREAD      : 1;    /* 16   The Index data can be read if Platform Authorization is provided. */
    int TPMA_NV_GLOBALLOCK      : 1;    /* 15   If TPM2_NV_GlobalLock() is successful, then further writes are not permitted until the next TPM Reset or TPM Restart. */
    int TPMA_NV_WRITE_STCLEAR   : 1;    /* 14   TPM2_NV_WriteLock() may be used to prevent further writes to this location until the next TPM Reset or TPM Restart. */
    int TPMA_NV_WRITEDEFINE     : 1;    /* 13   TPM2_NV_WriteLock() may be used to prevent further writes to this location. */
    int TPMA_NV_WRITEALL        : 1;    /* 12   A partial write of the Index data is not allowed. The write size shall match the defined space size. */
    int TPMA_NV_WRITELOCKED     : 1;    /* 11   Index cannot be written. */
    int TPMA_NV_POLICY_DELETE   : 1;    /* 10   Index may not be deleted unless the authPolicy is satisfied. */
    int Reserved1           : 3;    /* 9:7  shall be zero reserved for use in defining additional write controls */
    int TPMA_NV_EXTEND      : 1;    /* 6    Index contains a digest-sized value used like a PCR. */
    int TPMA_NV_BITS        : 1;    /* 5    Index contains an 8-octet value to be used as a bit field and can only be modified with TPM2_NV_SetBits(). */
    int TPMA_NV_COUNTER     : 1;    /* 4    Index contains an 8-octet value that is to be used as a counter and can only be modified with TPM2_NV_Increment(). */
    int TPMA_NV_POLICYWRITE     : 1;    /* 3    Authorizations to change the Index contents that require USER role may be provided with a policy session. */
    int TPMA_NV_AUTHWRITE       : 1;    /* 2    Authorizations to change the Index contents that require USER role may be provided with an HMAC session or password. */
    int TPMA_NV_OWNERWRITE      : 1;    /* 1    The Index data can be written if Owner Authorization is provided. */
    int TPMA_NV_PPWRITE     : 1;    /* 0    The Index data can be written if Platform Authorization is provided. */
    };
    UINT32 val;
} TPMA_NV;

#else 

typedef uint32_t TPMA_NV;

#define TPMA_NV_PPWRITE     0x00000001
#define TPMA_NV_OWNERWRITE  0x00000002
#define TPMA_NV_AUTHWRITE   0x00000004
#define TPMA_NV_POLICYWRITE 0x00000008
#define TPMA_NV_COUNTER     0x00000010
#define TPMA_NV_BITS        0x00000020
#define TPMA_NV_EXTEND      0x00000040
#define TPMA_NV_RESERVED1   0x00000380
#define TPMA_NV_POLICY_DELETE   0x00000400
#define TPMA_NV_WRITELOCKED 0x00000800
#define TPMA_NV_WRITEALL    0x00001000
#define TPMA_NV_WRITEDEFINE 0x00002000
#define TPMA_NV_WRITE_STCLEAR   0x00004000
#define TPMA_NV_GLOBALLOCK  0x00008000
#define TPMA_NV_PPREAD      0x00010000
#define TPMA_NV_OWNERREAD   0x00020000
#define TPMA_NV_AUTHREAD    0x00040000
#define TPMA_NV_POLICYREAD  0x00080000
#define TPMA_NV_RESERVED2   0x01f00000
#define TPMA_NV_NO_DA       0x02000000
#define TPMA_NV_ORDERLY     0x04000000
#define TPMA_NV_CLEAR_STCLEAR   0x08000000
#define TPMA_NV_READLOCKED  0x10000000
#define TPMA_NV_WRITTEN     0x20000000
#define TPMA_NV_PLATFORMCREATE  0x40000000
#define TPMA_NV_READ_STCLEAR    0x80000000

#endif

/* Table 197 - Definition of TPMS_NV_PUBLIC Structure */

typedef struct {
    TPMI_RH_NV_INDEX    nvIndex;    /* the handle of the data area */
    TPMI_ALG_HASH   nameAlg;    /* hash algorithm used to compute the name of the Index and used for the authPolicy */
    TPMA_NV     attributes; /* the Index attributes */
    TPM2B_DIGEST    authPolicy; /* the access policy for the Index */
    UINT16      dataSize;   /* the size of the data area */
} TPMS_NV_PUBLIC;

/* Table 198 - Definition of TPM2B_NV_PUBLIC Structure */

typedef struct {
    UINT16      size;       /* size of nvPublic */
    TPMS_NV_PUBLIC  nvPublic;   /* the public area */
} NV_PUBLIC_2B;

typedef union {
    NV_PUBLIC_2B t;
    TPM2B        b;
} TPM2B_NV_PUBLIC;

/* Table 199 - Definition of TPM2B_CONTEXT_SENSITIVE Structure <IN/OUT> */

typedef struct {
    UINT16  size;
    BYTE    buffer[MAX_CONTEXT_SIZE];   /* the sensitive data */
} CONTEXT_SENSITIVE_2B;

typedef union {
    CONTEXT_SENSITIVE_2B t;
    TPM2B                b;
} TPM2B_CONTEXT_SENSITIVE;

/* Table 200 - Definition of TPMS_CONTEXT_DATA Structure <IN/OUT, S> */

typedef struct {
    TPM2B_DIGEST        integrity;  /* the integrity value */
    TPM2B_CONTEXT_SENSITIVE encrypted;  /* the sensitive area */
} TPMS_CONTEXT_DATA;

/* Table 201 - Definition of TPM2B_CONTEXT_DATA Structure <IN/OUT> */

typedef struct {
    UINT16      size;
    BYTE        buffer[sizeof(TPMS_CONTEXT_DATA)];  
} CONTEXT_DATA_2B;

typedef union {
    CONTEXT_DATA_2B t;
    TPM2B           b;
} TPM2B_CONTEXT_DATA;

/* Table 202 - Definition of TPMS_CONTEXT Structure */

typedef struct {
    UINT64      sequence;   /* the sequence number of the context */
    TPMI_DH_CONTEXT savedHandle;    /* the handle of the session, object or sequence */
    TPMI_RH_HIERARCHY   hierarchy;  /* the hierarchy of the context */
    TPM2B_CONTEXT_DATA  contextBlob;    /* the context data and integrity HMAC */
} TPMS_CONTEXT;
 
/* Table 203 - Context Handle Values */

#define TPM_CONTEXT_HANDLE_HMAC         0x02000000  /* an HMAC session context */
#define TPM_CONTEXT_HANDLE_POLICY_SESSION   0x03000000  /* a policy session context */
#define TPM_CONTEXT_HANDLE_TRANSIENT        0x80000000  /* an ordinary transient object */
#define TPM_CONTEXT_HANDLE_SEQUENCE     0x80000001  /* a sequence object */
#define TPM_CONTEXT_HANDLE_STCLEAR      0x80000002  /* a transient object with the stClear attribute SET */

/* Table 204 - Definition of TPMS_CREATION_DATA Structure <OUT> */

typedef struct {
    TPML_PCR_SELECTION  pcrSelect;      /* list indicating the PCR included in pcrDigest */
    TPM2B_DIGEST    pcrDigest;      /* digest of the selected PCR using nameAlg of the object for which this structure is being created */
    TPMA_LOCALITY   locality;       /* the locality at which the object was created */
    TPM_ALG_ID      parentNameAlg;      /* nameAlg of the parent */
    TPM2B_NAME      parentName;     /* Name of the parent at time of creation */
    TPM2B_NAME      parentQualifiedName;    /* Qualified Name of the parent at the time of creation */
    TPM2B_DATA      outsideInfo;        /* association with additional information added by the key creator */
} TPMS_CREATION_DATA;
 
/* Table 205 - Definition of TPM2B_CREATION_DATA Structure <OUT> */

typedef struct {
    UINT16      size;   /* size of the creation data */
    TPMS_CREATION_DATA  creationData;
} CREATION_DATA_2B;

typedef union {
    CREATION_DATA_2B t;
    TPM2B            b;
} TPM2B_CREATION_DATA;

/* formerly TPMB.h */

#define TPM2B_TYPE(name, bytes)             \
    typedef union {                         \
        struct  {                           \
            UINT16  size;                   \
            BYTE    buffer[(bytes)];        \
        } t;                                \
        TPM2B   b;                          \
    } TPM2B_##name

#define TPM2B_INIT(TYPE, name)  \
    TPM2B_##TYPE    name = {sizeof(name.t.buffer), {0}}

#if 0
TPM2B_TYPE(SEED, PRIMARY_SEED_SIZE);
TPM2B_TYPE(HASH_BLOCK, MAX_HASH_BLOCK_SIZE);
TPM2B_TYPE(RSA_PRIME, MAX_RSA_KEY_BYTES/2);
TPM2B_TYPE(1_BYTE_VALUE, 1);
TPM2B_TYPE(2_BYTE_VALUE, 2);
TPM2B_TYPE(4_BYTE_VALUE, 4);
TPM2B_TYPE(20_BYTE_VALUE, 20);
TPM2B_TYPE(32_BYTE_VALUE, 32);
TPM2B_TYPE(48_BYTE_VALUE, 48);
TPM2B_TYPE(64_BYTE_VALUE, 64);
TPM2B_TYPE(MAX_HASH_BLOCK, MAX_HASH_BLOCK_SIZE);
#endif

#pragma pack (pop)

#endif

