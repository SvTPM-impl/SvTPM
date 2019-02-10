//**********************************************************************;
//*                                                                    *;
//* Intel Copyright 2013                                               *;
//*                                                                    *;
//**********************************************************************;

#ifndef TPMCLIENT_H
#define TPMCLIENT_H

#define TPMBUF_LEN 0x8000

#define GLOBAL_SYS_CONTEXT_SIZE 1024

// TPM indices and sizes
#define NV_AUX_INDEX_SIZE     96
#define NV_PS_INDEX_SIZE      34
#define NV_PO_INDEX_SIZE      34

#define INDEX_AUX                       0x01800003 // NV Storage
#define INDEX_LCP_OWN                   0x01400001 // Launch Policy Owner
#define INDEX_LCP_SUP                   0x01800001 // Launch Policy Default (Supplier)
#define TPM20_INDEX_TEST1               0x01500015
#define TPM20_INDEX_TEST2               0x01500016
#define TPM20_INDEX_PASSWORD_TEST       0x01500020


#define NUM_MAX_LOADKEY 20


#define RSA_KEY      1 // RSA Storage Key
#define SM2_KEY      2 // SM2 Storage Key

#define KEYED_HASH   3

#define RSA_KEY_SIGN 4
#define SM2_KEY_SIGN 5

#define RSA_KEY_ENC  6
#define SM2_KEY_ENC  7

#define AES_KEY      8
#define SM4_KEY	   9

#define RSA_KEY_PROTECT    10
#define RSA_KEY_DUPLICATED 11
#define SHA1_KEY     12
#define HMAC_HASH    13
#define CERTIFY_KEY  14
#define RSA_KEY_SSL  15
#define PUBLIC_KEY  16
#define AES_KEY_DUPLICATE 17
#define SM2_KEY_PROTECT 18
#define SM2_KEY_DUPLICATED 19
#define SM4_KEY_DUPLICATE 20

#define KEYID_SRK    -2
#define KEYID_EK     -3

#define HANDLE_PERMANENT_SRK   0x81000001
#define HANDLE_PERMANENT_EK    0x81000002

#define RSA_ENC_DEC  1
#define AES_ENC_DEC  2
#define SM4_ENC_DEC  3
#define SM4_ENC      4
#define SM4_DEC      5
#define RSA_ENC      6
#define RSA_DEC      7
#define AES_ENC      8
#define AES_DEC      9

#define normalload     1
#define importload     2
#define TSS2_RC_FEALAYER          0x01000000
#define TSS2_RC_CREATEKEYFAILED   TSS2_RC_FEALAYER + 1

#define TSS2_SUCCESS  0
#define TSS2_OTHERS   -1 
#define APP_RootKey 0
#define APP_WorkKey 1
#define APP_BackupKey 2
#define ENCRYPT 0
#define DECRYPT 1
#define MAXNUM 128

#define AUTH_METHOD_AUTO 0
#define AUTH_METHOD_MAN 1

#define AUTH_METHOD_SAPCE 1024


#define INIT_SIMPLE_TPM2B_SIZE(type) (type).t.size=sizeof(type)-2;
typedef struct Key_backup
{
	/* data */
	int tpm_id;
	int key_id;
	char key[2048];
	int key_type;
      int  bufferlen; 
} key_backup ;

typedef struct buf_Duplicate
{
	int len;	
	char str[1024];
}buf_duplicate;
typedef struct Backup_str
{
	buf_duplicate outSymSeedput;
	buf_duplicate outduplicate;
	buf_duplicate outpublicbuffer;
  int key_id;
  int user_id;
  int key_type;
	
}backup_str;

typedef buf_duplicate buf_ident;
typedef struct Ident_str
{
    buf_ident datasignature;
    buf_ident outpublicbuffer;
    buf_ident dataDigest;
    int user_id;
}ident_str;
typedef struct Register_str
{
    buf_ident datasignature;
    buf_ident outpublicbuffer;
    buf_ident dataDigest;
    int user_id;
}register_str;

typedef struct DupTicket
{
	char outpublicbuffer[1024];
}DupTic;

typedef backup_str TSS2_Dup ;

#endif

