/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: NVMem.c 809 2016-11-16 18:31:54Z kgoldman $			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2016					*/
/*										*/
/********************************************************************************/

/* C.6 NVMem.c */
/* C.6.1. Introduction */
/* This file contains the NV read and write access methods.  This implementation uses RAM/file and
   does not manage the RAM/file as NV blocks. The implementation may become more sophisticated over
   time. */
/* C.6.2. Includes */
/*#include "Tpm.h"*/

/*#include <memory.h>*/
#include <tlibc/mbusafecrt.h>
#include <string.h>
#include <assert.h>
#include "PlatformData.h"
#include "Platform_fp.h"

#include "tpm_library_intern.h"
#include "sgx_wrapper.h"
#include "sgx_tseal.h"
#include "sgx_attributes.h"
//#include "tseal_migration_attr.h"

#define FLAGS_NON_SECURITY_BITS     (0xFFFFFFFFFFFFC0ULL | SGX_FLAGS_MODE64BIT | SGX_FLAGS_PROVISION_KEY| SGX_FLAGS_EINITTOKEN_KEY)
#define TSEAL_DEFAULT_FLAGSMASK     (~FLAGS_NON_SECURITY_BITS)

#define MISC_NON_SECURITY_BITS      0x0FFFFFFF  /* bit[27:0]: have no security implications */
#define TSEAL_DEFAULT_MISCMASK (~MISC_NON_SECURITY_BITS)

// SGX
int g_firstUse = 0;
sgx_sealed_data_t *s_NV_sealed;
unsigned int s_NV_sealed_len;
uint8_t *s_NV_unsealed;

uint8_t seal_uuid[16];
uint8_t unseal_uuid[16];

/*ecall_plat__TPM_Init(
  const char *path,              // the path of NVChip
)
{
    _plat__NVEnable_Path(NULL, path);
    _plat__SetNvAvail();

    _plat__NvInit();
    _plat__NvLoad(qemu_uuid);

    if(g_firstUse){
      TPM_Manufacture(1);
    }
    _plat__Signal_PowerOn();
    _TPM_Init();

}*/

/* C.6.3. Functions */
/* C.6.3.1. _plat__NvErrors() */
/* This function is used by the simulator to set the error flags in the NV subsystem to simulate an
   error in the NV loading process */
LIB_EXPORT void
_plat__NvErrors(
		int              recoverable,
		int            unrecoverable
		)
{
    s_NV_unrecoverable = unrecoverable;
    s_NV_recoverable = recoverable;
}
/* C.6.3.2. _plat__NVEnable() */
/* Enable NV memory. */
/* This version just pulls in data from a file. In a real TPM, with NV on chip, this function would
   verify the integrity of the saved context. If the NV memory was not on chip but was in something
   like RPMB, the NV state would be read in, decrypted and integrity checked. */
/* The recovery from an integrity failure depends on where the error occurred. It it was in the
   state that is discarded by TPM Reset, then the error is recoverable if the TPM is
   reset. Otherwise, the TPM must go into failure mode. */
/* Return Values Meaning */
/* 0 if success */
/* > 0 if receive recoverable error */
/* <0 if unrecoverable error */
/*LIB_EXPORT int
_plat__NVEnable(
		void            *platParameter  // IN: platform specific parameters
		)
{
    NOT_REFERENCED(platParameter);          // to keep compiler quiet
    // Start assuming everything is OK
    s_NV_unrecoverable = FALSE;
    s_NV_recoverable = FALSE;
#ifdef FILE_BACKED_NV
    if(s_NVFile != NULL)
	return 0;
    // Try to open an exist NVChip file for read/write
#if defined _MSC_VER && 1
    if(0 != fopen_s(&s_NVFile, "NVChip", "r+b"))
	s_NVFile = NULL;
#else
    s_NVFile = fopen("NVChip", "r+b");
#endif
    if(NULL != s_NVFile)
	{
	    // See if the NVChip file is empty
	    fseek(s_NVFile, 0, SEEK_END);
	    if(0 == ftell(s_NVFile))
		s_NVFile = NULL;
	}
    if(s_NVFile == NULL)
	{
	    // Initialize all the byte in the new file to 0
	    memset(s_NV, 0, NV_MEMORY_SIZE);
	    // If NVChip file does not exist, try to create it for read/write
#if defined _MSC_VER && 1
	    if(0 != fopen_s(&s_NVFile, "NVChip", "w+b"))
		s_NVFile = NULL;
#else
	    s_NVFile = fopen("NVChip", "w+b");
#endif
	    if(s_NVFile != NULL)
		{
		    // Start initialize at the end of new file
		    fseek(s_NVFile, 0, SEEK_END);
		    // Write 0s to NVChip file
		    fwrite(s_NV, 1, NV_MEMORY_SIZE, s_NVFile);
		}
	}
    else
	{
	    // If NVChip file exist, assume the size is correct
	    fseek(s_NVFile, 0, SEEK_END);
	    assert(ftell(s_NVFile) == NV_MEMORY_SIZE);
	    // read NV file data to memory
	    fseek(s_NVFile, 0, SEEK_SET);
	    fread(s_NV, NV_MEMORY_SIZE, 1, s_NVFile);
	}
#endif
    // NV contents have been read and the error checks have been performed. For
    // simulation purposes, use the signaling interface to indicate if an error is
    // to be simulated and the type of the error.
    if(s_NV_unrecoverable)
	return -1;
    return s_NV_recoverable;
}*/

//**Functions

//***_plat__NVEnable()
// Enable NV memory
// return type: int
//      0           if success
//      non-0       if fail
LIB_EXPORT int
_plat__NVEnable(
    void    *platParameter             // IN: platform specific parameters
)
{
    //return 1;
    return  _plat__NVEnable_Path(NULL,NULL);
}

//***_plat__NVEnable_Path()
// Enable NV memory
// return type: int
//      0           if success
//      non-0       if fail

LIB_EXPORT int
_plat__NVEnable_Path(
    void    *platParameter,              // IN: platform specific parameters
	const char *path              // the path of NVChip
)
{
    platParameter = 0;      // to try to satisfy the compiler and remove warning

//    printf("~~~path:%s\n",path);
//    printf("NV_File:%.4x\n",s_NVFile);

/*#ifdef FILE_BACKED_NV

    if(s_NVFile != NULL) return 0;
	
	if(path==NULL)
		path="NVChip";

    // Try to open an exist NVChip file for read/write
    s_NVFile = fopen(path, "r+b");
    if(NULL != s_NVFile)
    {
        // See if the NVChip file is empty
        fseek(s_NVFile, 0, SEEK_END);
        int ret;
        ret = ftell(s_NVFile);
        if(0 == ret){
          s_NVFile = NULL;
        }          
    }

    if(s_NVFile == NULL)
    {
        // Initialize all the byte in the new file to 0
        memset(s_NV, 0, NV_MEMORY_SIZE);

        // If NVChip file does not exist, try to create it for read/write
        s_NVFile = fopen(path, "w+b");
        //fopen(s_NVFile, path, "w+b");
        // Start initialize at the end of new file
        fseek(s_NVFile, 0, SEEK_END);
        // Write 0s to NVChip file
        fwrite(s_NV, 1, NV_MEMORY_SIZE, s_NVFile);

        g_firstUse = 1;
        
		// printf("NVEnable-->s_NVFile == NULL");
    }
    else
    {
      // If NVChip file exist, assume the size is correct
      fseek(s_NVFile, 0, SEEK_END);
      assert(ftell(s_NVFile) == NV_MEMORY_SIZE);
      // read NV file data to memory
      fseek(s_NVFile, 0, SEEK_SET);
      //fread(s_NV, NV_MEMORY_SIZE, 1, s_NVFile);
	}
#endif*/
	return 0;
}



/* C.6.3.3. _plat__NVDisable() */
/* Disable NV memory */
LIB_EXPORT void
_plat__NVDisable(
		 void
		 )
{
#ifdef  FILE_BACKED_NV
    // assert(s_NVFile != NULL);
    if(s_NVFile == NULL){
      abort();
    }
    // Close NV file
    // fclose(s_NVFile);
    // Set file handle to NULL
    // s_NVFile = NULL;
#endif
    return;
}
/* C.6.3.4. _plat__IsNvAvailable() */
/* Check if NV is available */
/* Return Values Meaning */
/* 0 NV is available */
/* 1 NV is not available due to write failure */
/* 2 NV is not available due to rate limit */
LIB_EXPORT int
_plat__IsNvAvailable(
		     void
		     )
{
    // NV is not available if the TPM is in failure mode
    if(!s_NvIsAvailable)
	return 1;
#ifdef FILE_BACKED_NV
    if(s_NVFile == NULL)
	return 1;
#endif
    return 0;
}
/* C.6.3.5. _plat__NvMemoryRead() */
/* Function: Read a chunk of NV memory */
LIB_EXPORT void
_plat__NvMemoryRead(
		    unsigned int     startOffset,   // IN: read start
		    unsigned int     size,          // IN: size of bytes to read
		    void            *data           // OUT: data buffer
		    )
{
    // assert(startOffset + size <= NV_MEMORY_SIZE);
    if(startOffset + size > NV_MEMORY_SIZE){
      abort();
    }
    // Copy data from RAM
    memcpy(data, &s_NV[startOffset], size);
    return;
}
/* C.6.3.6. _plat__NvIsDifferent() */
/* This function checks to see if the NV is different from the test value. This is so that NV will
   not be written if it has not changed. */
/* Return Values Meaning */
/* TRUE(1) the NV location is different from the test value */
/* FALSE(0) the NV location is the same as the test value */
LIB_EXPORT int
_plat__NvIsDifferent(
		     unsigned int     startOffset,   // IN: read start
		     unsigned int     size,          // IN: size of bytes to read
		     void            *data           // IN: data buffer
		     )
{
    return (memcmp(&s_NV[startOffset], data, size) != 0);
}

// 20180303
//***_plat__NvInit()
// Init NV chip
// return type: int
//  0       NV init success
//  non-0   NV init fail
LIB_EXPORT int
_plat__NvInit(uint8_t *qemu_uuid)
{

    memcpy(seal_uuid, qemu_uuid, 16);
    TPM_RESULT  rc = 0;

    _plat__SetNvAvail();

    //struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();
     /* call user-provided function if available, otherwise execute
       default behavior */
    //ocall_tpm_ltpms_nvram_init(&rc);
    tpm_ltpms_nvram_init(&rc);
/*    if (cbs->tpm_nvram_init) {
            rc = cbs->tpm_nvram_init();

     }*/
    return rc;
}

/*LIB_EXPORT int
ecall_plat__NvInit(void)
{
    TPM_RESULT  rc = 0;

    _plat__SetNvAvail();

    struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();
     // call user-provided function if available, otherwise execute
       // default behavior 
        if (cbs->tpm_nvram_init) {
            rc = cbs->tpm_nvram_init();
     }
    return rc;
}*/


/* C.6.3.7. _plat__NvMemoryWrite() */
/* This function is used to update NV memory. The write is to a memory copy of NV. At the end of the
   current command, any changes are written to the actual NV memory. */
/* NOTE: A useful optimization would be for this code to compare the current contents of NV with the
   local copy and note the blocks that have changed. Then only write those blocks when
   _plat__NvCommit() is called. */
LIB_EXPORT void
_plat__NvMemoryWrite(
		     unsigned int     startOffset,   // IN: write start
		     unsigned int     size,          // IN: size of bytes to write
		     void            *data           // OUT: data buffer
		     )
{
    // assert(startOffset + size <= NV_MEMORY_SIZE);
    if(startOffset + size > NV_MEMORY_SIZE){
      abort();
    }
    // Copy the data to the NV image
    memcpy(&s_NV[startOffset], data, size);
}
/* C.6.3.8. _plat__NvMemoryClear() */
/* Function is used to set a range of NV memory bytes to an implementation-dependent value. The
   value represents the erase state of the memory. */
LIB_EXPORT void
_plat__NvMemoryClear(
		     unsigned int     start,         // IN: clear start
		     unsigned int     size           // IN: number of bytes to clear
		     )
{
    //assert(start + size <= NV_MEMORY_SIZE);
    if(start + size > NV_MEMORY_SIZE){
      abort();
    }
    // In this implementation, assume that the errase value for NV is all 1s
    memset(&s_NV[start], 0xff, size);
}
/* C.6.3.9. _plat__NvMemoryMove() */
/* Function: Move a chunk of NV memory from source to destination This function should ensure that
   if there overlap, the original data is copied before it is written */
LIB_EXPORT void
_plat__NvMemoryMove(
		    unsigned int     sourceOffset,  // IN: source offset
		    unsigned int     destOffset,    // IN: destination offset
		    unsigned int     size           // IN: size of data being moved
		    )
{
    // assert(sourceOffset + size <= NV_MEMORY_SIZE);
    if(sourceOffset + size > NV_MEMORY_SIZE){
      abort();
    }
    // assert(destOffset + size <= NV_MEMORY_SIZE);
    if(destOffset + size > NV_MEMORY_SIZE){
      abort();
    }
    // Move data in RAM
    memmove(&s_NV[destOffset], &s_NV[sourceOffset], size);
    return;
}

/* C.6.3.10. _plat__NvCommit() */
/* Update NV chip */
/* Return Values Meaning */
/* 0 NV write success */
/* non-0 NV write fail */
/*LIB_EXPORT int
_plat__NvCommit(
		void
		)
{
#ifdef FILE_BACKED_NV
    // If NV file is not available, return failure
    if(s_NVFile == NULL)
	return 1;
    // Write RAM data to NV
    fseek(s_NVFile, 0, SEEK_SET);
    fwrite(s_NV, 1, NV_MEMORY_SIZE, s_NVFile);
    return 0;
#else
    return 0;
#endif
}*/
/*int init_seal_data(){

}*/

int libtpms_seal_nvram()
{
    unsigned int ret = 0;
    unsigned int s_NV_len = NV_MEMORY_SIZE;
    s_NV_sealed_len = 16960;
    /*s_NV_sealed_len = sgx_calc_sealed_data_size(0, s_NV_len);
      if (0xFFFFFFFF == s_NV_sealed_len) {
        return ret;
    }*/
    if(s_NV_sealed == NULL){
        s_NV_sealed = (sgx_sealed_data_t *)malloc(s_NV_sealed_len * sizeof(uint8_t));
    }

    sgx_attributes_t attribute_mask;
    attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
    attribute_mask.xfrm = 0x0;  
    // if (SGX_SUCCESS != sgx_seal_data(0, NULL, s_NV_len, s_NV, s_NV_sealed_len, s_NV_sealed)) {
/*    if (SGX_SUCCESS != sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE, attribute_mask, TSEAL_DEFAULT_MISCMASK, 0, NULL, s_NV_len, s_NV, s_NV_sealed_len, s_NV_sealed)) {
        abort();
        //return ret;
    }*/
    //int size = sgx_calc_sealed_data_size(16, 16384);
    sgx_status_t rs = sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE, attribute_mask, TSEAL_DEFAULT_MISCMASK, 16, seal_uuid, s_NV_len, s_NV, s_NV_sealed_len, s_NV_sealed);
    if (SGX_SUCCESS != rs) {
        abort();
        //return ret;
    }
    //free(s_NV_sealed);
    return ret;
}

int libtpms_unseal_nvram(unsigned char *data)
{
    unsigned int ret = 0;
    //len = sgx_calc_sealed_data_size(add_len, txt_len);
    //unsigned int s_NV_unsealed_len = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)data);
    unsigned int s_NV_unsealed_len = NV_MEMORY_SIZE;
    if(s_NV_unsealed == NULL){
      s_NV_unsealed = (uint8_t *)malloc(s_NV_unsealed_len * sizeof(uint8_t));
    }
    uint8_t add_mac[16];
    uint32_t mac_lenghth = sgx_get_add_mac_txt_len(data);
    sgx_status_t rc = sgx_unseal_data((sgx_sealed_data_t *)data, add_mac, &mac_lenghth, s_NV_unsealed, &s_NV_unsealed_len);
    if (SGX_SUCCESS != rc || memcmp(add_mac, unseal_uuid, 16) != 0) {
        abort();
    }
    //free(s_NV_unsealed);
    return ret;
}


// 20180303
//***_plat__NvCommit()
// Update NV chip
// return type: int
//  0       NV write success
//  non-0   NV write fail
LIB_EXPORT int
_plat__NvCommit(void)
{
#ifdef FILE_BACKED_NV
    int rc;
    // If NV file is not available, return failure
    if(s_NVFile == NULL || s_NvIsAvailable == FALSE)
    {
        // printf("NV_File:%.4x,available:%d\n",s_NVFile,s_NvIsAvailable);
        return 1;
    }

    //struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();
     //call user-provided function if available, otherwise execute
      // default behavior 
    libtpms_seal_nvram();
        //rc = cbs->tpm_nvram_storedata((unsigned char *)s_NV_sealed,s_NV_sealed_len,0,"permall");
    //ocall_tpm_ltpms_nvram_storedata(&rc, (unsigned char *)s_NV_sealed, s_NV_sealed_len, 0, "permall");
    tpm_ltpms_nvram_storedata(&rc, (unsigned char *)s_NV_sealed, s_NV_sealed_len, 0, "permall");
        //cbs->tpm_nvram_storedata(s_NV,NV_MEMORY_SIZE,0,"permall");
    if(rc != 0){
        abort();
    }
/*     if (cbs->tpm_nvram_storedata) {
        libtpms_seal_nvram();
        //rc = cbs->tpm_nvram_storedata((unsigned char *)s_NV_sealed,s_NV_sealed_len,0,"permall");
        ocall_tpm_ltpms_nvram_storedata(&rc, (unsigned char *)s_NV_sealed, s_NV_sealed_len, 0, "permall");
        //cbs->tpm_nvram_storedata(s_NV,NV_MEMORY_SIZE,0,"permall");
        if(rc != 0){
          abort();
        }
      }*/

    return 0;
#else
    return 0;
#endif

}


// 20180303
//***_plat__NvLoad()
// Update NV chip
// return type: int
//  0       NV load success
//  non-0   NV load fail
LIB_EXPORT int
_plat__NvLoad(uint8_t* qemu_uuid)
{
#ifdef FILE_BACKED_NV
    //struct libtpms_callbacks *cbs = TPMLIB_GetCallbacks();
     /* call user-provided function if available, otherwise execute
       default behavior */
    uint32_t length = 0;    
    uint32_t rc;
    unsigned char *data=NULL;
    if(data == NULL){
      data = malloc(16960 * sizeof(uint8_t));
    }
    //ocall_tpm_ltpms_nvram_loaddata(&rc, data, &length, 0, "permall");
    tpm_ltpms_nvram_loaddata(&rc, data, &length, 0, "permall");
/*    if (cbs->tpm_nvram_loaddata) {       
        // rc=cbs->tpm_nvram_loaddata(&data,&length,0,"permall");
        // rc = cbs->tpm_nvram_loaddata(&data, &length, 0, "permall");
        ocall_tpm_ltpms_nvram_loaddata(&rc, &data, &length, 0, "permall");
        
    }*/
    if(rc == 0){
        memcpy(unseal_uuid, qemu_uuid, 16);
        //ocall_getTime();
        libtpms_unseal_nvram(data);
        //ocall_getTime();
        memcpy(s_NV, s_NV_unsealed, NV_MEMORY_SIZE);
        //memcpy(s_NV, data, length);
    }
    free(data);    
    return 0;
#else
    return 0;
#endif
}


/* C.6.3.11. _plat__SetNvAvail() */
/* Set the current NV state to available.  This function is for testing purpose only.  It is not
   part of the platform NV logic */
LIB_EXPORT void
_plat__SetNvAvail(
		  void
		  )
{
    s_NvIsAvailable = TRUE;
    return;
}
/* C.6.3.12. _plat__ClearNvAvail() */
/* Set the current NV state to unavailable.  This function is for testing purpose only.  It is not
   part of the platform NV logic */
LIB_EXPORT void
_plat__ClearNvAvail(
		    void
		    )
{
    s_NvIsAvailable = FALSE;
    return;
}


