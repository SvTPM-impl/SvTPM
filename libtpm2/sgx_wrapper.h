
typedef void FILE;

#define TPM_VolatileAll_Store(a) ecall_TPM_VolatileAll_Store(a)
#define TPM_VolatileAll_Load(a,b) ecall_TPM_VolatileAll_Load(a,b)
#define ExecuteCommand(a,b,c,d) ecall_ExecuteCommand(a,b,c,d)
#define _plat__NVEnable_Path(a,b) ecall_plat__NVEnable_Path(a,b)
#define _plat__LocalitySet(a) ecall_plat__LocalitySet(a)
#define _plat__Signal_PowerOff(a) ecall_plat__Signal_PowerOff(a)
#define TPM_Manufacture(a) ecall_TPM_Manufacture(a)
#define _plat__NvInit(a) ecall_plat__NvInit(a)
#define _plat__NvLoad(a) ecall_plat__NvLoad(a)
#define _plat__Signal_PowerOn(a) ecall_plat__Signal_PowerOn(a)
#define _TPM_Init(a) ecall_TPM_Init(a) 


#define fopen(a,b) sgx_fopen_auto_key(a,b)
// #define fopen(a,b) sgx_fopen(a,b)
#define fread(a,b,c,d) sgx_fread(a,b,c,d)
#define fwrite(a,b,c,d) sgx_fwrite(a,b,c,d)
#define fseek(a,b,c) sgx_fseek(a,b,c)
#define ftell(a) sgx_ftell(a)
#define fclose(a) sgx_fclose(a)

/*#define memcpy(a,b,c) memcpy_s(a,c,b,c)
#define memcpy memcpy_s*/

// #define rand(a,b) sgx_read_rand(a,b)
//#define fopen(a,b) ocall_fopen(a,b)
/*#define fread(a,b,c,d) ocall_fread(a,b,c,d)
#define fwrite(a,b,c,d) ocall_fwrite(a,b,c,d)*/

//#define rand(a) ocall_rand(a)
#define gettimeofday(a,b) ocall_gettimeofday(a,b)
#define tpm_ltpms_nvram_init(a) ocall_tpm_ltpms_nvram_init(a) 
#define tpm_ltpms_nvram_storedata(a,b,c,d,e) ocall_tpm_ltpms_nvram_storedata(a,b,c,d,e)
#define tpm_ltpms_nvram_loaddata(a,b,c,d,e) ocall_tpm_ltpms_nvram_loaddata(a,b,c,d,e)