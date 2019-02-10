/*(Copyright)

        Microsoft Copyright 2009, 2010, 2011, 2012, 2013
        Confidential Information

*/

#ifndef    PLATFORM_H
#define    PLATFORM_H

//** Includes
#include "bool.h"
#include "stdint.h"

//****************************************************************************
//** Power Functions
//****************************************************************************

//***_plat__Signal_PowerOn
// Signal power on
//      This signal is simulate by a RPC call
void
_plat__Signal_PowerOn(void);

//***_plat__Signal_PowerOff()
// Signal power off
//      This signal is simulate by a RPC call
void
_plat__Signal_PowerOn_Path(const char * path);
//***_plat__Signal_PowerOff()
// Signal power off
//      This signal is simulate by a RPC call
void
_plat__Signal_PowerOff(void);

//****************************************************************************
//** Physical Presence Functions
//****************************************************************************

//***_plat__PhysicalPresenceAsserted()
// Check if physical presence is signaled
// return type: BOOL
//      TRUE          if physical presence is signaled
//      FALSE         if physical presence is not signaled
BOOL
_plat__PhysicalPresenceAsserted(void);

//***_plat__Signal_PhysicalPresenceOn
// Signal physical presence on
//      This signal is simulate by a RPC call
void
_plat__Signal_PhysicalPresenceOn(void);

//***_plat__Signal_PhysicalPresenceOff()
// Signal physical presence off
//      This signal is simulate by a RPC call
void
_plat__Signal_PhysicalPresenceOff(void);

//****************************************************************************
//** Command Canceling Functions
//****************************************************************************
//***_plat__IsCanceled()
// Check if the cancel flag is set
// return type: BOOL
//      TRUE          if cancel flag is set
//      FALSE         if cancel flag is not set
BOOL
_plat__IsCanceled(void);

//***_plat__SetCancel()

// Set cancel flag.
void
_plat__SetCancel(void);

//***_plat__ClearCancel()
// Clear cancel flag
void
_plat__ClearCancel( void);


//****************************************************************************
//** NV memory functions
//****************************************************************************

//***_plat__NVEnable()
// Enable platform NV memory
// NV memory is automatically enabled at power on event.  This function is
// mostly for TPM_Manufacture to access NV memory without a power on event
// return type: int
//      0           if success
//      non-0       if fail
int
_plat__NVEnable(
    void    *platParameter              // IN: platform specific parameters
);

//***_plat__NVEnable_Path()
// Enable platform NV memory
// NV memory is automatically enabled at power on event.  This function is
// mostly for TPM_Manufacture to access NV memory without a power on event
// return type: int
//      0           if success
//      non-0       if fail
int
_plat__NVEnable_Path(
    void    *platParameter,              // IN: platform specific parameters
	const char * path              // the path of NVChip
);

//***_plat__NVDisable()
// Disable platform NV memory
// NV memory is automatically disabled at power off event.  This function is
// mostly for TPM_Manufacture to disable NV memory without a power off event
void
_plat__NVDisable(void);

//***_plat__IsNvAvailable()
// Check if NV is available
// return type: int
//      0               NV is available
//      1               NV is not available due to write failure
//      2               NV is not available due to rate limit
int
_plat__IsNvAvailable(void);

//***_plat__NvInit()
// Init NV chip
// return type: int
//  0       NV init success
//  non-0   NV init fail
int
_plat__NvInit(void);

//***_plat__NvCommit()
// Update NV chip
// return type: int
//  0       NV write success
//  non-0   NV write fail
int
_plat__NvCommit(void);

//***_plat__NvLoad()
// Update NV chip
// return type: int
//  0       NV load success
//  non-0   NV load fail
int
_plat__NvLoad(void);

//***_plat__NvMemoryRead()
// Read a chunk of NV memory
void
_plat__NvMemoryRead(
    unsigned int        startOffset,         // IN: read start
    unsigned int        size,                // IN: size of bytes to read
    void                *data                // OUT: data buffer
);

//*** _plat__NvIsDifferent()
// This function checks to see if the NV is different from the test value. This is
// so that NV will not be written if it has not changed.
// return value: BOOL
//  TRUE    the NV location is different from the test value
//  FALSE   the NV location is the same as the test value
BOOL
_plat__NvIsDifferent(
    unsigned int         startOffset,         // IN: read start
    unsigned int         size,                // IN: size of bytes to compare
    void                *data                 // IN: data buffer
    );

//***_plat__NvMemoryWrite()
// Write a chunk of NV memory
void
_plat__NvMemoryWrite(
    unsigned int        startOffset,         // IN: read start
    unsigned int        size,                // IN: size of bytes to read
    void                *data                // OUT: data buffer
);

//***_plat__NvMemoryMove()
// Move a chunk of NV memory from source to destination
//      This function should ensure that if there overlap, the original data is
//      copied before it is written
void
_plat__NvMemoryMove(
    unsigned int        sourceOffset,         // IN: source offset
    unsigned int        destOffset,           // IN: destination offset
    unsigned int        size                  // IN: size of data being moved
);

//***_plat__SetNvAvail()
// Set the current NV state to available.  This function is for testing purposes
// only.  It is not part of the platform NV logic
void
_plat__SetNvAvail(void);

//***_plat__ClearNvAvail()
// Set the current NV state to unavailable.  This function is for testing purposes
// only.  It is not part of the platform NV logic
void
_plat__ClearNvAvail(void);

//****************************************************************************
//** Locality Functions
//****************************************************************************

//***_plat__LocalityGet()
// Get the most recent command locality in locality value form
unsigned char
_plat__LocalityGet(void);

//***_plat__LocalitySet()
// Set the most recent command locality in locality value form
void
_plat__LocalitySet(
    unsigned char   locality
);


//-+
//****************************************************************************
//** RSA Key Cache Control
//***************************************************************************
//*** _plat__RsaKeyCacheControl()
// This function is used to set the key RsaKeyCache control state.
void
_plat__RsaKeyCacheControl(
    int    state
    );
//--

//*** _plat__IsRsaKeyCacheEnabled()
// This function is used to check if the RSA key cache is enabled or not.
int
_plat__IsRsaKeyCacheEnabled(
    void
    );


//****************************************************************************
//** Clock Constants and Functions
//****************************************************************************

// Assume that the nominal divisor is 30000
#define     CLOCK_NOMINAL           30000
// A 1% change in rate is 300 counts
#define     CLOCK_ADJUST_COARSE     300
// A .1 change in rate is 30 counts
#define     CLOCK_ADJUST_MEDIUM     30
// A minimum change in rate is 1 count
#define     CLOCK_ADJUST_FINE       1
// The clock tolerance is +/-15% (4500 counts)
// Allow some guard band (16.7%)
#define     CLOCK_ADJUST_LIMIT      5000

//*** _plat__ClockReset()
// This function sets the current clock time as initial time.  This function is 
// called at a power on event to reset the clock
void
_plat__ClockReset(void);

//*** _plat__ClockTimeFromStart()
// Function returns the compensated time from the start of the command when 
// _plat__ClockTimeFromStart() was called.
unsigned long long
_plat__ClockTimeFromStart(
    void
    );

//***_plat__ClockTimeElapsed()
// Get the time elapsed from current to the last time the _plat__ClockTimeElapsed
// is called.  For the first _plat__ClockTimeElapsed call after a power on
// event, this call report the elapsed time from power on to the current call
unsigned long long
_plat__ClockTimeElapsed(void);

//***_plat__ClockAdjustRate()
// Adjust the clock rate
void
_plat__ClockAdjustRate(
    int         adjust              // IN: the adjust number.  It could be 
                                    // positive or negative
    );

//** Single Function Files

//****************************************************************************
//********** Entropy Constants and Functions
//****************************************************************************
//** _plat__GetEntropy()
// This funtion is used to get available hardare entropy. In a hardware
// implementation of this function, there would be no call to the system
// to get entropy.
// If the caller does not ask for any entropy, then this is a startup indication
// and 'firstValue' should be reset.

// return type: int32_t
//  < 0        hardare failure of the entropy generator, this is sticky
// >= 0          the returned amount of entropy (bytes)
//
int32_t
_plat__GetEntropy(
    unsigned char       *entropy,           // output buffer
    uint32_t             amount             // amount requested
);


//****************************************************************************
//*********** Failure Mode
//****************************************************************************
// *** _plat__TpmFail()
// Put TPM in failure mode.
int
_plat__TpmFail(
    const char      *function, 
    int              line, 
    int              code);

//-+
//****************************************************************************
//********** Unique
//****************************************************************************
// *** _plat__GetUnique
// Get the device unique value
uint32_t
_plat__GetUnique(
    uint32_t             bSize,         // size of the buffer
    unsigned char       *b              // output buffer
);
//--

#endif
