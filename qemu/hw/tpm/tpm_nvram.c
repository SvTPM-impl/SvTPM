/*
 * TPM NVRAM - enables storage of persistent NVRAM data on an image file
 *
 * Copyright (C) 2013 IBM Corporation
 *
 * Authors:
 *  Stefan Berger    <address@hidden>
 *  Corey Bryant     <address@hidden>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "tpm_nvram.h"
#include "block/block_int.h"
#include "qemu/thread.h"
#include "sysemu/sysemu.h"

#include <libtpms2/tpm_store.h>

#define TPM_SUCCESS 0x0

#define TPM_NVRAM_DEBUG 0
#define DPRINTF(fmt, ...) \
    do { \
        if (TPM_NVRAM_DEBUG) { \
            fprintf(stderr, fmt, ## __VA_ARGS__); \
        } \
    } while (0)

/* Read/write request data */
typedef struct TPMNvramRWRequest {
    BlockDriverState *bdrv;
    bool is_write;
    uint64_t offset;
    uint8_t **blob_r;
    uint8_t *blob_w;
    uint32_t size;
    int rc;

    QemuMutex completion_mutex;
    QemuCond completion;

    QSIMPLEQ_ENTRY(TPMNvramRWRequest) list;
} TPMNvramRWRequest;

/* Mutex protected queue of read/write requests */
static QemuMutex tpm_nvram_rwrequests_mutex;
static QSIMPLEQ_HEAD(, TPMNvramRWRequest) tpm_nvram_rwrequests =
    QSIMPLEQ_HEAD_INITIALIZER(tpm_nvram_rwrequests);

static QEMUBH *tpm_nvram_bh;

/*
 * Get the disk size in kilobytes needed to store a blob (rounded up to next 
b)
 */
static uint64_t tpm_nvram_required_size_kb(uint64_t offset, uint32_t size)
{
    uint64_t required_size = offset + size;
    return DIV_ROUND_UP(required_size, 1024);
}

/*
 * Increase the drive size if it's too small to store the blob
 */
static int tpm_nvram_adjust_size(BlockDriverState *bdrv, uint64_t offset,
                                 uint32_t size)
{
    int rc = 0;
    int64_t drive_size, required_size;

    rc = bdrv_getlength(bdrv);
    if (rc < 0) {
        DPRINTF("%s: Unable to determine TPM NVRAM drive size\n", __func__);
        return rc;
    }

    drive_size = rc;
    required_size = tpm_nvram_required_size_kb(offset, size) * 1024;

    if (drive_size < required_size) {
        rc = bdrv_truncate(bdrv, required_size);
        if (rc < 0) {
            DPRINTF("%s: TPM NVRAM drive too small\n", __func__);
        }
    }

    return rc;
}

/*
 * Coroutine that reads a blob from the drive asynchronously
 */
static void coroutine_fn tpm_nvram_co_read(void *opaque)
{
    int rc;
    TPMNvramRWRequest *rwr = opaque;

    rc = TPM_Malloc((unsigned char **)rwr->blob_r, rwr->size);
    if (rc != TPM_SUCCESS) {
        goto exit;
    }

    rc = bdrv_pread(rwr->bdrv, rwr->offset, *rwr->blob_r, rwr->size);
    if (rc != rwr->size) {
        TPM_Free(*rwr->blob_r);
        *rwr->blob_r = NULL;
    }

exit:
    qemu_mutex_lock(&rwr->completion_mutex);
    rwr->rc = rc;
    qemu_cond_signal(&rwr->completion);
    qemu_mutex_unlock(&rwr->completion_mutex);
}

/*
 * Coroutine that writes a blob to the drive asynchronously
 */
static void coroutine_fn tpm_nvram_co_write(void *opaque)
{
    int rc;
    TPMNvramRWRequest *rwr = opaque;

    rc = tpm_nvram_adjust_size(rwr->bdrv, rwr->offset, rwr->size);
    if (rc < 0) {
        goto exit;
    }

    rc = bdrv_pwrite(rwr->bdrv, rwr->offset, rwr->blob_w, rwr->size);

exit:
    qemu_mutex_lock(&rwr->completion_mutex);
    rwr->rc = rc;
    qemu_cond_signal(&rwr->completion);
    qemu_mutex_unlock(&rwr->completion_mutex);
}

/*
 * Enter a coroutine to read a blob from the drive
 */
static void tpm_nvram_do_co_read(TPMNvramRWRequest *rwr)
{
    Coroutine *co;

    co = qemu_coroutine_create(tpm_nvram_co_read);
    qemu_coroutine_enter(co, rwr);
}

/*
 * Enter a coroutine to write a blob to the drive
 */
static void tpm_nvram_do_co_write(TPMNvramRWRequest *rwr)
{
    Coroutine *co;

    co = qemu_coroutine_create(tpm_nvram_co_write);
    qemu_coroutine_enter(co, rwr);
}

/*
 * Initialization for read requests
 */
static TPMNvramRWRequest *tpm_nvram_rwrequest_init_read(BlockDriverState *bdrv,
                                                        uint64_t offset,
                                                        uint8_t **blob,
                                                        uint32_t size)
{
    TPMNvramRWRequest *rwr;

    rwr = g_new0(TPMNvramRWRequest, 1);
    rwr->bdrv = bdrv;
    rwr->is_write = false;
    rwr->offset = offset;
    rwr->blob_r = blob;
    rwr->size = size;
    rwr->rc = -EINPROGRESS;

    qemu_mutex_init(&rwr->completion_mutex);
    qemu_cond_init(&rwr->completion);

    return rwr;
}

/*
 * Initialization for write requests
 */
static TPMNvramRWRequest *tpm_nvram_rwrequest_init_write(BlockDriverState *bdrv,
                                                         uint64_t offset,
                                                         uint8_t *blob,
                                                         uint32_t size)
{
    TPMNvramRWRequest *rwr;

    rwr = g_new0(TPMNvramRWRequest, 1);
    rwr->bdrv = bdrv;
    rwr->is_write = true;
    rwr->offset = offset;
    rwr->blob_w = blob;
    rwr->size = size;
    rwr->rc = -EINPROGRESS;

    qemu_mutex_init(&rwr->completion_mutex);
    qemu_cond_init(&rwr->completion);

    return rwr;
}

/*
 * Execute a read or write of TPM NVRAM blob data
 */
static void tpm_nvram_rwrequest_exec(TPMNvramRWRequest *rwr)
{
    if (rwr->is_write) {
        tpm_nvram_do_co_write(rwr);
    } else {
        tpm_nvram_do_co_read(rwr);
    }
}

/*
 * Bottom-half callback that is invoked by QEMU's main thread to
 * process TPM NVRAM read/write requests.
 */
static void tpm_nvram_rwrequest_callback(void *opaque)
{
    TPMNvramRWRequest *rwr, *next;

    qemu_mutex_lock(&tpm_nvram_rwrequests_mutex);

    QSIMPLEQ_FOREACH_SAFE(rwr, &tpm_nvram_rwrequests, list, next) {
        QSIMPLEQ_REMOVE(&tpm_nvram_rwrequests, rwr, TPMNvramRWRequest, list);

        qemu_mutex_unlock(&tpm_nvram_rwrequests_mutex);
        tpm_nvram_rwrequest_exec(rwr);
        qemu_mutex_lock(&tpm_nvram_rwrequests_mutex);
    }

    qemu_mutex_unlock(&tpm_nvram_rwrequests_mutex);
}

/*
 * Schedule a bottom-half to read or write a blob to the TPM NVRAM drive
 */
static void tpm_nvram_rwrequest_schedule(TPMNvramRWRequest *rwr)
{
    qemu_mutex_lock(&tpm_nvram_rwrequests_mutex);
    QSIMPLEQ_INSERT_TAIL(&tpm_nvram_rwrequests, rwr, list);
    qemu_mutex_unlock(&tpm_nvram_rwrequests_mutex);

    qemu_bh_schedule(tpm_nvram_bh);

    // Wait for completion of the read/write request
    qemu_mutex_lock(&rwr->completion_mutex);
    while (rwr->rc == -EINPROGRESS) {
        qemu_cond_wait(&rwr->completion, &rwr->completion_mutex);
    }
    qemu_mutex_unlock(&rwr->completion_mutex);
}

/*
 * Initialize a TPM NVRAM drive
 */
int tpm_nvram_bdrv_init(BlockDriverState *bdrv)
{
    qemu_mutex_init(&tpm_nvram_rwrequests_mutex);
    tpm_nvram_bh = qemu_bh_new(tpm_nvram_rwrequest_callback, NULL);

    if (bdrv_is_read_only(bdrv)) {
        DPRINTF("%s: TPM NVRAM drive '%s' is read-only\n", __func__,
                bdrv->filename);
        return -EPERM;
    }

    bdrv_lock_medium(bdrv, true);

    DPRINTF("%s: TPM NVRAM drive '%s' initialized successfully\n", __func__,
            bdrv->filename);

    return 0;
}

/*
 * Read a TPM NVRAM blob from the drive
 */
int tpm_nvram_bdrv_read(BlockDriverState *bdrv, uint64_t offset,
                        uint8_t **blob, uint32_t size)
{
    int rc;
    TPMNvramRWRequest *rwr;

    if (!tpm_nvram_bh) {
        DPRINTF("%s: tpm_nvram_bdrv_init must be called first\n", __func__);
        return -EPERM;
    }

    *blob = NULL;

    rwr = tpm_nvram_rwrequest_init_read(bdrv, offset, blob, size);
    tpm_nvram_rwrequest_schedule(rwr);
    rc = rwr->rc;

    if (rc != rwr->size) {
        DPRINTF("%s: TPM NVRAM read failed\n", __func__);
    } else {
        DPRINTF("%s: TPM NVRAM read successful: offset=%"PRIu64", "
                "size=%"PRIu32"\n", __func__, rwr->offset, rwr->size);
    }

    g_free(rwr);
    return rc;
}

/*
 * Write a TPM NVRAM blob to the drive
 */
int tpm_nvram_bdrv_write(BlockDriverState *bdrv, uint64_t offset,
                         uint8_t *blob, uint32_t size)
{
    int rc;
    TPMNvramRWRequest *rwr;

    if (!tpm_nvram_bh) {
        DPRINTF("%s: tpm_nvram_bdrv_init must be called first\n", __func__);
        return -EPERM;
    }

    rwr = tpm_nvram_rwrequest_init_write(bdrv, offset, blob, size);
    tpm_nvram_rwrequest_schedule(rwr);
    rc = rwr->rc;

    if (rc != rwr->size) {
        DPRINTF("%s: TPM NVRAM write failed\n", __func__);
    } else {
        DPRINTF("%s: TPM NVRAM write successful: offset=%"PRIu64", "
                "size=%"PRIu32"\n", __func__, rwr->offset, rwr->size);
    }

    g_free(rwr);
    return rc;
}
