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

#ifndef TPM_TPM_NVRAM_H
#define TPM_TPM_NVRAM_H

#include "block/block.h"

int tpm_nvram_bdrv_init(BlockDriverState *bdrv);
int tpm_nvram_bdrv_read(BlockDriverState *bdrv, uint64_t offset,
                        uint8_t **blob, uint32_t size);
int tpm_nvram_bdrv_write(BlockDriverState *bdrv, uint64_t offset,
                         uint8_t *blob, uint32_t size);

#endif
