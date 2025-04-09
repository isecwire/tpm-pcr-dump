/*
 * tpm-pcr-dump — TPM 2.0 interface layer
 *
 * Reads PCR values from sysfs or by invoking tpm2_pcrread as fallback.
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#ifndef TPM_INTERFACE_H
#define TPM_INTERFACE_H

#include "tpm_pcr_dump.h"

/* TPM access method (auto-detected or forced) */
typedef enum {
    TPM_METHOD_AUTO,     /* try sysfs first, then tpm2-tools          */
    TPM_METHOD_SYSFS,    /* /sys/class/tpm/tpm0/pcr-<bank>/<index>    */
    TPM_METHOD_TOOLS,    /* shell out to tpm2_pcrread                  */
} tpm_method_t;

/* Opaque context — stack-allocated, no heap */
typedef struct {
    tpm_method_t method;
    char         sysfs_base[TPM_PATH_MAX];
    bool         opened;
} tpm_ctx_t;

/*
 * Initialise the TPM context.  Probes for available access methods.
 * Returns TPM_OK on success.
 */
tpm_err_t tpm_open(tpm_ctx_t *ctx, tpm_method_t preferred);

/*
 * Release the TPM context.
 */
void tpm_close(tpm_ctx_t *ctx);

/*
 * Read a single PCR value.
 * pcr must point to a valid tpm_pcr_value_t; digest_len is set
 * according to the bank.
 */
tpm_err_t tpm_read_pcr(tpm_ctx_t *ctx, tpm_bank_t bank,
                        int index, tpm_pcr_value_t *pcr);

/*
 * Read all 24 PCRs for the given bank.
 */
tpm_err_t tpm_read_all_pcrs(tpm_ctx_t *ctx, tpm_bank_t bank,
                             tpm_pcr_set_t *set);

#endif /* TPM_INTERFACE_H */
