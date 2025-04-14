/*
 * tpm-pcr-dump — PCR verification against golden values
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#ifndef PCR_VERIFY_H
#define PCR_VERIFY_H

#include "tpm_pcr_dump.h"

/* Maximum path length for the config file */
#define PCR_VERIFY_PATH_MAX  512

/* A single expected PCR entry */
typedef struct {
    int     index;
    uint8_t digest[TPM_MAX_DIGEST_SIZE];
    size_t  digest_len;
    bool    present;  /* true if this entry was loaded from config */
} pcr_expected_t;

/* Full set of expected values */
typedef struct {
    pcr_expected_t entries[TPM_PCR_COUNT];
    tpm_bank_t     bank;
    int            count;   /* number of entries with present == true */
} pcr_golden_t;

/* Verification result for one PCR */
typedef struct {
    int  index;
    bool match;
    char expected_hex[TPM_MAX_HEX_SIZE];
    char actual_hex[TPM_MAX_HEX_SIZE];
} pcr_mismatch_t;

/* Overall verification report */
typedef struct {
    pcr_mismatch_t results[TPM_PCR_COUNT];
    int            total_checked;
    int            total_matched;
    int            total_mismatched;
    uint8_t        composite_hash[TPM_MAX_DIGEST_SIZE];
    size_t         composite_len;
    char           composite_hex[TPM_MAX_HEX_SIZE];
} pcr_report_t;

/*
 * Load expected PCR values from a JSON-like config file.
 * Format:
 *   { "bank": "sha256",
 *     "pcrs": { "0": "hex...", "7": "hex...", ... } }
 */
tpm_err_t pcr_golden_load(const char *path, pcr_golden_t *golden);

/*
 * Verify a measured PCR set against golden values.
 * Fills in report with match/mismatch details.
 */
tpm_err_t pcr_verify(const tpm_pcr_set_t *measured,
                      const pcr_golden_t  *golden,
                      pcr_report_t        *report);

/*
 * Compute a composite hash over all valid PCRs in the set.
 * Uses SHA-256 (via OpenSSL) regardless of the PCR bank.
 */
tpm_err_t pcr_composite_hash(const tpm_pcr_set_t *set,
                              uint8_t *out, size_t *out_len);

#endif /* PCR_VERIFY_H */
