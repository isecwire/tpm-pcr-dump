/*
 * tpm-pcr-dump — Attestation helpers
 *
 * Helpers for TPM2_Quote generation and verification, and
 * structured attestation report generation.
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#ifndef TPM_ATTESTATION_H
#define TPM_ATTESTATION_H

#include "tpm_pcr_dump.h"
#include "event_log.h"

/* Maximum nonce size */
#define ATTEST_NONCE_MAX  64

/* PCR selection bitmap (24 PCRs = 3 bytes) */
#define PCR_SELECT_BYTES  3

/* PCR selection structure (mirrors TPMS_PCR_SELECTION) */
typedef struct {
    uint16_t hash_alg;
    uint8_t  size_of_select;
    uint8_t  pcr_select[PCR_SELECT_BYTES];
} pcr_selection_t;

/* Quote preparation structure */
typedef struct {
    uint8_t         nonce[ATTEST_NONCE_MAX];
    size_t          nonce_len;
    pcr_selection_t selection;
    tpm_bank_t      bank;
    /* PCR composite digest (Hash of selected PCR values) */
    uint8_t         pcr_digest[TPM_MAX_DIGEST_SIZE];
    size_t          pcr_digest_len;
} quote_params_t;

/* Attestation report sections */
typedef struct {
    /* System information */
    char     hostname[256];
    char     timestamp[64];
    char     kernel_version[256];

    /* TPM information */
    tpm_bank_t bank;
    int        pcr_count;

    /* PCR values */
    tpm_pcr_set_t pcrs;

    /* Event log summary */
    int      event_count;
    bool     event_log_available;
    bool     event_log_verified;
    int      events_per_pcr[TPM_PCR_COUNT];

    /* Verification status */
    bool     golden_verified;
    int      golden_matched;
    int      golden_mismatched;

    /* Quote parameters (if generated) */
    bool     quote_prepared;
    quote_params_t quote;
} attest_report_t;

/*
 * Generate a random nonce for TPM2_Quote.
 */
tpm_err_t attest_generate_nonce(uint8_t *nonce, size_t len);

/*
 * Build a PCR selection structure for specified PCR indices.
 * pcr_mask is a 24-bit mask where bit N = select PCR N.
 */
void attest_build_selection(pcr_selection_t *sel, tpm_bank_t bank,
                             uint32_t pcr_mask);

/*
 * Compute the PCR composite digest over selected PCRs.
 * This is the digest that would appear in a TPM2_Quote.
 */
tpm_err_t attest_pcr_digest(const tpm_pcr_set_t *pcrs,
                              const pcr_selection_t *sel,
                              uint8_t *digest, size_t *digest_len);

/*
 * Prepare quote parameters: generate nonce, build selection,
 * compute PCR digest.
 */
tpm_err_t attest_prepare_quote(const tpm_pcr_set_t *pcrs,
                                tpm_bank_t bank, uint32_t pcr_mask,
                                quote_params_t *params);

/*
 * Verify a quote digest against actual PCR values.
 * Returns TPM_OK if the provided digest matches the computed one.
 */
tpm_err_t attest_verify_quote_digest(const tpm_pcr_set_t *pcrs,
                                      const pcr_selection_t *sel,
                                      const uint8_t *expected_digest,
                                      size_t expected_len);

/*
 * Build a full attestation report.
 */
tpm_err_t attest_build_report(attest_report_t *report,
                               const tpm_pcr_set_t *pcrs,
                               const event_log_t *elog,
                               const replay_report_t *replay);

/*
 * Print the attestation report in human-readable format.
 */
void attest_print_report(const attest_report_t *report);

/*
 * Print the attestation report as JSON.
 */
void attest_print_report_json(const attest_report_t *report);

#endif /* TPM_ATTESTATION_H */
