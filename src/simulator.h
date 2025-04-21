/*
 * tpm-pcr-dump — PCR simulation engine
 *
 * Compute expected PCR values without a TPM, run what-if analysis,
 * and check policy matching.
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#ifndef TPM_SIMULATOR_H
#define TPM_SIMULATOR_H

#include "tpm_pcr_dump.h"

/* Maximum number of extend operations in a simulation */
#define SIM_MAX_EXTENDS  1024

/* A single simulated extend operation */
typedef struct {
    int      pcr_index;
    uint8_t  measurement[TPM_MAX_DIGEST_SIZE];
    size_t   measurement_len;
    char     label[128];  /* human-readable label for this measurement */
} sim_extend_t;

/* Simulation context */
typedef struct {
    tpm_bank_t    bank;
    tpm_pcr_set_t state;              /* current simulated PCR values */
    sim_extend_t  history[SIM_MAX_EXTENDS];
    int           history_count;
} sim_ctx_t;

/* Policy match result */
typedef struct {
    int  pcr_index;
    bool expected_present;
    bool match;
    char expected_hex[TPM_MAX_HEX_SIZE];
    char actual_hex[TPM_MAX_HEX_SIZE];
} policy_match_t;

typedef struct {
    policy_match_t entries[TPM_PCR_COUNT];
    int            count;
    int            matched;
    int            mismatched;
    bool           policy_pass;
} policy_report_t;

/*
 * Initialize a simulation context with all PCRs set to zero.
 */
void sim_init(sim_ctx_t *ctx, tpm_bank_t bank);

/*
 * Initialize a simulation context from actual TPM PCR values.
 */
void sim_init_from(sim_ctx_t *ctx, const tpm_pcr_set_t *actual);

/*
 * Extend a simulated PCR with a raw digest measurement.
 */
tpm_err_t sim_extend(sim_ctx_t *ctx, int pcr_index,
                      const uint8_t *measurement, size_t len,
                      const char *label);

/*
 * Extend a simulated PCR with data (hash the data first, then extend).
 */
tpm_err_t sim_extend_data(sim_ctx_t *ctx, int pcr_index,
                           const uint8_t *data, size_t data_len,
                           const char *label);

/*
 * What-if analysis: given the current state, simulate extending PCR
 * with a measurement and return the resulting value without modifying
 * the simulation state.
 */
tpm_err_t sim_what_if(const sim_ctx_t *ctx, int pcr_index,
                       const uint8_t *measurement, size_t len,
                       uint8_t *result, size_t *result_len);

/*
 * Get the current simulated value of a PCR.
 */
tpm_err_t sim_get_pcr(const sim_ctx_t *ctx, int pcr_index,
                       tpm_pcr_value_t *out);

/*
 * Check if simulated PCR values match a set of expected values
 * (policy matching for TPM2_PolicyPCR).
 */
tpm_err_t sim_policy_check(const tpm_pcr_set_t *actual,
                            const tpm_pcr_set_t *expected,
                            policy_report_t *report);

/*
 * Get measurement chain for a specific PCR in the simulation.
 * Returns number of entries written to out (up to max_out).
 */
int sim_get_chain(const sim_ctx_t *ctx, int pcr_index,
                   const sim_extend_t **out, int max_out);

#endif /* TPM_SIMULATOR_H */
