/*
 * tpm-pcr-dump — PCR simulation engine
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#include "simulator.h"
#include "utils.h"

#include <string.h>
#include <openssl/evp.h>

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

static const EVP_MD *bank_md(tpm_bank_t bank)
{
    switch (bank) {
    case TPM_BANK_SHA1:    return EVP_sha1();
    case TPM_BANK_SHA256:  return EVP_sha256();
    case TPM_BANK_SHA384:  return EVP_sha384();
    case TPM_BANK_SHA512:  return EVP_sha512();
    default:               return NULL;
    }
}

static tpm_err_t do_extend(tpm_bank_t bank, uint8_t *pcr_value,
                            size_t digest_len,
                            const uint8_t *measurement)
{
    const EVP_MD *md = bank_md(bank);
    if (!md)
        return TPM_ERR_UNSUPPORTED;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return TPM_ERR_NOMEM;

    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, pcr_value, digest_len);
    EVP_DigestUpdate(ctx, measurement, digest_len);

    unsigned int out_len = 0;
    EVP_DigestFinal_ex(ctx, pcr_value, &out_len);
    EVP_MD_CTX_free(ctx);

    return TPM_OK;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void sim_init(sim_ctx_t *ctx, tpm_bank_t bank)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->bank = bank;

    size_t digest_len = tpm_bank_digest_len(bank);
    for (int i = 0; i < TPM_PCR_COUNT; i++) {
        memset(ctx->state.pcrs[i].digest, 0, digest_len);
        ctx->state.pcrs[i].digest_len = digest_len;
        ctx->state.pcrs[i].index = i;
        ctx->state.pcrs[i].valid = true;
    }
    ctx->state.bank = bank;
    ctx->state.count = TPM_PCR_COUNT;
}

void sim_init_from(sim_ctx_t *ctx, const tpm_pcr_set_t *actual)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->bank = actual->bank;
    memcpy(&ctx->state, actual, sizeof(tpm_pcr_set_t));
}

tpm_err_t sim_extend(sim_ctx_t *ctx, int pcr_index,
                      const uint8_t *measurement, size_t len,
                      const char *label)
{
    if (pcr_index < 0 || pcr_index >= TPM_PCR_COUNT)
        return TPM_ERR_INDEX;

    size_t digest_len = tpm_bank_digest_len(ctx->bank);
    if (len != digest_len)
        return TPM_ERR_PARSE;

    tpm_err_t rc = do_extend(ctx->bank,
                              ctx->state.pcrs[pcr_index].digest,
                              digest_len, measurement);
    if (rc != TPM_OK)
        return rc;

    /* Record in history */
    if (ctx->history_count < SIM_MAX_EXTENDS) {
        sim_extend_t *h = &ctx->history[ctx->history_count];
        h->pcr_index = pcr_index;
        memcpy(h->measurement, measurement, len);
        h->measurement_len = len;
        if (label) {
            snprintf(h->label, sizeof(h->label), "%s", label);
        } else {
            h->label[0] = '\0';
        }
        ctx->history_count++;
    }

    return TPM_OK;
}

tpm_err_t sim_extend_data(sim_ctx_t *ctx, int pcr_index,
                           const uint8_t *data, size_t data_len,
                           const char *label)
{
    if (pcr_index < 0 || pcr_index >= TPM_PCR_COUNT)
        return TPM_ERR_INDEX;

    const EVP_MD *md = bank_md(ctx->bank);
    if (!md)
        return TPM_ERR_UNSUPPORTED;

    /* Hash the data first */
    uint8_t measurement[TPM_MAX_DIGEST_SIZE];
    unsigned int mlen = 0;

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (!mctx)
        return TPM_ERR_NOMEM;

    EVP_DigestInit_ex(mctx, md, NULL);
    EVP_DigestUpdate(mctx, data, data_len);
    EVP_DigestFinal_ex(mctx, measurement, &mlen);
    EVP_MD_CTX_free(mctx);

    return sim_extend(ctx, pcr_index, measurement, mlen, label);
}

tpm_err_t sim_what_if(const sim_ctx_t *ctx, int pcr_index,
                       const uint8_t *measurement, size_t len,
                       uint8_t *result, size_t *result_len)
{
    if (pcr_index < 0 || pcr_index >= TPM_PCR_COUNT)
        return TPM_ERR_INDEX;

    size_t digest_len = tpm_bank_digest_len(ctx->bank);
    if (len != digest_len)
        return TPM_ERR_PARSE;

    /* Copy current PCR value */
    memcpy(result, ctx->state.pcrs[pcr_index].digest, digest_len);
    *result_len = digest_len;

    return do_extend(ctx->bank, result, digest_len, measurement);
}

tpm_err_t sim_get_pcr(const sim_ctx_t *ctx, int pcr_index,
                       tpm_pcr_value_t *out)
{
    if (pcr_index < 0 || pcr_index >= TPM_PCR_COUNT)
        return TPM_ERR_INDEX;

    *out = ctx->state.pcrs[pcr_index];
    return TPM_OK;
}

tpm_err_t sim_policy_check(const tpm_pcr_set_t *actual,
                            const tpm_pcr_set_t *expected,
                            policy_report_t *report)
{
    memset(report, 0, sizeof(*report));

    for (int i = 0; i < TPM_PCR_COUNT; i++) {
        if (!expected->pcrs[i].valid)
            continue;

        policy_match_t *m = &report->entries[report->count];
        m->pcr_index = i;
        m->expected_present = true;

        bin_to_hex(expected->pcrs[i].digest, expected->pcrs[i].digest_len,
                   m->expected_hex, sizeof(m->expected_hex));

        if (!actual->pcrs[i].valid) {
            snprintf(m->actual_hex, sizeof(m->actual_hex), "<unavailable>");
            m->match = false;
            report->mismatched++;
        } else {
            bin_to_hex(actual->pcrs[i].digest, actual->pcrs[i].digest_len,
                       m->actual_hex, sizeof(m->actual_hex));

            size_t cmp_len = expected->pcrs[i].digest_len;
            if (cmp_len == actual->pcrs[i].digest_len &&
                memcmp(expected->pcrs[i].digest,
                       actual->pcrs[i].digest, cmp_len) == 0) {
                m->match = true;
                report->matched++;
            } else {
                m->match = false;
                report->mismatched++;
            }
        }
        report->count++;
    }

    report->policy_pass = (report->mismatched == 0 && report->count > 0);
    return (report->mismatched > 0) ? TPM_ERR_VERIFY : TPM_OK;
}

int sim_get_chain(const sim_ctx_t *ctx, int pcr_index,
                   const sim_extend_t **out, int max_out)
{
    int count = 0;
    for (int i = 0; i < ctx->history_count && count < max_out; i++) {
        if (ctx->history[i].pcr_index == pcr_index) {
            out[count++] = &ctx->history[i];
        }
    }
    return count;
}
