/*
 * tpm-pcr-dump — Attestation helpers
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#include "attestation.h"
#include "json_writer.h"
#include "table_fmt.h"
#include "color.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef __linux__
#include <sys/utsname.h>
#include <unistd.h>
#endif

/* ------------------------------------------------------------------ */

tpm_err_t attest_generate_nonce(uint8_t *nonce, size_t len)
{
    if (len > ATTEST_NONCE_MAX)
        len = ATTEST_NONCE_MAX;

    if (RAND_bytes(nonce, (int)len) != 1) {
        err_print("failed to generate random nonce");
        return TPM_ERR_NOMEM;
    }
    return TPM_OK;
}

void attest_build_selection(pcr_selection_t *sel, tpm_bank_t bank,
                             uint32_t pcr_mask)
{
    memset(sel, 0, sizeof(*sel));
    sel->hash_alg = tpm_bank_alg_id(bank);
    sel->size_of_select = PCR_SELECT_BYTES;

    for (int i = 0; i < TPM_PCR_COUNT && i < 24; i++) {
        if (pcr_mask & (1u << i))
            sel->pcr_select[i / 8] |= (1u << (i % 8));
    }
}

tpm_err_t attest_pcr_digest(const tpm_pcr_set_t *pcrs,
                              const pcr_selection_t *sel,
                              uint8_t *digest, size_t *digest_len)
{
    const EVP_MD *md = NULL;
    tpm_bank_t bank = tpm_bank_from_alg_id(sel->hash_alg);
    size_t dlen = tpm_bank_digest_len(bank);

    switch (bank) {
    case TPM_BANK_SHA1:   md = EVP_sha1();   break;
    case TPM_BANK_SHA256: md = EVP_sha256(); break;
    case TPM_BANK_SHA384: md = EVP_sha384(); break;
    case TPM_BANK_SHA512: md = EVP_sha512(); break;
    default:
        return TPM_ERR_UNSUPPORTED;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return TPM_ERR_NOMEM;

    EVP_DigestInit_ex(ctx, md, NULL);

    for (int i = 0; i < TPM_PCR_COUNT; i++) {
        int byte_idx = i / 8;
        int bit_idx  = i % 8;
        if (byte_idx < PCR_SELECT_BYTES &&
            (sel->pcr_select[byte_idx] & (1u << bit_idx))) {
            if (pcrs->pcrs[i].valid) {
                EVP_DigestUpdate(ctx, pcrs->pcrs[i].digest, dlen);
            } else {
                /* Use zero-filled digest for unavailable PCRs */
                uint8_t zero[TPM_MAX_DIGEST_SIZE] = {0};
                EVP_DigestUpdate(ctx, zero, dlen);
            }
        }
    }

    unsigned int out_len = 0;
    EVP_DigestFinal_ex(ctx, digest, &out_len);
    *digest_len = out_len;

    EVP_MD_CTX_free(ctx);
    return TPM_OK;
}

tpm_err_t attest_prepare_quote(const tpm_pcr_set_t *pcrs,
                                tpm_bank_t bank, uint32_t pcr_mask,
                                quote_params_t *params)
{
    memset(params, 0, sizeof(*params));
    params->bank = bank;

    /* Generate nonce */
    params->nonce_len = 32;  /* 256-bit nonce */
    tpm_err_t rc = attest_generate_nonce(params->nonce, params->nonce_len);
    if (rc != TPM_OK)
        return rc;

    /* Build selection */
    attest_build_selection(&params->selection, bank, pcr_mask);

    /* Compute PCR composite digest */
    rc = attest_pcr_digest(pcrs, &params->selection,
                            params->pcr_digest, &params->pcr_digest_len);
    return rc;
}

tpm_err_t attest_verify_quote_digest(const tpm_pcr_set_t *pcrs,
                                      const pcr_selection_t *sel,
                                      const uint8_t *expected_digest,
                                      size_t expected_len)
{
    uint8_t computed[TPM_MAX_DIGEST_SIZE];
    size_t computed_len = 0;

    tpm_err_t rc = attest_pcr_digest(pcrs, sel, computed, &computed_len);
    if (rc != TPM_OK)
        return rc;

    if (computed_len != expected_len ||
        memcmp(computed, expected_digest, computed_len) != 0) {
        return TPM_ERR_SIGNATURE;
    }

    return TPM_OK;
}

/* ------------------------------------------------------------------ */
/* Report generation                                                   */
/* ------------------------------------------------------------------ */

tpm_err_t attest_build_report(attest_report_t *report,
                               const tpm_pcr_set_t *pcrs,
                               const event_log_t *elog,
                               const replay_report_t *replay)
{
    memset(report, 0, sizeof(*report));

    /* System info */
#ifdef __linux__
    gethostname(report->hostname, sizeof(report->hostname) - 1);
    struct utsname uts;
    if (uname(&uts) == 0)
        snprintf(report->kernel_version, sizeof(report->kernel_version),
                 "%s %s %s", uts.sysname, uts.release, uts.machine);
#endif

    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    if (tm_info)
        strftime(report->timestamp, sizeof(report->timestamp),
                 "%Y-%m-%dT%H:%M:%SZ", tm_info);

    /* PCR values */
    report->bank = pcrs->bank;
    report->pcr_count = pcrs->count;
    memcpy(&report->pcrs, pcrs, sizeof(tpm_pcr_set_t));

    /* Event log info */
    if (elog && elog->count > 0) {
        report->event_log_available = true;
        report->event_count = elog->count;

        for (int i = 0; i < elog->count; i++) {
            int idx = (int)elog->entries[i].pcr_index;
            if (idx >= 0 && idx < TPM_PCR_COUNT &&
                elog->entries[i].event_type != EV_NO_ACTION)
                report->events_per_pcr[idx]++;
        }
    }

    /* Replay verification */
    if (replay) {
        report->event_log_verified = (replay->total_mismatched == 0);
    }

    return TPM_OK;
}

/* ------------------------------------------------------------------ */

void attest_print_report(const attest_report_t *report)
{
    printf("\n");
    color_fprintf(stdout, CLR_BOLD_WHITE,
                  "  ATTESTATION REPORT\n");
    color_fprintf(stdout, CLR_DIM,
                  "  ==================\n\n");

    /* System info */
    printf("  %sHostname:%s       %s\n",
           clr(CLR_CYAN), clr(CLR_RESET), report->hostname);
    printf("  %sTimestamp:%s      %s\n",
           clr(CLR_CYAN), clr(CLR_RESET), report->timestamp);
    printf("  %sKernel:%s         %s\n",
           clr(CLR_CYAN), clr(CLR_RESET), report->kernel_version);
    printf("  %sHash bank:%s      %s\n",
           clr(CLR_CYAN), clr(CLR_RESET), tpm_bank_name(report->bank));
    printf("  %sValid PCRs:%s     %d / %d\n",
           clr(CLR_CYAN), clr(CLR_RESET), report->pcr_count, TPM_PCR_COUNT);
    printf("\n");

    /* PCR summary table */
    table_col_t cols[] = {
        { "PCR",    3,  TABLE_ALIGN_RIGHT },
        { "Value",  (int)(tpm_bank_digest_len(report->bank) * 2),
                        TABLE_ALIGN_LEFT },
        { "Events", 6,  TABLE_ALIGN_RIGHT },
    };
    table_t tbl;
    table_init(&tbl, stdout, 3, cols);
    table_header(&tbl);

    for (int i = 0; i < TPM_PCR_COUNT; i++) {
        char idx_str[8];
        snprintf(idx_str, sizeof(idx_str), "%d", i);

        char hex[TPM_MAX_HEX_SIZE] = "<unavailable>";
        if (report->pcrs.pcrs[i].valid) {
            bin_to_hex(report->pcrs.pcrs[i].digest,
                       report->pcrs.pcrs[i].digest_len,
                       hex, sizeof(hex));
        }

        char evt_str[16];
        snprintf(evt_str, sizeof(evt_str), "%d",
                 report->events_per_pcr[i]);

        /* Color all-zero PCRs dimly */
        bool is_zero = report->pcrs.pcrs[i].valid;
        if (is_zero) {
            is_zero = true;
            for (size_t b = 0; b < report->pcrs.pcrs[i].digest_len; b++) {
                if (report->pcrs.pcrs[i].digest[b] != 0) {
                    is_zero = false;
                    break;
                }
            }
        }

        color_code_t val_color = is_zero ? CLR_DIM : CLR_GREEN;
        if (!report->pcrs.pcrs[i].valid)
            val_color = CLR_RED;

        table_cell(&tbl, idx_str, CLR_BOLD);
        table_cell(&tbl, hex, val_color);
        table_cell(&tbl, evt_str, CLR_CYAN);
    }

    table_bottom(&tbl);
    printf("\n");

    /* Event log status */
    printf("  %sEvent Log:%s      ", clr(CLR_CYAN), clr(CLR_RESET));
    if (report->event_log_available) {
        color_fprintf(stdout, CLR_GREEN, "Available");
        printf(" (%d events)\n", report->event_count);
    } else {
        color_fprintf(stdout, CLR_YELLOW, "Not available\n");
    }

    if (report->event_log_available) {
        printf("  %sLog Integrity:%s  ", clr(CLR_CYAN), clr(CLR_RESET));
        if (report->event_log_verified) {
            color_fprintf(stdout, CLR_BOLD_GREEN, "VERIFIED\n");
        } else {
            color_fprintf(stdout, CLR_BOLD_RED, "MISMATCH DETECTED\n");
        }
    }

    /* Golden verification */
    if (report->golden_verified || report->golden_mismatched > 0) {
        printf("  %sGolden Check:%s   ", clr(CLR_CYAN), clr(CLR_RESET));
        if (report->golden_mismatched == 0) {
            color_fprintf(stdout, CLR_BOLD_GREEN,
                          "PASS (%d/%d matched)\n",
                          report->golden_matched,
                          report->golden_matched + report->golden_mismatched);
        } else {
            color_fprintf(stdout, CLR_BOLD_RED,
                          "FAIL (%d mismatched)\n",
                          report->golden_mismatched);
        }
    }

    /* Quote parameters */
    if (report->quote_prepared) {
        char nonce_hex[ATTEST_NONCE_MAX * 2 + 1];
        bin_to_hex(report->quote.nonce, report->quote.nonce_len,
                   nonce_hex, sizeof(nonce_hex));
        char pcr_digest_hex[TPM_MAX_HEX_SIZE];
        bin_to_hex(report->quote.pcr_digest, report->quote.pcr_digest_len,
                   pcr_digest_hex, sizeof(pcr_digest_hex));

        printf("\n");
        color_fprintf(stdout, CLR_BOLD_WHITE, "  QUOTE PARAMETERS\n");
        color_fprintf(stdout, CLR_DIM, "  ----------------\n");
        printf("  %sNonce:%s          %s\n",
               clr(CLR_CYAN), clr(CLR_RESET), nonce_hex);
        printf("  %sPCR Digest:%s     %s\n",
               clr(CLR_CYAN), clr(CLR_RESET), pcr_digest_hex);
        printf("  %sSelection:%s      ", clr(CLR_CYAN), clr(CLR_RESET));
        for (int i = 0; i < TPM_PCR_COUNT; i++) {
            int byte_idx = i / 8;
            int bit_idx  = i % 8;
            if (report->quote.selection.pcr_select[byte_idx] &
                (1u << bit_idx))
                printf("%d ", i);
        }
        printf("\n");
    }

    printf("\n");
}

/* ------------------------------------------------------------------ */

void attest_print_report_json(const attest_report_t *report)
{
    json_writer_t jw;
    jw_init(&jw);

    jw_object_begin(&jw);
    jw_kv_string(&jw, "tool", "tpm-pcr-dump");
    jw_kv_string(&jw, "version", TPM_PCR_DUMP_VERSION_STRING);
    jw_kv_string(&jw, "type", "attestation_report");

    /* System info */
    jw_key(&jw, "system");
    jw_object_begin(&jw);
    jw_kv_string(&jw, "hostname", report->hostname);
    jw_kv_string(&jw, "timestamp", report->timestamp);
    jw_kv_string(&jw, "kernel", report->kernel_version);
    jw_object_end(&jw);

    /* TPM info */
    jw_key(&jw, "tpm");
    jw_object_begin(&jw);
    jw_kv_string(&jw, "bank", tpm_bank_name(report->bank));
    jw_kv_int(&jw, "valid_pcrs", report->pcr_count);
    jw_object_end(&jw);

    /* PCR values */
    jw_key(&jw, "pcrs");
    jw_array_begin(&jw);
    for (int i = 0; i < TPM_PCR_COUNT; i++) {
        jw_object_begin(&jw);
        jw_kv_int(&jw, "index", i);
        jw_kv_bool(&jw, "valid", report->pcrs.pcrs[i].valid);
        if (report->pcrs.pcrs[i].valid) {
            char hex[TPM_MAX_HEX_SIZE];
            bin_to_hex(report->pcrs.pcrs[i].digest,
                       report->pcrs.pcrs[i].digest_len,
                       hex, sizeof(hex));
            jw_kv_string(&jw, "value", hex);
        } else {
            jw_key(&jw, "value");
            jw_null(&jw);
        }
        jw_kv_int(&jw, "events", report->events_per_pcr[i]);
        jw_object_end(&jw);
    }
    jw_array_end(&jw);

    /* Event log */
    jw_key(&jw, "event_log");
    jw_object_begin(&jw);
    jw_kv_bool(&jw, "available", report->event_log_available);
    jw_kv_int(&jw, "event_count", report->event_count);
    jw_kv_bool(&jw, "verified", report->event_log_verified);
    jw_object_end(&jw);

    /* Verification */
    jw_key(&jw, "verification");
    jw_object_begin(&jw);
    jw_kv_bool(&jw, "golden_pass",
               report->golden_verified && report->golden_mismatched == 0);
    jw_kv_int(&jw, "golden_matched", report->golden_matched);
    jw_kv_int(&jw, "golden_mismatched", report->golden_mismatched);
    jw_object_end(&jw);

    /* Quote parameters */
    if (report->quote_prepared) {
        jw_key(&jw, "quote");
        jw_object_begin(&jw);

        char nonce_hex[ATTEST_NONCE_MAX * 2 + 1];
        bin_to_hex(report->quote.nonce, report->quote.nonce_len,
                   nonce_hex, sizeof(nonce_hex));
        jw_kv_string(&jw, "nonce", nonce_hex);

        char digest_hex[TPM_MAX_HEX_SIZE];
        bin_to_hex(report->quote.pcr_digest, report->quote.pcr_digest_len,
                   digest_hex, sizeof(digest_hex));
        jw_kv_string(&jw, "pcr_digest", digest_hex);

        jw_kv_string(&jw, "bank", tpm_bank_name(report->quote.bank));
        jw_object_end(&jw);
    }

    jw_object_end(&jw);

    printf("%s", jw_finish(&jw));
}
