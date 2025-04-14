/*
 * tpm-pcr-dump — PCR verification against golden values
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#include "pcr_verify.h"
#include "utils.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <openssl/evp.h>

/* ------------------------------------------------------------------ */
/* Minimal JSON-like config parser                                     */
/*                                                                     */
/* Expected format:                                                    */
/*   {                                                                 */
/*     "bank": "sha256",                                               */
/*     "pcrs": {                                                       */
/*       "0": "abcdef0123...",                                         */
/*       "7": "0123456789..."                                          */
/*     }                                                               */
/*   }                                                                 */
/*                                                                     */
/* This is intentionally simplistic: no nested objects beyond "pcrs",  */
/* no arrays, no escaped characters in values.  Good enough for a      */
/* config file that we control.                                        */
/* ------------------------------------------------------------------ */

#define CFG_LINE_MAX  512
#define CFG_FILE_MAX  (32 * 1024)

/* Skip whitespace and structural characters to extract key/value */
static char *skip_ws(char *p)
{
    while (*p && isspace((unsigned char)*p))
        p++;
    return p;
}

/* Extract a quoted string starting at p (which points at the opening ").
 * Writes the unquoted content into out (up to out_size-1 chars).
 * Returns pointer past the closing quote, or NULL on error.           */
static char *extract_quoted(char *p, char *out, size_t out_size)
{
    if (*p != '"')
        return NULL;
    p++;
    size_t i = 0;
    while (*p && *p != '"') {
        if (i < out_size - 1)
            out[i++] = *p;
        p++;
    }
    out[i] = '\0';
    if (*p == '"')
        p++;
    return p;
}

tpm_err_t pcr_golden_load(const char *path, pcr_golden_t *golden)
{
    memset(golden, 0, sizeof(*golden));

    FILE *fp = fopen(path, "r");
    if (!fp) {
        err_print("cannot open %s: %s", path, strerror(errno));
        return TPM_ERR_IO;
    }

    /* Read entire file into stack buffer */
    char file_buf[CFG_FILE_MAX];
    size_t total = fread(file_buf, 1, sizeof(file_buf) - 1, fp);
    fclose(fp);
    file_buf[total] = '\0';

    /* Default bank */
    golden->bank = TPM_BANK_SHA256;

    /* State machine: look for "bank" and "pcrs" keys */
    bool in_pcrs = false;
    char *p = file_buf;

    while (*p) {
        p = skip_ws(p);

        /* Skip structural chars */
        if (*p == '{' || *p == '}' || *p == ',' || *p == ':') {
            if (*p == '}' && in_pcrs)
                in_pcrs = false;
            p++;
            continue;
        }

        /* Extract a key */
        if (*p == '"') {
            char key[64];
            p = extract_quoted(p, key, sizeof(key));
            if (!p) break;

            p = skip_ws(p);
            if (*p == ':') p++;
            p = skip_ws(p);

            if (strcmp(key, "bank") == 0) {
                char val[32];
                if (*p == '"') {
                    p = extract_quoted(p, val, sizeof(val));
                    if (!p) break;
                    tpm_bank_t b = tpm_bank_from_name(val);
                    if (b < TPM_BANK_COUNT)
                        golden->bank = b;
                    else
                        golden->bank = TPM_BANK_SHA256;
                }
            } else if (strcmp(key, "pcrs") == 0) {
                if (*p == '{') {
                    p++;
                    in_pcrs = true;
                }
            } else if (in_pcrs) {
                /* key should be a PCR index, value is a hex string */
                char *end;
                long idx = strtol(key, &end, 10);
                if (*end == '\0' && idx >= 0 && idx < TPM_PCR_COUNT) {
                    char hex_val[TPM_MAX_HEX_SIZE];
                    if (*p == '"') {
                        p = extract_quoted(p, hex_val, sizeof(hex_val));
                        if (!p) break;

                        pcr_expected_t *e = &golden->entries[idx];
                        e->index = (int)idx;
                        size_t expected_len = tpm_bank_digest_len(golden->bank);
                        int got = hex_to_bin(hex_val, e->digest,
                                             sizeof(e->digest));
                        if (got >= 0 && (size_t)got == expected_len) {
                            e->digest_len = expected_len;
                            e->present = true;
                            golden->count++;
                        } else {
                            err_print("bad hex for PCR %ld in %s",
                                      idx, path);
                        }
                    }
                }
            } else {
                /* Unknown key — skip value */
                if (*p == '"') {
                    char dummy[256];
                    p = extract_quoted(p, dummy, sizeof(dummy));
                    if (!p) break;
                }
            }
            continue;
        }

        /* Skip anything else */
        p++;
    }

    if (golden->count == 0) {
        err_print("no valid PCR entries found in %s", path);
        return TPM_ERR_PARSE;
    }

    dbg_print("loaded %d golden PCR values (bank=%s) from %s",
              golden->count, tpm_bank_name(golden->bank), path);
    return TPM_OK;
}

/* ------------------------------------------------------------------ */

tpm_err_t pcr_verify(const tpm_pcr_set_t *measured,
                      const pcr_golden_t  *golden,
                      pcr_report_t        *report)
{
    memset(report, 0, sizeof(*report));

    for (int i = 0; i < TPM_PCR_COUNT; i++) {
        if (!golden->entries[i].present)
            continue;

        pcr_mismatch_t *r = &report->results[report->total_checked];
        r->index = i;

        /* Format expected hex */
        bin_to_hex(golden->entries[i].digest, golden->entries[i].digest_len,
                   r->expected_hex, sizeof(r->expected_hex));

        if (!measured->pcrs[i].valid) {
            /* Could not read this PCR — automatic mismatch */
            snprintf(r->actual_hex, sizeof(r->actual_hex), "<unreadable>");
            r->match = false;
            report->total_mismatched++;
        } else {
            bin_to_hex(measured->pcrs[i].digest,
                       measured->pcrs[i].digest_len,
                       r->actual_hex, sizeof(r->actual_hex));

            if (golden->entries[i].digest_len == measured->pcrs[i].digest_len &&
                memcmp(golden->entries[i].digest,
                       measured->pcrs[i].digest,
                       golden->entries[i].digest_len) == 0) {
                r->match = true;
                report->total_matched++;
            } else {
                r->match = false;
                report->total_mismatched++;
            }
        }
        report->total_checked++;
    }

    /* Compute composite hash */
    tpm_err_t rc = pcr_composite_hash(measured,
                                       report->composite_hash,
                                       &report->composite_len);
    if (rc == TPM_OK) {
        bin_to_hex(report->composite_hash, report->composite_len,
                   report->composite_hex, sizeof(report->composite_hex));
    }

    return (report->total_mismatched > 0) ? TPM_ERR_VERIFY : TPM_OK;
}

/* ------------------------------------------------------------------ */

tpm_err_t pcr_composite_hash(const tpm_pcr_set_t *set,
                              uint8_t *out, size_t *out_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return TPM_ERR_NOMEM;

    const EVP_MD *md = EVP_sha256();
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return TPM_ERR_NOMEM;
    }

    for (int i = 0; i < TPM_PCR_COUNT; i++) {
        if (!set->pcrs[i].valid)
            continue;
        EVP_DigestUpdate(ctx, set->pcrs[i].digest,
                         set->pcrs[i].digest_len);
    }

    unsigned int digest_len = 0;
    EVP_DigestFinal_ex(ctx, out, &digest_len);
    *out_len = digest_len;

    EVP_MD_CTX_free(ctx);
    return TPM_OK;
}
