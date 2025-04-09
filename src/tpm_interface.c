/*
 * tpm-pcr-dump — TPM 2.0 interface layer
 *
 * Reads PCR values from sysfs or by invoking tpm2_pcrread as fallback.
 * Supports SHA-1, SHA-256, SHA-384, SHA-512, and SM3-256 banks.
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#include "tpm_interface.h"
#include "utils.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Default sysfs base path for TPM 2.0 PCR pseudo-files */
#define SYSFS_TPM_BASE  "/sys/class/tpm/tpm0"

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

static bool path_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static tpm_err_t read_sysfs_pcr(const char *base, tpm_bank_t bank,
                                  int index, tpm_pcr_value_t *pcr)
{
    char path[TPM_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/pcr-%s/%d",
                     base, tpm_bank_name(bank), index);
    if (n < 0 || (size_t)n >= sizeof(path))
        return TPM_ERR_IO;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        dbg_print("cannot open %s: %s", path, strerror(errno));
        return TPM_ERR_READ;
    }

    char line[TPM_MAX_HEX_SIZE + 32];
    if (!fgets(line, (int)sizeof(line), fp)) {
        fclose(fp);
        return TPM_ERR_READ;
    }
    fclose(fp);

    char *hex = str_trim(line);
    size_t expected_len = tpm_bank_digest_len(bank);
    int got = hex_to_bin(hex, pcr->digest, sizeof(pcr->digest));
    if (got < 0 || (size_t)got != expected_len) {
        err_print("bad hex in %s", path);
        return TPM_ERR_PARSE;
    }

    pcr->digest_len = expected_len;
    pcr->index = index;
    pcr->valid = true;
    return TPM_OK;
}

/* ------------------------------------------------------------------ */
/* tpm2_pcrread fallback                                               */
/* ------------------------------------------------------------------ */

static tpm_err_t read_tools_pcr(tpm_bank_t bank, int index,
                                 tpm_pcr_value_t *pcr)
{
    char cmd[256];
    const char *alg = tpm_bank_name(bank);

    int n = snprintf(cmd, sizeof(cmd),
                     "tpm2_pcrread %s:%d 2>/dev/null", alg, index);
    if (n < 0 || (size_t)n >= sizeof(cmd))
        return TPM_ERR_IO;

    dbg_print("running: %s", cmd);

    FILE *fp = popen(cmd, "r");
    if (!fp)
        return TPM_ERR_READ;

    /*
     * tpm2_pcrread output looks like:
     *   sha256:
     *     0 : 0x<hex>
     *
     * We search for the line containing "0x".
     */
    char line[512];
    bool found = false;
    while (fgets(line, (int)sizeof(line), fp)) {
        char *p = strstr(line, "0x");
        if (!p)
            p = strstr(line, "0X");
        if (!p)
            continue;

        char *hex = str_trim(p);
        size_t expected_len = tpm_bank_digest_len(bank);
        int got = hex_to_bin(hex, pcr->digest, sizeof(pcr->digest));
        if (got >= 0 && (size_t)got == expected_len) {
            pcr->digest_len = expected_len;
            pcr->index = index;
            pcr->valid = true;
            found = true;
            break;
        }
    }
    pclose(fp);

    return found ? TPM_OK : TPM_ERR_PARSE;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

tpm_err_t tpm_open(tpm_ctx_t *ctx, tpm_method_t preferred)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->method = preferred;

    if (preferred == TPM_METHOD_AUTO || preferred == TPM_METHOD_SYSFS) {
        /* Probe sysfs */
        if (path_exists(SYSFS_TPM_BASE)) {
            snprintf(ctx->sysfs_base, sizeof(ctx->sysfs_base),
                     "%s", SYSFS_TPM_BASE);
            ctx->method = TPM_METHOD_SYSFS;
            ctx->opened = true;
            dbg_print("using sysfs at %s", ctx->sysfs_base);
            return TPM_OK;
        }
        if (preferred == TPM_METHOD_SYSFS) {
            err_print("sysfs path %s not found", SYSFS_TPM_BASE);
            return TPM_ERR_OPEN;
        }
    }

    /* Fall back to tpm2-tools */
    ctx->method = TPM_METHOD_TOOLS;
    ctx->opened = true;
    dbg_print("using tpm2-tools fallback");
    return TPM_OK;
}

void tpm_close(tpm_ctx_t *ctx)
{
    ctx->opened = false;
}

tpm_err_t tpm_read_pcr(tpm_ctx_t *ctx, tpm_bank_t bank,
                        int index, tpm_pcr_value_t *pcr)
{
    if (!ctx->opened)
        return TPM_ERR_OPEN;
    if (index < 0 || index >= TPM_PCR_COUNT)
        return TPM_ERR_INDEX;

    memset(pcr, 0, sizeof(*pcr));

    if (ctx->method == TPM_METHOD_SYSFS) {
        tpm_err_t rc = read_sysfs_pcr(ctx->sysfs_base, bank, index, pcr);
        if (rc == TPM_OK)
            return TPM_OK;
        dbg_print("sysfs read failed for PCR %d, trying tpm2-tools", index);
    }

    return read_tools_pcr(bank, index, pcr);
}

tpm_err_t tpm_read_all_pcrs(tpm_ctx_t *ctx, tpm_bank_t bank,
                             tpm_pcr_set_t *set)
{
    memset(set, 0, sizeof(*set));
    set->bank = bank;

    for (int i = 0; i < TPM_PCR_COUNT; i++) {
        tpm_err_t rc = tpm_read_pcr(ctx, bank, i, &set->pcrs[i]);
        if (rc == TPM_OK) {
            set->count++;
        } else {
            dbg_print("PCR %d: read failed (rc=%d)", i, rc);
            set->pcrs[i].index = i;
            set->pcrs[i].valid = false;
        }
    }

    return (set->count > 0) ? TPM_OK : TPM_ERR_READ;
}
