/*
 * tpm-pcr-dump — TCG TPM2 event log parser
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#include "event_log.h"
#include "utils.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <openssl/evp.h>

/* Default event log path */
#define DEFAULT_EVENT_LOG_PATH \
    "/sys/kernel/security/tpm0/binary_bios_measurements"

/* ------------------------------------------------------------------ */
/* Binary reading helpers (little-endian)                              */
/* ------------------------------------------------------------------ */

static inline uint16_t read_u16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline uint32_t read_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Return digest size for a TPM2 algorithm ID */
static size_t alg_digest_size(uint16_t alg_id)
{
    switch (alg_id) {
    case TPM2_ALG_SHA1:    return TPM_SHA1_DIGEST_SIZE;
    case TPM2_ALG_SHA256:  return TPM_SHA256_DIGEST_SIZE;
    case TPM2_ALG_SHA384:  return TPM_SHA384_DIGEST_SIZE;
    case TPM2_ALG_SHA512:  return TPM_SHA512_DIGEST_SIZE;
    case TPM2_ALG_SM3_256: return TPM_SM3_256_DIGEST_SIZE;
    default:               return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Parse the Spec ID Event (first event, determines log format)       */
/* ------------------------------------------------------------------ */

static bool parse_spec_id_event(const uint8_t *data, uint32_t data_size,
                                 spec_id_event_t *spec)
{
    memset(spec, 0, sizeof(*spec));

    /* Minimum: signature(16) + platformClass(4) + versions(3) +
     * uintnSize(1) + numberOfAlgorithms(4) = 28 */
    if (data_size < 28)
        return false;

    memcpy(spec->signature, data, 16);

    /* Check for "Spec ID Event03" (TCG2 crypto-agile) */
    if (memcmp(spec->signature, "Spec ID Event03", 15) != 0)
        return false;

    size_t off = 16;
    spec->platform_class    = read_u32(data + off); off += 4;
    spec->spec_version_minor = data[off++];
    spec->spec_version_major = data[off++];
    spec->spec_errata       = data[off++];
    spec->uintn_size        = data[off++];
    spec->num_algorithms    = read_u32(data + off); off += 4;

    if (spec->num_algorithms > EVENT_MAX_DIGESTS)
        spec->num_algorithms = EVENT_MAX_DIGESTS;

    for (uint32_t i = 0; i < spec->num_algorithms; i++) {
        if (off + 4 > data_size) break;
        spec->algorithms[i].alg_id     = read_u16(data + off); off += 2;
        spec->algorithms[i].digest_size = read_u16(data + off); off += 2;
    }

    return true;
}

/* Get digest size for an algorithm from the spec ID event */
static size_t spec_digest_size(const spec_id_event_t *spec, uint16_t alg_id)
{
    for (uint32_t i = 0; i < spec->num_algorithms; i++) {
        if (spec->algorithms[i].alg_id == alg_id)
            return spec->algorithms[i].digest_size;
    }
    return alg_digest_size(alg_id);
}

/* ------------------------------------------------------------------ */
/* Parse TCG1 (SHA-1 only) event                                       */
/* ------------------------------------------------------------------ */

static size_t parse_tcg1_event(const uint8_t *buf, size_t buf_size,
                                size_t offset, event_entry_t *entry)
{
    /* TCG1 event: PCR(4) + Type(4) + SHA1Digest(20) + EventSize(4) + Data */
    const size_t header_size = 4 + 4 + TPM_SHA1_DIGEST_SIZE + 4;

    if (offset + header_size > buf_size)
        return 0;

    const uint8_t *p = buf + offset;
    entry->pcr_index   = read_u32(p);     p += 4;
    entry->event_type  = read_u32(p);     p += 4;
    entry->raw_offset  = offset;

    entry->digest_count = 1;
    entry->digests[0].alg_id = TPM2_ALG_SHA1;
    entry->digests[0].digest_len = TPM_SHA1_DIGEST_SIZE;
    memcpy(entry->digests[0].digest, p, TPM_SHA1_DIGEST_SIZE);
    p += TPM_SHA1_DIGEST_SIZE;

    uint32_t event_size = read_u32(p); p += 4;

    if (event_size > EVENT_DATA_MAX)
        event_size = EVENT_DATA_MAX;
    if (offset + header_size + event_size > buf_size)
        return 0;

    entry->event_data_size = event_size;
    memcpy(entry->event_data, p, event_size);

    return header_size + event_size;
}

/* ------------------------------------------------------------------ */
/* Parse TCG2 (crypto-agile) event                                     */
/* ------------------------------------------------------------------ */

static size_t parse_tcg2_event(const uint8_t *buf, size_t buf_size,
                                size_t offset, const spec_id_event_t *spec,
                                event_entry_t *entry)
{
    /* TCG2 event: PCR(4) + Type(4) + DigestCount(4) + Digests... +
     * EventSize(4) + Data */
    if (offset + 12 > buf_size)
        return 0;

    const uint8_t *p = buf + offset;
    entry->pcr_index   = read_u32(p);     p += 4;
    entry->event_type  = read_u32(p);     p += 4;
    entry->raw_offset  = offset;

    uint32_t digest_count = read_u32(p);  p += 4;
    if (digest_count > EVENT_MAX_DIGESTS)
        digest_count = EVENT_MAX_DIGESTS;

    entry->digest_count = (int)digest_count;

    for (uint32_t i = 0; i < digest_count; i++) {
        size_t consumed = (size_t)(p - buf);
        if (consumed + 2 > buf_size)
            return 0;

        uint16_t alg_id = read_u16(p); p += 2;
        size_t dsize = spec_digest_size(spec, alg_id);
        if (dsize == 0)
            return 0;

        consumed = (size_t)(p - buf);
        if (consumed + dsize > buf_size)
            return 0;

        entry->digests[i].alg_id = alg_id;
        entry->digests[i].digest_len = dsize;
        if (dsize <= TPM_MAX_DIGEST_SIZE)
            memcpy(entry->digests[i].digest, p, dsize);
        p += dsize;
    }

    size_t consumed = (size_t)(p - buf);
    if (consumed + 4 > buf_size)
        return 0;

    uint32_t event_size = read_u32(p); p += 4;

    consumed = (size_t)(p - buf);
    if (event_size > EVENT_DATA_MAX)
        event_size = EVENT_DATA_MAX;
    if (consumed + event_size > buf_size)
        return 0;

    entry->event_data_size = event_size;
    memcpy(entry->event_data, p, event_size);

    return (size_t)(p - (buf + offset)) + event_size;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

tpm_err_t event_log_parse(const char *path, event_log_t *log)
{
    memset(log, 0, sizeof(*log));

    if (!path)
        path = DEFAULT_EVENT_LOG_PATH;
    snprintf(log->log_path, sizeof(log->log_path), "%s", path);

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        err_print("cannot open event log %s: %s", path, strerror(errno));
        return TPM_ERR_IO;
    }

    /* Read entire log into a static buffer.
     * We use a function-local static to avoid blowing the stack. */
    static uint8_t raw[EVENT_LOG_MAX_SIZE];
    size_t total = fread(raw, 1, sizeof(raw), fp);
    fclose(fp);

    if (total == 0) {
        err_print("event log %s is empty", path);
        return TPM_ERR_READ;
    }

    dbg_print("read %zu bytes from %s", total, path);

    /* First event is always TCG1 format.  Parse it to check for
     * Spec ID Event (crypto-agile indicator). */
    size_t offset = 0;
    event_entry_t first;
    memset(&first, 0, sizeof(first));

    size_t consumed = parse_tcg1_event(raw, total, 0, &first);
    if (consumed == 0) {
        err_print("failed to parse first event in log");
        return TPM_ERR_PARSE;
    }

    /* Check if the first event is a Spec ID Event03 */
    if (first.event_type == EV_NO_ACTION &&
        parse_spec_id_event(first.event_data, first.event_data_size,
                            &log->spec_id)) {
        log->crypto_agile = true;
        dbg_print("detected crypto-agile (TCG2) event log, %u algorithms",
                  log->spec_id.num_algorithms);
    }

    /* Store the first event */
    log->entries[0] = first;
    log->count = 1;
    offset = consumed;

    /* Parse remaining events */
    while (offset < total && log->count < EVENT_MAX_ENTRIES) {
        event_entry_t *entry = &log->entries[log->count];
        memset(entry, 0, sizeof(*entry));

        if (log->crypto_agile) {
            consumed = parse_tcg2_event(raw, total, offset,
                                         &log->spec_id, entry);
        } else {
            consumed = parse_tcg1_event(raw, total, offset, entry);
        }

        if (consumed == 0)
            break;  /* Reached end or parse error */

        log->count++;
        offset += consumed;
    }

    dbg_print("parsed %d events from event log", log->count);
    return TPM_OK;
}

/* ------------------------------------------------------------------ */
/* Replay: recompute PCR values from event log                        */
/* ------------------------------------------------------------------ */

static const EVP_MD *bank_to_evp_md(tpm_bank_t bank)
{
    switch (bank) {
    case TPM_BANK_SHA1:    return EVP_sha1();
    case TPM_BANK_SHA256:  return EVP_sha256();
    case TPM_BANK_SHA384:  return EVP_sha384();
    case TPM_BANK_SHA512:  return EVP_sha512();
    default:               return NULL;
    }
}

static void pcr_extend(uint8_t *pcr_value, size_t digest_len,
                        const uint8_t *measurement, tpm_bank_t bank)
{
    const EVP_MD *md = bank_to_evp_md(bank);
    if (!md) return;

    /* PCR_new = Hash(PCR_old || measurement) */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return;

    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, pcr_value, digest_len);
    EVP_DigestUpdate(ctx, measurement, digest_len);

    unsigned int out_len = 0;
    EVP_DigestFinal_ex(ctx, pcr_value, &out_len);
    EVP_MD_CTX_free(ctx);
}

tpm_err_t event_log_replay(const event_log_t *log, tpm_bank_t bank,
                            tpm_pcr_set_t *simulated)
{
    memset(simulated, 0, sizeof(*simulated));
    simulated->bank = bank;

    size_t digest_len = tpm_bank_digest_len(bank);
    if (digest_len == 0)
        return TPM_ERR_UNSUPPORTED;

    uint16_t target_alg = tpm_bank_alg_id(bank);

    /* Initialize all PCRs to zero (localities 0-3 start at all zeros) */
    for (int i = 0; i < TPM_PCR_COUNT; i++) {
        memset(simulated->pcrs[i].digest, 0, digest_len);
        simulated->pcrs[i].digest_len = digest_len;
        simulated->pcrs[i].index = i;
        simulated->pcrs[i].valid = true;
    }
    simulated->count = TPM_PCR_COUNT;

    for (int i = 0; i < log->count; i++) {
        const event_entry_t *entry = &log->entries[i];

        /* Skip EV_NO_ACTION events (informational only) */
        if (entry->event_type == EV_NO_ACTION)
            continue;

        if (entry->pcr_index >= TPM_PCR_COUNT)
            continue;

        /* Find the digest for our target algorithm */
        const uint8_t *digest_data = NULL;

        for (int d = 0; d < entry->digest_count; d++) {
            if (entry->digests[d].alg_id == target_alg &&
                entry->digests[d].digest_len == digest_len) {
                digest_data = entry->digests[d].digest;
                break;
            }
        }

        if (!digest_data) {
            /* For TCG1 logs, SHA-1 digest is always index 0.
             * If we are replaying SHA-256 from a SHA-1-only log,
             * skip (cannot replay). */
            if (!log->crypto_agile && bank == TPM_BANK_SHA1 &&
                entry->digest_count > 0) {
                digest_data = entry->digests[0].digest;
            } else {
                continue;
            }
        }

        pcr_extend(simulated->pcrs[entry->pcr_index].digest,
                    digest_len, digest_data, bank);
    }

    return TPM_OK;
}

/* ------------------------------------------------------------------ */

tpm_err_t event_log_verify(const event_log_t *log,
                            const tpm_pcr_set_t *actual,
                            tpm_bank_t bank,
                            replay_report_t *report)
{
    memset(report, 0, sizeof(*report));
    report->bank = bank;

    tpm_pcr_set_t simulated;
    tpm_err_t rc = event_log_replay(log, bank, &simulated);
    if (rc != TPM_OK)
        return rc;

    size_t digest_len = tpm_bank_digest_len(bank);

    /* Count events per PCR */
    int pcr_event_count[TPM_PCR_COUNT] = {0};
    for (int i = 0; i < log->count; i++) {
        if (log->entries[i].pcr_index < TPM_PCR_COUNT &&
            log->entries[i].event_type != EV_NO_ACTION) {
            pcr_event_count[log->entries[i].pcr_index]++;
        }
    }

    for (int i = 0; i < TPM_PCR_COUNT; i++) {
        if (!actual->pcrs[i].valid)
            continue;

        replay_result_t *r = &report->pcrs[report->total_verified];
        r->pcr_index = i;
        r->digest_len = digest_len;
        r->event_count = pcr_event_count[i];

        memcpy(r->replayed, simulated.pcrs[i].digest, digest_len);
        memcpy(r->actual, actual->pcrs[i].digest, digest_len);

        r->match = (memcmp(r->replayed, r->actual, digest_len) == 0);

        if (r->match)
            report->total_matched++;
        else
            report->total_mismatched++;

        report->total_verified++;
    }

    return (report->total_mismatched > 0) ? TPM_ERR_REPLAY : TPM_OK;
}

/* ------------------------------------------------------------------ */

int event_log_pcr_chain(const event_log_t *log, int pcr_index,
                         const event_entry_t **out, int max_out)
{
    int count = 0;
    for (int i = 0; i < log->count && count < max_out; i++) {
        if ((int)log->entries[i].pcr_index == pcr_index &&
            log->entries[i].event_type != EV_NO_ACTION) {
            out[count++] = &log->entries[i];
        }
    }
    return count;
}

/* ------------------------------------------------------------------ */

char *event_data_description(const event_entry_t *entry,
                              char *buf, size_t buf_size)
{
    if (buf_size == 0) return buf;
    buf[0] = '\0';

    if (entry->event_data_size == 0) {
        snprintf(buf, buf_size, "(no data)");
        return buf;
    }

    /* For EV_EFI_VARIABLE_DRIVER_CONFIG and similar, the data starts
     * with a UEFI_VARIABLE_DATA structure: GUID(16) + UnicodeNameLen(8)
     * + DataLen(8) + UnicodeName + Data.  Try to extract the name. */
    if ((entry->event_type == EV_EFI_VARIABLE_DRIVER_CONFIG ||
         entry->event_type == EV_EFI_VARIABLE_BOOT ||
         entry->event_type == EV_EFI_VARIABLE_AUTHORITY) &&
        entry->event_data_size > 32) {

        /* Skip GUID (16 bytes), read name length (8 bytes LE) */
        uint64_t name_len = 0;
        for (int i = 0; i < 8 && i + 16 < (int)entry->event_data_size; i++)
            name_len |= ((uint64_t)entry->event_data[16 + i]) << (i * 8);

        /* Name starts at offset 32, encoded as UTF-16LE */
        size_t name_off = 32;
        size_t out_pos = 0;
        for (uint64_t i = 0; i < name_len && name_off + 1 < entry->event_data_size; i++) {
            uint8_t lo = entry->event_data[name_off];
            name_off += 2;  /* skip UTF-16 pair */
            if (lo >= 0x20 && lo < 0x7F && out_pos < buf_size - 1)
                buf[out_pos++] = (char)lo;
        }
        buf[out_pos] = '\0';
        if (out_pos > 0)
            return buf;
    }

    /* For EV_EFI_BOOT_SERVICES_APPLICATION, try to extract the
     * device path description.  It contains a binary structure but
     * sometimes has readable ASCII/UTF-16 substrings. */
    if (entry->event_type == EV_EFI_BOOT_SERVICES_APPLICATION &&
        entry->event_data_size > 32) {
        /* Try to find readable substrings in the event data */
        size_t out_pos = 0;
        bool in_string = false;
        int consecutive = 0;

        for (uint32_t i = 0; i < entry->event_data_size && out_pos < buf_size - 2; i++) {
            uint8_t c = entry->event_data[i];
            if (c >= 0x20 && c < 0x7F) {
                consecutive++;
                if (consecutive >= 4) {
                    if (!in_string && out_pos > 0)
                        buf[out_pos++] = ' ';
                    if (!in_string && consecutive > 4) {
                        /* Backfill characters we skipped */
                        for (int j = consecutive - 1; j >= 4 && out_pos < buf_size - 2; j--) {
                            /* Already past, just start from here */
                        }
                    }
                    in_string = true;
                    buf[out_pos++] = (char)c;
                } else if (in_string) {
                    buf[out_pos++] = (char)c;
                }
            } else {
                if (in_string && consecutive < 4) {
                    /* Remove short false positives */
                }
                in_string = false;
                consecutive = 0;
            }
        }
        buf[out_pos] = '\0';
        if (out_pos > 4)
            return buf;
    }

    /* For EV_ACTION / EV_EFI_ACTION, data is typically ASCII */
    if (entry->event_type == EV_ACTION ||
        entry->event_type == EV_EFI_ACTION ||
        entry->event_type == EV_S_CRTM_VERSION) {
        size_t copy_len = entry->event_data_size;
        if (copy_len >= buf_size)
            copy_len = buf_size - 1;
        memcpy(buf, entry->event_data, copy_len);
        buf[copy_len] = '\0';
        /* Strip non-printable characters */
        for (size_t i = 0; i < copy_len; i++) {
            if ((unsigned char)buf[i] < 0x20 || (unsigned char)buf[i] > 0x7E)
                buf[i] = '.';
        }
        return buf;
    }

    /* Fallback: show first N bytes as hex */
    size_t show = entry->event_data_size;
    if (show > 32) show = 32;
    size_t pos = 0;
    for (size_t i = 0; i < show && pos + 3 < buf_size; i++) {
        static const char hex[] = "0123456789abcdef";
        buf[pos++] = hex[(entry->event_data[i] >> 4) & 0x0F];
        buf[pos++] = hex[entry->event_data[i] & 0x0F];
    }
    if (show < entry->event_data_size && pos + 3 < buf_size) {
        buf[pos++] = '.';
        buf[pos++] = '.';
        buf[pos++] = '.';
    }
    buf[pos] = '\0';
    return buf;
}
