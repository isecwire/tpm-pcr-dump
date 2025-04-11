/*
 * tpm-pcr-dump — TCG TPM2 event log parser
 *
 * Parses the binary BIOS measurements log from:
 *   /sys/kernel/security/tpm0/binary_bios_measurements
 *
 * Reference: TCG PC Client Platform Firmware Profile Specification
 *            TCG EFI Protocol Specification
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#ifndef TPM_EVENT_LOG_H
#define TPM_EVENT_LOG_H

#include "tpm_pcr_dump.h"
#include "event_types.h"

/* Maximum event log size we will read (2 MB) */
#define EVENT_LOG_MAX_SIZE  (2 * 1024 * 1024)

/* Maximum event data size for a single event */
#define EVENT_DATA_MAX      (64 * 1024)

/* Maximum number of events we track */
#define EVENT_MAX_ENTRIES   4096

/* Maximum digest count per event (crypto-agile log) */
#define EVENT_MAX_DIGESTS   8

/* A single digest within a crypto-agile event */
typedef struct {
    uint16_t alg_id;
    uint8_t  digest[TPM_MAX_DIGEST_SIZE];
    size_t   digest_len;
} event_digest_t;

/* A parsed event log entry */
typedef struct {
    uint32_t       pcr_index;
    uint32_t       event_type;
    event_digest_t digests[EVENT_MAX_DIGESTS];
    int            digest_count;
    uint8_t        event_data[EVENT_DATA_MAX];
    uint32_t       event_data_size;
    size_t         raw_offset;     /* byte offset in original log */
} event_entry_t;

/* Spec ID Event header (first event in crypto-agile log) */
typedef struct {
    char     signature[16];
    uint32_t platform_class;
    uint8_t  spec_version_minor;
    uint8_t  spec_version_major;
    uint8_t  spec_errata;
    uint8_t  uintn_size;
    uint32_t num_algorithms;
    struct {
        uint16_t alg_id;
        uint16_t digest_size;
    } algorithms[EVENT_MAX_DIGESTS];
} spec_id_event_t;

/* Complete parsed event log */
typedef struct {
    event_entry_t   entries[EVENT_MAX_ENTRIES];
    int             count;
    spec_id_event_t spec_id;
    bool            crypto_agile;     /* true if TCG2 crypto-agile format */
    char            log_path[TPM_PATH_MAX];
} event_log_t;

/* Replay result for a single PCR */
typedef struct {
    int     pcr_index;
    uint8_t replayed[TPM_MAX_DIGEST_SIZE];
    uint8_t actual[TPM_MAX_DIGEST_SIZE];
    size_t  digest_len;
    bool    match;
    int     event_count;  /* number of events that extended this PCR */
} replay_result_t;

/* Full replay verification report */
typedef struct {
    replay_result_t pcrs[TPM_PCR_COUNT];
    int             total_verified;
    int             total_matched;
    int             total_mismatched;
    tpm_bank_t      bank;
} replay_report_t;

/*
 * Read and parse the TPM2 event log from the given path.
 * If path is NULL, uses the default sysfs path.
 */
tpm_err_t event_log_parse(const char *path, event_log_t *log);

/*
 * Replay the event log to compute expected PCR values.
 * The resulting values should match the actual TPM PCR values
 * if the log is intact and complete.
 */
tpm_err_t event_log_replay(const event_log_t *log, tpm_bank_t bank,
                            tpm_pcr_set_t *simulated);

/*
 * Verify event log integrity: replay events and compare against
 * actual TPM PCR values.
 */
tpm_err_t event_log_verify(const event_log_t *log,
                            const tpm_pcr_set_t *actual,
                            tpm_bank_t bank,
                            replay_report_t *report);

/*
 * Get the events that contributed to a specific PCR value.
 * Returns number of matching events found (up to max_out).
 */
int event_log_pcr_chain(const event_log_t *log, int pcr_index,
                         const event_entry_t **out, int max_out);

/*
 * Extract a printable description from event data.
 * Writes to buf (up to buf_size chars). Returns buf.
 */
char *event_data_description(const event_entry_t *entry,
                              char *buf, size_t buf_size);

#endif /* TPM_EVENT_LOG_H */
