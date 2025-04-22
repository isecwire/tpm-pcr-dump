/*
 * tpm-pcr-dump — Subcommand dispatcher
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#ifndef TPM_COMMANDS_H
#define TPM_COMMANDS_H

#include "tpm_pcr_dump.h"

/* Global options shared across all subcommands */
typedef struct {
    tpm_bank_t   bank;
    output_fmt_t format;
    bool         color;
    bool         no_color;
    bool         debug;
    bool         show_banner;
    int          pcr_index;     /* -1 = all */
    const char  *verify_path;
    const char  *eventlog_path;
    const char  *golden_path;
    const char  *diff_path_a;
    const char  *diff_path_b;
    const char  *extend_hex;
    uint32_t     pcr_mask;      /* bitmask for attestation PCR selection */
} global_opts_t;

/* Subcommand identifiers */
typedef enum {
    CMD_READ,
    CMD_VERIFY,
    CMD_EVENTLOG,
    CMD_SIMULATE,
    CMD_ATTEST,
    CMD_DIFF,
    CMD_HELP,
    CMD_VERSION,
} cmd_id_t;

/* Subcommand handler function signature */
typedef int (*cmd_handler_t)(const global_opts_t *opts);

/* Subcommand definition */
typedef struct {
    const char    *name;
    const char    *description;
    cmd_id_t       id;
    cmd_handler_t  handler;
} cmd_def_t;

/* Resolve a subcommand name to its handler.  Returns NULL on unknown. */
const cmd_def_t *cmd_lookup(const char *name);

/* Get the list of all commands (NULL-terminated) */
const cmd_def_t *cmd_list(void);

/* Command handlers */
int cmd_read(const global_opts_t *opts);
int cmd_verify(const global_opts_t *opts);
int cmd_eventlog(const global_opts_t *opts);
int cmd_simulate(const global_opts_t *opts);
int cmd_attest(const global_opts_t *opts);
int cmd_diff(const global_opts_t *opts);

#endif /* TPM_COMMANDS_H */
