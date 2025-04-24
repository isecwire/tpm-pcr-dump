/*
 * tpm-pcr-dump v2.0.0 — TPM 2.0 PCR reader, event log parser,
 *                        simulator, and attestation tool
 *
 * Usage:
 *   tpm-pcr-dump read [-b BANK] [-p INDEX]
 *   tpm-pcr-dump verify --golden FILE
 *   tpm-pcr-dump eventlog [--log PATH]
 *   tpm-pcr-dump simulate [--log PATH] [--extend HEX -p INDEX]
 *   tpm-pcr-dump attest [--golden FILE] [--log PATH]
 *   tpm-pcr-dump diff FILE_A FILE_B
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#include "tpm_pcr_dump.h"
#include "commands.h"
#include "color.h"
#include "utils.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */

static void usage(const char *progname)
{
    fprintf(stderr,
        "tpm-pcr-dump v%s — TPM 2.0 PCR Analysis Tool\n"
        "Copyright (c) 2026 isecwire GmbH\n"
        "\n"
        "Usage: %s <command> [options]\n"
        "\n"
        "Commands:\n"
        "  read       Read PCR values from TPM\n"
        "  verify     Verify PCRs against golden values\n"
        "  eventlog   Parse and display TPM2 event log\n"
        "  simulate   PCR simulation and what-if analysis\n"
        "  attest     Generate attestation report\n"
        "  diff       Compare two PCR snapshots\n"
        "\n"
        "Global Options:\n"
        "  -b, --bank BANK     Hash bank: sha1, sha256, sha384, sha512, sm3_256\n"
        "                      (default: sha256)\n"
        "  -p, --pcr INDEX     Select a single PCR (0-23)\n"
        "  --format FMT        Output format: table (default), json, csv\n"
        "  --color             Force colored output\n"
        "  --no-color          Disable colored output\n"
        "  --no-banner         Suppress the ASCII art banner\n"
        "  -d, --debug         Enable debug output\n"
        "  -h, --help          Show this help\n"
        "  -V, --version       Show version\n"
        "\n"
        "Command-Specific Options:\n"
        "  verify:\n"
        "    --golden FILE     Path to golden PCR values file\n"
        "\n"
        "  eventlog:\n"
        "    --log PATH        Path to binary_bios_measurements\n"
        "                      (default: /sys/kernel/security/tpm0/binary_bios_measurements)\n"
        "\n"
        "  simulate:\n"
        "    --log PATH        Replay event log into simulator\n"
        "    --extend HEX      Extend a PCR with this digest (use with -p)\n"
        "\n"
        "  attest:\n"
        "    --golden FILE     Verify against golden values in report\n"
        "    --log PATH        Include event log analysis in report\n"
        "    --pcr-mask MASK   PCR selection bitmask for quote (hex, e.g. 0xFF)\n"
        "\n"
        "  diff:\n"
        "    <file_a> <file_b>  Two PCR snapshot files to compare\n"
        "\n"
        "Examples:\n"
        "  %s read                                  Read all SHA-256 PCRs\n"
        "  %s read -b sha384 --format json           SHA-384 PCRs as JSON\n"
        "  %s verify --golden expected_pcrs.json     Verify boot chain\n"
        "  %s eventlog                               Parse BIOS event log\n"
        "  %s simulate --log /path/to/measurements   Replay event log\n"
        "  %s simulate -p 7 --extend <sha256hex>     What-if: extend PCR 7\n"
        "  %s attest --golden golden.json             Full attestation report\n"
        "  %s diff snapshot_a.json snapshot_b.json   Compare snapshots\n",
        TPM_PCR_DUMP_VERSION_STRING,
        progname, progname, progname, progname, progname,
        progname, progname, progname, progname);
}

/* Long options */
static struct option long_opts[] = {
    { "bank",       required_argument, NULL, 'b' },
    { "pcr",        required_argument, NULL, 'p' },
    { "format",     required_argument, NULL, 'F' },
    { "color",      no_argument,       NULL, 'C' },
    { "no-color",   no_argument,       NULL, 'N' },
    { "no-banner",  no_argument,       NULL, 'B' },
    { "golden",     required_argument, NULL, 'g' },
    { "log",        required_argument, NULL, 'l' },
    { "extend",     required_argument, NULL, 'e' },
    { "pcr-mask",   required_argument, NULL, 'm' },
    { "debug",      no_argument,       NULL, 'd' },
    { "help",       no_argument,       NULL, 'h' },
    { "version",    no_argument,       NULL, 'V' },
    /* Legacy short options for backward compatibility */
    { NULL, 0, NULL, 0 },
};

/* ------------------------------------------------------------------ */
/* Legacy mode: if no subcommand, behave like v1.x                     */
/* ------------------------------------------------------------------ */

static bool is_legacy_mode(int argc, char *argv[])
{
    /* If the first non-option argument matches a known command, not legacy.
     * If user uses -a, -j, or -v flags, it is legacy mode. */
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            /* Check for legacy-only flags */
            if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "-j") == 0)
                return true;
            if (strcmp(argv[i], "-v") == 0)
                return true;
            continue;
        }
        /* First non-option arg: check if it is a command name */
        if (cmd_lookup(argv[i]))
            return false;
        /* Not a known command — might be a file arg from legacy */
        return true;
    }
    /* No positional args and no legacy flags — require subcommand */
    return false;
}

static int run_legacy(int argc, char *argv[])
{
    global_opts_t opts = {0};
    opts.bank = TPM_BANK_SHA256;
    opts.format = OUTPUT_TABLE;
    opts.pcr_index = -1;
    opts.show_banner = true;

    bool read_all = false;
    bool json_out = false;

    int opt;
    optind = 1;
    while ((opt = getopt(argc, argv, "b:p:ajv:dh")) != -1) {
        switch (opt) {
        case 'b': {
            tpm_bank_t b = tpm_bank_from_name(optarg);
            if (b >= TPM_BANK_COUNT) {
                err_print("unknown bank '%s'", optarg);
                return 1;
            }
            opts.bank = b;
            break;
        }
        case 'p': {
            char *end;
            long idx = strtol(optarg, &end, 10);
            if (*end != '\0' || idx < 0 || idx >= TPM_PCR_COUNT) {
                err_print("invalid PCR index '%s' (0-23)", optarg);
                return 1;
            }
            opts.pcr_index = (int)idx;
            break;
        }
        case 'a':
            read_all = true;
            break;
        case 'j':
            json_out = true;
            break;
        case 'v':
            opts.verify_path = optarg;
            break;
        case 'd':
            opts.debug = true;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (json_out)
        opts.format = OUTPUT_JSON;

    dbg_set_enabled(opts.debug);
    color_init(false, json_out);

    if (opts.verify_path) {
        return cmd_verify(&opts);
    }

    if (!read_all && opts.pcr_index < 0) {
        err_print("specify -a, -p INDEX, or -v FILE (see -h for help)");
        return 1;
    }

    return cmd_read(&opts);
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    /* Check for legacy v1.x invocation style */
    if (is_legacy_mode(argc, argv))
        return run_legacy(argc, argv);

    /* Find the subcommand */
    const char *cmd_name = NULL;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            cmd_name = argv[i];
            break;
        }
        /* Skip option arguments */
        if (i + 1 < argc && argv[i][0] == '-' &&
            (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "-p") == 0 ||
             strcmp(argv[i], "--bank") == 0 || strcmp(argv[i], "--pcr") == 0 ||
             strcmp(argv[i], "--format") == 0)) {
            i++; /* skip the value */
        }
    }

    if (!cmd_name) {
        usage(argv[0]);
        return 1;
    }

    /* Handle help / version pseudo-commands */
    if (strcmp(cmd_name, "help") == 0 || strcmp(cmd_name, "--help") == 0) {
        usage(argv[0]);
        return 0;
    }
    if (strcmp(cmd_name, "version") == 0 || strcmp(cmd_name, "--version") == 0) {
        printf("tpm-pcr-dump %s\n", TPM_PCR_DUMP_VERSION_STRING);
        return 0;
    }

    const cmd_def_t *cmd = cmd_lookup(cmd_name);
    if (!cmd) {
        err_print("unknown command '%s' (see --help)", cmd_name);
        return 1;
    }

    /* Parse global options (options can appear before or after command) */
    global_opts_t opts = {0};
    opts.bank = TPM_BANK_SHA256;
    opts.format = OUTPUT_TABLE;
    opts.pcr_index = -1;
    opts.show_banner = true;

    /* Reset getopt */
    optind = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "b:p:g:l:e:m:dhV",
                               long_opts, NULL)) != -1) {
        switch (opt) {
        case 'b': {
            tpm_bank_t b = tpm_bank_from_name(optarg);
            if (b >= TPM_BANK_COUNT) {
                err_print("unknown bank '%s' (sha1, sha256, sha384, sha512, sm3_256)",
                          optarg);
                return 1;
            }
            opts.bank = b;
            break;
        }
        case 'p': {
            char *end;
            long idx = strtol(optarg, &end, 10);
            if (*end != '\0' || idx < 0 || idx >= TPM_PCR_COUNT) {
                err_print("invalid PCR index '%s' (0-23)", optarg);
                return 1;
            }
            opts.pcr_index = (int)idx;
            break;
        }
        case 'F':
            if (strcmp(optarg, "json") == 0)
                opts.format = OUTPUT_JSON;
            else if (strcmp(optarg, "csv") == 0)
                opts.format = OUTPUT_CSV;
            else if (strcmp(optarg, "table") == 0)
                opts.format = OUTPUT_TABLE;
            else {
                err_print("unknown format '%s' (table, json, csv)", optarg);
                return 1;
            }
            break;
        case 'C':
            opts.color = true;
            break;
        case 'N':
            opts.no_color = true;
            break;
        case 'B':
            opts.show_banner = false;
            break;
        case 'g':
            opts.verify_path = optarg;
            opts.golden_path = optarg;
            break;
        case 'l':
            opts.eventlog_path = optarg;
            break;
        case 'e':
            opts.extend_hex = optarg;
            break;
        case 'm': {
            char *end;
            unsigned long mask = strtoul(optarg, &end, 0);
            if (*end != '\0' || mask > 0x00FFFFFF) {
                err_print("invalid PCR mask '%s'", optarg);
                return 1;
            }
            opts.pcr_mask = (uint32_t)mask;
            break;
        }
        case 'd':
            opts.debug = true;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        case 'V':
            printf("tpm-pcr-dump %s\n", TPM_PCR_DUMP_VERSION_STRING);
            return 0;
        default:
            break;  /* ignore unknown opts for forward compat */
        }
    }

    /* Collect remaining positional arguments for diff command */
    if (cmd->id == CMD_DIFF) {
        int pos = 0;
        for (int i = optind; i < argc; i++) {
            if (strcmp(argv[i], cmd_name) == 0)
                continue;
            if (pos == 0)
                opts.diff_path_a = argv[i];
            else if (pos == 1)
                opts.diff_path_b = argv[i];
            pos++;
        }
    }

    dbg_set_enabled(opts.debug);
    color_init(opts.color, opts.no_color || opts.format == OUTPUT_JSON);

    return cmd->handler(&opts);
}
