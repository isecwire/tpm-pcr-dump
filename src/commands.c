/*
 * tpm-pcr-dump — Subcommand implementations
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#include "commands.h"
#include "tpm_interface.h"
#include "pcr_verify.h"
#include "json_writer.h"
#include "event_log.h"
#include "event_types.h"
#include "simulator.h"
#include "attestation.h"
#include "table_fmt.h"
#include "color.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Command registry                                                    */
/* ------------------------------------------------------------------ */

static const cmd_def_t g_commands[] = {
    { "read",     "Read PCR values from TPM",              CMD_READ,     cmd_read     },
    { "verify",   "Verify PCRs against golden values",     CMD_VERIFY,   cmd_verify   },
    { "eventlog", "Parse and display TPM2 event log",      CMD_EVENTLOG, cmd_eventlog },
    { "simulate", "PCR simulation and what-if analysis",   CMD_SIMULATE, cmd_simulate },
    { "attest",   "Generate attestation report",           CMD_ATTEST,   cmd_attest   },
    { "diff",     "Compare two PCR snapshots",             CMD_DIFF,     cmd_diff     },
    { NULL, NULL, 0, NULL },
};

const cmd_def_t *cmd_lookup(const char *name)
{
    if (!name) return NULL;
    for (int i = 0; g_commands[i].name; i++) {
        if (strcmp(g_commands[i].name, name) == 0)
            return &g_commands[i];
    }
    return NULL;
}

const cmd_def_t *cmd_list(void)
{
    return g_commands;
}

/* ------------------------------------------------------------------ */
/* Helper: open TPM and read PCRs                                      */
/* ------------------------------------------------------------------ */

static tpm_err_t open_and_read(const global_opts_t *opts, tpm_pcr_set_t *set)
{
    tpm_ctx_t tpm;
    tpm_err_t rc = tpm_open(&tpm, TPM_METHOD_AUTO);
    if (rc != TPM_OK) {
        err_print("failed to open TPM (rc=%d)", rc);
        return rc;
    }

    if (opts->pcr_index >= 0) {
        memset(set, 0, sizeof(*set));
        set->bank = opts->bank;
        rc = tpm_read_pcr(&tpm, opts->bank, opts->pcr_index,
                            &set->pcrs[opts->pcr_index]);
        if (rc == TPM_OK)
            set->count = 1;
    } else {
        rc = tpm_read_all_pcrs(&tpm, opts->bank, set);
    }

    tpm_close(&tpm);

    if (rc != TPM_OK)
        err_print("failed to read PCR values");

    return rc;
}

/* ------------------------------------------------------------------ */
/* Helper: print PCR set in different formats                          */
/* ------------------------------------------------------------------ */

static void print_pcrs_table(const tpm_pcr_set_t *set)
{
    size_t hex_width = tpm_bank_digest_len(set->bank) * 2;
    table_col_t cols[] = {
        { "PCR",   3,           TABLE_ALIGN_RIGHT },
        { "Value", (int)hex_width, TABLE_ALIGN_LEFT },
    };
    table_t tbl;
    table_init(&tbl, stdout, 2, cols);
    table_header(&tbl);

    for (int i = 0; i < TPM_PCR_COUNT; i++) {
        const tpm_pcr_value_t *pcr = &set->pcrs[i];
        char idx_str[8];
        snprintf(idx_str, sizeof(idx_str), "%d", i);

        if (pcr->valid) {
            char hex[TPM_MAX_HEX_SIZE];
            bin_to_hex(pcr->digest, pcr->digest_len, hex, sizeof(hex));

            /* Color: dim for all-zeros, green for non-zero */
            bool is_zero = true;
            for (size_t b = 0; b < pcr->digest_len; b++) {
                if (pcr->digest[b] != 0) { is_zero = false; break; }
            }

            table_cell(&tbl, idx_str, CLR_BOLD);
            table_cell(&tbl, hex, is_zero ? CLR_DIM : CLR_GREEN);
        } else {
            table_cell(&tbl, idx_str, CLR_BOLD);
            table_cell(&tbl, "<unavailable>", CLR_RED);
        }
    }

    table_bottom(&tbl);
}

static void print_pcrs_json(const tpm_pcr_set_t *set)
{
    json_writer_t jw;
    jw_init(&jw);

    jw_object_begin(&jw);
    jw_kv_string(&jw, "tool", "tpm-pcr-dump");
    jw_kv_string(&jw, "version", TPM_PCR_DUMP_VERSION_STRING);
    jw_kv_string(&jw, "bank", tpm_bank_name(set->bank));
    jw_kv_int(&jw, "pcr_count", set->count);

    jw_key(&jw, "pcrs");
    jw_array_begin(&jw);
    for (int i = 0; i < TPM_PCR_COUNT; i++) {
        const tpm_pcr_value_t *pcr = &set->pcrs[i];
        jw_object_begin(&jw);
        jw_kv_int(&jw, "index", i);
        jw_kv_bool(&jw, "valid", pcr->valid);
        if (pcr->valid) {
            char hex[TPM_MAX_HEX_SIZE];
            bin_to_hex(pcr->digest, pcr->digest_len, hex, sizeof(hex));
            jw_kv_string(&jw, "value", hex);
        } else {
            jw_key(&jw, "value");
            jw_null(&jw);
        }
        jw_object_end(&jw);
    }
    jw_array_end(&jw);
    jw_object_end(&jw);

    printf("%s", jw_finish(&jw));
}

static void print_pcrs_csv(const tpm_pcr_set_t *set)
{
    printf("pcr_index,bank,value\n");
    for (int i = 0; i < TPM_PCR_COUNT; i++) {
        const tpm_pcr_value_t *pcr = &set->pcrs[i];
        if (pcr->valid) {
            char hex[TPM_MAX_HEX_SIZE];
            bin_to_hex(pcr->digest, pcr->digest_len, hex, sizeof(hex));
            printf("%d,%s,%s\n", i, tpm_bank_name(set->bank), hex);
        } else {
            printf("%d,%s,\n", i, tpm_bank_name(set->bank));
        }
    }
}

/* ------------------------------------------------------------------ */
/* cmd_read — Read PCR values                                          */
/* ------------------------------------------------------------------ */

int cmd_read(const global_opts_t *opts)
{
    tpm_pcr_set_t set;
    tpm_err_t rc = open_and_read(opts, &set);
    if (rc != TPM_OK)
        return 1;

    if (opts->show_banner && opts->format == OUTPUT_TABLE)
        print_banner(tpm_bank_name(set.bank), set.count);

    switch (opts->format) {
    case OUTPUT_JSON:
        print_pcrs_json(&set);
        break;
    case OUTPUT_CSV:
        print_pcrs_csv(&set);
        break;
    default:
        print_pcrs_table(&set);
        break;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_verify — Verify against golden values                           */
/* ------------------------------------------------------------------ */

int cmd_verify(const global_opts_t *opts)
{
    if (!opts->verify_path) {
        err_print("verify requires a golden values file (--golden FILE)");
        return 1;
    }

    pcr_golden_t golden;
    tpm_err_t rc = pcr_golden_load(opts->verify_path, &golden);
    if (rc != TPM_OK)
        return 1;

    global_opts_t mopts = *opts;
    mopts.bank = golden.bank;

    tpm_pcr_set_t set;
    rc = open_and_read(&mopts, &set);
    if (rc != TPM_OK)
        return 1;

    pcr_report_t report;
    tpm_err_t vrc = pcr_verify(&set, &golden, &report);

    if (opts->format == OUTPUT_JSON) {
        json_writer_t jw;
        jw_init(&jw);

        jw_object_begin(&jw);
        jw_kv_string(&jw, "tool", "tpm-pcr-dump");
        jw_kv_string(&jw, "version", TPM_PCR_DUMP_VERSION_STRING);
        jw_kv_string(&jw, "command", "verify");
        jw_kv_string(&jw, "bank", tpm_bank_name(set.bank));
        jw_kv_bool(&jw, "pass", report.total_mismatched == 0);
        jw_kv_int(&jw, "checked", report.total_checked);
        jw_kv_int(&jw, "matched", report.total_matched);
        jw_kv_int(&jw, "mismatched", report.total_mismatched);

        if (report.composite_len > 0)
            jw_kv_string(&jw, "composite_hash", report.composite_hex);

        jw_key(&jw, "results");
        jw_array_begin(&jw);
        for (int i = 0; i < report.total_checked; i++) {
            const pcr_mismatch_t *r = &report.results[i];
            jw_object_begin(&jw);
            jw_kv_int(&jw, "index", r->index);
            jw_kv_bool(&jw, "match", r->match);
            jw_kv_string(&jw, "expected", r->expected_hex);
            jw_kv_string(&jw, "actual", r->actual_hex);
            jw_object_end(&jw);
        }
        jw_array_end(&jw);
        jw_object_end(&jw);

        printf("%s", jw_finish(&jw));
    } else {
        if (opts->show_banner)
            print_banner(tpm_bank_name(set.bank), set.count);

        printf("\n");
        color_fprintf(stdout, CLR_BOLD_WHITE, "  Verification Results\n");
        color_fprintf(stdout, CLR_DIM, "  ====================\n\n");

        table_col_t cols[] = {
            { "PCR",      3,  TABLE_ALIGN_RIGHT },
            { "Status",   8,  TABLE_ALIGN_CENTER },
            { "Expected", (int)(tpm_bank_digest_len(golden.bank) * 2),
                              TABLE_ALIGN_LEFT },
            { "Actual",   (int)(tpm_bank_digest_len(golden.bank) * 2),
                              TABLE_ALIGN_LEFT },
        };
        table_t tbl;
        table_init(&tbl, stdout, 4, cols);
        table_header(&tbl);

        for (int i = 0; i < report.total_checked; i++) {
            const pcr_mismatch_t *r = &report.results[i];
            char idx_str[8];
            snprintf(idx_str, sizeof(idx_str), "%d", r->index);

            table_cell(&tbl, idx_str, CLR_BOLD);
            table_cell(&tbl, r->match ? "OK" : "FAIL",
                       r->match ? CLR_BOLD_GREEN : CLR_BOLD_RED);
            table_cell(&tbl, r->expected_hex, CLR_CYAN);
            table_cell(&tbl, r->actual_hex,
                       r->match ? CLR_GREEN : CLR_RED);
        }

        table_bottom(&tbl);
        printf("\n");

        printf("  Checked: %s%d%s  Matched: %s%d%s  Mismatched: %s%d%s\n",
               clr(CLR_BOLD), report.total_checked, clr(CLR_RESET),
               clr(CLR_GREEN), report.total_matched, clr(CLR_RESET),
               clr(report.total_mismatched > 0 ? CLR_RED : CLR_GREEN),
               report.total_mismatched, clr(CLR_RESET));

        if (report.composite_len > 0) {
            printf("  Composite hash: %s%s%s\n",
                   clr(CLR_CYAN), report.composite_hex, clr(CLR_RESET));
        }

        printf("  Result: ");
        if (report.total_mismatched == 0)
            color_fprintf(stdout, CLR_BOLD_GREEN, "PASS\n");
        else
            color_fprintf(stdout, CLR_BOLD_RED, "FAIL\n");
        printf("\n");
    }

    return (vrc == TPM_OK) ? 0 : 2;
}

/* ------------------------------------------------------------------ */
/* cmd_eventlog — Parse and display event log                          */
/* ------------------------------------------------------------------ */

int cmd_eventlog(const global_opts_t *opts)
{
    event_log_t elog;
    tpm_err_t rc = event_log_parse(opts->eventlog_path, &elog);
    if (rc != TPM_OK)
        return 1;

    if (opts->format == OUTPUT_JSON) {
        json_writer_t jw;
        jw_init(&jw);

        jw_object_begin(&jw);
        jw_kv_string(&jw, "tool", "tpm-pcr-dump");
        jw_kv_string(&jw, "version", TPM_PCR_DUMP_VERSION_STRING);
        jw_kv_string(&jw, "command", "eventlog");
        jw_kv_bool(&jw, "crypto_agile", elog.crypto_agile);
        jw_kv_int(&jw, "event_count", elog.count);
        jw_kv_string(&jw, "log_path", elog.log_path);

        jw_key(&jw, "events");
        jw_array_begin(&jw);
        for (int i = 0; i < elog.count; i++) {
            const event_entry_t *e = &elog.entries[i];
            jw_object_begin(&jw);
            jw_kv_int(&jw, "index", i);
            jw_kv_int(&jw, "pcr", (int)e->pcr_index);
            jw_kv_string(&jw, "event_type", event_type_name(e->event_type));

            /* Digests */
            jw_key(&jw, "digests");
            jw_array_begin(&jw);
            for (int d = 0; d < e->digest_count; d++) {
                jw_object_begin(&jw);
                char alg_name[16];
                tpm_bank_t bk = tpm_bank_from_alg_id(e->digests[d].alg_id);
                snprintf(alg_name, sizeof(alg_name), "%s",
                         bk < TPM_BANK_COUNT ? tpm_bank_name(bk) : "unknown");
                jw_kv_string(&jw, "algorithm", alg_name);
                char hex[TPM_MAX_HEX_SIZE];
                bin_to_hex(e->digests[d].digest, e->digests[d].digest_len,
                           hex, sizeof(hex));
                jw_kv_string(&jw, "digest", hex);
                jw_object_end(&jw);
            }
            jw_array_end(&jw);

            /* Description */
            char desc[512];
            event_data_description(e, desc, sizeof(desc));
            jw_kv_string(&jw, "description", desc);

            jw_object_end(&jw);
        }
        jw_array_end(&jw);
        jw_object_end(&jw);

        printf("%s", jw_finish(&jw));
    } else {
        if (opts->show_banner)
            print_banner(tpm_bank_name(opts->bank), 0);

        printf("  %sEvent Log:%s %s\n",
               clr(CLR_CYAN), clr(CLR_RESET), elog.log_path);
        printf("  %sFormat:%s    %s\n",
               clr(CLR_CYAN), clr(CLR_RESET),
               elog.crypto_agile ? "TCG2 (crypto-agile)" : "TCG1 (SHA-1)");
        printf("  %sEvents:%s    %d\n\n",
               clr(CLR_CYAN), clr(CLR_RESET), elog.count);

        table_col_t cols[] = {
            { "#",     4,  TABLE_ALIGN_RIGHT },
            { "PCR",   3,  TABLE_ALIGN_RIGHT },
            { "Type",  36, TABLE_ALIGN_LEFT },
            { "Description", 40, TABLE_ALIGN_LEFT },
        };
        table_t tbl;
        table_init(&tbl, stdout, 4, cols);
        table_header(&tbl);

        for (int i = 0; i < elog.count; i++) {
            const event_entry_t *e = &elog.entries[i];

            char idx_str[16];
            snprintf(idx_str, sizeof(idx_str), "%d", i);

            char pcr_str[16];
            snprintf(pcr_str, sizeof(pcr_str), "%u", e->pcr_index);

            char desc[512];
            event_data_description(e, desc, sizeof(desc));

            /* Color based on event type */
            color_code_t type_color = CLR_RESET;
            if (e->event_type == EV_SEPARATOR)
                type_color = CLR_YELLOW;
            else if (e->event_type == EV_NO_ACTION)
                type_color = CLR_DIM;
            else if (e->event_type >= EV_EFI_EVENT_BASE)
                type_color = CLR_CYAN;

            table_cell(&tbl, idx_str, CLR_DIM);
            table_cell(&tbl, pcr_str, CLR_BOLD);
            table_cell(&tbl, event_type_name(e->event_type), type_color);
            table_cell(&tbl, desc, CLR_RESET);
        }

        table_bottom(&tbl);

        /* Replay verification if TPM is available */
        printf("\n");
        color_fprintf(stdout, CLR_BOLD_WHITE,
                      "  Event Log Replay Verification\n");
        color_fprintf(stdout, CLR_DIM,
                      "  =============================\n\n");

        tpm_ctx_t tpm;
        rc = tpm_open(&tpm, TPM_METHOD_AUTO);
        if (rc == TPM_OK) {
            tpm_pcr_set_t actual;
            rc = tpm_read_all_pcrs(&tpm, opts->bank, &actual);
            tpm_close(&tpm);

            if (rc == TPM_OK) {
                replay_report_t replay;
                event_log_verify(&elog, &actual, opts->bank, &replay);

                table_col_t rcols[] = {
                    { "PCR",    3,  TABLE_ALIGN_RIGHT },
                    { "Status", 8,  TABLE_ALIGN_CENTER },
                    { "Events", 6,  TABLE_ALIGN_RIGHT },
                };
                table_t rtbl;
                table_init(&rtbl, stdout, 3, rcols);
                table_header(&rtbl);

                for (int i = 0; i < replay.total_verified; i++) {
                    const replay_result_t *r = &replay.pcrs[i];
                    char pcr_str[8];
                    snprintf(pcr_str, sizeof(pcr_str), "%d", r->pcr_index);
                    char evt_str[8];
                    snprintf(evt_str, sizeof(evt_str), "%d", r->event_count);

                    table_cell(&rtbl, pcr_str, CLR_BOLD);
                    table_cell(&rtbl, r->match ? "OK" : "FAIL",
                               r->match ? CLR_BOLD_GREEN : CLR_BOLD_RED);
                    table_cell(&rtbl, evt_str, CLR_CYAN);
                }
                table_bottom(&rtbl);

                printf("\n  Verified: %s%d%s  Matched: %s%d%s  "
                       "Mismatched: %s%d%s\n",
                       clr(CLR_BOLD), replay.total_verified, clr(CLR_RESET),
                       clr(CLR_GREEN), replay.total_matched, clr(CLR_RESET),
                       clr(replay.total_mismatched > 0 ? CLR_RED : CLR_GREEN),
                       replay.total_mismatched, clr(CLR_RESET));

                printf("  Integrity: ");
                if (replay.total_mismatched == 0)
                    color_fprintf(stdout, CLR_BOLD_GREEN, "VERIFIED\n");
                else
                    color_fprintf(stdout, CLR_BOLD_RED, "MISMATCH DETECTED\n");
            } else {
                color_fprintf(stdout, CLR_YELLOW,
                              "  Could not read TPM PCRs for replay verification\n");
            }
        } else {
            color_fprintf(stdout, CLR_YELLOW,
                          "  TPM not available for replay verification\n");
        }

        printf("\n");
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_simulate — PCR simulation                                       */
/* ------------------------------------------------------------------ */

int cmd_simulate(const global_opts_t *opts)
{
    sim_ctx_t sim;
    sim_init(&sim, opts->bank);

    /* If an event log path is given, replay it into the simulator */
    if (opts->eventlog_path) {
        event_log_t elog;
        tpm_err_t rc = event_log_parse(opts->eventlog_path, &elog);
        if (rc != TPM_OK)
            return 1;

        tpm_pcr_set_t replayed;
        rc = event_log_replay(&elog, opts->bank, &replayed);
        if (rc != TPM_OK) {
            err_print("failed to replay event log");
            return 1;
        }

        sim_init_from(&sim, &replayed);

        if (opts->format == OUTPUT_TABLE && opts->show_banner)
            print_banner(tpm_bank_name(opts->bank), replayed.count);

        printf("  %sSimulated PCR values from event log replay%s\n\n",
               clr(CLR_BOLD_CYAN), clr(CLR_RESET));
    } else {
        if (opts->format == OUTPUT_TABLE && opts->show_banner)
            print_banner(tpm_bank_name(opts->bank), TPM_PCR_COUNT);

        printf("  %sSimulated PCR values (all zeros)%s\n\n",
               clr(CLR_BOLD_CYAN), clr(CLR_RESET));
    }

    /* What-if analysis: extend a PCR if --extend is specified */
    if (opts->extend_hex && opts->pcr_index >= 0) {
        uint8_t measurement[TPM_MAX_DIGEST_SIZE];
        int mlen = hex_to_bin(opts->extend_hex, measurement,
                               sizeof(measurement));
        if (mlen < 0) {
            err_print("invalid hex for --extend");
            return 1;
        }

        uint8_t before[TPM_MAX_DIGEST_SIZE];
        size_t before_len = sim.state.pcrs[opts->pcr_index].digest_len;
        memcpy(before, sim.state.pcrs[opts->pcr_index].digest, before_len);

        uint8_t result[TPM_MAX_DIGEST_SIZE];
        size_t result_len = 0;
        tpm_err_t rc = sim_what_if(&sim, opts->pcr_index,
                                     measurement, (size_t)mlen,
                                     result, &result_len);
        if (rc != TPM_OK) {
            err_print("what-if simulation failed");
            return 1;
        }

        char before_hex[TPM_MAX_HEX_SIZE];
        char after_hex[TPM_MAX_HEX_SIZE];
        char meas_hex[TPM_MAX_HEX_SIZE];

        bin_to_hex(before, before_len, before_hex, sizeof(before_hex));
        bin_to_hex(result, result_len, after_hex, sizeof(after_hex));
        bin_to_hex(measurement, (size_t)mlen, meas_hex, sizeof(meas_hex));

        printf("  %sWhat-If Analysis: PCR[%d]%s\n\n",
               clr(CLR_BOLD_WHITE), opts->pcr_index, clr(CLR_RESET));
        printf("  %sBefore:%s  %s%s%s\n",
               clr(CLR_CYAN), clr(CLR_RESET),
               clr(CLR_DIM), before_hex, clr(CLR_RESET));
        printf("  %sExtend:%s  %s%s%s\n",
               clr(CLR_CYAN), clr(CLR_RESET),
               clr(CLR_YELLOW), meas_hex, clr(CLR_RESET));
        printf("  %sAfter:%s   %s%s%s\n\n",
               clr(CLR_CYAN), clr(CLR_RESET),
               clr(CLR_BOLD_GREEN), after_hex, clr(CLR_RESET));

        return 0;
    }

    /* Print simulated PCR values */
    switch (opts->format) {
    case OUTPUT_JSON:
        print_pcrs_json(&sim.state);
        break;
    case OUTPUT_CSV:
        print_pcrs_csv(&sim.state);
        break;
    default:
        print_pcrs_table(&sim.state);
        break;
    }

    /* Policy check against actual TPM if available */
    tpm_ctx_t tpm;
    if (tpm_open(&tpm, TPM_METHOD_AUTO) == TPM_OK) {
        tpm_pcr_set_t actual;
        if (tpm_read_all_pcrs(&tpm, opts->bank, &actual) == TPM_OK) {
            policy_report_t policy;
            sim_policy_check(&actual, &sim.state, &policy);

            printf("\n  %sPolicy Match Check (simulated vs actual):%s\n",
                   clr(CLR_BOLD_WHITE), clr(CLR_RESET));
            printf("  ");
            if (policy.policy_pass) {
                color_fprintf(stdout, CLR_BOLD_GREEN,
                              "PASS");
                printf(" (%d/%d PCRs match)\n",
                       policy.matched, policy.count);
            } else {
                color_fprintf(stdout, CLR_BOLD_RED,
                              "FAIL");
                printf(" (%d mismatched)\n", policy.mismatched);
            }
        }
        tpm_close(&tpm);
    }

    printf("\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_attest — Attestation report                                     */
/* ------------------------------------------------------------------ */

int cmd_attest(const global_opts_t *opts)
{
    tpm_pcr_set_t set;
    tpm_err_t rc = open_and_read(opts, &set);
    if (rc != TPM_OK)
        return 1;

    /* Try to parse event log */
    event_log_t elog;
    bool have_elog = false;
    replay_report_t replay;
    memset(&replay, 0, sizeof(replay));

    if (event_log_parse(opts->eventlog_path, &elog) == TPM_OK) {
        have_elog = true;
        event_log_verify(&elog, &set, opts->bank, &replay);
    }

    /* Build report */
    attest_report_t report;
    attest_build_report(&report, &set, have_elog ? &elog : NULL,
                         have_elog ? &replay : NULL);

    /* Generate quote parameters */
    uint32_t mask = opts->pcr_mask;
    if (mask == 0)
        mask = 0x00FFFFFF;  /* All 24 PCRs by default */

    quote_params_t qparams;
    rc = attest_prepare_quote(&set, opts->bank, mask, &qparams);
    if (rc == TPM_OK) {
        report.quote_prepared = true;
        report.quote = qparams;
    }

    /* Golden verification if path provided */
    if (opts->golden_path) {
        pcr_golden_t golden;
        if (pcr_golden_load(opts->golden_path, &golden) == TPM_OK) {
            pcr_report_t vreport;
            pcr_verify(&set, &golden, &vreport);
            report.golden_verified = true;
            report.golden_matched = vreport.total_matched;
            report.golden_mismatched = vreport.total_mismatched;
        }
    }

    /* Output */
    if (opts->format == OUTPUT_JSON) {
        attest_print_report_json(&report);
    } else {
        if (opts->show_banner)
            print_banner(tpm_bank_name(set.bank), set.count);
        attest_print_report(&report);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* cmd_diff — Compare two PCR snapshots                                */
/* ------------------------------------------------------------------ */

static tpm_err_t load_snapshot_json(const char *path, tpm_pcr_set_t *set)
{
    /* Load a JSON snapshot file (our own output format).
     * We use the same minimal parser approach as pcr_golden_load. */
    pcr_golden_t golden;
    tpm_err_t rc = pcr_golden_load(path, &golden);
    if (rc != TPM_OK)
        return rc;

    memset(set, 0, sizeof(*set));
    set->bank = golden.bank;

    for (int i = 0; i < TPM_PCR_COUNT; i++) {
        if (golden.entries[i].present) {
            set->pcrs[i].index = i;
            memcpy(set->pcrs[i].digest, golden.entries[i].digest,
                   golden.entries[i].digest_len);
            set->pcrs[i].digest_len = golden.entries[i].digest_len;
            set->pcrs[i].valid = true;
            set->count++;
        }
    }

    return TPM_OK;
}

int cmd_diff(const global_opts_t *opts)
{
    if (!opts->diff_path_a || !opts->diff_path_b) {
        err_print("diff requires two snapshot files: "
                  "tpm-pcr-dump diff <file_a> <file_b>");
        return 1;
    }

    tpm_pcr_set_t set_a, set_b;
    tpm_err_t rc;

    rc = load_snapshot_json(opts->diff_path_a, &set_a);
    if (rc != TPM_OK) {
        err_print("failed to load snapshot A: %s", opts->diff_path_a);
        return 1;
    }

    rc = load_snapshot_json(opts->diff_path_b, &set_b);
    if (rc != TPM_OK) {
        err_print("failed to load snapshot B: %s", opts->diff_path_b);
        return 1;
    }

    if (opts->format == OUTPUT_JSON) {
        json_writer_t jw;
        jw_init(&jw);

        jw_object_begin(&jw);
        jw_kv_string(&jw, "tool", "tpm-pcr-dump");
        jw_kv_string(&jw, "command", "diff");
        jw_kv_string(&jw, "file_a", opts->diff_path_a);
        jw_kv_string(&jw, "file_b", opts->diff_path_b);

        jw_key(&jw, "differences");
        jw_array_begin(&jw);

        for (int i = 0; i < TPM_PCR_COUNT; i++) {
            if (!set_a.pcrs[i].valid && !set_b.pcrs[i].valid)
                continue;

            bool differ = false;
            if (set_a.pcrs[i].valid != set_b.pcrs[i].valid) {
                differ = true;
            } else if (set_a.pcrs[i].valid && set_b.pcrs[i].valid) {
                differ = (memcmp(set_a.pcrs[i].digest,
                                 set_b.pcrs[i].digest,
                                 set_a.pcrs[i].digest_len) != 0);
            }

            if (differ) {
                jw_object_begin(&jw);
                jw_kv_int(&jw, "pcr", i);

                char hex_a[TPM_MAX_HEX_SIZE] = "";
                char hex_b[TPM_MAX_HEX_SIZE] = "";
                if (set_a.pcrs[i].valid)
                    bin_to_hex(set_a.pcrs[i].digest, set_a.pcrs[i].digest_len,
                               hex_a, sizeof(hex_a));
                if (set_b.pcrs[i].valid)
                    bin_to_hex(set_b.pcrs[i].digest, set_b.pcrs[i].digest_len,
                               hex_b, sizeof(hex_b));

                jw_kv_string(&jw, "value_a", hex_a);
                jw_kv_string(&jw, "value_b", hex_b);
                jw_object_end(&jw);
            }
        }

        jw_array_end(&jw);
        jw_object_end(&jw);

        printf("%s", jw_finish(&jw));
    } else {
        if (opts->show_banner)
            print_banner(NULL, 0);

        printf("  %sDiff: A=%s%s\n", clr(CLR_CYAN), clr(CLR_RESET),
               opts->diff_path_a);
        printf("  %sDiff: B=%s%s\n\n", clr(CLR_CYAN), clr(CLR_RESET),
               opts->diff_path_b);

        size_t hex_width = tpm_bank_digest_len(set_a.bank) * 2;
        if (hex_width == 0) hex_width = 64;

        table_col_t cols[] = {
            { "PCR",    3,              TABLE_ALIGN_RIGHT },
            { "Status", 8,              TABLE_ALIGN_CENTER },
            { "A",      (int)hex_width, TABLE_ALIGN_LEFT },
            { "B",      (int)hex_width, TABLE_ALIGN_LEFT },
        };
        table_t tbl;
        table_init(&tbl, stdout, 4, cols);
        table_header(&tbl);

        int diff_count = 0;

        for (int i = 0; i < TPM_PCR_COUNT; i++) {
            if (!set_a.pcrs[i].valid && !set_b.pcrs[i].valid)
                continue;

            char idx_str[8];
            snprintf(idx_str, sizeof(idx_str), "%d", i);

            char hex_a[TPM_MAX_HEX_SIZE] = "<missing>";
            char hex_b[TPM_MAX_HEX_SIZE] = "<missing>";
            if (set_a.pcrs[i].valid)
                bin_to_hex(set_a.pcrs[i].digest, set_a.pcrs[i].digest_len,
                           hex_a, sizeof(hex_a));
            if (set_b.pcrs[i].valid)
                bin_to_hex(set_b.pcrs[i].digest, set_b.pcrs[i].digest_len,
                           hex_b, sizeof(hex_b));

            bool match = set_a.pcrs[i].valid && set_b.pcrs[i].valid &&
                         set_a.pcrs[i].digest_len == set_b.pcrs[i].digest_len &&
                         memcmp(set_a.pcrs[i].digest, set_b.pcrs[i].digest,
                                set_a.pcrs[i].digest_len) == 0;

            if (!match) diff_count++;

            table_cell(&tbl, idx_str, CLR_BOLD);
            table_cell(&tbl, match ? "SAME" : "DIFF",
                       match ? CLR_DIM : CLR_BOLD_YELLOW);
            table_cell(&tbl, hex_a, match ? CLR_DIM : CLR_RED);
            table_cell(&tbl, hex_b, match ? CLR_DIM : CLR_GREEN);
        }

        table_bottom(&tbl);
        printf("\n  %sDifferences:%s %d PCR(s)\n\n",
               clr(CLR_BOLD), clr(CLR_RESET), diff_count);
    }

    return 0;
}
