/*
 * tpm-pcr-dump — unit tests for pcr_verify
 *
 * Tests golden value loading, PCR comparison, and composite hashing.
 * We cannot call pcr_golden_load() directly in unit tests because it
 * reads from a file; instead we construct pcr_golden_t in memory and
 * test pcr_verify() and pcr_composite_hash().  For parsing tests we
 * write a temp file and load it.
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#include "test_framework.h"
#include "pcr_verify.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Helper: write a string to a temp file and return the path           */
/* ------------------------------------------------------------------ */

static const char *TMPFILE = "/tmp/tpm_pcr_test_golden.json";

static bool write_tmp_file(const char *content)
{
    FILE *fp = fopen(TMPFILE, "w");
    if (!fp) return false;
    fputs(content, fp);
    fclose(fp);
    return true;
}

/* ------------------------------------------------------------------ */
/* pcr_golden_load tests (via temp files)                              */
/* ------------------------------------------------------------------ */

TEST(golden_load_valid_sha256)
{
    /* A valid golden file with two PCR entries (SHA-256 = 32 bytes = 64 hex) */
    const char *json =
        "{\n"
        "  \"bank\": \"sha256\",\n"
        "  \"pcrs\": {\n"
        "    \"0\": \"" "0000000000000000000000000000000000000000000000000000000000000000" "\",\n"
        "    \"7\": \"" "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" "\"\n"
        "  }\n"
        "}\n";

    ASSERT_TRUE(write_tmp_file(json));

    pcr_golden_t golden;
    tpm_err_t rc = pcr_golden_load(TMPFILE, &golden);

    ASSERT_EQ(rc, TPM_OK);
    ASSERT_EQ(golden.bank, TPM_BANK_SHA256);
    ASSERT_EQ(golden.count, 2);
    ASSERT_TRUE(golden.entries[0].present);
    ASSERT_TRUE(golden.entries[7].present);
    ASSERT_FALSE(golden.entries[1].present);
    ASSERT_EQ(golden.entries[0].digest_len, 32);
    ASSERT_EQ(golden.entries[7].digest_len, 32);

    /* Check that PCR 0 is all zeros */
    uint8_t zeros[32];
    memset(zeros, 0, sizeof(zeros));
    ASSERT_MEM_EQ(golden.entries[0].digest, zeros, 32);

    /* Check that PCR 7 is all 0xFF */
    uint8_t ffs[32];
    memset(ffs, 0xFF, sizeof(ffs));
    ASSERT_MEM_EQ(golden.entries[7].digest, ffs, 32);

    unlink(TMPFILE);
    PASS();
}

TEST(golden_load_valid_sha1)
{
    /* SHA-1 = 20 bytes = 40 hex chars */
    const char *json =
        "{\n"
        "  \"bank\": \"sha1\",\n"
        "  \"pcrs\": {\n"
        "    \"0\": \"" "0000000000000000000000000000000000000000" "\"\n"
        "  }\n"
        "}\n";

    ASSERT_TRUE(write_tmp_file(json));

    pcr_golden_t golden;
    tpm_err_t rc = pcr_golden_load(TMPFILE, &golden);

    ASSERT_EQ(rc, TPM_OK);
    ASSERT_EQ(golden.bank, TPM_BANK_SHA1);
    ASSERT_EQ(golden.count, 1);
    ASSERT_TRUE(golden.entries[0].present);
    ASSERT_EQ(golden.entries[0].digest_len, 20);

    unlink(TMPFILE);
    PASS();
}

TEST(golden_load_no_pcrs)
{
    const char *json =
        "{\n"
        "  \"bank\": \"sha256\",\n"
        "  \"pcrs\": {\n"
        "  }\n"
        "}\n";

    ASSERT_TRUE(write_tmp_file(json));

    pcr_golden_t golden;
    tpm_err_t rc = pcr_golden_load(TMPFILE, &golden);

    ASSERT_EQ(rc, TPM_ERR_PARSE);  /* no valid entries */

    unlink(TMPFILE);
    PASS();
}

TEST(golden_load_bad_hex)
{
    /* Invalid hex value (wrong length for SHA-256) */
    const char *json =
        "{\n"
        "  \"bank\": \"sha256\",\n"
        "  \"pcrs\": {\n"
        "    \"0\": \"not_valid_hex\"\n"
        "  }\n"
        "}\n";

    ASSERT_TRUE(write_tmp_file(json));

    pcr_golden_t golden;
    tpm_err_t rc = pcr_golden_load(TMPFILE, &golden);

    ASSERT_EQ(rc, TPM_ERR_PARSE);  /* count stays 0 */

    unlink(TMPFILE);
    PASS();
}

TEST(golden_load_nonexistent_file)
{
    pcr_golden_t golden;
    tpm_err_t rc = pcr_golden_load("/tmp/does_not_exist_xyzzy.json", &golden);

    ASSERT_EQ(rc, TPM_ERR_IO);
    PASS();
}

/* ------------------------------------------------------------------ */
/* pcr_verify tests                                                    */
/* ------------------------------------------------------------------ */

/* Helper: build a measured set with one valid PCR at given index */
static void make_measured_set(tpm_pcr_set_t *set, int index,
                              const uint8_t *digest, size_t len)
{
    memset(set, 0, sizeof(*set));
    set->bank = TPM_BANK_SHA256;
    set->pcrs[index].index = index;
    set->pcrs[index].valid = true;
    memcpy(set->pcrs[index].digest, digest, len);
    set->pcrs[index].digest_len = len;
    set->count = 1;
}

/* Helper: build a golden set with one expected PCR at given index */
static void make_golden(pcr_golden_t *golden, int index,
                        const uint8_t *digest, size_t len)
{
    memset(golden, 0, sizeof(*golden));
    golden->bank = TPM_BANK_SHA256;
    golden->entries[index].index = index;
    golden->entries[index].present = true;
    memcpy(golden->entries[index].digest, digest, len);
    golden->entries[index].digest_len = len;
    golden->count = 1;
}

TEST(verify_match)
{
    uint8_t digest[32];
    memset(digest, 0xAA, sizeof(digest));

    tpm_pcr_set_t measured;
    make_measured_set(&measured, 0, digest, 32);

    pcr_golden_t golden;
    make_golden(&golden, 0, digest, 32);

    pcr_report_t report;
    tpm_err_t rc = pcr_verify(&measured, &golden, &report);

    ASSERT_EQ(rc, TPM_OK);
    ASSERT_EQ(report.total_checked, 1);
    ASSERT_EQ(report.total_matched, 1);
    ASSERT_EQ(report.total_mismatched, 0);
    ASSERT_TRUE(report.results[0].match);
    PASS();
}

TEST(verify_mismatch)
{
    uint8_t measured_digest[32];
    uint8_t expected_digest[32];
    memset(measured_digest, 0xAA, sizeof(measured_digest));
    memset(expected_digest, 0xBB, sizeof(expected_digest));

    tpm_pcr_set_t measured;
    make_measured_set(&measured, 7, measured_digest, 32);

    pcr_golden_t golden;
    make_golden(&golden, 7, expected_digest, 32);

    pcr_report_t report;
    tpm_err_t rc = pcr_verify(&measured, &golden, &report);

    ASSERT_EQ(rc, TPM_ERR_VERIFY);
    ASSERT_EQ(report.total_checked, 1);
    ASSERT_EQ(report.total_matched, 0);
    ASSERT_EQ(report.total_mismatched, 1);
    ASSERT_FALSE(report.results[0].match);
    PASS();
}

TEST(verify_unreadable_pcr)
{
    /* Golden expects PCR 5, but measured set has it invalid */
    uint8_t expected_digest[32];
    memset(expected_digest, 0xCC, sizeof(expected_digest));

    tpm_pcr_set_t measured;
    memset(&measured, 0, sizeof(measured));
    measured.bank = TPM_BANK_SHA256;
    /* pcrs[5].valid is false (default) */

    pcr_golden_t golden;
    make_golden(&golden, 5, expected_digest, 32);

    pcr_report_t report;
    tpm_err_t rc = pcr_verify(&measured, &golden, &report);

    ASSERT_EQ(rc, TPM_ERR_VERIFY);
    ASSERT_EQ(report.total_mismatched, 1);
    ASSERT_FALSE(report.results[0].match);
    ASSERT_STR_CONTAINS(report.results[0].actual_hex, "<unreadable>");
    PASS();
}

TEST(verify_multiple_pcrs)
{
    /* Two matching, one mismatching */
    tpm_pcr_set_t measured;
    memset(&measured, 0, sizeof(measured));
    measured.bank = TPM_BANK_SHA256;

    pcr_golden_t golden;
    memset(&golden, 0, sizeof(golden));
    golden.bank = TPM_BANK_SHA256;

    uint8_t d0[32], d7[32], d7_bad[32];
    memset(d0, 0x11, sizeof(d0));
    memset(d7, 0x22, sizeof(d7));
    memset(d7_bad, 0x33, sizeof(d7_bad));

    /* PCR 0: match */
    measured.pcrs[0].valid = true;
    measured.pcrs[0].digest_len = 32;
    memcpy(measured.pcrs[0].digest, d0, 32);
    golden.entries[0].present = true;
    golden.entries[0].digest_len = 32;
    memcpy(golden.entries[0].digest, d0, 32);

    /* PCR 7: mismatch */
    measured.pcrs[7].valid = true;
    measured.pcrs[7].digest_len = 32;
    memcpy(measured.pcrs[7].digest, d7_bad, 32);
    golden.entries[7].present = true;
    golden.entries[7].digest_len = 32;
    memcpy(golden.entries[7].digest, d7, 32);

    golden.count = 2;
    measured.count = 2;

    pcr_report_t report;
    tpm_err_t rc = pcr_verify(&measured, &golden, &report);

    ASSERT_EQ(rc, TPM_ERR_VERIFY);
    ASSERT_EQ(report.total_checked, 2);
    ASSERT_EQ(report.total_matched, 1);
    ASSERT_EQ(report.total_mismatched, 1);
    PASS();
}

/* ------------------------------------------------------------------ */
/* pcr_composite_hash tests                                            */
/* ------------------------------------------------------------------ */

TEST(composite_hash_single_pcr)
{
    tpm_pcr_set_t set;
    memset(&set, 0, sizeof(set));
    set.bank = TPM_BANK_SHA256;

    uint8_t digest[32];
    memset(digest, 0xAA, sizeof(digest));
    set.pcrs[0].valid = true;
    set.pcrs[0].digest_len = 32;
    memcpy(set.pcrs[0].digest, digest, 32);
    set.count = 1;

    uint8_t out[TPM_MAX_DIGEST_SIZE];
    size_t out_len = 0;
    tpm_err_t rc = pcr_composite_hash(&set, out, &out_len);

    ASSERT_EQ(rc, TPM_OK);
    ASSERT_EQ(out_len, 32);  /* SHA-256 output */

    /* Convert to hex to verify it is a plausible hash */
    char hex[65];
    bin_to_hex(out, out_len, hex, sizeof(hex));
    ASSERT_EQ(strlen(hex), 64);
    PASS();
}

TEST(composite_hash_deterministic)
{
    /* Same input should produce same output */
    tpm_pcr_set_t set;
    memset(&set, 0, sizeof(set));
    set.bank = TPM_BANK_SHA256;

    uint8_t digest[32];
    memset(digest, 0x55, sizeof(digest));
    set.pcrs[0].valid = true;
    set.pcrs[0].digest_len = 32;
    memcpy(set.pcrs[0].digest, digest, 32);
    set.count = 1;

    uint8_t out1[TPM_MAX_DIGEST_SIZE], out2[TPM_MAX_DIGEST_SIZE];
    size_t len1 = 0, len2 = 0;

    pcr_composite_hash(&set, out1, &len1);
    pcr_composite_hash(&set, out2, &len2);

    ASSERT_EQ(len1, len2);
    ASSERT_MEM_EQ(out1, out2, len1);
    PASS();
}

TEST(composite_hash_changes_with_data)
{
    /* Different PCR data should produce different composite hashes */
    tpm_pcr_set_t set1, set2;
    memset(&set1, 0, sizeof(set1));
    memset(&set2, 0, sizeof(set2));
    set1.bank = TPM_BANK_SHA256;
    set2.bank = TPM_BANK_SHA256;

    uint8_t d1[32], d2[32];
    memset(d1, 0x00, sizeof(d1));
    memset(d2, 0xFF, sizeof(d2));

    set1.pcrs[0].valid = true;
    set1.pcrs[0].digest_len = 32;
    memcpy(set1.pcrs[0].digest, d1, 32);
    set1.count = 1;

    set2.pcrs[0].valid = true;
    set2.pcrs[0].digest_len = 32;
    memcpy(set2.pcrs[0].digest, d2, 32);
    set2.count = 1;

    uint8_t out1[TPM_MAX_DIGEST_SIZE], out2[TPM_MAX_DIGEST_SIZE];
    size_t len1 = 0, len2 = 0;

    pcr_composite_hash(&set1, out1, &len1);
    pcr_composite_hash(&set2, out2, &len2);

    ASSERT_EQ(len1, 32);
    ASSERT_EQ(len2, 32);
    /* Hashes must differ */
    ASSERT_TRUE(memcmp(out1, out2, 32) != 0);
    PASS();
}

/* ------------------------------------------------------------------ */

void test_suite_pcr_verify(void)
{
    fprintf(stderr, "\n--- pcr_verify tests ---\n");
    RUN_TEST(golden_load_valid_sha256);
    RUN_TEST(golden_load_valid_sha1);
    RUN_TEST(golden_load_no_pcrs);
    RUN_TEST(golden_load_bad_hex);
    RUN_TEST(golden_load_nonexistent_file);
    RUN_TEST(verify_match);
    RUN_TEST(verify_mismatch);
    RUN_TEST(verify_unreadable_pcr);
    RUN_TEST(verify_multiple_pcrs);
    RUN_TEST(composite_hash_single_pcr);
    RUN_TEST(composite_hash_deterministic);
    RUN_TEST(composite_hash_changes_with_data);
}
