/*
 * tpm-pcr-dump — test runner
 *
 * Calls all test suites and reports pass/fail counts.
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>

/* Global counters used by test_framework.h macros */
int g_tests_run    = 0;
int g_tests_passed = 0;
int g_tests_failed = 0;

/* Suite declarations */
extern void test_suite_utils(void);
extern void test_suite_json_writer(void);
extern void test_suite_pcr_verify(void);

int main(void)
{
    fprintf(stderr, "=== tpm-pcr-dump unit tests ===\n");

    test_suite_utils();
    test_suite_json_writer();
    test_suite_pcr_verify();

    fprintf(stderr, "\n=== Results ===\n");
    fprintf(stderr, "  Run:    %d\n", g_tests_run);
    fprintf(stderr, "  Passed: %d\n", g_tests_passed);
    fprintf(stderr, "  Failed: %d\n", g_tests_failed);

    if (g_tests_failed > 0) {
        fprintf(stderr, "\n*** %d TEST(S) FAILED ***\n", g_tests_failed);
        return 1;
    }

    fprintf(stderr, "\nAll tests passed.\n");
    return 0;
}
