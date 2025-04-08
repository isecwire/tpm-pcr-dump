/*
 * tpm-pcr-dump — minimal hand-rolled test framework
 *
 * No external dependencies.  Fixed buffers, no heap allocation.
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>

/* Counters — defined in test_main.c */
extern int g_tests_run;
extern int g_tests_passed;
extern int g_tests_failed;

/* Current test name for error reporting */
static const char *g_current_test = "";

#define TEST(name)                                                      \
    static void test_##name(void);                                      \
    static void run_##name(void) {                                      \
        g_current_test = #name;                                         \
        g_tests_run++;                                                  \
        test_##name();                                                  \
    }                                                                   \
    static void test_##name(void)

#define FAIL_FMT(msg, ...)                                              \
    do {                                                                \
        fprintf(stderr, "  FAIL %s (%s:%d): " msg "\n",                \
                g_current_test, __FILE__, __LINE__, __VA_ARGS__);       \
        g_tests_failed++;                                               \
        return;                                                         \
    } while (0)

#define PASS()                                                          \
    do {                                                                \
        g_tests_passed++;                                               \
        fprintf(stderr, "  ok   %s\n", g_current_test);                \
    } while (0)

#define ASSERT_TRUE(expr)                                               \
    do {                                                                \
        if (!(expr))                                                    \
            FAIL_FMT("expected true: %s", #expr);                           \
    } while (0)

#define ASSERT_FALSE(expr)                                              \
    do {                                                                \
        if (expr)                                                       \
            FAIL_FMT("expected false: %s", #expr);                          \
    } while (0)

#define ASSERT_EQ(a, b)                                                 \
    do {                                                                \
        long long _a = (long long)(a);                                  \
        long long _b = (long long)(b);                                  \
        if (_a != _b)                                                   \
            FAIL_FMT("expected %lld == %lld  (%s == %s)", _a, _b, #a, #b); \
    } while (0)

#define ASSERT_STR_EQ(a, b)                                             \
    do {                                                                \
        const char *_a = (a);                                           \
        const char *_b = (b);                                           \
        if (strcmp(_a, _b) != 0)                                        \
            FAIL_FMT("expected \"%s\" == \"%s\"  (%s == %s)",               \
                 _a, _b, #a, #b);                                       \
    } while (0)

#define ASSERT_MEM_EQ(a, b, len)                                        \
    do {                                                                \
        if (memcmp((a), (b), (len)) != 0)                               \
            FAIL_FMT("memory mismatch (%s vs %s, %zu bytes)",               \
                 #a, #b, (size_t)(len));                                \
    } while (0)

#define ASSERT_STR_CONTAINS(haystack, needle)                           \
    do {                                                                \
        if (strstr((haystack), (needle)) == NULL)                       \
            FAIL_FMT("expected \"%s\" to contain \"%s\"",                   \
                 (haystack), (needle));                                  \
    } while (0)

/* Run a test function — call from suite runners */
#define RUN_TEST(name) run_##name()

#endif /* TEST_FRAMEWORK_H */
