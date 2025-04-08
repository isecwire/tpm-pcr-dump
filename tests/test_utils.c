/*
 * tpm-pcr-dump — unit tests for utils (hex conversion, string trim)
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#include "test_framework.h"
#include "utils.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* hex_to_bin tests                                                    */
/* ------------------------------------------------------------------ */

TEST(hex_to_bin_basic)
{
    uint8_t buf[4];
    int n = hex_to_bin("deadbeef", buf, sizeof(buf));

    ASSERT_EQ(n, 4);
    ASSERT_EQ(buf[0], 0xDE);
    ASSERT_EQ(buf[1], 0xAD);
    ASSERT_EQ(buf[2], 0xBE);
    ASSERT_EQ(buf[3], 0xEF);
    PASS();
}

TEST(hex_to_bin_uppercase)
{
    uint8_t buf[2];
    int n = hex_to_bin("AABB", buf, sizeof(buf));

    ASSERT_EQ(n, 2);
    ASSERT_EQ(buf[0], 0xAA);
    ASSERT_EQ(buf[1], 0xBB);
    PASS();
}

TEST(hex_to_bin_mixed_case)
{
    uint8_t buf[3];
    int n = hex_to_bin("aAbBcC", buf, sizeof(buf));

    ASSERT_EQ(n, 3);
    ASSERT_EQ(buf[0], 0xAA);
    ASSERT_EQ(buf[1], 0xBB);
    ASSERT_EQ(buf[2], 0xCC);
    PASS();
}

TEST(hex_to_bin_0x_prefix)
{
    uint8_t buf[2];
    int n = hex_to_bin("0xFF00", buf, sizeof(buf));

    ASSERT_EQ(n, 2);
    ASSERT_EQ(buf[0], 0xFF);
    ASSERT_EQ(buf[1], 0x00);
    PASS();
}

TEST(hex_to_bin_0X_prefix)
{
    uint8_t buf[1];
    int n = hex_to_bin("0X42", buf, sizeof(buf));

    ASSERT_EQ(n, 1);
    ASSERT_EQ(buf[0], 0x42);
    PASS();
}

TEST(hex_to_bin_empty_string)
{
    uint8_t buf[4];
    int n = hex_to_bin("", buf, sizeof(buf));

    ASSERT_EQ(n, -1);
    PASS();
}

TEST(hex_to_bin_odd_length)
{
    uint8_t buf[4];
    int n = hex_to_bin("abc", buf, sizeof(buf));

    ASSERT_EQ(n, -1);
    PASS();
}

TEST(hex_to_bin_invalid_char)
{
    uint8_t buf[4];
    int n = hex_to_bin("xxyz", buf, sizeof(buf));

    ASSERT_EQ(n, -1);
    PASS();
}

TEST(hex_to_bin_buffer_too_small)
{
    uint8_t buf[1];
    int n = hex_to_bin("aabbccdd", buf, sizeof(buf));

    ASSERT_EQ(n, -1);
    PASS();
}

TEST(hex_to_bin_0x_only)
{
    uint8_t buf[4];
    int n = hex_to_bin("0x", buf, sizeof(buf));

    ASSERT_EQ(n, -1);  /* after stripping prefix, empty string */
    PASS();
}

/* ------------------------------------------------------------------ */
/* bin_to_hex tests                                                    */
/* ------------------------------------------------------------------ */

TEST(bin_to_hex_basic)
{
    const uint8_t data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    char hex[16];
    int rc = bin_to_hex(data, 4, hex, sizeof(hex));

    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(hex, "deadbeef");
    PASS();
}

TEST(bin_to_hex_single_byte)
{
    const uint8_t data[] = { 0x00 };
    char hex[4];
    int rc = bin_to_hex(data, 1, hex, sizeof(hex));

    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(hex, "00");
    PASS();
}

TEST(bin_to_hex_all_zeros)
{
    const uint8_t data[4] = { 0 };
    char hex[16];
    int rc = bin_to_hex(data, 4, hex, sizeof(hex));

    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(hex, "00000000");
    PASS();
}

TEST(bin_to_hex_buffer_too_small)
{
    const uint8_t data[] = { 0xAA, 0xBB };
    char hex[4];  /* needs 5 bytes (4 hex chars + NUL) */
    int rc = bin_to_hex(data, 2, hex, sizeof(hex));

    ASSERT_EQ(rc, -1);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Roundtrip tests                                                     */
/* ------------------------------------------------------------------ */

TEST(roundtrip_hex_bin_hex)
{
    const char *original = "0123456789abcdef";
    uint8_t bin[8];
    int n = hex_to_bin(original, bin, sizeof(bin));
    ASSERT_EQ(n, 8);

    char hex[17];
    int rc = bin_to_hex(bin, 8, hex, sizeof(hex));
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(hex, original);
    PASS();
}

TEST(roundtrip_sha256_size)
{
    /* A typical SHA-256 PCR value (64 hex chars = 32 bytes) */
    const char *sha256_hex =
        "a5a5a5a5b6b6b6b6c7c7c7c7d8d8d8d8"
        "e9e9e9e9f0f0f0f0a1a1a1a1b2b2b2b2";
    uint8_t bin[32];
    int n = hex_to_bin(sha256_hex, bin, sizeof(bin));
    ASSERT_EQ(n, 32);

    char hex_out[65];
    int rc = bin_to_hex(bin, 32, hex_out, sizeof(hex_out));
    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(hex_out, sha256_hex);
    PASS();
}

/* ------------------------------------------------------------------ */
/* str_trim tests                                                      */
/* ------------------------------------------------------------------ */

TEST(str_trim_no_whitespace)
{
    char s[] = "hello";
    ASSERT_STR_EQ(str_trim(s), "hello");
    PASS();
}

TEST(str_trim_leading)
{
    char s[] = "   hello";
    ASSERT_STR_EQ(str_trim(s), "hello");
    PASS();
}

TEST(str_trim_trailing)
{
    char s[] = "hello   ";
    ASSERT_STR_EQ(str_trim(s), "hello");
    PASS();
}

TEST(str_trim_both)
{
    char s[] = "  hello  ";
    ASSERT_STR_EQ(str_trim(s), "hello");
    PASS();
}

TEST(str_trim_newlines)
{
    char s[] = "\n\thello\r\n";
    ASSERT_STR_EQ(str_trim(s), "hello");
    PASS();
}

TEST(str_trim_empty)
{
    char s[] = "";
    ASSERT_STR_EQ(str_trim(s), "");
    PASS();
}

TEST(str_trim_all_whitespace)
{
    char s[] = "   \t\n  ";
    ASSERT_STR_EQ(str_trim(s), "");
    PASS();
}

/* ------------------------------------------------------------------ */

void test_suite_utils(void)
{
    fprintf(stderr, "\n--- utils tests ---\n");
    RUN_TEST(hex_to_bin_basic);
    RUN_TEST(hex_to_bin_uppercase);
    RUN_TEST(hex_to_bin_mixed_case);
    RUN_TEST(hex_to_bin_0x_prefix);
    RUN_TEST(hex_to_bin_0X_prefix);
    RUN_TEST(hex_to_bin_empty_string);
    RUN_TEST(hex_to_bin_odd_length);
    RUN_TEST(hex_to_bin_invalid_char);
    RUN_TEST(hex_to_bin_buffer_too_small);
    RUN_TEST(hex_to_bin_0x_only);
    RUN_TEST(bin_to_hex_basic);
    RUN_TEST(bin_to_hex_single_byte);
    RUN_TEST(bin_to_hex_all_zeros);
    RUN_TEST(bin_to_hex_buffer_too_small);
    RUN_TEST(roundtrip_hex_bin_hex);
    RUN_TEST(roundtrip_sha256_size);
    RUN_TEST(str_trim_no_whitespace);
    RUN_TEST(str_trim_leading);
    RUN_TEST(str_trim_trailing);
    RUN_TEST(str_trim_both);
    RUN_TEST(str_trim_newlines);
    RUN_TEST(str_trim_empty);
    RUN_TEST(str_trim_all_whitespace);
}
