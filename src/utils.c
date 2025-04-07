/*
 * tpm-pcr-dump — utility functions
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#include "utils.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static bool g_debug_enabled = false;

/* ------------------------------------------------------------------ */

int bin_to_hex(const uint8_t *bin, size_t len,
               char *hex_buf, size_t hex_buf_size)
{
    if (hex_buf_size < (len * 2 + 1))
        return -1;

    static const char lut[] = "0123456789abcdef";

    for (size_t i = 0; i < len; i++) {
        hex_buf[i * 2]     = lut[(bin[i] >> 4) & 0x0F];
        hex_buf[i * 2 + 1] = lut[bin[i] & 0x0F];
    }
    hex_buf[len * 2] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_size)
{
    size_t hex_len = strlen(hex);

    /* skip optional "0x" prefix */
    if (hex_len >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
        hex_len -= 2;
    }

    /* must be even length */
    if (hex_len == 0 || (hex_len & 1) != 0)
        return -1;

    size_t out_len = hex_len / 2;
    if (out_len > bin_size)
        return -1;

    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        bin[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)out_len;
}

/* ------------------------------------------------------------------ */

char *str_trim(char *s)
{
    while (isspace((unsigned char)*s))
        s++;

    if (*s == '\0')
        return s;

    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        end--;
    end[1] = '\0';

    return s;
}

/* ------------------------------------------------------------------ */

void err_print(const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "tpm-pcr-dump: error: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

void dbg_print(const char *fmt, ...)
{
    if (!g_debug_enabled)
        return;
    va_list ap;
    fprintf(stderr, "tpm-pcr-dump: debug: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

void dbg_set_enabled(bool enabled)
{
    g_debug_enabled = enabled;
}
