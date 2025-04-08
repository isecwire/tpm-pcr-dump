/*
 * tpm-pcr-dump — ANSI color output helpers
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#ifndef TPM_COLOR_H
#define TPM_COLOR_H

#include <stdbool.h>
#include <stdio.h>

/* Color codes */
typedef enum {
    CLR_RESET = 0,
    CLR_BOLD,
    CLR_DIM,
    CLR_RED,
    CLR_GREEN,
    CLR_YELLOW,
    CLR_BLUE,
    CLR_CYAN,
    CLR_MAGENTA,
    CLR_WHITE,
    CLR_BOLD_RED,
    CLR_BOLD_GREEN,
    CLR_BOLD_YELLOW,
    CLR_BOLD_CYAN,
    CLR_BOLD_WHITE,
} color_code_t;

/* Initialize color system.  auto_detect: check isatty(). */
void color_init(bool force_on, bool force_off);

/* Returns true if color output is active */
bool color_enabled(void);

/* Return the ANSI escape string for a given color (or "" if disabled) */
const char *clr(color_code_t code);

/* Convenience: write colored text to stream */
void color_fprintf(FILE *stream, color_code_t code, const char *fmt, ...);

#endif /* TPM_COLOR_H */
