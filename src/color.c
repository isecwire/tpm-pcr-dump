/*
 * tpm-pcr-dump — ANSI color output helpers
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#include "color.h"

#include <stdarg.h>
#include <unistd.h>

static bool g_color_on = false;

static const char *g_ansi[] = {
    [CLR_RESET]        = "\033[0m",
    [CLR_BOLD]         = "\033[1m",
    [CLR_DIM]          = "\033[2m",
    [CLR_RED]          = "\033[31m",
    [CLR_GREEN]        = "\033[32m",
    [CLR_YELLOW]       = "\033[33m",
    [CLR_BLUE]         = "\033[34m",
    [CLR_CYAN]         = "\033[36m",
    [CLR_MAGENTA]      = "\033[35m",
    [CLR_WHITE]        = "\033[37m",
    [CLR_BOLD_RED]     = "\033[1;31m",
    [CLR_BOLD_GREEN]   = "\033[1;32m",
    [CLR_BOLD_YELLOW]  = "\033[1;33m",
    [CLR_BOLD_CYAN]    = "\033[1;36m",
    [CLR_BOLD_WHITE]   = "\033[1;37m",
};

void color_init(bool force_on, bool force_off)
{
    if (force_off) {
        g_color_on = false;
    } else if (force_on) {
        g_color_on = true;
    } else {
        /* Auto-detect: enable if stdout is a terminal */
        g_color_on = isatty(STDOUT_FILENO) != 0;
    }
}

bool color_enabled(void)
{
    return g_color_on;
}

const char *clr(color_code_t code)
{
    if (!g_color_on)
        return "";
    if (code > CLR_BOLD_WHITE)
        return "";
    return g_ansi[code];
}

void color_fprintf(FILE *stream, color_code_t code, const char *fmt, ...)
{
    va_list ap;
    if (g_color_on)
        fputs(g_ansi[code], stream);
    va_start(ap, fmt);
    vfprintf(stream, fmt, ap);
    va_end(ap);
    if (g_color_on)
        fputs(g_ansi[CLR_RESET], stream);
}
