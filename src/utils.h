/*
 * tpm-pcr-dump — utility functions
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#ifndef TPM_UTILS_H
#define TPM_UTILS_H

#include "tpm_pcr_dump.h"
#include <stdio.h>

/*
 * Convert a binary buffer to a lower-case hex string.
 * hex_buf must be at least (len * 2 + 1) bytes.
 * Returns 0 on success, -1 if hex_buf_size is too small.
 */
int bin_to_hex(const uint8_t *bin, size_t len,
               char *hex_buf, size_t hex_buf_size);

/*
 * Convert a hex string to a binary buffer.
 * Returns the number of bytes written, or -1 on error.
 */
int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_size);

/*
 * Strip leading/trailing whitespace in place.  Returns pointer
 * into the same buffer (does not allocate).
 */
char *str_trim(char *s);

/*
 * Print an error message to stderr with a "tpm-pcr-dump: " prefix.
 */
void err_print(const char *fmt, ...);

/*
 * Print a verbose/debug message to stderr (only if enabled).
 */
void dbg_print(const char *fmt, ...);

/* Enable or disable debug output */
void dbg_set_enabled(bool enabled);

#endif /* TPM_UTILS_H */
