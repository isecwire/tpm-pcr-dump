/*
 * tpm-pcr-dump — ASCII table formatter with box drawing characters
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#ifndef TPM_TABLE_FMT_H
#define TPM_TABLE_FMT_H

#include "tpm_pcr_dump.h"
#include "color.h"
#include <stdio.h>

/* Maximum columns in a table */
#define TABLE_MAX_COLS  8
#define TABLE_MAX_COL_WIDTH 80

/* Column alignment */
typedef enum {
    TABLE_ALIGN_LEFT,
    TABLE_ALIGN_RIGHT,
    TABLE_ALIGN_CENTER,
} table_align_t;

/* Table column definition */
typedef struct {
    const char   *header;
    int           width;
    table_align_t align;
} table_col_t;

/* Table context */
typedef struct {
    table_col_t cols[TABLE_MAX_COLS];
    int         ncols;
    FILE       *out;
} table_t;

/* Initialize a table with column definitions */
void table_init(table_t *t, FILE *out, int ncols, const table_col_t *cols);

/* Print the top border */
void table_top(const table_t *t);

/* Print the header row + separator */
void table_header(const table_t *t);

/* Print a mid-table separator line */
void table_separator(const table_t *t);

/* Print the bottom border */
void table_bottom(const table_t *t);

/* Print a data cell (call ncols times per row, auto line break) */
void table_cell(table_t *t, const char *text, color_code_t color);

/* Begin and end a row explicitly (alternative to cell-counting) */
void table_row_begin(const table_t *t);
void table_row_end(const table_t *t);

/* Print the ASCII art banner with TPM info */
void print_banner(const char *bank_name, int pcr_count);

#endif /* TPM_TABLE_FMT_H */
