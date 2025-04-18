/*
 * tpm-pcr-dump — ASCII table formatter with box drawing characters
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#include "table_fmt.h"

#include <string.h>

/* Unicode box drawing characters */
#define BOX_TL  "\xe2\x94\x8c"  /* top-left corner     */
#define BOX_TR  "\xe2\x94\x90"  /* top-right corner    */
#define BOX_BL  "\xe2\x94\x94"  /* bottom-left corner  */
#define BOX_BR  "\xe2\x94\x98"  /* bottom-right corner */
#define BOX_H   "\xe2\x94\x80"  /* horizontal line     */
#define BOX_V   "\xe2\x94\x82"  /* vertical line       */
#define BOX_LT  "\xe2\x94\x9c"  /* left T-junction     */
#define BOX_RT  "\xe2\x94\xa4"  /* right T-junction    */
#define BOX_TT  "\xe2\x94\xac"  /* top T-junction      */
#define BOX_BT  "\xe2\x94\xb4"  /* bottom T-junction   */
#define BOX_X   "\xe2\x94\xbc"  /* cross junction      */

/* Track cell position for auto row break */
static int g_cell_col = 0;

/* ------------------------------------------------------------------ */

void table_init(table_t *t, FILE *out, int ncols, const table_col_t *cols)
{
    memset(t, 0, sizeof(*t));
    t->out = out;
    t->ncols = (ncols > TABLE_MAX_COLS) ? TABLE_MAX_COLS : ncols;
    for (int i = 0; i < t->ncols; i++)
        t->cols[i] = cols[i];
    g_cell_col = 0;
}

static void print_hline(const table_t *t, const char *left,
                         const char *mid, const char *right)
{
    fprintf(t->out, "%s", left);
    for (int c = 0; c < t->ncols; c++) {
        for (int i = 0; i < t->cols[c].width + 2; i++)
            fprintf(t->out, "%s", BOX_H);
        if (c < t->ncols - 1)
            fprintf(t->out, "%s", mid);
    }
    fprintf(t->out, "%s\n", right);
}

void table_top(const table_t *t)
{
    print_hline(t, BOX_TL, BOX_TT, BOX_TR);
}

void table_separator(const table_t *t)
{
    print_hline(t, BOX_LT, BOX_X, BOX_RT);
}

void table_bottom(const table_t *t)
{
    print_hline(t, BOX_BL, BOX_BT, BOX_BR);
}

void table_header(const table_t *t)
{
    table_top(t);

    fprintf(t->out, "%s", BOX_V);
    for (int c = 0; c < t->ncols; c++) {
        int w = t->cols[c].width;
        const char *h = t->cols[c].header ? t->cols[c].header : "";
        fprintf(t->out, " %s%-*s%s ", clr(CLR_BOLD), w, h, clr(CLR_RESET));
        fprintf(t->out, "%s", BOX_V);
    }
    fprintf(t->out, "\n");

    table_separator(t);
}

void table_row_begin(const table_t *t)
{
    fprintf(t->out, "%s", BOX_V);
    (void)t;
}

void table_row_end(const table_t *t)
{
    fprintf(t->out, "\n");
    (void)t;
}

void table_cell(table_t *t, const char *text, color_code_t color)
{
    if (g_cell_col == 0)
        fprintf(t->out, "%s", BOX_V);

    int w = t->cols[g_cell_col].width;
    const char *txt = text ? text : "";

    switch (t->cols[g_cell_col].align) {
    case TABLE_ALIGN_RIGHT:
        fprintf(t->out, " %s%*s%s ", clr(color), w, txt, clr(CLR_RESET));
        break;
    case TABLE_ALIGN_CENTER: {
        int len = (int)strlen(txt);
        if (len > w) len = w;
        int pad_left = (w - len) / 2;
        int pad_right = w - len - pad_left;
        fprintf(t->out, " %s%*s%.*s%*s%s ",
                clr(color), pad_left, "", w, txt, pad_right, "",
                clr(CLR_RESET));
        break;
    }
    default: /* LEFT */
        fprintf(t->out, " %s%-*.*s%s ", clr(color), w, w, txt,
                clr(CLR_RESET));
        break;
    }

    fprintf(t->out, "%s", BOX_V);

    g_cell_col++;
    if (g_cell_col >= t->ncols) {
        fprintf(t->out, "\n");
        g_cell_col = 0;
    }
}

/* ------------------------------------------------------------------ */

void print_banner(const char *bank_name, int pcr_count)
{
    printf("\n");
    color_fprintf(stdout, CLR_BOLD_CYAN,
        "  _______ ____  __  __            ____   ____ ____  \n"
        " |__   __|  _ \\|  \\/  |          |  _ \\ / ___|  _ \\ \n"
        "    | |  | |_) | \\  / |  ______  | |_) | |   | |_) |\n"
        "    | |  |  __/| |\\/| | |______| |  __/| |   |  _ < \n"
        "    | |  | |   | |  | |          | |   | |___| |_) |\n"
        "    |_|  |_|   |_|  |_|          |_|    \\____|____/ \n");
    printf("\n");
    color_fprintf(stdout, CLR_BOLD_WHITE,
        "  tpm-pcr-dump v%s", TPM_PCR_DUMP_VERSION_STRING);
    printf(" -- TPM 2.0 PCR Analysis Tool\n");
    color_fprintf(stdout, CLR_DIM,
        "  Copyright (c) 2026 isecwire GmbH\n");
    printf("\n");

    if (bank_name) {
        printf("  %sBank:%s %s%s%s   %sPCRs:%s %d\n",
               clr(CLR_DIM), clr(CLR_RESET),
               clr(CLR_BOLD_CYAN), bank_name, clr(CLR_RESET),
               clr(CLR_DIM), clr(CLR_RESET),
               pcr_count);
        printf("\n");
    }
}
