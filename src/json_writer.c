/*
 * tpm-pcr-dump — minimal JSON writer
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#include "json_writer.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

static void jw_append(json_writer_t *jw, const char *s, size_t len)
{
    if (jw->overflow)
        return;
    if (jw->pos + len >= JSON_BUF_SIZE) {
        jw->overflow = true;
        return;
    }
    memcpy(jw->buf + jw->pos, s, len);
    jw->pos += len;
    jw->buf[jw->pos] = '\0';
}

static void jw_appendc(json_writer_t *jw, char c)
{
    jw_append(jw, &c, 1);
}

static void jw_indent(json_writer_t *jw)
{
    for (int i = 0; i < jw->depth; i++)
        jw_append(jw, "  ", 2);
}

static void jw_comma_newline(json_writer_t *jw)
{
    if (jw->need_comma) {
        jw_appendc(jw, ',');
    }
    jw_appendc(jw, '\n');
    jw_indent(jw);
}

/* Write a JSON-escaped string (handles \, ", control chars) */
static void jw_write_escaped(json_writer_t *jw, const char *s)
{
    jw_appendc(jw, '"');
    for (; *s; s++) {
        switch (*s) {
        case '"':  jw_append(jw, "\\\"", 2); break;
        case '\\': jw_append(jw, "\\\\", 2); break;
        case '\b': jw_append(jw, "\\b", 2);  break;
        case '\f': jw_append(jw, "\\f", 2);  break;
        case '\n': jw_append(jw, "\\n", 2);  break;
        case '\r': jw_append(jw, "\\r", 2);  break;
        case '\t': jw_append(jw, "\\t", 2);  break;
        default:
            if ((unsigned char)*s < 0x20) {
                char esc[8];
                int n = snprintf(esc, sizeof(esc), "\\u%04x",
                                 (unsigned char)*s);
                jw_append(jw, esc, (size_t)n);
            } else {
                jw_appendc(jw, *s);
            }
            break;
        }
    }
    jw_appendc(jw, '"');
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void jw_init(json_writer_t *jw)
{
    memset(jw, 0, sizeof(*jw));
}

void jw_object_begin(json_writer_t *jw)
{
    if (jw->depth > 0)
        jw_comma_newline(jw);
    jw_appendc(jw, '{');
    jw->depth++;
    jw->need_comma = false;
}

void jw_object_end(json_writer_t *jw)
{
    jw->depth--;
    jw_appendc(jw, '\n');
    jw_indent(jw);
    jw_appendc(jw, '}');
    jw->need_comma = true;
}

void jw_array_begin(json_writer_t *jw)
{
    if (jw->depth > 0 && jw->need_comma) {
        jw_appendc(jw, ',');
    }
    jw_appendc(jw, '\n');
    jw_indent(jw);
    jw_appendc(jw, '[');
    jw->depth++;
    jw->need_comma = false;
}

void jw_array_end(json_writer_t *jw)
{
    jw->depth--;
    jw_appendc(jw, '\n');
    jw_indent(jw);
    jw_appendc(jw, ']');
    jw->need_comma = true;
}

void jw_key(json_writer_t *jw, const char *key)
{
    jw_comma_newline(jw);
    jw_write_escaped(jw, key);
    jw_append(jw, ": ", 2);
    jw->need_comma = false;
}

void jw_string(json_writer_t *jw, const char *val)
{
    if (jw->need_comma) {
        jw_comma_newline(jw);
    }
    jw_write_escaped(jw, val);
    jw->need_comma = true;
}

void jw_int(json_writer_t *jw, int val)
{
    if (jw->need_comma) {
        jw_comma_newline(jw);
    }
    char tmp[32];
    int n = snprintf(tmp, sizeof(tmp), "%d", val);
    jw_append(jw, tmp, (size_t)n);
    jw->need_comma = true;
}

void jw_bool(json_writer_t *jw, bool val)
{
    if (jw->need_comma) {
        jw_comma_newline(jw);
    }
    if (val)
        jw_append(jw, "true", 4);
    else
        jw_append(jw, "false", 5);
    jw->need_comma = true;
}

void jw_null(json_writer_t *jw)
{
    if (jw->need_comma) {
        jw_comma_newline(jw);
    }
    jw_append(jw, "null", 4);
    jw->need_comma = true;
}

void jw_kv_string(json_writer_t *jw, const char *key, const char *val)
{
    jw_key(jw, key);
    jw_write_escaped(jw, val);
    jw->need_comma = true;
}

void jw_kv_int(json_writer_t *jw, const char *key, int val)
{
    jw_key(jw, key);
    char tmp[32];
    int n = snprintf(tmp, sizeof(tmp), "%d", val);
    jw_append(jw, tmp, (size_t)n);
    jw->need_comma = true;
}

void jw_kv_bool(json_writer_t *jw, const char *key, bool val)
{
    jw_key(jw, key);
    if (val)
        jw_append(jw, "true", 4);
    else
        jw_append(jw, "false", 5);
    jw->need_comma = true;
}

const char *jw_finish(json_writer_t *jw)
{
    jw_appendc(jw, '\n');
    return jw->buf;
}
