/*
 * tpm-pcr-dump — minimal JSON writer (no external dependencies)
 *
 * Writes JSON to a fixed-size buffer.  No heap allocation.
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#ifndef JSON_WRITER_H
#define JSON_WRITER_H

#include <stddef.h>
#include <stdbool.h>

/* Maximum output buffer size */
#define JSON_BUF_SIZE  (64 * 1024)

typedef struct {
    char   buf[JSON_BUF_SIZE];
    size_t pos;
    int    depth;           /* nesting depth for indentation          */
    bool   need_comma;      /* true if next element needs a leading , */
    bool   overflow;        /* set if buffer was exhausted            */
} json_writer_t;

/* Initialise a writer (zero the struct) */
void jw_init(json_writer_t *jw);

/* Structural */
void jw_object_begin(json_writer_t *jw);
void jw_object_end(json_writer_t *jw);
void jw_array_begin(json_writer_t *jw);
void jw_array_end(json_writer_t *jw);

/* Key (inside an object — must be followed by a value call) */
void jw_key(json_writer_t *jw, const char *key);

/* Values */
void jw_string(json_writer_t *jw, const char *val);
void jw_int(json_writer_t *jw, int val);
void jw_bool(json_writer_t *jw, bool val);
void jw_null(json_writer_t *jw);

/* Convenience: key + value in one call */
void jw_kv_string(json_writer_t *jw, const char *key, const char *val);
void jw_kv_int(json_writer_t *jw, const char *key, int val);
void jw_kv_bool(json_writer_t *jw, const char *key, bool val);

/* Return pointer to NUL-terminated JSON string */
const char *jw_finish(json_writer_t *jw);

#endif /* JSON_WRITER_H */
