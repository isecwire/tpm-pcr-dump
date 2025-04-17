/*
 * tpm-pcr-dump — unit tests for json_writer
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#include "test_framework.h"
#include "json_writer.h"

#include <string.h>

/* ------------------------------------------------------------------ */

TEST(jw_empty_object)
{
    json_writer_t jw;
    jw_init(&jw);
    jw_object_begin(&jw);
    jw_object_end(&jw);
    const char *out = jw_finish(&jw);

    ASSERT_STR_CONTAINS(out, "{");
    ASSERT_STR_CONTAINS(out, "}");
    ASSERT_FALSE(jw.overflow);
    PASS();
}

TEST(jw_empty_array)
{
    json_writer_t jw;
    jw_init(&jw);
    jw_object_begin(&jw);
    jw_key(&jw, "items");
    jw_array_begin(&jw);
    jw_array_end(&jw);
    jw_object_end(&jw);
    const char *out = jw_finish(&jw);

    ASSERT_STR_CONTAINS(out, "[");
    ASSERT_STR_CONTAINS(out, "]");
    ASSERT_STR_CONTAINS(out, "\"items\"");
    ASSERT_FALSE(jw.overflow);
    PASS();
}

TEST(jw_kv_string_simple)
{
    json_writer_t jw;
    jw_init(&jw);
    jw_object_begin(&jw);
    jw_kv_string(&jw, "name", "hello");
    jw_object_end(&jw);
    const char *out = jw_finish(&jw);

    ASSERT_STR_CONTAINS(out, "\"name\": \"hello\"");
    ASSERT_FALSE(jw.overflow);
    PASS();
}

TEST(jw_string_escaping_quotes)
{
    json_writer_t jw;
    jw_init(&jw);
    jw_object_begin(&jw);
    jw_kv_string(&jw, "val", "say \"hi\"");
    jw_object_end(&jw);
    const char *out = jw_finish(&jw);

    ASSERT_STR_CONTAINS(out, "say \\\"hi\\\"");
    ASSERT_FALSE(jw.overflow);
    PASS();
}

TEST(jw_string_escaping_backslash)
{
    json_writer_t jw;
    jw_init(&jw);
    jw_object_begin(&jw);
    jw_kv_string(&jw, "path", "c:\\windows\\system32");
    jw_object_end(&jw);
    const char *out = jw_finish(&jw);

    ASSERT_STR_CONTAINS(out, "c:\\\\windows\\\\system32");
    ASSERT_FALSE(jw.overflow);
    PASS();
}

TEST(jw_string_escaping_newlines)
{
    json_writer_t jw;
    jw_init(&jw);
    jw_object_begin(&jw);
    jw_kv_string(&jw, "msg", "line1\nline2\ttab");
    jw_object_end(&jw);
    const char *out = jw_finish(&jw);

    ASSERT_STR_CONTAINS(out, "line1\\nline2\\ttab");
    ASSERT_FALSE(jw.overflow);
    PASS();
}

TEST(jw_int_value)
{
    json_writer_t jw;
    jw_init(&jw);
    jw_object_begin(&jw);
    jw_kv_int(&jw, "count", 42);
    jw_object_end(&jw);
    const char *out = jw_finish(&jw);

    ASSERT_STR_CONTAINS(out, "\"count\": 42");
    ASSERT_FALSE(jw.overflow);
    PASS();
}

TEST(jw_int_negative)
{
    json_writer_t jw;
    jw_init(&jw);
    jw_object_begin(&jw);
    jw_kv_int(&jw, "err", -1);
    jw_object_end(&jw);
    const char *out = jw_finish(&jw);

    ASSERT_STR_CONTAINS(out, "\"err\": -1");
    ASSERT_FALSE(jw.overflow);
    PASS();
}

TEST(jw_bool_true)
{
    json_writer_t jw;
    jw_init(&jw);
    jw_object_begin(&jw);
    jw_kv_bool(&jw, "ok", true);
    jw_object_end(&jw);
    const char *out = jw_finish(&jw);

    ASSERT_STR_CONTAINS(out, "\"ok\": true");
    ASSERT_FALSE(jw.overflow);
    PASS();
}

TEST(jw_bool_false)
{
    json_writer_t jw;
    jw_init(&jw);
    jw_object_begin(&jw);
    jw_kv_bool(&jw, "ok", false);
    jw_object_end(&jw);
    const char *out = jw_finish(&jw);

    ASSERT_STR_CONTAINS(out, "\"ok\": false");
    ASSERT_FALSE(jw.overflow);
    PASS();
}

TEST(jw_null_value)
{
    json_writer_t jw;
    jw_init(&jw);
    jw_object_begin(&jw);
    jw_key(&jw, "val");
    jw_null(&jw);
    jw_object_end(&jw);
    const char *out = jw_finish(&jw);

    ASSERT_STR_CONTAINS(out, "\"val\": null");
    ASSERT_FALSE(jw.overflow);
    PASS();
}

TEST(jw_nested_object)
{
    json_writer_t jw;
    jw_init(&jw);
    jw_object_begin(&jw);
    jw_kv_string(&jw, "type", "outer");
    jw_key(&jw, "inner");
    jw_object_begin(&jw);
    jw_kv_int(&jw, "x", 1);
    jw_kv_int(&jw, "y", 2);
    jw_object_end(&jw);
    jw_object_end(&jw);
    const char *out = jw_finish(&jw);

    ASSERT_STR_CONTAINS(out, "\"type\": \"outer\"");
    ASSERT_STR_CONTAINS(out, "\"inner\":");
    ASSERT_STR_CONTAINS(out, "\"x\": 1");
    ASSERT_STR_CONTAINS(out, "\"y\": 2");
    ASSERT_FALSE(jw.overflow);
    PASS();
}

TEST(jw_array_of_objects)
{
    json_writer_t jw;
    jw_init(&jw);
    jw_object_begin(&jw);
    jw_key(&jw, "items");
    jw_array_begin(&jw);

    jw_object_begin(&jw);
    jw_kv_int(&jw, "id", 0);
    jw_object_end(&jw);

    jw_object_begin(&jw);
    jw_kv_int(&jw, "id", 1);
    jw_object_end(&jw);

    jw_array_end(&jw);
    jw_object_end(&jw);
    const char *out = jw_finish(&jw);

    ASSERT_STR_CONTAINS(out, "\"items\":");
    ASSERT_STR_CONTAINS(out, "\"id\": 0");
    ASSERT_STR_CONTAINS(out, "\"id\": 1");
    ASSERT_FALSE(jw.overflow);
    PASS();
}

TEST(jw_array_of_strings)
{
    json_writer_t jw;
    jw_init(&jw);
    jw_object_begin(&jw);
    jw_key(&jw, "tags");
    jw_array_begin(&jw);
    jw_string(&jw, "alpha");
    jw_string(&jw, "beta");
    jw_array_end(&jw);
    jw_object_end(&jw);
    const char *out = jw_finish(&jw);

    ASSERT_STR_CONTAINS(out, "\"alpha\"");
    ASSERT_STR_CONTAINS(out, "\"beta\"");
    ASSERT_FALSE(jw.overflow);
    PASS();
}

TEST(jw_multiple_kvs)
{
    json_writer_t jw;
    jw_init(&jw);
    jw_object_begin(&jw);
    jw_kv_string(&jw, "a", "1");
    jw_kv_string(&jw, "b", "2");
    jw_kv_string(&jw, "c", "3");
    jw_object_end(&jw);
    const char *out = jw_finish(&jw);

    /* Commas should separate key-value pairs */
    ASSERT_STR_CONTAINS(out, "\"a\": \"1\"");
    ASSERT_STR_CONTAINS(out, "\"b\": \"2\"");
    ASSERT_STR_CONTAINS(out, "\"c\": \"3\"");
    ASSERT_FALSE(jw.overflow);
    PASS();
}

TEST(jw_overflow_protection)
{
    /*
     * The JSON_BUF_SIZE is 64K.  Write enough data to exceed it.
     * After overflow, the writer must set the overflow flag and
     * stop writing (no crash, no buffer overrun).
     */
    json_writer_t jw;
    jw_init(&jw);
    jw_object_begin(&jw);

    /* Each kv_string writes ~30 chars overhead + value.
     * Write 2000 keys with 40-char values => ~140K, well over 64K */
    char val[41];
    memset(val, 'A', 40);
    val[40] = '\0';

    for (int i = 0; i < 2000; i++) {
        char key[16];
        snprintf(key, sizeof(key), "k%d", i);
        jw_kv_string(&jw, key, val);
    }

    jw_object_end(&jw);
    jw_finish(&jw);

    ASSERT_TRUE(jw.overflow);
    /* pos should not exceed buffer size */
    ASSERT_TRUE(jw.pos < JSON_BUF_SIZE);
    PASS();
}

/* ------------------------------------------------------------------ */

void test_suite_json_writer(void)
{
    fprintf(stderr, "\n--- json_writer tests ---\n");
    RUN_TEST(jw_empty_object);
    RUN_TEST(jw_empty_array);
    RUN_TEST(jw_kv_string_simple);
    RUN_TEST(jw_string_escaping_quotes);
    RUN_TEST(jw_string_escaping_backslash);
    RUN_TEST(jw_string_escaping_newlines);
    RUN_TEST(jw_int_value);
    RUN_TEST(jw_int_negative);
    RUN_TEST(jw_bool_true);
    RUN_TEST(jw_bool_false);
    RUN_TEST(jw_null_value);
    RUN_TEST(jw_nested_object);
    RUN_TEST(jw_array_of_objects);
    RUN_TEST(jw_array_of_strings);
    RUN_TEST(jw_multiple_kvs);
    RUN_TEST(jw_overflow_protection);
}
