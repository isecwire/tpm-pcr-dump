/*
 * tpm-pcr-dump — TPM 2.0 PCR reader, event log parser, and attestation tool
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#ifndef TPM_PCR_DUMP_H
#define TPM_PCR_DUMP_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define TPM_PCR_DUMP_VERSION_MAJOR  2
#define TPM_PCR_DUMP_VERSION_MINOR  1
#define TPM_PCR_DUMP_VERSION_PATCH  0
#define TPM_PCR_DUMP_VERSION_STRING "2.1.0"

/* TPM 2.0 defines 24 PCR banks (indices 0-23) */
#define TPM_PCR_COUNT       24

/* Maximum hash digest sizes */
#define TPM_SHA1_DIGEST_SIZE    20
#define TPM_SHA256_DIGEST_SIZE  32
#define TPM_SHA384_DIGEST_SIZE  48
#define TPM_SHA512_DIGEST_SIZE  64
#define TPM_SM3_256_DIGEST_SIZE 32
#define TPM_MAX_DIGEST_SIZE     TPM_SHA512_DIGEST_SIZE

/* Hex string buffer sizes (digest * 2 + NUL) */
#define TPM_SHA1_HEX_SIZE      ((TPM_SHA1_DIGEST_SIZE * 2) + 1)
#define TPM_SHA256_HEX_SIZE    ((TPM_SHA256_DIGEST_SIZE * 2) + 1)
#define TPM_SHA384_HEX_SIZE    ((TPM_SHA384_DIGEST_SIZE * 2) + 1)
#define TPM_SHA512_HEX_SIZE    ((TPM_SHA512_DIGEST_SIZE * 2) + 1)
#define TPM_MAX_HEX_SIZE       ((TPM_MAX_DIGEST_SIZE * 2) + 1)

/* Fixed path buffer size */
#define TPM_PATH_MAX  512

/* TPM 2.0 algorithm identifiers (TCG Algorithm Registry) */
#define TPM2_ALG_SHA1       0x0004
#define TPM2_ALG_SHA256     0x000B
#define TPM2_ALG_SHA384     0x000C
#define TPM2_ALG_SHA512     0x000D
#define TPM2_ALG_SM3_256    0x0012

/* Hash algorithm bank identifiers */
typedef enum {
    TPM_BANK_SHA1    = 0,
    TPM_BANK_SHA256  = 1,
    TPM_BANK_SHA384  = 2,
    TPM_BANK_SHA512  = 3,
    TPM_BANK_SM3_256 = 4,
    TPM_BANK_COUNT   = 5,
} tpm_bank_t;

/* A single PCR value */
typedef struct {
    uint8_t  digest[TPM_MAX_DIGEST_SIZE];
    size_t   digest_len;
    int      index;
    bool     valid;
} tpm_pcr_value_t;

/* A complete set of 24 PCR values for one bank */
typedef struct {
    tpm_pcr_value_t pcrs[TPM_PCR_COUNT];
    tpm_bank_t      bank;
    int             count;   /* number of valid entries */
} tpm_pcr_set_t;

/* Output format */
typedef enum {
    OUTPUT_TABLE = 0,
    OUTPUT_JSON  = 1,
    OUTPUT_CSV   = 2,
} output_fmt_t;

/* Return codes */
typedef enum {
    TPM_OK              =  0,
    TPM_ERR_OPEN        = -1,
    TPM_ERR_READ        = -2,
    TPM_ERR_PARSE       = -3,
    TPM_ERR_INDEX       = -4,
    TPM_ERR_VERIFY      = -5,
    TPM_ERR_IO          = -6,
    TPM_ERR_NOMEM       = -7,
    TPM_ERR_UNSUPPORTED = -8,
    TPM_ERR_SIGNATURE   = -9,
    TPM_ERR_REPLAY      = -10,
} tpm_err_t;

/* Return the human-readable bank name */
static inline const char *tpm_bank_name(tpm_bank_t bank)
{
    switch (bank) {
    case TPM_BANK_SHA1:    return "sha1";
    case TPM_BANK_SHA256:  return "sha256";
    case TPM_BANK_SHA384:  return "sha384";
    case TPM_BANK_SHA512:  return "sha512";
    case TPM_BANK_SM3_256: return "sm3_256";
    default:               return "unknown";
    }
}

/* Return digest length for a given bank */
static inline size_t tpm_bank_digest_len(tpm_bank_t bank)
{
    switch (bank) {
    case TPM_BANK_SHA1:    return TPM_SHA1_DIGEST_SIZE;
    case TPM_BANK_SHA256:  return TPM_SHA256_DIGEST_SIZE;
    case TPM_BANK_SHA384:  return TPM_SHA384_DIGEST_SIZE;
    case TPM_BANK_SHA512:  return TPM_SHA512_DIGEST_SIZE;
    case TPM_BANK_SM3_256: return TPM_SM3_256_DIGEST_SIZE;
    default:               return 0;
    }
}

/* Return TPM2 algorithm ID for a bank */
static inline uint16_t tpm_bank_alg_id(tpm_bank_t bank)
{
    switch (bank) {
    case TPM_BANK_SHA1:    return TPM2_ALG_SHA1;
    case TPM_BANK_SHA256:  return TPM2_ALG_SHA256;
    case TPM_BANK_SHA384:  return TPM2_ALG_SHA384;
    case TPM_BANK_SHA512:  return TPM2_ALG_SHA512;
    case TPM_BANK_SM3_256: return TPM2_ALG_SM3_256;
    default:               return 0;
    }
}

/* Parse bank name string to enum */
static inline tpm_bank_t tpm_bank_from_name(const char *name)
{
    if (!name) return TPM_BANK_SHA256;
    if (strcmp(name, "sha1") == 0)    return TPM_BANK_SHA1;
    if (strcmp(name, "sha256") == 0)  return TPM_BANK_SHA256;
    if (strcmp(name, "sha384") == 0)  return TPM_BANK_SHA384;
    if (strcmp(name, "sha512") == 0)  return TPM_BANK_SHA512;
    if (strcmp(name, "sm3_256") == 0) return TPM_BANK_SM3_256;
    if (strcmp(name, "sm3") == 0)     return TPM_BANK_SM3_256;
    return TPM_BANK_COUNT; /* invalid sentinel */
}

/* Parse TPM2 algorithm ID to bank enum */
static inline tpm_bank_t tpm_bank_from_alg_id(uint16_t alg)
{
    switch (alg) {
    case TPM2_ALG_SHA1:    return TPM_BANK_SHA1;
    case TPM2_ALG_SHA256:  return TPM_BANK_SHA256;
    case TPM2_ALG_SHA384:  return TPM_BANK_SHA384;
    case TPM2_ALG_SHA512:  return TPM_BANK_SHA512;
    case TPM2_ALG_SM3_256: return TPM_BANK_SM3_256;
    default:               return TPM_BANK_COUNT;
    }
}

#endif /* TPM_PCR_DUMP_H */
