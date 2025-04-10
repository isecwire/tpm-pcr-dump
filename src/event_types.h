/*
 * tpm-pcr-dump — TCG event type definitions and decoders
 *
 * Reference: TCG PC Client Platform Firmware Profile Specification
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#ifndef TPM_EVENT_TYPES_H
#define TPM_EVENT_TYPES_H

#include <stdint.h>

/* TCG Event Types (EV_*) */
#define EV_PREBOOT_CERT                 0x00000000
#define EV_POST_CODE                    0x00000001
#define EV_UNUSED                       0x00000002
#define EV_NO_ACTION                    0x00000003
#define EV_SEPARATOR                    0x00000004
#define EV_ACTION                       0x00000005
#define EV_EVENT_TAG                    0x00000006
#define EV_S_CRTM_CONTENTS             0x00000007
#define EV_S_CRTM_VERSION              0x00000008
#define EV_CPU_MICROCODE                0x00000009
#define EV_PLATFORM_CONFIG_FLAGS        0x0000000A
#define EV_TABLE_OF_DEVICES             0x0000000B
#define EV_COMPACT_HASH                 0x0000000C
#define EV_IPL                          0x0000000D
#define EV_IPL_PARTITION_DATA           0x0000000E
#define EV_NONHOST_CODE                 0x0000000F
#define EV_NONHOST_CONFIG               0x00000010
#define EV_NONHOST_INFO                 0x00000011
#define EV_OMIT_BOOT_DEVICE_EVENTS     0x00000012

/* EFI Event Types */
#define EV_EFI_EVENT_BASE               0x80000000
#define EV_EFI_VARIABLE_DRIVER_CONFIG   0x80000001
#define EV_EFI_VARIABLE_BOOT           0x80000002
#define EV_EFI_BOOT_SERVICES_APPLICATION 0x80000003
#define EV_EFI_BOOT_SERVICES_DRIVER    0x80000004
#define EV_EFI_RUNTIME_SERVICES_DRIVER 0x80000005
#define EV_EFI_GPT_EVENT               0x80000006
#define EV_EFI_ACTION                  0x80000007
#define EV_EFI_PLATFORM_FIRMWARE_BLOB  0x80000008
#define EV_EFI_HANDOFF_TABLES          0x80000009
#define EV_EFI_PLATFORM_FIRMWARE_BLOB2 0x8000000A
#define EV_EFI_HANDOFF_TABLES2         0x8000000B
#define EV_EFI_VARIABLE_BOOT2          0x8000000C
#define EV_EFI_HCRTM_EVENT            0x80000010
#define EV_EFI_VARIABLE_AUTHORITY      0x800000E0
#define EV_EFI_SPDM_FIRMWARE_BLOB     0x800000E1
#define EV_EFI_SPDM_FIRMWARE_CONFIG   0x800000E2

/* Return a human-readable name for an event type */
const char *event_type_name(uint32_t event_type);

/* Return a short description of what a given event type measures */
const char *event_type_description(uint32_t event_type);

/* Return the typical PCR index for an event type, or -1 if variable */
int event_type_typical_pcr(uint32_t event_type);

#endif /* TPM_EVENT_TYPES_H */
