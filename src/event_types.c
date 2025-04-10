/*
 * tpm-pcr-dump — TCG event type definitions and decoders
 *
 * Copyright (c) 2026 isecwire GmbH
 * SPDX-License-Identifier: MIT
 */

#include "event_types.h"

#include <stddef.h>

typedef struct {
    uint32_t    type;
    const char *name;
    const char *description;
} event_type_entry_t;

static const event_type_entry_t g_event_types[] = {
    { EV_PREBOOT_CERT,
      "EV_PREBOOT_CERT",
      "Pre-boot certificate" },
    { EV_POST_CODE,
      "EV_POST_CODE",
      "BIOS/UEFI POST code" },
    { EV_UNUSED,
      "EV_UNUSED",
      "Unused event" },
    { EV_NO_ACTION,
      "EV_NO_ACTION",
      "Informational (not measured)" },
    { EV_SEPARATOR,
      "EV_SEPARATOR",
      "Separator between pre-OS and OS events" },
    { EV_ACTION,
      "EV_ACTION",
      "Platform action (ASCII string)" },
    { EV_EVENT_TAG,
      "EV_EVENT_TAG",
      "Tagged event data" },
    { EV_S_CRTM_CONTENTS,
      "EV_S_CRTM_CONTENTS",
      "Static CRTM contents measurement" },
    { EV_S_CRTM_VERSION,
      "EV_S_CRTM_VERSION",
      "Static CRTM version string" },
    { EV_CPU_MICROCODE,
      "EV_CPU_MICROCODE",
      "CPU microcode measurement" },
    { EV_PLATFORM_CONFIG_FLAGS,
      "EV_PLATFORM_CONFIG_FLAGS",
      "Platform configuration flags" },
    { EV_TABLE_OF_DEVICES,
      "EV_TABLE_OF_DEVICES",
      "Table of devices attached to platform" },
    { EV_COMPACT_HASH,
      "EV_COMPACT_HASH",
      "Compact hash for large data" },
    { EV_IPL,
      "EV_IPL",
      "Initial Program Loader code" },
    { EV_IPL_PARTITION_DATA,
      "EV_IPL_PARTITION_DATA",
      "IPL partition data" },
    { EV_NONHOST_CODE,
      "EV_NONHOST_CODE",
      "Non-host platform code" },
    { EV_NONHOST_CONFIG,
      "EV_NONHOST_CONFIG",
      "Non-host platform configuration" },
    { EV_NONHOST_INFO,
      "EV_NONHOST_INFO",
      "Non-host platform information" },
    { EV_OMIT_BOOT_DEVICE_EVENTS,
      "EV_OMIT_BOOT_DEVICE_EVENTS",
      "Boot device events omitted" },
    { EV_EFI_VARIABLE_DRIVER_CONFIG,
      "EV_EFI_VARIABLE_DRIVER_CONFIG",
      "EFI variable: Secure Boot config (PK, KEK, db, dbx)" },
    { EV_EFI_VARIABLE_BOOT,
      "EV_EFI_VARIABLE_BOOT",
      "EFI Boot#### variable measurement" },
    { EV_EFI_BOOT_SERVICES_APPLICATION,
      "EV_EFI_BOOT_SERVICES_APPLICATION",
      "EFI boot application (shim, GRUB, kernel)" },
    { EV_EFI_BOOT_SERVICES_DRIVER,
      "EV_EFI_BOOT_SERVICES_DRIVER",
      "EFI boot services driver" },
    { EV_EFI_RUNTIME_SERVICES_DRIVER,
      "EV_EFI_RUNTIME_SERVICES_DRIVER",
      "EFI runtime services driver" },
    { EV_EFI_GPT_EVENT,
      "EV_EFI_GPT_EVENT",
      "EFI GPT partition table measurement" },
    { EV_EFI_ACTION,
      "EV_EFI_ACTION",
      "EFI platform action string" },
    { EV_EFI_PLATFORM_FIRMWARE_BLOB,
      "EV_EFI_PLATFORM_FIRMWARE_BLOB",
      "EFI platform firmware blob measurement" },
    { EV_EFI_HANDOFF_TABLES,
      "EV_EFI_HANDOFF_TABLES",
      "EFI handoff tables" },
    { EV_EFI_PLATFORM_FIRMWARE_BLOB2,
      "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
      "EFI platform firmware blob v2" },
    { EV_EFI_HANDOFF_TABLES2,
      "EV_EFI_HANDOFF_TABLES2",
      "EFI handoff tables v2" },
    { EV_EFI_VARIABLE_BOOT2,
      "EV_EFI_VARIABLE_BOOT2",
      "EFI Boot variable v2" },
    { EV_EFI_HCRTM_EVENT,
      "EV_EFI_HCRTM_EVENT",
      "Host CRTM event" },
    { EV_EFI_VARIABLE_AUTHORITY,
      "EV_EFI_VARIABLE_AUTHORITY",
      "EFI Secure Boot authority (certificate used)" },
    { EV_EFI_SPDM_FIRMWARE_BLOB,
      "EV_EFI_SPDM_FIRMWARE_BLOB",
      "SPDM firmware blob measurement" },
    { EV_EFI_SPDM_FIRMWARE_CONFIG,
      "EV_EFI_SPDM_FIRMWARE_CONFIG",
      "SPDM firmware config measurement" },
};

#define NUM_EVENT_TYPES (sizeof(g_event_types) / sizeof(g_event_types[0]))

const char *event_type_name(uint32_t event_type)
{
    for (size_t i = 0; i < NUM_EVENT_TYPES; i++) {
        if (g_event_types[i].type == event_type)
            return g_event_types[i].name;
    }
    return "UNKNOWN";
}

const char *event_type_description(uint32_t event_type)
{
    for (size_t i = 0; i < NUM_EVENT_TYPES; i++) {
        if (g_event_types[i].type == event_type)
            return g_event_types[i].description;
    }
    return "Unknown event type";
}

int event_type_typical_pcr(uint32_t event_type)
{
    switch (event_type) {
    case EV_S_CRTM_CONTENTS:
    case EV_S_CRTM_VERSION:
    case EV_POST_CODE:
    case EV_EFI_PLATFORM_FIRMWARE_BLOB:
    case EV_EFI_PLATFORM_FIRMWARE_BLOB2:
        return 0;
    case EV_EFI_VARIABLE_DRIVER_CONFIG:
    case EV_PLATFORM_CONFIG_FLAGS:
        return 1;
    case EV_NONHOST_CODE:
    case EV_TABLE_OF_DEVICES:
        return 2;
    case EV_NONHOST_CONFIG:
        return 3;
    case EV_EFI_BOOT_SERVICES_APPLICATION:
    case EV_EFI_BOOT_SERVICES_DRIVER:
    case EV_COMPACT_HASH:
        return 4;
    case EV_EFI_GPT_EVENT:
    case EV_EFI_ACTION:
        return 5;
    case EV_EFI_VARIABLE_AUTHORITY:
    case EV_EFI_VARIABLE_BOOT:
        return 7;
    default:
        return -1;
    }
}
