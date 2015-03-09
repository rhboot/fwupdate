/*
 * fwup-efi.h: shared structures between the linux frontend and the efi backend.
 *
 * Copyright 2015 Red Hat, Inc.
 *
 * See "COPYING" for license terms.
 *
 * Author: Peter Jones <pjones@redhat.com>
 */
#ifndef _FWUP_EFI_H
#define _FWUP_EFI_H

#define FWUPDATE_GUID EFI_GUID(0x0abba7dc,0xe516,0x4167,0xbbf5,0x4d,0x9d,0x1c,0x73,0x94,0x16)

#define FWUPDATE_ATTEMPT_UPDATE		0x00000001
#define FWUPDATE_ATTEMPTED		0x00000002

#define UPDATE_INFO_VERSION	7

typedef struct {
	uint16_t year;
	uint8_t month;
	uint8_t day;
	uint8_t hour;
	uint8_t minute;
	uint8_t second;
	uint8_t pad1;
	uint32_t nanosecond;
	uint16_t timezone;
	uint8_t daylight;
	uint8_t pad2;
} efi_time_t;

typedef struct update_info_s {
	uint32_t update_info_version;

	/* stuff we need to apply an update */
	efi_guid_t guid;
	uint64_t hw_inst;

	efi_time_t time_attempted;

	/* our metadata */
	uint32_t status;

	/* variadic device path */
	union {
		efidp_header *dp_ptr;
		uint8_t dp[sizeof(efidp_header)];
	};
} update_info;

#endif /* _FWUP_EFI_H */
