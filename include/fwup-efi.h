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

#define FWUPDATE_ATTEMPT_UPDATE		0x00000001
#define FWUPDATE_ATTEMPTED		0x00000002

#define UPDATE_INFO_VERSION	7

typedef struct update_info_s {
	uint32_t update_info_version;

	/* stuff we need to apply an update */
	efi_guid_t guid;
	uint32_t capsule_flags;
	uint64_t hw_inst;

	EFI_TIME time_attempted;

	/* our metadata */
	uint32_t status;

	/* variadic device path */
	union {
		efidp_header *dp_ptr;
		uint8_t dp[sizeof(efidp_header)];
	};
} __attribute__((__packed__)) update_info;

#endif /* _FWUP_EFI_H */
