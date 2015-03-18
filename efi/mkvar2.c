#include <efi.h>
#include <efilib.h>

#define efidp_header EFI_DEVICE_PATH
#define efi_guid_t EFI_GUID

#include "fwup-efi.h"

typedef struct esre {
	EFI_GUID	fw_class;
	UINT32		fw_type;
	UINT32		fw_version;
	UINT32		lowest_supported_fw_version;
	UINT32		capsule_flags;
	UINT32		last_attempt_version;
	UINT32		last_attempt_status;
} __attribute__ ((__packed__)) esre_t;

#define guid0 {0x0712233d,0xfe15,0x434c,{0xbf,0x4d,0xa3,0x4a,0x05,0x03,0x14,0x4a}}
#define guid1 {{0xeac48586,0xebf7,0x4901,0xb2,0x32,0x0b,0x29,0xe9,0x9a,0xe6,0xa9}}

uint8_t devicepath[] =
	                "\x02\x01\x0c\x00\xd0\x41\x03\x0a\x00\x00\x00\x00"
	"\x01\x01\x06\x00\x01\x01\x03\x01\x08\x00\x00\x00\x00\x00\x04\x01"
	"\x2a\x00\x01\x00\x00\x00\xa1\x07\x00\x00\x00\x00\x00\x00\x3e\x20"
	"\x00\x00\x00\x00\x00\x00\xe7\x2f\x41\x52\xa7\x80\x72\x4c\x8b\x0b"
	"\x02\x9e\xab\x6f\x0c\x2b\x02\x02\x04\x04\x1a\x00\x5c\x00\x65\x00"
	"\x73\x00\x72\x00\x65\x00\x30\x00\x2e\x00\x63\x00\x61\x00\x70\x00"
	"\x00\x00\x7f\xff\x04\x00";

EFI_STATUS
efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_GUID fwupdate_guid = {0x0abba7dc,0xe516,0x4167,{0xbb,0xf5,0x4d,0x9d,0x1c,0x73,0x94,0x16}};
	UINT8 buf[EFI_FIELD_OFFSET(update_info, dp)+sizeof(devicepath)-1];
	update_info *info = (update_info *)buf;
	efi_guid_t guid = guid0;

	info->update_info_version = UPDATE_INFO_VERSION;
	info->capsule_flags = 0x80f1;
	info->hw_inst = 0;
	info->status = FWUPDATE_ATTEMPT_UPDATE;

	InitializeLib(image, systab);

	ZeroMem(&info->time_attempted, sizeof (info->time_attempted));
	CopyMem(info->dp, devicepath, sizeof (devicepath)-1);
	CopyMem(&info->guid, &guid, sizeof (guid));

	EFI_STATUS rc = uefi_call_wrapper(RT->SetVariable, 5, L"FwUpdates",
			&fwupdate_guid, EFI_VARIABLE_NON_VOLATILE |
					EFI_VARIABLE_BOOTSERVICE_ACCESS |
					EFI_VARIABLE_RUNTIME_ACCESS,
			sizeof (buf), buf);
	Print(L"SetVariable: %r\n", rc);
	return 0;
}
