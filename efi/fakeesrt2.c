#include <efi.h>
#include <efilib.h>

typedef struct esre {
	EFI_GUID	fw_class;
	UINT32		fw_type;
	UINT32		fw_version;
	UINT32		lowest_supported_fw_version;
	UINT32		capsule_flags;
	UINT32		last_attempt_version;
	UINT32		last_attempt_status;
} __attribute__ ((__packed__)) esre_t;

#define guid0 { 0x0712233d, 0xfe15, 0x434c, { 0xbf, 0x4d, 0xa3, 0x4a, 0x05, 0x03, 0x14, 0x4a }}
#define guid1 { 0xeac48586, 0xebf7, 0x4901, { 0xb2, 0x32, 0x0b, 0x29, 0xe9, 0x9a, 0xe6, 0xa9 }}
#define fake_capsule_header_guid {0x32e678e9, 0x263f, 0x4eae, {0xa2, 0x39, 0x38, 0xa3, 0xca, 0xd6, 0xa1, 0xb5}}

EFI_STATUS
efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *systab)
{
	esre_t esre0 = { guid0, 0, 0, 0, 0x80f1, 0, 0 };
	esre_t esre1 = { guid1, 1, 9, 7, 0x80f1, 0, 0 };
	EFI_GUID fchg = fake_capsule_header_guid;

	EFI_STATUS status;

	InitializeLib(image_handle, systab);

	status = systab->RuntimeServices->SetVariable (
			      L"Esrt0000",
			      &fchg,
			      EFI_VARIABLE_NON_VOLATILE
			        | EFI_VARIABLE_BOOTSERVICE_ACCESS
				| EFI_VARIABLE_RUNTIME_ACCESS,
			      sizeof (esre0),
			      &esre0);
	if (EFI_ERROR(status)) {
		Print(L"SetVariable(esre0) failed: %r\n", status);
		return status;
	}

	status = systab->RuntimeServices->SetVariable (
			      L"Esrt0001",
			      &fchg,
			      EFI_VARIABLE_NON_VOLATILE
			        | EFI_VARIABLE_BOOTSERVICE_ACCESS
				| EFI_VARIABLE_RUNTIME_ACCESS,
			      sizeof (esre1),
			      &esre1);
	if (EFI_ERROR(status)) {
		Print(L"SetVariable(esre1) failed: %r\n", status);
		return status;
	}

	return 0;
}

