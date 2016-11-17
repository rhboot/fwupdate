#include <efi.h>
#include <efilib.h>

typedef struct esrt {
	UINT32 fw_resource_count;
	UINT32 fw_resource_count_max;
	UINT64 version;
} esrt_t;

typedef struct esre {
	EFI_GUID	fw_class;
	UINT32		fw_type;
	UINT32		fw_version;
	UINT32		lowest_supported_fw_version;
	UINT32		capsule_flags;
	UINT32		last_attempt_version;
	UINT32		last_attempt_status;
} esre_t;

#define guid0 { 0x0712233d, 0xfe15, 0x434c, { 0xbf, 0x4d, 0xa3, 0x4a, 0x05, 0x03, 0x14, 0x4a }}
#define guid1 { 0xeac48586, 0xebf7, 0x4901, { 0xb2, 0x32, 0x0b, 0x29, 0xe9, 0x9a, 0xe6, 0xa9 }}
#define esrt_guid {  0xb122a263, 0x3661, 0x4f68, { 0x99, 0x29, 0x78, 0xf8, 0xb0, 0xd6, 0x21, 0x80 }}

static EFI_GUID EsrtGuid = esrt_guid;

EFI_STATUS
efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *systab)
{
	struct {
		esrt_t esrt;
		esre_t esre0;
		esre_t esre1;
	} __attribute__((packed)) esrt = {
		.esrt = { 2, 2, 1 },
		.esre0 = { guid0, 0, 0, 0, 0x80f1, 0, 0 },
		.esre1 = { guid1, 1, 9, 7, 0x80f1, 0, 0 },
	};
	EFI_STATUS status;
	EFI_PHYSICAL_ADDRESS mem = 0;
	EFI_ALLOCATE_TYPE type = AllocateAnyPages;

	InitializeLib(image_handle, systab);

	if (sizeof (VOID *) == 4) {
		mem = 0xffffffffULL - 8192;
		type = AllocateMaxAddress;
	}
	status = uefi_call_wrapper(systab->BootServices->AllocatePages, 4,
				   type, EfiRuntimeServicesData, 1, &mem);
	if (EFI_ERROR(status)) {
		Print(L"AllocatePages failed: %r\n", status);
		return status;
	}
	if (sizeof (VOID *) == 4 && mem > 0xffffffffULL) {
		Print(L"Got bad allocation at 0x%016x\n", (UINT64)mem);
		return EFI_OUT_OF_RESOURCES;
	}
	VOID *ptr = (VOID *)(UINTN)mem;

	CopyMem(ptr, &esrt, sizeof (esrt));

	status = uefi_call_wrapper(
				systab->BootServices->InstallConfigurationTable,
				2, &EsrtGuid, ptr);
	if (EFI_ERROR(status)) {
		Print(L"InstallConfigurationTable failed: %r\n", status);
		uefi_call_wrapper(systab->BootServices->FreePages, 2,
				  mem, 1);
		return status;
	}

	return 0;
}

