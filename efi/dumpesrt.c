#include <efi.h>
#include <efilib.h>

typedef struct esrt {
	UINT32 fw_resource_count;
	UINT32 fw_resource_count_max;
	UINT64 version;
} __attribute__((__packed__)) esrt_t;

typedef struct esre1 {
	EFI_GUID	fw_class;
	UINT32		fw_type;
	UINT32		fw_version;
	UINT32		lowest_supported_fw_version;
	UINT32		capsule_flags;
	UINT32		last_attempt_version;
	UINT32		last_attempt_status;
} __attribute__((__packed__)) esre1_t;

#define esrt_guid {  0xb122a263, 0x3661, 0x4f68, { 0x99, 0x29, 0x78, 0xf8, 0xb0, 0xd6, 0x21, 0x80 }}

static EFI_GUID EsrtGuid = esrt_guid;

#include "hexdump.h"

static void
dump_esrt(VOID *data)
{
	esrt_t *esrt = data;
	esre1_t *esre1 = (esre1_t *)((UINT8 *)data + sizeof (*esrt));

	hexdump(data, sizeof(*esrt));

	for (unsigned int i = 0; i < esrt->fw_resource_count; i++) {
		if (esrt->version == 1) {
			Print(L"{%g}:\n", &esre1->fw_class);
			Print(L"  type:%d fv:0x%08x lsfv:0x%08x fl:0x%08x ",
			      esre1->fw_type, esre1->fw_version,
			      esre1->lowest_supported_fw_version,
			      esre1->capsule_flags);
			Print(L"lav: 0x%08x las: %d\n",
			      esre1->last_attempt_version,
			      esre1->last_attempt_status);
			hexdump((void *)esre1, sizeof (*esre1));
			esre1++;
		} else {
			Print(L"Weird ESRT version %d\n", esrt->version);
		}
	}
}

EFI_STATUS
efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *systab)
{
	EFI_CONFIGURATION_TABLE *ect = systab->ConfigurationTable;

	InitializeLib(image_handle, systab);

	for (unsigned int i = 0; i < systab->NumberOfTableEntries; i++) {
		if (CompareMem(&ect->VendorGuid, &EsrtGuid, sizeof(EsrtGuid))) {
			ect++;
			continue;
		}

		Print(L"Dumping VendorTable at %016x\n", ect->VendorTable);
		dump_esrt(ect->VendorTable);
		return 0;
	}

	Print(L"ESRT not found.\n");
	return 0;
}

