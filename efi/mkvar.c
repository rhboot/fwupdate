#include <efi.h>
#include <efilib.h>

struct fwupdate_entry {
	EFI_GUID guid;
	UINT32 version;
	UINT32 flags;
	CHAR16 path[1024];
};

EFI_STATUS
efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_GUID fwupdate_guid = {0x0abba7dc,0xe516,0x4167,{0xbb,0xf5,0x4d,0x9d,0x1c,0x73,0x94,0x16}};
#if 0
	EFI_GUID fw_guid = {0xffd4675e, 0xff47, 0x46d9,{0xac,0x24,0x8b,0x33,0x1f,0x93,0x77,0x37}};
#else
	EFI_GUID fw_guid = {0x819b858e,0xc52c,0x402f,{0x80,0xe1,0x5b,0x31,0x1b,0x6c,0x19,0x59}};
#endif
	struct fwupdate_entry fwue = {
		.guid = fw_guid,
		.version = 1413742592,
		.flags = 0x1,
	//	CAPSULE_FLAGS_PERSIST_ACROSS_RESET | CAPSULE_FLAGS_INITIATE_RESET,
		.path = L"\\UEFIDevKit_S1200RP_vB2\\SDV_RP_B2_debug.cap",
	};

	InitializeLib(image, systab);

	EFI_STATUS rc = uefi_call_wrapper(RT->SetVariable, 5, L"FwUpdates",
			&fwupdate_guid, EFI_VARIABLE_NON_VOLATILE |
					EFI_VARIABLE_BOOTSERVICE_ACCESS |
					EFI_VARIABLE_RUNTIME_ACCESS,
			sizeof (fwue), &fwue);
	Print(L"SetVariable: %r\n", rc);
	return 0;
}
