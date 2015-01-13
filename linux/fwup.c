

#include <efivar.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <uchar.h>

#define CAPSULE_FLAGS_PERSIST_ACROSS_RESET    0x00010000
#define CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE   0x00020000
#define CAPSULE_FLAGS_INITIATE_RESET          0x00040000

struct fwupdate_entry {
	efi_guid_t guid;
	uint32_t version;
	uint32_t flags;
	char16_t path[1024];
};

int main(void)
{
	efi_guid_t fwupdate_guid = EFI_GUID(0x0abba7dc,0xe516,0x4167,0xbbf5,0x4d,0x9d,0x1c,0x73,0x94,0x16);
	efi_guid_t fw_guid = EFI_GUID(0xffd4675e, 0xff47, 0x46d9,0xac24,0x8b,0x33,0x1f,0x93,0x77,0x37);

	struct fwupdate_entry fwue = {
		.guid = fw_guid,
		.version = 1413742592,
		.flags = CAPSULE_FLAGS_PERSIST_ACROSS_RESET | CAPSULE_FLAGS_INITIATE_RESET,
		//.path = L"\\EFI\\fedora\\capsule\\isflash.bin",
		.path = L"\\UEFIDevKit_S1200RP_vB2\\SDV_RP_B2_debug.cap",
	};
	void *data = &fwue;

	int rc;

	rc = efi_set_variable(fwupdate_guid, "FwUpdates",
			      data, sizeof (fwue),
			      EFI_VARIABLE_NON_VOLATILE |
			      EFI_VARIABLE_BOOTSERVICE_ACCESS |
			      EFI_VARIABLE_RUNTIME_ACCESS,
			      0600);
	printf("rc: %d\n", rc);
	return 0;
}
