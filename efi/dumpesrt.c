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

#define esrt_guid {  0xb122a263, 0x3661, 0x4f68, { 0x99, 0x29, 0x78, 0xf8, 0xb0, 0xd6, 0x21, 0x80 }}

static EFI_GUID EsrtGuid = esrt_guid;

static int
isprint(char c)
{
	if (c < 0x20)
		return 0;
	if (c > 0x7e)
		return 0;
	return 1;
}

static UINTN
format_hex(UINT8 *data, UINTN size, CHAR16 *buf)
{
	UINTN sz = (UINTN)data % 16;
	CHAR16 hexchars[] = L"0123456789abcdef";
	int offset = 0;
	int i;
	int j;

	for (i = 0; i < sz; i++) {
		buf[offset++] = L' ';
		buf[offset++] = L' ';
		buf[offset++] = L' ';
		if (i == 7)
			buf[offset++] = L' ';
	}
	for (j = sz; j < 16 && j < size; j++) {
		UINT8 d = data[j-sz];
		buf[offset++] = hexchars[(d & 0xf0) >> 4];
		buf[offset++] = hexchars[(d & 0x0f)];
		if (j != 15)
			buf[offset++] = L' ';
		if (j == 7)
			buf[offset++] = L' ';
	}
	for (i = j; i < 16; i++) {
		buf[offset++] = L' ';
		buf[offset++] = L' ';
		if (i != 15)
			buf[offset++] = L' ';
		if (i == 7)
			buf[offset++] = L' ';
	}
	buf[offset] = L'\0';
	return j - sz;
}

static void
format_text(UINT8 *data, UINTN size, CHAR16 *buf)
{
	UINTN sz = (UINTN)data % 16;
	int offset = 0;
	int i;

	for (i = 0; i < sz; i++)
		buf[offset++] = L' ';
	buf[offset++] = L'|';
	for (; i < 16 && i < size; i++) {
		if (isprint(data[i]))
			buf[offset++] = data[i];
		else
			buf[offset++] = L'.';
	}
	buf[offset++] = L'|';
	for (; i < 16; i++)
		buf[offset++] = L' ';
	buf[offset] = L'\0';
}

static void
hexdump(UINT8 *data, UINTN size)
{
	UINTN display_offset = (UINTN)data & 0xffffffff;
	UINTN offset = 0;
	//Print(L"hexdump: data=0x%016x size=0x%x\n", data, size);

	while (offset < size) {
		CHAR16 hexbuf[49];
		CHAR16 txtbuf[19];
		UINTN sz;

		sz = format_hex(data+offset, size-offset, hexbuf);
		if (sz == 0)
			return;
		uefi_call_wrapper(BS->Stall, 1, 200000);

		format_text(data+offset, size-offset, txtbuf);
		Print(L"%08x  %s  %s\n", display_offset, hexbuf, txtbuf);
		uefi_call_wrapper(BS->Stall, 1, 200000);

		display_offset += sz;
		offset += sz;
	}
}

static void
dump_esrt(VOID *data)
{
	esrt_t *esrt = data;
	esre_t *esre = data + sizeof (*esrt);

	hexdump(data, sizeof(*esrt));

	for (int i = 0; i < esrt->fw_resource_count; i++) {
		hexdump((void *)esre, sizeof (*esre));
		esre++;
	}
}

EFI_STATUS
efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *systab)
{
	EFI_CONFIGURATION_TABLE *ect = systab->ConfigurationTable;

	InitializeLib(image_handle, systab);

	for (int i = 0; i < systab->NumberOfTableEntries; i++) {
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

