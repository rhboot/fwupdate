#include <efi.h>
#include <efilib.h>

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
	int j;

	for (i = 0; i < sz; i++)
		buf[offset++] = L' ';
	buf[offset++] = L'|';
	for (j = sz; j < 16 && j < size; j++) {
		if (isprint(data[j-sz]))
			buf[offset++] = data[j-sz];
		else
			buf[offset++] = L'.';
	}
	buf[offset++] = L'|';
	for (i = j; i < 16; i++)
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

EFI_STATUS
efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *systab)
{
	InitializeLib(image_handle, systab);

	hexdump((void *)0xE0000000, 128);
	hexdump((void *)0xFEB00000, 128);
	hexdump((void *)0xFEC00000, 128);
	hexdump((void *)0xFED10000, 128);
	hexdump((void *)0xFED1C000, 128);
	hexdump((void *)0xFEE00000, 128);
	hexdump((void *)0xFFD00000, 128);
	return 0;
}

