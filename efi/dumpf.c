#include <efi.h>
#include <efilib.h>

#include "hexdump.h"

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

