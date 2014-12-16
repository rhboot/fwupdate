/*
 * fwupdate.c - apply firmware updates
 *
 * Copyright 2014 Red Hat, Inc.
 *
 * See "COPYING" for license terms.
 *
 * Author: Peter Jones <pjones@redhat.com>
 */

#include <efi.h>
#include <efilib.h>

EFI_GUID fwupdate_guid = {0x0abba7dc,0xe516,0x4167,{0xbb,0xf5,0x4d,0x9d,0x1c,0x73,0x94,0x16}};

struct fwupdate_entry {
	EFI_GUID guid;
	UINT32 version;
	UINT32 flags;
	CHAR16 path[1024];
};

static EFI_STATUS
get_file_size(EFI_FILE_HANDLE fh, CHAR16 *fullpath, UINTN *retsize)
{
	EFI_STATUS rc;
	void *buffer = NULL;
	UINTN bs = 0;
	EFI_GUID finfo = EFI_FILE_INFO_ID;
	EFI_FILE_HANDLE fh2;

	rc = uefi_call_wrapper(fh->Open, 5, fh, &fh2, fullpath,
				EFI_FILE_READ_ONLY, 0);
	if (EFI_ERROR(rc)) {
		Print(L"Couldn't open \"%s\": %d\n", fullpath, rc);
		return rc;
	}

	/* The API here is "Call it once with bs=0, it fills in bs,
	 * then allocate a buffer and ask again to get it filled. */
	rc = uefi_call_wrapper(fh2->GetInfo, 4, fh2, &finfo, &bs, NULL);
	if (rc == EFI_BUFFER_TOO_SMALL) {
		buffer = AllocateZeroPool(bs);
		if (!buffer) {
			uefi_call_wrapper(fh2->Close, 1, fh2);
			Print(L"Could not allocate memory\n");
			return EFI_OUT_OF_RESOURCES;
		}
		rc = uefi_call_wrapper(fh->GetInfo, 4, fh, &finfo,
					&bs, buffer);
	}
	/* This checks *either* the error from the first GetInfo, if it isn't
	 * the EFI_BUFFER_TOO_SMALL we're expecting, or the second GetInfo call
	 * in *any* case. */
	if (EFI_ERROR(rc)) {
		uefi_call_wrapper(fh2->Close, 1, fh2);
		Print(L"Could not get file info: %r\n", rc);
		if (buffer)
			FreePool(buffer);
		return rc;
	}
	EFI_FILE_INFO *fi = buffer;
	*retsize = fi->FileSize;
	FreePool(buffer);
	uefi_call_wrapper(fh2->Close, 1, fh2);
	return EFI_SUCCESS;
}

EFI_STATUS
read_file(EFI_FILE_HANDLE fh, CHAR16 *fullpath, UINT8 **buffer, UINT64 *bs)
{
	EFI_FILE_HANDLE fh2;
	EFI_STATUS rc = uefi_call_wrapper(fh->Open, 5, fh, &fh2, fullpath,
				EFI_FILE_READ_ONLY, 0);
	if (EFI_ERROR(rc)) {
		Print(L"Couldn't open \"%s\": %d\n", fullpath, rc);
		return rc;
	}

	UINTN len = 0;
	UINT8 *b = NULL;
	rc = get_file_size(fh, fullpath, &len);
	if (EFI_ERROR(rc)) {
		uefi_call_wrapper(fh2->Close, 1, fh2);
		return rc;
	}

	b = AllocateZeroPool(len + 2);
	if (!buffer) {
		Print(L"Could not allocate memory\n");
		uefi_call_wrapper(fh2->Close, 1, fh2);
		return EFI_OUT_OF_RESOURCES;
	}

	rc = uefi_call_wrapper(fh->Read, 3, fh, &len, b);
	if (EFI_ERROR(rc)) {
		FreePool(buffer);
		uefi_call_wrapper(fh2->Close, 1, fh2);
		Print(L"Could not read file: %d\n", rc);
		return rc;
	}
	*buffer = b;
	*bs = len;
	uefi_call_wrapper(fh2->Close, 1, fh2);
	return EFI_SUCCESS;
}

EFI_STATUS
open_volume(EFI_HANDLE device, EFI_FILE_HANDLE *fh_ret)
{
	EFI_STATUS rc = EFI_SUCCESS;

	EFI_FILE_IO_INTERFACE *fio = NULL;
	rc = uefi_call_wrapper(BS->HandleProtocol, 3, device,
				&FileSystemProtocol, (void **)&fio);
	if (EFI_ERROR(rc)) {
		Print(L"Couldn't find file system: %r\n", rc);
		return rc;
	}

	/* EFI_FILE_HANDLE is a pointer to an EFI_FILE, and I have
	 * *no idea* what frees the memory allocated here. Hopefully
	 * Close() does. */
	EFI_FILE_HANDLE fh = NULL;
	rc = uefi_call_wrapper(fio->OpenVolume, 2, fio, &fh);
	if (EFI_ERROR(rc) || fh == NULL) {
		Print(L"Couldn't open file system: %r\n", rc);
		return rc;
	}

	*fh_ret = fh;
	return EFI_SUCCESS;
}

EFI_STATUS
efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS rc;
	struct fwupdate_entry *updates = NULL;
	UINTN size = 0;
	UINT32 attributes;
	EFI_LOADED_IMAGE *this_image = NULL;
	EFI_FILE_HANDLE fh = NULL;

	InitializeLib(image, systab);

	rc = uefi_call_wrapper(BS->HandleProtocol, 3, image, &LoadedImageProtocol, (void *)&this_image);
	if (EFI_ERROR(rc)) {
		Print(L"Error: could not find loaded image: %d\n", rc);
		return rc;
	}

	rc = uefi_call_wrapper(RT->GetVariable, 5, L"FwUpdates",
			       &fwupdate_guid, &attributes,
			       &size, updates);
	if (EFI_ERROR(rc)) {
		if (rc == EFI_BUFFER_TOO_SMALL) {
			updates = AllocatePool(size);
			if (!updates) {
				Print(L"Couldn't allocate memory\n");
				return EFI_OUT_OF_RESOURCES;
			}
		} else {
			Print(L"Couldn't get variable \"Fwupdates\": %r\n", rc);
			return rc;
		}
	} else {
		Print(L"GetVariable() succeeded with size=0.\n");
		return EFI_INVALID_PARAMETER;
	}
	rc = uefi_call_wrapper(RT->GetVariable, 5, L"FwUpdates",
			       &fwupdate_guid, &attributes,
			       &size, updates);
	if (EFI_ERROR(rc)) {
		Print(L"Couldn't get variable \"Fwupdates\": %r\n", rc);
		return rc;
	}

	/* We don't want to get stuck in a failure loop... */
	uefi_call_wrapper(RT->SetVariable, 5, L"FwUpdates", &fwupdate_guid,
			  attributes, 0, NULL);

	if (size % sizeof (struct fwupdate_entry)) {
		Print(L"FwUpdates has unreasonable size %d.\n", size);
		return EFI_INVALID_PARAMETER;
	}
	UINTN num_updates = size / sizeof (struct fwupdate_entry);

	rc = open_volume(this_image->DeviceHandle, &fh);
	if (EFI_ERROR(rc))
		return rc;

	EFI_CAPSULE_HEADER *capsules[num_updates];
	EFI_CAPSULE_BLOCK_DESCRIPTOR cbd[num_updates + 1];
	int i;

	for (i = 0; i < num_updates; i++) {
		UINTN fsize = 0;
		EFI_CAPSULE_HEADER *capsule;
		UINT8 *buffer;

		rc = get_file_size(fh, updates[i].path, &fsize);
		if (EFI_ERROR(rc)) {
			Print(L"Cannot load update \"%s\": %r\n", rc);
			return rc;
		}

		capsule = AllocatePool(fsize + sizeof (*capsule));
		if (!capsule) {
			Print(L"Could not allocate memory for capsule buffer.\n");
			return EFI_OUT_OF_RESOURCES;
		}

		capsule->CapsuleGuid = updates[i].guid;
		capsule->HeaderSize = sizeof (*capsule);
		capsule->Flags = updates[i].flags;
		capsule->CapsuleImageSize = fsize + sizeof (*capsule);
		buffer = (UINT8 *)capsule + sizeof (*capsule);
		UINT64 bs = capsule->CapsuleImageSize - sizeof (*capsule);

		rc = read_file(fh, updates[i].path, &buffer, &bs);
		if (EFI_ERROR(rc)) {
			Print(L"Could not read update file: %r\n", rc);
			return rc;
		}
		cbd[i].Length = capsule->CapsuleImageSize;
		cbd[i].Union.DataBlock = (EFI_PHYSICAL_ADDRESS)(VOID *)capsule;

		capsules[i] = capsule;
	}
	cbd[i].Length = 0;
	cbd[i].Union.ContinuationPointer = 0;

	rc = uefi_call_wrapper(RT->UpdateCapsule, 3, capsules, num_updates,
			       (EFI_PHYSICAL_ADDRESS)(VOID *)cbd);
	if (EFI_ERROR(rc)) {
		Print(L"Could not apply capsule update.\n");
		return rc;
	}

	Print(L"Reset System\n");
	uefi_call_wrapper(RT->ResetSystem, 4, EfiResetWarm,
			  EFI_SUCCESS, 0, NULL);

	return EFI_SUCCESS;
}
