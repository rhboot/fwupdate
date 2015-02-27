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
	CHAR16 path[40];
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
		Print(L"Couldn't open \"%s\": %r\n", fullpath, rc);
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
		rc = uefi_call_wrapper(fh->GetInfo, 4, fh2, &finfo,
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
		Print(L"Couldn't open \"%s\": %r\n", fullpath, rc);
		return rc;
	}

	UINTN len = 0;
	UINT8 *b = NULL;
	rc = get_file_size(fh, fullpath, &len);
	if (EFI_ERROR(rc)) {
		uefi_call_wrapper(fh2->Close, 1, fh2);
		return rc;
	}

	b = AllocateZeroPool(len);
	if (!b) {
		Print(L"Could not allocate memory\n");
		uefi_call_wrapper(fh2->Close, 1, fh2);
		return EFI_OUT_OF_RESOURCES;
	}

	rc = uefi_call_wrapper(fh2->Read, 3, fh2, &len, b);
	if (EFI_ERROR(rc)) {
		FreePool(b);
		uefi_call_wrapper(fh2->Close, 1, fh2);
		Print(L"Could not read file: %r\n", rc);
		return rc;
	}
	uefi_call_wrapper(fh2->Close, 1, fh2);
	*buffer = b;
	*bs = len;
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
		Print(L"Error: could not find loaded image: %r\n", rc);
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
#if 0
	uefi_call_wrapper(RT->SetVariable, 5, L"FwUpdates", &fwupdate_guid,
			  attributes, 0, NULL);
#endif

	if (size % sizeof (struct fwupdate_entry)) {
		Print(L"FwUpdates has unreasonable size %r.\n", size);
		return EFI_INVALID_PARAMETER;
	}
	UINTN num_updates = size / sizeof (struct fwupdate_entry);
	Print(L"num_updates: %d\n", num_updates);

	rc = open_volume(this_image->DeviceHandle, &fh);
	if (EFI_ERROR(rc))
		return rc;

	EFI_CAPSULE_HEADER *capsules[num_updates + 1];
	EFI_CAPSULE_BLOCK_DESCRIPTOR *cbd;
	int i;

	cbd = AllocateZeroPool(sizeof (EFI_CAPSULE_BLOCK_DESCRIPTOR) * (num_updates + 1));
	if (!cbd) {
		Print(L"Could not allocate memory for cbd.\n");
		return EFI_OUT_OF_RESOURCES;
	}

	for (i = 0; i < num_updates; i++) {
		UINTN fsize = 0;
		UINT8 *fbuf = NULL;
		UINTN bs;
		EFI_CAPSULE_HEADER *capsule;

		rc = get_file_size(fh, updates[i].path, &fsize);
		if (EFI_ERROR(rc)) {
			Print(L"Cannot load update \"%s\": %r\n", updates[i].path, rc);
			return rc;
		}

		bs = fsize;
		rc = read_file(fh, updates[i].path, &fbuf, &fsize);
		if (EFI_ERROR(rc)) {
			Print(L"Could not read update file: %r\n", rc);
			return rc;
		}
		Print(L"fsize: %ld\n", fsize);

		if (CompareMem(&updates[i].guid, fbuf,
				sizeof (updates[i].guid)) == 0) {
			Print(L"Image has capsule image embedded\n");
			Print(L"updates guid: %g\n", &updates[i].guid);
			Print(L"File guid: %g\n", fbuf);
			cbd[i].Length = bs;
			cbd[i].Union.DataBlock =
				(EFI_PHYSICAL_ADDRESS)(UINTN)fbuf;
			capsule = (EFI_CAPSULE_HEADER *)fbuf;
			capsule->Flags |= updates[i].flags;
			Print(L"Flags: 0x%08x\n", capsule->Flags);
		} else {
			Print(L"Image does not have embedded header\n");
			capsule = AllocatePool(sizeof (*capsule) + fsize);
			if (!capsule) {
				Print(L"Could not allocate space for update.\n");
				return EFI_OUT_OF_RESOURCES;
			}
			capsule->CapsuleGuid = updates[i].guid;
			capsule->HeaderSize = sizeof (*capsule);
			capsule->Flags = updates[i].flags;
			Print(L"Flags: 0x%08x\n", capsule->Flags);
			capsule->CapsuleImageSize = fsize + sizeof (*capsule);

			UINT8 *buffer = (UINT8 *)capsule + capsule->HeaderSize;
			CopyMem(buffer, fbuf, fsize);
			cbd[i].Length = capsule->CapsuleImageSize;
			cbd[i].Union.DataBlock =
				(EFI_PHYSICAL_ADDRESS)(UINTN)capsule;
		}

		capsules[i] = capsule;
	}

	uefi_call_wrapper(fh->Close, 1, fh);
	Print(L"i: %d\n", i);
	cbd[i].Length = 0;
	cbd[i].Union.ContinuationPointer = 0;

	capsules[i] = NULL;

	EFI_RESET_TYPE reset;
	UINT64 max_capsule_size;
	rc = uefi_call_wrapper(RT->QueryCapsuleCapabilities, 4, capsules,
				num_updates, &max_capsule_size, &reset);
	Print(L"QueryCapsuleCapabilities: %r max: %ld reset:%d\n",
		rc, max_capsule_size, reset);
	Print(L"Capsules: %d\n", num_updates);

	uefi_call_wrapper(BS->Stall, 1, 1000000);
	rc = uefi_call_wrapper(RT->UpdateCapsule, 3, capsules, num_updates,
			       (EFI_PHYSICAL_ADDRESS)(VOID *)cbd);
	if (EFI_ERROR(rc)) {
		Print(L"Could not apply capsule update: %r\n", rc);
		return rc;
	}

#if 0
	Print(L"Reset System\n");
	uefi_call_wrapper(BS->Stall, 1, 2000000);
	uefi_call_wrapper(RT->ResetSystem, 4, reset, EFI_SUCCESS, 0, NULL);
#endif

	return EFI_SUCCESS;
}
