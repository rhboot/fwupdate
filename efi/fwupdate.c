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

#include "hexdump.h"

#define efidp_header EFI_DEVICE_PATH
#define efi_guid_t EFI_GUID

EFI_GUID empty_guid = {0x0,0x0,0x0,{0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0}};
EFI_GUID fwupdate_guid =
	{0x0abba7dc,0xe516,0x4167,{0xbb,0xf5,0x4d,0x9d,0x1c,0x73,0x94,0x16}};

#include "fwup-efi.h"

typedef struct update_table_s {
	CHAR16 *name;
	UINT32 attributes;
	UINTN size;
	update_info *info;
} update_table;

/*
 * Allocate some raw pages that aren't part of the pool allocator.
 */
static EFI_STATUS
allocate(void **addr, UINTN size)
{
	/*
	 * We're actually guaranteed that page size is 4096 by UEFI.
	 */
	UINTN pages = size / 4096 + ((size % 4096) ? 1 : 0);
	EFI_STATUS rc;
	EFI_PHYSICAL_ADDRESS pageaddr = 0;

	rc = uefi_call_wrapper(BS->AllocatePages, 4, AllocateAnyPages,
			       EfiLoaderData, pages,
			       &pageaddr);
	*addr = (void *)pageaddr;
	return rc;
}

/*
 * Free our raw page allocations.
 */
static EFI_STATUS
free(void *addr, UINTN size)
{
	UINTN pages = size / 4096 + ((size % 4096) ? 1 : 0);
	EFI_STATUS rc;

	rc = uefi_call_wrapper(BS->FreePages, 2, (EFI_PHYSICAL_ADDRESS)addr,
			       pages);
	return rc;
}

EFI_STATUS
read_file(EFI_FILE_HANDLE fh, UINT8 **buf_out, UINTN *buf_size_out)
{
	UINT8 *b;
	UINTN bs = 512;
	UINTN n_blocks = 4096;
	UINTN i = 0;
	EFI_STATUS rc;

	while (1) {
		void *newb = NULL;
		rc = allocate(&newb, bs * n_blocks * 2);
		if (EFI_ERROR(rc)) {
			Print(L"Could not allocate memory: %r (%d).\n",
			      rc, __LINE__);
			return EFI_OUT_OF_RESOURCES;
		}
		if (b) {
			CopyMem(newb, b, bs * n_blocks);
			free(b, bs * n_blocks);
		}
		b = newb;
		n_blocks *= 2;

		for (; i < n_blocks; i++) {
			EFI_STATUS rc;
			UINTN sz = bs;

			rc = uefi_call_wrapper(fh->Read, 3, fh, &sz, &b[i *bs]);
			if (EFI_ERROR(rc)) {
				free(b, bs * n_blocks);
				Print(L"Could not read file: %r.\n", rc);
				return rc;
			}

			if (sz != bs) {
				*buf_size_out = bs * i + sz;
				*buf_out = b;
				return EFI_SUCCESS;
			}
		}
	}
	return EFI_SUCCESS;
}

static EFI_STATUS
delete_variable(CHAR16 *name, EFI_GUID guid, UINT32 attributes)
{
	return uefi_call_wrapper(RT->SetVariable, 4, name, &guid, attributes,
				 0, NULL);
}

static EFI_STATUS
read_variable(CHAR16 *name, EFI_GUID guid, void **buf_out, UINTN *buf_size_out,
	      UINT32 *attributes_out)
{
	EFI_STATUS rc;
	UINT32 attributes;
	UINTN size = 0;
	void *buf;

	rc = uefi_call_wrapper(RT->GetVariable, 5, name,
			       &guid, &attributes, &size, NULL);
	if (EFI_ERROR(rc)) {
		if (rc == EFI_BUFFER_TOO_SMALL) {
			buf = AllocatePool(size);
			if (!buf) {
				Print(L"Could not allocate memory (%d)\n",
				      __LINE__);
				return EFI_OUT_OF_RESOURCES;
			}
		} else {
			Print(L"Could not get variable \"%s\": %r\n", name, rc);
			return rc;
		}
	} else {
		Print(L"GetVariable(%s) succeeded with size=0.\n", name);
		return EFI_INVALID_PARAMETER;
	}
	rc = uefi_call_wrapper(RT->GetVariable, 5, name, &guid, &attributes,
			       &size, buf);
	if (EFI_ERROR(rc)) {
		Print(L"Could not get variable \"%s\": %r\n", name, rc);
		FreePool(buf);
		return rc;
	}
	*buf_out = buf;
	*buf_size_out = size;
	*attributes_out = attributes;
	return EFI_SUCCESS;
}

static EFI_STATUS
get_info(CHAR16 *name, update_table *info_out)
{
	EFI_STATUS rc;
	update_info *info = NULL;
	UINTN info_size = 0;
	UINT32 attributes = 0;

	rc = read_variable(name, fwupdate_guid, (void **)&info, &info_size,
			   &attributes);
	if (EFI_ERROR(rc))
		return rc;

	if (info_size < sizeof (*info)) {
		Print(L"Update \"%s\" is is too small.\n", name);
		delete_variable(name, fwupdate_guid, attributes);
		return EFI_INVALID_PARAMETER;
	}

	if (info_size - sizeof (EFI_DEVICE_PATH) <= sizeof (*info)) {
		Print(L"Update \"%s\" is cannot have file path.\n", name);
		delete_variable(name, fwupdate_guid, attributes);
		return EFI_INVALID_PARAMETER;
	}

	UINTN is = info_size - EFI_FIELD_OFFSET(update_info, dp);
	EFI_DEVICE_PATH *hdr = (EFI_DEVICE_PATH *)&info->dp;
	UINTN sz = DevicePathSize(hdr);
	if (is != sz) {
		Print(L"Update \"%s\" has an invalid file path (%d %d %d).\n", name, is, sz, info_size);
		delete_variable(name, fwupdate_guid, attributes);
		return EFI_INVALID_PARAMETER;
	}

	info_out->info = info;
	info_out->size = info_size;
	info_out->attributes = attributes;

	return EFI_SUCCESS;
}

static EFI_STATUS
find_updates(UINTN *n_updates_out, update_table ***updates_out)
{
	EFI_STATUS rc;
	update_table **updates = NULL;
	UINTN n_updates = 0;
	UINTN n_updates_allocated = 128;
	EFI_STATUS ret = EFI_OUT_OF_RESOURCES;

#define GNVN_BUF_SIZE 1024
	UINTN variable_name_allocation = GNVN_BUF_SIZE;
	UINTN variable_name_size = 0;
	CHAR16 *variable_name;
	EFI_GUID vendor_guid = empty_guid;

	updates = AllocateZeroPool(sizeof (update_table *) *n_updates_allocated);
	if (!updates) {
		Print(L"Could not allocate memory (%d)\n", __LINE__);
		return EFI_OUT_OF_RESOURCES;
	}

	/* How much do we trust "size of the VariableName buffer" to mean
	 * sizeof(vn) and not sizeof(vn)/sizeof(vn[0]) ? */
	variable_name = AllocateZeroPool(GNVN_BUF_SIZE * 2);

	while (1) {
		variable_name_size = variable_name_allocation;
		rc = uefi_call_wrapper(RT->GetNextVariableName, 3,
				       &variable_name_size, variable_name,
				       &vendor_guid);
		if (rc == EFI_BUFFER_TOO_SMALL) {
			UINTN new_allocation;
			CHAR16 *new_name;

			new_allocation = variable_name_size;
			new_name = AllocatePool(new_allocation * 2);
			if (!new_name)
				goto err;
			CopyMem(new_name, variable_name,
				variable_name_allocation);
			variable_name_allocation = new_allocation;
			FreePool(variable_name);
			variable_name = new_name;
			continue;
		} else if (rc == EFI_NOT_FOUND) {
			break;
		} else if (EFI_ERROR(rc)) {
			Print(L"Could not get variable name: %r.\n", rc);
			ret = rc;
			goto err;
		}

		if (CompareMem(&vendor_guid, &fwupdate_guid,
			       sizeof (vendor_guid))) {
			continue;
		}

		UINTN vns = StrLen(variable_name);
		CHAR16 vn[vns + 1];
		CopyMem(vn, variable_name, vns * sizeof (vn[0]));
		vn[vns] = L'\0';
		Print(L"Found update %s\n", vn);

		if (n_updates == n_updates_allocated) {
			update_table **new_ups;

			new_ups = AllocateZeroPool(sizeof (update_table *) *
						   n_updates_allocated * 2);
			if (!new_ups) {
				Print(L"Tried to allocate %d\n",
				      sizeof (update_table *) * n_updates_allocated * 2);
				Print(L"Could not allocate memory (%d).\n", __LINE__);
				goto err;
			}
			CopyMem(new_ups, updates, sizeof (update_table *) *
						      n_updates_allocated);
			n_updates_allocated *= 2;
			FreePool(updates);
			updates = new_ups;
		}

		updates[n_updates]->name = StrDuplicate(vn);
		rc = get_info(vn, updates[n_updates]);
		if (EFI_ERROR(rc)) {
			ret = rc;
			Print(L"Could not allocate memory (%d).\n", __LINE__);
			goto err;
		}
		if (updates[n_updates]->info->status & FWUPDATE_ATTEMPT_UPDATE){
			EFI_TIME_CAPABILITIES timecaps = { 0, };
			uefi_call_wrapper(RT->GetTime, 2,
				&updates[n_updates]->info->time_attempted,
				&timecaps);
			updates[n_updates]->info->status = FWUPDATE_ATTEMPTED;
			n_updates++;
		} else {
			FreePool(updates[n_updates]->info);
			FreePool(updates[n_updates]);
			updates[n_updates] = NULL;
		}
	}

	*n_updates_out = n_updates;
	*updates_out = updates;

	return EFI_SUCCESS;
err:
	if (variable_name)
		FreePool(variable_name);

	for (int i = 0; i < n_updates && updates[i]; i++)
		FreePool(updates[i]);

	FreePool(updates);

	Print(L"Could not allocate memory (%d).\n", __LINE__);
	return ret;
}

static EFI_STATUS
open_file(EFI_DEVICE_PATH *dp, EFI_FILE_HANDLE *fh)
{
	EFI_DEVICE_PATH *file_dp = dp;
	EFI_GUID sfsp = SIMPLE_FILE_SYSTEM_PROTOCOL;
	EFI_HANDLE device;
	EFI_FILE_IO_INTERFACE *drive;
	EFI_FILE_HANDLE root;
	EFI_STATUS rc;

	rc = uefi_call_wrapper(BS->LocateDevicePath, 3, &sfsp, &file_dp,
			       &device);
	if (EFI_ERROR(rc)) {
		Print(L"Could not locate device handle: %r.\n", rc);
		return rc;
	}

	if (DevicePathType(file_dp) != MEDIA_DEVICE_PATH ||
			DevicePathSubType(file_dp) != MEDIA_FILEPATH_DP) {
		Print(L"Could not find appropriate device.\n");
		return EFI_UNSUPPORTED;
	}

	UINTN sz = *(UINT16 *)file_dp->Length - 4;
	if (sz <= 6 || sz % 2 != 0) {
		Print(L"Invalid file device path.\n");
		return EFI_INVALID_PARAMETER;
	}

	sz /= sizeof (CHAR16);
	CHAR16 filename[sz+1];
	CopyMem(filename, (UINT8 *)file_dp + 4, sz * sizeof (CHAR16));
	filename[sz] = L'\0';

	rc = uefi_call_wrapper(BS->HandleProtocol, 3, device, &sfsp,
			       (void **)&drive);
	if (EFI_ERROR(rc)) {
		Print(L"Could not open device interface: %r.\n", rc);
		return rc;
	}

	rc = uefi_call_wrapper(drive->OpenVolume, 2, drive, &root);
	if (EFI_ERROR(rc)) {
		Print(L"Could not open volume: %r.\n", rc);
		return rc;
	}

	rc = uefi_call_wrapper(root->Open, 5, root, fh, filename,
			       EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(rc)) {
		Print(L"Could not open \"%s\": %r.\n", filename, rc);
		return rc;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS
add_capsule(update_table *update, EFI_CAPSULE_HEADER **capsule_out,
	    EFI_CAPSULE_BLOCK_DESCRIPTOR *cbd_out)
{
	EFI_STATUS rc;
	EFI_FILE_HANDLE fh = NULL;
	UINT8 *fbuf = NULL;
	UINTN fsize = 0;
	EFI_CAPSULE_HEADER *capsule;

	rc = open_file((EFI_DEVICE_PATH *)update->info->dp, &fh);
	if (EFI_ERROR(rc))
	    return rc;

	rc = read_file(fh, &fbuf, &fsize);
	if (EFI_ERROR(rc))
		return rc;

	uefi_call_wrapper(fh->Close, 1, fh);

	if (CompareMem(&update->info->guid, fbuf,
			sizeof (update->info->guid)) == 0 && fsize != 40) {
#if 0
		Print(L"Image has capsule image embedded\n");
		Print(L"updates guid: %g\n", &update->info->guid);
		Print(L"File guid: %g\n", fbuf);
#endif
		cbd_out->Length = fsize;
		cbd_out->Union.DataBlock =
			(EFI_PHYSICAL_ADDRESS)(UINTN)fbuf;
		*capsule_out = (EFI_CAPSULE_HEADER *)fbuf;
		(*capsule_out)->Flags |= update->info->capsule_flags;
	} else {
#if 0
		Print(L"Image does not have embedded header\n");
		Print(L"Allocating %d for capsule header.\n", sizeof (*capsule)+fsize);
#endif
		rc = allocate((void **)&capsule, sizeof (*capsule) + fsize);
		if (EFI_ERROR(rc)) {
			Print(L"Could not allocate space for update: %r.\n",rc);
			return EFI_OUT_OF_RESOURCES;
		}
		capsule->CapsuleGuid = update->info->guid;
		capsule->HeaderSize = sizeof (*capsule);
		capsule->Flags = update->info->capsule_flags;
		capsule->CapsuleImageSize = fsize + sizeof (*capsule);

		UINT8 *buffer = (UINT8 *)capsule + capsule->HeaderSize;
		CopyMem(buffer, fbuf, fsize);
		cbd_out->Length = capsule->CapsuleImageSize;
		cbd_out->Union.DataBlock =
			(EFI_PHYSICAL_ADDRESS)(UINTN)capsule;
		*capsule_out = capsule;
		free(fbuf, fsize);
	}

	return EFI_SUCCESS;
}


static EFI_STATUS
apply_capsules(EFI_CAPSULE_HEADER **capsules,
	       EFI_CAPSULE_BLOCK_DESCRIPTOR *cbd,
	       UINTN num_updates)
{
	EFI_RESET_TYPE reset;
	UINT64 max_capsule_size;
	EFI_STATUS rc;

	rc = uefi_call_wrapper(RT->QueryCapsuleCapabilities, 4, capsules,
				num_updates, &max_capsule_size, &reset);
#if 0
	Print(L"QueryCapsuleCapabilities: %r max: %ld reset:%d\n",
		rc, max_capsule_size, reset);
	Print(L"Capsules: %d\n", num_updates);
#endif

	uefi_call_wrapper(BS->Stall, 1, 1000000);
	rc = uefi_call_wrapper(RT->UpdateCapsule, 3, capsules, num_updates,
			       (EFI_PHYSICAL_ADDRESS)(VOID *)cbd);
	if (EFI_ERROR(rc)) {
		Print(L"Could not apply capsule update: %r\n", rc);
		return rc;
	}

	return EFI_SUCCESS;
}

static
EFI_STATUS
set_statuses(UINTN n_updates, update_table **updates)
{
	EFI_STATUS rc;
	for (UINTN i = 0; i < n_updates; i++) {
		rc = uefi_call_wrapper(RT->SetVariable, 5, updates[i]->name,
				       &fwupdate_guid, updates[i]->attributes,
				       updates[i]->size, updates[i]->info);
		if (EFI_ERROR(rc)) {
			Print(L"%a:%a():%d: Could not update variable "
			      L"status for \"%s\": %r\n",
			      __FILE__, __func__, __LINE__,
			      updates[i]->name, rc);
			return rc;
		}
	}
	return EFI_SUCCESS;
}

EFI_GUID SHIM_LOCK_GUID =
 {0x605dab50,0xe046,0x4300,{0xab,0xb6,0x3d,0xd8,0x10,0xdd,0x8b,0x23}};

static void
__attribute__((__optimize__("0")))
debug_hook(void)
{
	EFI_GUID guid = SHIM_LOCK_GUID;
	UINT8 *data = NULL;
	UINTN data_size = 0;
	EFI_STATUS efi_status;
	UINT32 attributes;
	volatile register int x = 0;
	extern char _text, _data;

	efi_status = read_variable(L"SHIM_DEBUG", guid, (void **)&data,
				   &data_size, &attributes);
	if (EFI_ERROR(efi_status)) {
		return;
	}

	if (x)
		return;

	x = 1;
	Print(L"add-symbol-file "DEBUGDIR
	      L"fwupdate.debug %p -s .data %p\n", &_text,
	      &_data);
}

EFI_STATUS
efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS rc;
	update_table **updates = NULL;
	UINTN n_updates = 0;

	InitializeLib(image, systab);

	/*
	 * if SHIM_DEBUG is set, print info for our attached debugger.
	 */
	debug_hook();

	rc = find_updates(&n_updates, &updates);
	if (EFI_ERROR(rc)) {
		Print(L"fwupdate: Could not find updates: %r\n", rc);
		return rc;
	}
	if (n_updates == 0) {
		Print(L"fwupdate: called in error?\n");
		return EFI_INVALID_PARAMETER;
	}

	EFI_CAPSULE_HEADER *capsules[n_updates + 1];
	EFI_CAPSULE_BLOCK_DESCRIPTOR *cbd_data;
	UINTN i;
	rc = allocate((void **)&cbd_data,
		      sizeof (EFI_CAPSULE_BLOCK_DESCRIPTOR)*(n_updates+1));
	if (EFI_ERROR(rc)) {
		Print(L"fwupdate: Could not allocate memory (%d)\n", __LINE__);
		return rc;
	}
	for (i = 0; i < n_updates; i++) {
		rc = add_capsule(updates[i], &capsules[i], &cbd_data[i]);
		if (EFI_ERROR(rc)) {
			Print(L"fwupdate: Could not build update list: %r\n",
			      rc);
			return rc;
		}
	}

	cbd_data[i].Length = 0;
	cbd_data[i].Union.ContinuationPointer = 0;

	rc = set_statuses(n_updates, updates);
	if (EFI_ERROR(rc)) {
		Print(L"fwupdate: Could not set update status: %r\n", rc);
		return rc;
	}

	rc = apply_capsules(capsules, cbd_data, n_updates);
	if (EFI_ERROR(rc)) {
		Print(L"fwupdate: Could not apply capsules: %r\n", rc);
		return rc;
	}

	Print(L"Reset System\n");
	uefi_call_wrapper(BS->Stall, 1, 2000000);
	uefi_call_wrapper(RT->ResetSystem, 4, EfiResetWarm, EFI_SUCCESS, 0, NULL);

	return EFI_SUCCESS;
}
