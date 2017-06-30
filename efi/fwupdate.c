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

static int debugging;

#define SECONDS 1000000

/*
 * I'm not actually sure when these appear, but they're present in the
 * version in front of me.
 */
#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#if __GNUC__ >= 5 && __GNUC_MINOR__ >= 1
#define uintn_mult(a, b, c) __builtin_mul_overflow(a, b, c)
#endif
#endif
#ifndef uintn_mult
#define uintn_mult(a, b, c) ({					\
		const UINTN _limit = ~0UL;			\
		int _ret = 1;					\
		if ((a) != 0 && (b) != 0) {			\
			_ret = _limit / (a) < (b);		\
		}						\
		if (!_ret)					\
			*(c) = ((a) * (b));			\
		_ret;						\
	})
#endif

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
	EFI_ALLOCATE_TYPE type = AllocateAnyPages;

	if (sizeof (VOID *) == 4) {
		pageaddr = 0xffffffffULL - 8192;
		type = AllocateMaxAddress;
	}

	rc = uefi_call_wrapper(BS->AllocatePages, 4, type,
			       EfiLoaderData, pages,
			       &pageaddr);
	if (EFI_ERROR(rc))
		return rc;
	if (sizeof (VOID *) == 4 && pageaddr > 0xffffffffULL) {
		uefi_call_wrapper(BS->FreePages, 2, pageaddr, pages);
		Print(L"Got bad allocation at 0x%016x\n", (UINT64)pageaddr);
		return EFI_OUT_OF_RESOURCES;
	}
	*addr = (void *)(UINTN)pageaddr;
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

	rc = uefi_call_wrapper(BS->FreePages, 2,
			       (EFI_PHYSICAL_ADDRESS)(UINTN)addr,
			       pages);
	return rc;
}

EFI_STATUS
read_file(EFI_FILE_HANDLE fh, UINT8 **buf_out, UINTN *buf_size_out)
{
	UINT8 *b = NULL;
	const UINTN bs = 512;
	UINTN n_blocks = 4096;
	UINTN i = 0;
	EFI_STATUS rc;

	while (1) {
		void *newb = NULL;
		UINTN news = 0;
		if (uintn_mult(bs * 2, n_blocks, &news)) {
			if (b)
				free(b, bs * n_blocks);
			Print(L"%a:%a():%d: allocation %d * %d would overflow size\n",
			      __FILE__, __func__, __LINE__, bs * 2, n_blocks);
			return EFI_OUT_OF_RESOURCES;
		}
		rc = allocate(&newb, news);
		if (EFI_ERROR(rc)) {
			Print(L"%a:%a():%d: Tried to allocate %d\n",
			      __FILE__, __func__, __LINE__,
			      bs * n_blocks * 2);
			Print(L"Could not allocate memory.\n");
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

			rc = uefi_call_wrapper(fh->Read, 3, fh, &sz,
					       &b[i * bs]);
			if (EFI_ERROR(rc)) {
				free(b, bs * n_blocks);
				Print(L"%a:%a():%d: Could not read file: %r\n",
				      __FILE__, __func__, __LINE__, rc);
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
	void *buf = NULL;

	rc = uefi_call_wrapper(RT->GetVariable, 5, name,
			       &guid, &attributes, &size, NULL);
	if (EFI_ERROR(rc)) {
		if (rc == EFI_BUFFER_TOO_SMALL) {
			buf = AllocatePool(size);
			if (!buf) {
				Print(L"%a:%a():%d: Tried to allocate %d\n",
				      __FILE__, __func__, __LINE__, size);
				Print(L"Could not allocate memory.\n");
				return EFI_OUT_OF_RESOURCES;
			}
		} else if (rc != EFI_NOT_FOUND) {
			Print(L"%a:%a():%d: "
			      L"Could not get variable \"%s\": %r\n",
			      __FILE__, __func__, __LINE__, name, rc);
			return rc;
		}
	} else {
		Print(L"%a:%a():%d: "
		      L"GetVariable(%s) succeeded with size=0.\n",
		      __FILE__, __func__, __LINE__, name);
		return EFI_INVALID_PARAMETER;
	}
	rc = uefi_call_wrapper(RT->GetVariable, 5, name, &guid, &attributes,
			       &size, buf);
	if (EFI_ERROR(rc)) {
		Print(L"%a:%a():%d: Could not get variable \"%s\": %r\n",
		      __FILE__, __func__, __LINE__, name, rc);
		FreePool(buf);
		return rc;
	}
	*buf_out = buf;
	*buf_size_out = size;
	*attributes_out = attributes;
	return EFI_SUCCESS;
}

static INTN
dp_size(EFI_DEVICE_PATH *dp, INTN limit)
{
	INTN ret = 0;
	while (1) {
		if (limit < 4)
			break;
		INTN nodelen = DevicePathNodeLength(dp);
		if (nodelen > limit)
			break;
		limit -= nodelen;
		ret += nodelen;

		if (IsDevicePathEnd(dp))
			return ret;
		dp = NextDevicePathNode(dp);
	}
	return -1;
}

static EFI_STATUS
get_info(CHAR16 *name, update_table *info_out)
{
	EFI_STATUS rc;
	update_info *info = NULL;
	UINTN info_size = 0;
	UINT32 attributes = 0;
	void *info_ptr = NULL;

	rc = read_variable(name, fwupdate_guid, &info_ptr, &info_size,
			   &attributes);
	if (EFI_ERROR(rc))
		return rc;
	info = (update_info *)info_ptr;

	if (info_size < sizeof (*info)) {
		Print(L"Update \"%s\" is is too small.\n", name);
		delete_variable(name, fwupdate_guid, attributes);
		return EFI_INVALID_PARAMETER;
	}

	if (info_size - sizeof (EFI_DEVICE_PATH) <= sizeof (*info)) {
		Print(L"Update \"%s\" is malformed, "
		      L"and cannot hold a file path.\n", name);
		delete_variable(name, fwupdate_guid, attributes);
		return EFI_INVALID_PARAMETER;
	}

	EFI_DEVICE_PATH *hdr = (EFI_DEVICE_PATH *)&info->dp;
	INTN is = EFI_FIELD_OFFSET(update_info, dp);
	if (is > (INTN)info_size) {
		Print(L"Update \"%s\" has an invalid file path.\n"
		      L"Device path offset is %d, but total size is %d\n",
		      name, is, info_size);
		delete_variable(name, fwupdate_guid, attributes);
		return EFI_INVALID_PARAMETER;
	}

	is = info_size - is;
	INTN sz = dp_size(hdr, info_size);
	if (sz < 0 || is < 0) {
invalid_size:
		Print(L"Update \"%s\" has an invalid file path.\n"
		      L"update info size: %d dp size: %d size for dp: %d\n",
		      name, info_size, sz, is);
		delete_variable(name, fwupdate_guid, attributes);
		return EFI_INVALID_PARAMETER;
	}
	if (is > (INTN)info_size)
		goto invalid_size;
	if (is != sz)
		goto invalid_size;

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
	UINTN mult_res;

	if (uintn_mult(sizeof (update_table *), n_updates_allocated,
			&mult_res)) {
		Print(L"%a:%a():%d: allocation %d * %d would overflow size\n",
		      __FILE__, __func__, __LINE__,
		      sizeof (update_table *), n_updates_allocated);
		return EFI_OUT_OF_RESOURCES;
	}

	updates = AllocateZeroPool(mult_res);
	if (!updates) {
		Print(L"%a:%a():%d: Tried to allocate %d\n",
		      __FILE__, __func__, __LINE__, mult_res);
		Print(L"Could not allocate memory.\n");
		return EFI_OUT_OF_RESOURCES;
	}

	/* How much do we trust "size of the VariableName buffer" to mean
	 * sizeof(vn) and not sizeof(vn)/sizeof(vn[0]) ? */
	variable_name = AllocateZeroPool(GNVN_BUF_SIZE * 2);
	if (!variable_name) {
		Print(L"%a:%a():%d: Tried to allocate %d\n",
		      __FILE__, __func__, __LINE__,
		      GNVN_BUF_SIZE * 2);
		Print(L"Could not allocate memory.\n");
		FreePool(updates);
		return EFI_OUT_OF_RESOURCES;
	}

	while (1) {
		variable_name_size = variable_name_allocation;
		rc = uefi_call_wrapper(RT->GetNextVariableName, 3,
				       &variable_name_size, variable_name,
				       &vendor_guid);
		if (rc == EFI_BUFFER_TOO_SMALL) {
			/* If we don't have a big enough buffer to hold the
			 * name, allocate a bigger one and try again */
			UINTN new_allocation;
			CHAR16 *new_name;

			new_allocation = variable_name_size;
			if (uintn_mult(new_allocation, 2, &mult_res)) {
				Print(L"%a:%a():%d: %d * 2 would overflow size\n",
				      __FILE__, __func__, __LINE__,
				      new_allocation);
				ret = EFI_OUT_OF_RESOURCES;
				goto err;
			}
			new_name = AllocatePool(new_allocation * 2);
			if (!new_name) {
				Print(L"%a:%a():%d: Tried to allocate %d\n",
				      __FILE__, __func__, __LINE__,
				      new_allocation * 2);
				Print(L"Could not allocate memory.\n");
				ret = EFI_OUT_OF_RESOURCES;
				goto err;
			}
			CopyMem(new_name, variable_name,
				variable_name_allocation);
			variable_name_allocation = new_allocation;
			FreePool(variable_name);
			variable_name = new_name;
			continue;
		} else if (rc == EFI_NOT_FOUND) {
			break;
		} else if (EFI_ERROR(rc)) {
			Print(L"%a:%a():%d: "
			      L"Could not get variable name: %r\n",
			      __FILE__, __func__, __LINE__, rc);
			ret = rc;
			goto err;
		}

		/*
		 * If it's not one of our state variables, keep going.
		 */
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
			UINTN mul_a, mul_b;
			if (uintn_mult(n_updates_allocated, 2, &mult_res)) {
				mul_a = n_updates_allocated;
				mul_b = 2;
mult_err:
				Print(L"%a:%a():%d: allocation %d * %d would overflow size\n",
				      __FILE__, __func__, __LINE__,
				      mul_a, mul_b);
				ret = EFI_OUT_OF_RESOURCES;
				goto err;
			}
			if (uintn_mult(mult_res, sizeof (update_table *),
					&mult_res)) {
				mul_a = mult_res;
				mul_b = sizeof (update_table *);
				goto mult_err;
			}

			new_ups = AllocateZeroPool(mult_res);
			if (!new_ups) {
				Print(L"%a:%a():%d: Tried to allocate %d\n",
				      __FILE__, __func__, __LINE__, mult_res);
				Print(L"Could not allocate memory.\n");
				ret = EFI_OUT_OF_RESOURCES;
				goto err;
			}
			CopyMem(new_ups, updates, mult_res);
			n_updates_allocated *= 2;
			FreePool(updates);
			updates = new_ups;
		}

		update_table *update = AllocatePool(sizeof (update_table));
		if (!update) {
			Print(L"%a:%a():%d: Tried to allocate %d\n",
			      __FILE__, __func__, __LINE__,
			      sizeof (update_table));
			ret = EFI_OUT_OF_RESOURCES;
			goto err;
		}

		update->name = StrDuplicate(vn);
		if (!update->name) {
			Print(L"%a:%a():%d: Tried to allocate %d\n",
			      __FILE__, __func__, __LINE__,
			      StrSize(vn));
			ret = EFI_OUT_OF_RESOURCES;
			FreePool(update);
			goto err;
		}

		rc = get_info(vn, update);
		if (EFI_ERROR(rc)) {
			Print(L"Could not get update info for \"%s\", "
			      L"aborting.\n", vn);
			ret = rc;
			FreePool(update->name);
			FreePool(update);
			goto err;
		}
		if (update->info->status & FWUPDATE_ATTEMPT_UPDATE) {
			EFI_TIME_CAPABILITIES timecaps = { 0, };

			uefi_call_wrapper(RT->GetTime, 2,
					  &update->info->time_attempted,
					  &timecaps);
			update->info->status = FWUPDATE_ATTEMPTED;
			updates[n_updates++] = update;
		} else {
			FreePool(update->info);
			FreePool(update->name);
			FreePool(update);
		}
	}

	FreePool(variable_name);

	*n_updates_out = n_updates;
	*updates_out = updates;

	return EFI_SUCCESS;
err:
	FreePool(variable_name);

	for (unsigned int i = 0; i < n_updates; i++) {
		FreePool(updates[i]->name);
		FreePool(updates[i]->info);
		FreePool(updates[i]);
	}

	FreePool(updates);
	return ret;
}

static EFI_STATUS
search_file(EFI_DEVICE_PATH **file_dp, EFI_FILE_HANDLE *fh)
{
	EFI_DEVICE_PATH *dp, *parent_dp;
	EFI_GUID sfsp = SIMPLE_FILE_SYSTEM_PROTOCOL;
	EFI_GUID dpp = DEVICE_PATH_PROTOCOL;
	EFI_FILE_HANDLE *devices;
	UINTN i, n_handles, count;
	EFI_STATUS rc;

	rc = uefi_call_wrapper(BS->LocateHandleBuffer, 5, ByProtocol, &sfsp,
			       NULL, &n_handles, (EFI_HANDLE **)&devices);
	if (EFI_ERROR(rc)) {
		Print(L"Could not find handles.\n");
		return rc;
	}

	dp = *file_dp;

	if (debugging)
		Print(L"Searching Device Path: %s ...\n", DevicePathToStr(dp));

	parent_dp = DuplicateDevicePath(dp);
	if (!parent_dp) {
		rc = EFI_INVALID_PARAMETER;
		goto out;
	}

	dp = parent_dp;
	count = 0;
	while (1) {
		if (IsDevicePathEnd(dp)) {
			rc = EFI_INVALID_PARAMETER;
			goto out;
		}

		if (DevicePathType(dp) == MEDIA_DEVICE_PATH &&
		    DevicePathSubType(dp) == MEDIA_FILEPATH_DP)
			break;

		dp = NextDevicePathNode(dp);
		++count;
	}

	SetDevicePathEndNode(dp);

	if (debugging)
		Print(L"Device Path prepared: %s\n",
		      DevicePathToStr(parent_dp));

	for (i = 0; i < n_handles; i++) {
		EFI_DEVICE_PATH *path;

		rc = uefi_call_wrapper(BS->HandleProtocol, 3, devices[i], &dpp,
				       (void **)&path);
		if (EFI_ERROR(rc))
			continue;

		if (debugging)
			Print(L"Device supporting SFSP: %s\n",
			      DevicePathToStr(path));

		rc = EFI_UNSUPPORTED;
		while (!IsDevicePathEnd(path)) {
			if (debugging)
				Print(L"Comparing: %s and %s\n",
				      DevicePathToStr(parent_dp),
				      DevicePathToStr(path));

			if (LibMatchDevicePaths(path, parent_dp) == TRUE) {
				*fh = devices[i];
				for (i = 0; i < count; i++)
					*file_dp = NextDevicePathNode(*file_dp);
				rc = EFI_SUCCESS;

				if (debugging)
					Print(L"Match up! Returning %s\n",
					      DevicePathToStr(*file_dp));

				goto out;
			}

			path = NextDevicePathNode(path);
		}
	}

out:
	if (!EFI_ERROR(rc))
		Print(L"File %s searched\n", DevicePathToStr(*file_dp));

	uefi_call_wrapper(BS->FreePool, 1, devices);
	return rc;
}

static EFI_STATUS
open_file(EFI_DEVICE_PATH *dp, EFI_FILE_HANDLE *fh)
{
	EFI_DEVICE_PATH *file_dp = dp;
	EFI_GUID sfsp = SIMPLE_FILE_SYSTEM_PROTOCOL;
	EFI_FILE_HANDLE device;
	EFI_FILE_IO_INTERFACE *drive;
	EFI_FILE_HANDLE root;
	EFI_STATUS rc;

	rc = uefi_call_wrapper(BS->LocateDevicePath, 3, &sfsp, &file_dp,
			       (EFI_HANDLE *)&device);
	if (EFI_ERROR(rc)) {
		rc = search_file(&file_dp, &device);
		if (EFI_ERROR(rc)) {
			Print(L"%a:%a():%d: Could not locate device handle: %r\n",
				      __FILE__, __func__, __LINE__, rc);
			return rc;
		}
	}

	if (DevicePathType(file_dp) != MEDIA_DEVICE_PATH ||
			DevicePathSubType(file_dp) != MEDIA_FILEPATH_DP) {
		Print(L"%a:%a():%d: Could not find appropriate device.\n",
			      __FILE__, __func__, __LINE__);
		return EFI_UNSUPPORTED;
	}

	UINT16 sz16;
	UINTN sz;
	CopyMem(&sz16, &file_dp->Length[0], sizeof(sz16));
	sz = sz16;
	sz -= 4;
	if (sz <= 6 || sz % 2 != 0) {
		Print(L"%a:%a():%d: Invalid file device path.\n",
			      __FILE__, __func__, __LINE__);
		return EFI_INVALID_PARAMETER;
	}

	sz /= sizeof (CHAR16);
	/*
	 * check against some arbitrary limit to avoid having a stack
	 * overflow here.
	 */
	if (sz > 1024) {
		Print(L"%a:%a():%d: Invalid file device path.\n",
			      __FILE__, __func__, __LINE__);
		return EFI_INVALID_PARAMETER;
	}
	CHAR16 filename[sz+1];
	CopyMem(filename, (UINT8 *)file_dp + 4, sz * sizeof (CHAR16));
	filename[sz] = L'\0';

	rc = uefi_call_wrapper(BS->HandleProtocol, 3, device, &sfsp,
			       (void **)&drive);
	if (EFI_ERROR(rc)) {
		Print(L"%a:%a():%d: Could not open device interface: %r.\n",
			      __FILE__, __func__, __LINE__, rc);
		return rc;
	}

	rc = uefi_call_wrapper(drive->OpenVolume, 2, drive, &root);
	if (EFI_ERROR(rc)) {
		Print(L"%a:%a():%d: Could not open volume: %r.\n",
			      __FILE__, __func__, __LINE__, rc);
		return rc;
	}

	rc = uefi_call_wrapper(root->Open, 5, root, fh, filename,
			       EFI_FILE_MODE_READ, 0);
	if (EFI_ERROR(rc)) {
		Print(L"%a:%a():%d: Could not open file \"%s\": %r.\n",
			      __FILE__, __func__, __LINE__, filename, rc);
		return rc;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS
delete_boot_order(CHAR16 *name, EFI_GUID guid)
{

	UINTN i;
	UINT16 boot_num;
	EFI_STATUS rc;
	UINTN info_size = 0;
	UINT32 attributes = 0;
	void *info_ptr = NULL;
	UINT16 *new_info_ptr = NULL;
	BOOLEAN num_found = FALSE;
	UINTN new_list_num = 0;

	/* get boot hex number */
	boot_num = xtoi((CHAR16 *)((UINT8 *)name + sizeof(L"Boot")));

	rc = read_variable(L"BootOrder", guid, &info_ptr, &info_size,
					&attributes);
	if (EFI_ERROR(rc))
		return rc;

	new_info_ptr = AllocatePool(info_size);
	if (!new_info_ptr) {
		Print(L"%a:%a():%d: Tried to allocate %d\n",
			__FILE__, __func__, __LINE__, info_size);
		Print(L"Could not allocate memory.\n");
		FreePool(info_ptr);
		return EFI_OUT_OF_RESOURCES;
	}

	for (i = 0; i < (info_size / sizeof(UINT16)) ; i++) {
		if (((UINT16 *)info_ptr)[i] != boot_num) {
			new_info_ptr[i] = ((UINT16 *)info_ptr)[i];
			new_list_num++;

		} else {
			num_found = TRUE;
		}
	}

	/* if not in the BootOrder list, do not update BootOrder */
	if (!num_found) {
		rc = EFI_SUCCESS;
		goto out;
	}

	rc = uefi_call_wrapper(RT->SetVariable, 5, L"BootOrder", &guid,
				attributes, new_list_num * sizeof(UINT16),
				new_info_ptr);
	if (EFI_ERROR(rc)) {
		Print(L"%a:%a():%d: Could not update variable "
			L"status for \"%s\": %r\n",
			__FILE__, __func__, __LINE__, name, rc);
		goto out;
	}

out:

	FreePool(info_ptr);
	FreePool(new_info_ptr);

	return rc;
}

static EFI_STATUS
delete_boot_entry(void)
{
	EFI_STATUS rc;

	UINTN variable_name_allocation = GNVN_BUF_SIZE;
	UINTN variable_name_size = 0;
	CHAR16 *variable_name;
	EFI_GUID vendor_guid = empty_guid;
	UINTN mult_res;
	EFI_STATUS ret = EFI_OUT_OF_RESOURCES;

	variable_name = AllocateZeroPool(GNVN_BUF_SIZE * 2);
	if (!variable_name) {
		Print(L"%a:%a():%d: Tried to allocate %d\n",
		      __FILE__, __func__, __LINE__,
		      GNVN_BUF_SIZE * 2);
		Print(L"Could not allocate memory.\n");
		return EFI_OUT_OF_RESOURCES;
	}

	while (1) {
		variable_name_size = variable_name_allocation;
		rc = uefi_call_wrapper(RT->GetNextVariableName, 3,
				       &variable_name_size, variable_name,
				       &vendor_guid);
		if (rc == EFI_BUFFER_TOO_SMALL) {

			UINTN new_allocation;
			CHAR16 *new_name;

			new_allocation = variable_name_size;
			if (uintn_mult(new_allocation, 2, &mult_res)) {
				Print(L"%a:%a():%d: %d * 2 would overflow size\n",
				      __FILE__, __func__, __LINE__,
				      new_allocation);
				ret = EFI_OUT_OF_RESOURCES;
				goto err;
			}
			new_name = AllocatePool(new_allocation * 2);
			if (!new_name) {
				Print(L"%a:%a():%d: Tried to allocate %d\n",
				      __FILE__, __func__, __LINE__,
				      new_allocation * 2);
				Print(L"Could not allocate memory.\n");
				ret = EFI_OUT_OF_RESOURCES;
				goto err;
			}
			CopyMem(new_name, variable_name,
				variable_name_allocation);
			variable_name_allocation = new_allocation;
			FreePool(variable_name);
			variable_name = new_name;
			continue;
		} else if (rc == EFI_NOT_FOUND) {
			break;
		} else if (EFI_ERROR(rc)) {
			Print(L"%a:%a():%d: "
			      L"Could not get variable name: %r\n",
			      __FILE__, __func__, __LINE__, rc);
			ret = rc;
			goto err;
		}

		/* check if the variable name is Boot#### */
		UINTN vns = StrLen(variable_name);
		if (vns == 8 && CompareMem(variable_name, L"Boot", 8) == 0) {
			UINTN info_size = 0;
			UINT32 attributes = 0;
			void *info_ptr = NULL;
			CHAR16 *load_op_description = NULL;

			rc = read_variable(variable_name, vendor_guid, &info_ptr,
				&info_size, &attributes);
			if (EFI_ERROR(rc)) {
				ret = rc;
				goto err;
			}

			/*
			 * check if the boot path created by fwupdate,
			 * check with EFI_LOAD_OPTION decription
			 */
			load_op_description = (CHAR16 *)((UINT8 *)info_ptr +
				sizeof(UINT32) + sizeof(UINT16));

			if (CompareMem(load_op_description,
					L"Linux-Firmware-Updater",
					sizeof (L"Linux-Firmware-Updater") - 2)
					 == 0) {
				rc = delete_variable(variable_name, vendor_guid,
						attributes);

				if (EFI_ERROR(rc)) {
					Print(L"fail to delete Linux-Firmware-"
						L"Updater boot path.\n");
					FreePool(info_ptr);
					ret = rc;
					goto out;
				}

				/* delete the boot path from BootOrder list */
				rc = delete_boot_order(variable_name,
								vendor_guid);

				if (EFI_ERROR(rc)) {
					Print(L"fail to delete the boot path "
						L"from BootOrder boot path.\n");
					FreePool(info_ptr);
					ret = rc;
					goto out;
				}
			}

			FreePool(info_ptr);
		}
	}

out:
	FreePool(variable_name);
	return EFI_SUCCESS;

err:
	FreePool(variable_name);

	return ret;
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

	rc = open_file((EFI_DEVICE_PATH *)update->info->dp_buf, &fh);
	if (EFI_ERROR(rc))
		return rc;

	rc = read_file(fh, &fbuf, &fsize);
	if (EFI_ERROR(rc))
		return rc;

	uefi_call_wrapper(fh->Close, 1, fh);

	/*
	 * See if it has the capsule header, and if not, add one.
	 *
	 * Unfortunately there's not a good way to do this, so we're just
	 * checking if the capsule has the fw_class guid at the right place.
	 */
	if (CompareMem(&update->info->guid, fbuf,
			sizeof (update->info->guid)) == 0 &&
	    /*
	     * We're ignoring things that are 40 bytes here, because that's
	     * the size of the variables used in the test code I wrote for
	     * edk2 - It's basically a capsule header with no payload, so
	     * there's nothing real it can do anyway.
	     *
	     * At some point I'll update that to be slightly different and
	     * take the exception out, but it's not pressing.
	     */
	    fsize != 40) {
		if (debugging) {
			Print(L"Image has capsule image embedded\n");
			Print(L"updates guid: %g\n", &update->info->guid);
			Print(L"File guid: %g\n", fbuf);
		}
		cbd_out->Length = fsize;
		cbd_out->Union.DataBlock =
			(EFI_PHYSICAL_ADDRESS)(UINTN)fbuf;
		*capsule_out = (EFI_CAPSULE_HEADER *)fbuf;
		(*capsule_out)->Flags |= update->info->capsule_flags |
			CAPSULE_FLAGS_PERSIST_ACROSS_RESET |
			CAPSULE_FLAGS_INITIATE_RESET;
	} else {
		if (debugging) {
			Print(L"Image does not have embedded header\n");
			Print(L"Allocating %d for capsule header.\n",
			      sizeof (*capsule)+fsize);
		}
		rc = allocate((void **)&capsule, sizeof (*capsule) + fsize);
		if (EFI_ERROR(rc)) {
			Print(L"%a:%a():%d: Tried to allocate %d\n",
			      __FILE__, __func__, __LINE__,
			      sizeof (*capsule) + fsize);
			Print(L"Could not allocate space for update: %r.\n",rc);
			return EFI_OUT_OF_RESOURCES;
		}
		capsule->CapsuleGuid = update->info->guid;
		capsule->HeaderSize = sizeof (*capsule);
		capsule->Flags = update->info->capsule_flags |
			CAPSULE_FLAGS_PERSIST_ACROSS_RESET |
			CAPSULE_FLAGS_INITIATE_RESET;
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
	       UINTN num_updates, EFI_RESET_TYPE *reset)
{
	UINT64 max_capsule_size;
	EFI_STATUS rc;

	rc = delete_boot_entry();
	if (EFI_ERROR(rc)) {
		/*
		 * Print out deleting boot entry error, but still try to apply
		 * capsule.
		 */
		Print(L"%a:%a():%d: Could not delete boot entry: %r\n",
			      __FILE__, __func__, __LINE__, rc);
	}

	rc = uefi_call_wrapper(RT->QueryCapsuleCapabilities, 4, capsules,
				num_updates, &max_capsule_size, reset);
	if (debugging) {
		Print(L"QueryCapsuleCapabilities: %r max: %ld reset:%d\n",
		      rc, max_capsule_size, *reset);
		Print(L"Capsules: %d\n", num_updates);
	}

	uefi_call_wrapper(BS->Stall, 1, 1 * SECONDS);
	rc = uefi_call_wrapper(RT->UpdateCapsule, 3, capsules, num_updates,
			       (EFI_PHYSICAL_ADDRESS)(UINTN)cbd);
	if (EFI_ERROR(rc)) {
		Print(L"%a:%a():%d: Could not apply capsule update: %r\n",
			      __FILE__, __func__, __LINE__, rc);
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
	UINTN data = 0;
	UINTN data_size = 1;
	EFI_STATUS efi_status;
	UINT32 attributes;
	register volatile int x = 0;
	extern char _text, _data;

	/*
	 * If SHIM_DEBUG is set, we're going to assume shim has done whatever
	 * is needed to get a debugger attached, and we just need to explain
	 * who and where we are, and also enable our debugging output.
	 */
	efi_status = uefi_call_wrapper(RT->GetVariable, 5, L"SHIM_DEBUG",
				       &guid, &attributes,  &data_size, &data);
	if (EFI_ERROR(efi_status) || data != 1) {
		efi_status = uefi_call_wrapper(RT->GetVariable, 5,
					       L"FWUPDATE_VERBOSE",
					       &fwupdate_guid, &attributes,
					       &data_size, &data);
		if (EFI_ERROR(efi_status) || data != 1) {
			return;
		}
		debugging = 1;
		return;
	}

	debugging = 1;
	if (x)
		return;

	x = 1;
	Print(L"add-symbol-file "DEBUGDIR
	      L"fwupdate.efi.debug %p -s .data %p\n",
	      &_text, &_data);
}

EFI_STATUS
efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS rc;
	update_table **updates = NULL;
	UINTN n_updates = 0;
	EFI_RESET_TYPE reset_type = EfiResetWarm;

	InitializeLib(image, systab);

	/*
	 * if SHIM_DEBUG is set, print info for our attached debugger.
	 */
	debug_hook();

	/*
	 * Basically the workflow here is:
	 * 1) find and validate any update state variables with the right GUID
	 * 2) allocate our capsule data structures and add the capsules
	 *    #1 described
	 * 3) update status variables
	 * 4) apply the capsule updates
	 * 5) reboot
	 */

	/*
	 * Step 1: find and validate update state variables
	 */
	/* XXX TODO:
	 * 1) survey the reset types first, and separate into groups
	 *    according to them
	 * 2) if there's more than one, mirror BootCurrent back into BootNext
	 *    so we can do multiple runs
	 * 3) only select the ones from one type for the first go
	 */
	rc = find_updates(&n_updates, &updates);
	if (EFI_ERROR(rc)) {
		Print(L"fwupdate: Could not find updates: %r\n", rc);
		return rc;
	}
	if (n_updates == 0) {
		Print(L"fwupdate: No updates to process.  Called in error?\n");
		return EFI_INVALID_PARAMETER;
	}

	/*
	 * Step 2: Build our data structure and add the capsules to it.
	 */
	EFI_CAPSULE_HEADER *capsules[n_updates + 1];
	EFI_CAPSULE_BLOCK_DESCRIPTOR *cbd_data;
	UINTN i;
	rc = allocate((void **)&cbd_data,
		      sizeof (EFI_CAPSULE_BLOCK_DESCRIPTOR)*(n_updates+1));
	if (EFI_ERROR(rc)) {
		Print(L"%a:%a():%d: Tried to allocate %d\n",
		      __FILE__, __func__, __LINE__,
		      sizeof (EFI_CAPSULE_BLOCK_DESCRIPTOR)*(n_updates+1));
		Print(L"fwupdate: Could not allocate memory: %r.\n",rc);
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

	/*
	 * Step 3: update the state variables.
	 */
	rc = set_statuses(n_updates, updates);
	if (EFI_ERROR(rc)) {
		Print(L"fwupdate: Could not set update status: %r\n", rc);
		return rc;
	}

	/*
	 * Step 4: apply the capsules.
	 */
	rc = apply_capsules(capsules, cbd_data, n_updates, &reset_type);
	if (EFI_ERROR(rc)) {
		Print(L"fwupdate: Could not apply capsules: %r\n", rc);
		return rc;
	}

	/*
	 * Step 5: if #4 didn't reboot us, do it manually.
	 */
	if (debugging) {
		Print(L"Reset System\n");
		uefi_call_wrapper(BS->Stall, 1, 5 * SECONDS);
	}
	uefi_call_wrapper(BS->Stall, 1, 5 * SECONDS);
	uefi_call_wrapper(RT->ResetSystem, 4, reset_type, EFI_SUCCESS,
			  0, NULL);

	return EFI_SUCCESS;
}
