/*
 * libfw - library interface to apply firmware updates
 *
 * Copyright 2015 Red Hat, Inc.
 *
 * See "COPYING" for license terms.
 *
 * Author: Peter Jones <pjones@redhat.com>
 */

#include <dirent.h>
#include <efiboot.h>
#include <efivar.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define EFI_TIME efi_time_t

#include <fwup.h>
#include "util.h"
#include "ucs2.h"
#include "fwup-efi.h"

#include </usr/include/smbios_c/token.h>
#define DELL_CAPSULE_FIRMWARE_UPDATES_ENABLED 0x0461
#define DELL_CAPSULE_FIRMWARE_UPDATES_DISABLED 0x0462

static char *arch_names_32[] = {
#if defined(__x86_64__) || defined(__i386__) || defined(__i686__)
	"ia32",
#endif
	""
	};

static int n_arches_32 = sizeof(arch_names_32) / sizeof(arch_names_32[0]);

static char *arch_names_64[] = {
#if defined(__x86_64__)
	"x64",
#elif defined(__aarch64__)
	"aa64",
#endif
	""
	};

static int n_arches_64 = sizeof(arch_names_64) / sizeof(arch_names_64[0]);

#define ESRT_DIR "/sys/firmware/efi/esrt/"
#define get_esrt_dir(entries)						\
	({								\
		char *_esrt_dir = ESRT_DIR;				\
		char *_alt_dir = getenv("LIBFWUP_ESRT_DIR");		\
		char *_ret;						\
		if (entries) {						\
			_ret = alloca(strlen(_alt_dir?_alt_dir:_esrt_dir) \
				      + strlen("entries/") + 1);	\
			strcpy(_ret, _alt_dir?_alt_dir:_esrt_dir);	\
			strcat(_ret, "entries/");			\
		} else {						\
			_ret = strdupa(_alt_dir?_alt_dir:_esrt_dir);	\
		}							\
		_ret;						\
	})

static int
efidp_end_entire(efidp_header *dp)
{
	if (!dp)
		return 0;
	if (efidp_type((efidp)dp) != EFIDP_END_TYPE)
		return 0;
	if (efidp_subtype((efidp)dp) != EFIDP_END_ENTIRE)
		return 0;
	return 1;
}

/*
	fwup_esrt_disabled
	tests if ESRT is disabled (but can be enabled)
	return codes:
		-1 : the tokens were not found. system is unsupported
		-2 : libsmbios failure, this scenario shouldn't be reached
		 2 : ESRT is currently disabled and can be enabled.
		 3 : tokens were found, will be enabled next boot

 */
int
fwup_esrt_disabled(void)
{
	if (!token_is_bool(DELL_CAPSULE_FIRMWARE_UPDATES_DISABLED))
		return -1;
	if (!token_is_active(DELL_CAPSULE_FIRMWARE_UPDATES_DISABLED))
	{
		if (token_is_active(DELL_CAPSULE_FIRMWARE_UPDATES_ENABLED))
			return 3;
		return -2;
	}
	return 2;
}

/*
	fwup_enable_esrt
	attempts to enable ESRT
	return codes:
		 <= 0 : failure
		 1 : already enabled
		 2 : success
		 3 : tokens were found, will be enabled next boot

 */
int
fwup_enable_esrt(void)
{
	int rc;
	rc = fwup_supported();
	/* can't enable or already enabled */
	if (rc != 2)
		return rc;
	/* disabled in BIOS, but supported to be enabled via tool */
	rc = token_is_bool(DELL_CAPSULE_FIRMWARE_UPDATES_ENABLED);
	if (!rc)
		return -1;
	rc = token_is_active(DELL_CAPSULE_FIRMWARE_UPDATES_ENABLED);
	if (rc)
		return -2;
	token_activate(DELL_CAPSULE_FIRMWARE_UPDATES_ENABLED);
	rc = token_is_active(DELL_CAPSULE_FIRMWARE_UPDATES_ENABLED);
	if (!rc)
		return -3;
	return 2;
}

/*
	fwup_supported
	tests if firmware updating supported
	return codes:
	 <0 : error
		0 : unsupported
		1 : supported
		2 : ESRT is currently disabled but can be enabled
		3 : ESRT is currently disabled but will be enabled on next boot

 */
int
fwup_supported(void)
{
	struct stat buf;
	int rc;

	rc = stat(get_esrt_dir(1), &buf);
	if (rc < 0)
	{
		/* check if we have the ability to turn on ESRT */
		rc = fwup_esrt_disabled();
		if (rc < 0)
			return 0;
		return rc;
	}
	if (buf.st_nlink < 3)
		return 0;
	return 1;
}

typedef struct esre_s {
	efi_guid_t guid;
	uint32_t fw_type;
	uint32_t fw_version;
	uint32_t lowest_supported_fw_version;
	uint32_t capsule_flags;
	uint32_t last_attempt_version;
	uint32_t last_attempt_status;
} esre;

static void
free_info(update_info *info)
{
	if (info) {
		if (info->dp_ptr)
			free(info->dp_ptr);
		free(info);
	}
}

#define FWUPDATE_GUID EFI_GUID(0x0abba7dc,0xe516,0x4167,0xbbf5,0x4d,0x9d,0x1c,0x73,0x94,0x16)

static int
get_info(efi_guid_t *guid, uint64_t hw_inst, update_info **info)
{
	efi_guid_t varguid = FWUPDATE_GUID;
	char *varname = NULL;
	char *guidstr = NULL;
	int rc;
	update_info *local;
	int error;

	rc = efi_guid_to_str(guid, &guidstr);
	if (rc < 0)
		return -1;
	guidstr = onstack(guidstr, strlen(guidstr)+1);

	rc = asprintf(&varname, "fwupdate-%s-%"PRIx64, guidstr, hw_inst);
	if (rc < 0)
		return -1;
	varname = onstack(varname, strlen(varname)+1);

	uint8_t *data = NULL;
	size_t data_size = 0;
	uint32_t attributes;

	rc = efi_get_variable(varguid, varname, &data, &data_size, &attributes);
	if (rc < 0) {
		if (errno != ENOENT)
			return -1;
		local = calloc(1, sizeof (*local));
		if (!local)
			return -1;

		local->update_info_version = UPDATE_INFO_VERSION;
		local->guid = *guid;
		local->hw_inst = hw_inst;

		local->dp_ptr = calloc(1, 1024);
		if (!local->dp_ptr) {
alloc_err:
			error = errno;
			free_info(local);
			errno = error;
			return -1;
		}

		ssize_t sz;
		sz = efidp_make_end_entire((uint8_t *)local->dp_ptr, 1024);
		if (sz < 0) {
			rc = sz;
			goto alloc_err;
		}
		*info = local;
		return 0;
	}

	/* If our size is wrong, or our data is otherwise bad, try to delete
	 * the variable and create a new one. */
	if (data_size < sizeof (*local) || !data) {
		if (data)
			free(data);
get_err:
		rc = efi_del_variable(varguid, varname);
		if (rc < 0)
			return -1;
		return get_info(guid, hw_inst, info);
	}
	local = (update_info *)data;

	if (local->update_info_version != UPDATE_INFO_VERSION)
		goto get_err;

	ssize_t sz = efidp_size((efidp)local->dp);
	if (sz < 0) {
		free(data);
		errno = EINVAL;
		return -1;
	}

	efidp_header *dp = malloc((size_t)sz);
	if (!dp) {
		free(data);
		errno = ENOMEM;
		return -1;
	}

	memcpy(dp, local->dp, (size_t)sz);
	local->dp_ptr = dp;

	*info = local;
	return 0;
}

static int
put_info(update_info *info)
{
	efi_guid_t varguid = FWUPDATE_GUID;
	ssize_t dps, is;
	char *guidstr = NULL;
	char *varname;
	int error;
	int rc;

	rc = efi_guid_to_str(&info->guid, &guidstr);
	if (rc < 0) {
err:
		return rc;
	}
	guidstr = onstack(guidstr, strlen(guidstr)+1);

	rc = asprintf(&varname, "fwupdate-%s-%"PRIx64, guidstr, info->hw_inst);
	if (rc < 0)
		goto err;
	varname = onstack(varname, strlen(varname)+1);

	dps = efidp_size((efidp)info->dp_ptr);
	/* make sure dps is at least big enough to have our structure */
	if (dps < 0 || (size_t)dps < sizeof(*info)) {
		errno = EINVAL;
		return -1;
	}
	/* Make sure sizeof(*info) + dps won't integer overflow */
	if ((size_t)dps > SSIZE_MAX - sizeof(*info)) {
		errno = EOVERFLOW;
		return -1;
	}

	is = sizeof(*info) + dps - sizeof(info->dp_ptr);

	update_info *info2;
	info2 = malloc(is);
	if (!info2)
		return -1;

	memcpy(info2, info, sizeof(*info));
	memcpy(info2->dp, info->dp_ptr, dps);

	uint32_t attributes = EFI_VARIABLE_NON_VOLATILE
			      | EFI_VARIABLE_BOOTSERVICE_ACCESS
			      | EFI_VARIABLE_RUNTIME_ACCESS;
	rc = efi_set_variable(varguid, varname, (uint8_t *)info2,
			      is, attributes, 0600);
	error = errno;
	free(info2);
	errno = error;
	return rc;
}

typedef struct fwup_resource_s
{
	esre esre;
	update_info *info;
} fwup_resource;

typedef struct fwup_resource_iter_s {
	DIR *dir;
	int dirfd;
	fwup_resource re;
} fwup_resource_iter;

int
fwup_resource_iter_create(fwup_resource_iter **iter)
{
	int error;
	if (!iter) {
		errno = EINVAL;
		return -1;
	}
	fwup_resource_iter *new = calloc(1, sizeof (fwup_resource_iter));
	if (!new) {
		errno = ENOMEM;
		return -1;
	}

	new->dir = opendir(get_esrt_dir(1));
	if (!new->dir) {
err:
		error = errno;
		free(new);
		errno = error;
		return -1;
	}

	new->dirfd = dirfd(new->dir);
	if (new->dirfd < 0)
		goto err;

	*iter = new;
	return 0;
}

static void
clear_res(fwup_resource *res)
{
	if (res->info) {
		if (res->info->dp_ptr)
			free(res->info->dp_ptr);
		free(res->info);
	}
	memset(res, 0, sizeof (*res));
}

int
fwup_resource_iter_destroy(fwup_resource_iter **iterp)
{
	if (!iterp) {
		errno = EINVAL;
		return -1;
	}
	fwup_resource_iter *iter = *iterp;
	if (!iter)
		return 0;

	clear_res(&iter->re);
	if (iter->dir)
		closedir(iter->dir);

	free(iter);
	*iterp = NULL;
	return 0;
}

int
fwup_resource_iter_next(fwup_resource_iter *iter, fwup_resource **re)
{
	fwup_resource *res;
	if (!iter || !re) {
		errno = EINVAL;
		return -1;
	}
	res = &iter->re;
	clear_res(res);

	struct dirent *entry;
	while (1) {
		errno = 0;
		entry = readdir(iter->dir);
		if (!entry) {
			if (errno != 0)
				return -1;
			return 0;
		}
		if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
			break;
	}

	int dfd = openat(iter->dirfd, entry->d_name, O_RDONLY|O_DIRECTORY);
	if (dfd < 0) {
		return -1;
	}

	char *class = NULL;
	get_string_from_file(dfd, "fw_class", &class);
	int rc = efi_str_to_guid(class, &res->esre.guid);
	if (rc < 0) {
		return rc;
	}
	res->esre.fw_type = get_value_from_file(dfd, "fw_type");
	res->esre.fw_version = get_value_from_file(dfd, "fw_version");
	res->esre.capsule_flags = get_value_from_file(dfd, "capsule_flags");
	res->esre.last_attempt_status =
			get_value_from_file(dfd, "last_attempt_status");
	res->esre.last_attempt_version =
			get_value_from_file(dfd, "last_attempt_version");
	res->esre.lowest_supported_fw_version =
			get_value_from_file(dfd, "lowest_supported_fw_version");

	rc = get_info(&res->esre.guid, 0, &res->info);
	if (rc < 0)
		return rc;

	res->info->capsule_flags = res->esre.capsule_flags;

	*re = res;

	return 1;
}

int
fwup_set_guid(fwup_resource_iter *iter, fwup_resource **re, const efi_guid_t *guid) {
	fwup_resource *res;
	if (!iter || !re) {
		errno = EINVAL;
		return -1;
	}
	res = &iter->re;
	res->esre.guid = *guid;
	*re = res;
	return 1;
}

int
fwup_clear_status(fwup_resource *re)
{
	if (!re) {
		errno = EINVAL;
		return -1;
	}

	int rc;

	re->info->status = 0;

	rc = put_info(re->info);
	return rc;
}

int
fwup_get_guid(fwup_resource *re, efi_guid_t **guid)
{
	if (!re || !guid) {
		errno = EINVAL;
		return -1;
	}

	*guid = &re->esre.guid;
	return 0;
}

int
fwup_get_fw_version(fwup_resource *re, uint32_t *version)
{
	if (!re || !version) {
		errno = EINVAL;
		return -1;
	}

	*version = re->esre.fw_version;
	return 0;
}

int
fwup_get_fw_type(fwup_resource *re, uint32_t *type)
{
	if (!re || !type) {
		errno = EINVAL;
		return -1;
	}

	*type = re->esre.fw_type;
	return 0;
}

int
fwup_get_lowest_supported_fw_version(fwup_resource *re, uint32_t *version)
{
	if (!re || !version) {
		errno = EINVAL;
		return -1;
	}

	*version = re->esre.lowest_supported_fw_version;
	return 0;
}

int
fwup_get_attempt_status(fwup_resource *re, uint32_t *status)
{
	if (!re || !status) {
		errno = EINVAL;
		return -1;
	}

	if (re->info->status & FWUPDATE_ATTEMPTED)
		*status = 1;
	return 0;
}

int
fwup_get_last_attempt_info(fwup_resource *re, uint32_t *version,
			   uint32_t *status, time_t *when)
{
	if (!re || !version || !status || !when) {
		errno = EINVAL;
		return -1;
	}

	if (!re->info->status) {
		errno = ENOENT;
		return -1;
	}

	if (!(re->info->status & FWUPDATE_ATTEMPTED))
		return 0;

	*version = re->esre.last_attempt_version;
	*status = re->esre.last_attempt_status;

	struct tm tm = {
		.tm_year = re->info->time_attempted.year - 1900,
		.tm_mon = re->info->time_attempted.month - 1,
		.tm_mday = re->info->time_attempted.day,
		.tm_hour = re->info->time_attempted.hour,
		.tm_min = re->info->time_attempted.minute,
		.tm_sec = re->info->time_attempted.second,
		.tm_isdst = re->info->time_attempted.daylight,
	};

	*when = mktime(&tm);

	return 1;
}

/* XXX PJFIX: this should be in efiboot-loadopt.h in efivar */
#define LOAD_OPTION_ACTIVE      0x00000001

static int
get_paths(char **shim_fs_path, char **fwup_fs_path, char **fwup_esp_path)
{
	int ret = -1;

	char shim_fs_path_tmpl[] = "/boot/efi/EFI/"FWUP_EFI_DIR_NAME"/shim";
	char fwup_fs_path_tmpl[] = "/boot/efi/EFI/"FWUP_EFI_DIR_NAME"/fwup";
	uint8_t fwup_esp_path_tmpl[] = "\\fwup";

	char *shim_fs_path_tmp = NULL;
	char *fwup_fs_path_tmp = NULL;
	char *fwup_esp_path_tmp = NULL;

	uint64_t firmware_bits = 0;

	firmware_bits = get_value_from_file_at_dir("/sys/firmware/efi/",
						   "fw_platform_size");
	char **arch_names = firmware_bits == 64 ? arch_names_64
						 : arch_names_32;
	int n_arches = firmware_bits == 64 ? n_arches_64 : n_arches_32;
	int i;

	int rc;

	*shim_fs_path = NULL;
	*fwup_fs_path = NULL;
	*fwup_esp_path = NULL;

	i = find_matching_file(shim_fs_path_tmpl, ".efi", arch_names,
			       n_arches, &shim_fs_path_tmp);

	i = find_matching_file(fwup_fs_path_tmpl, ".efi", arch_names,
				       n_arches, &fwup_fs_path_tmp);
	if (i < 0) {
		errno = ENOENT;
		ret = i;
		goto out;
	}
	rc = asprintf(&fwup_esp_path_tmp, "%s%s.efi", fwup_esp_path_tmpl,
		      arch_names[i]);
	if (rc < 0)
		goto out;

	if (shim_fs_path_tmp) {
		*shim_fs_path = strdup(shim_fs_path_tmp);
		if (!*shim_fs_path)
			goto out;
	}
	if (fwup_fs_path_tmp) {
		*fwup_fs_path = strdup(fwup_fs_path_tmp);
		if (!*fwup_fs_path)
			goto out;
	}
	if (fwup_esp_path_tmp)
		*fwup_esp_path = fwup_esp_path_tmp;

	return 0;
out:
	if (*shim_fs_path)
		free(*shim_fs_path);
	if (*fwup_fs_path)
		free(*fwup_fs_path);
	if (fwup_esp_path_tmp)
		free(fwup_esp_path_tmp);
	return ret;
}

static int
set_up_boot_next(void)
{
	ssize_t sz, dp_size = 0;
	uint8_t *dp_buf = NULL;
	int rc;
	int saved_errno;
	int ret = -1;

	uint16_t *loader_str = NULL;
	size_t loader_sz = 0;

	char *shim_fs_path = NULL;
	char *fwup_fs_path = NULL;
	char *fwup_esp_path = NULL;
	int use_fwup_path = 0;

	char *label = NULL;

	rc = get_paths(&shim_fs_path, &fwup_fs_path, &fwup_esp_path);
	if (rc < 0)
		return -1;

	if (!shim_fs_path)
		use_fwup_path = 1;

	sz = efi_generate_file_device_path(dp_buf, dp_size, use_fwup_path
							    ? fwup_fs_path
							    : shim_fs_path,
					   EFIBOOT_OPTIONS_IGNORE_FS_ERROR|
					   EFIBOOT_ABBREV_HD);
	if (sz < 0)
		goto out;

	dp_size=sz;
	dp_buf = calloc(1, dp_size);
	if (!dp_buf)
		goto out;

	if (!use_fwup_path) {
		loader_str = utf8_to_ucs2((uint8_t *)fwup_esp_path, -1);
		loader_sz = ucs2len(loader_str, -1) * 2;
		if (loader_sz)
			loader_sz += 2;
		loader_str = onstack(loader_str, loader_sz);
	}

	sz = efi_generate_file_device_path(dp_buf, dp_size, use_fwup_path
							    ? fwup_fs_path
							    : shim_fs_path,
					   EFIBOOT_OPTIONS_IGNORE_FS_ERROR|
					   EFIBOOT_ABBREV_HD);
	if (sz != dp_size)
		goto out;

	uint8_t *opt=NULL;
	ssize_t opt_size=0;
	uint32_t attributes = LOAD_OPTION_ACTIVE;

	rc = asprintf(&label, "Linux-Firmware-Updater %s", fwup_esp_path);
	if (rc < 0)
		goto out;

	sz = efi_loadopt_create(opt, opt_size, attributes,
				  (efidp)dp_buf, dp_size,
				  (uint8_t *)label,
				  (uint8_t *)loader_str, loader_sz);
	if (sz < 0)
		goto out;
	opt = calloc(1, sz);
	if (!opt)
		goto out;
	opt_size = sz;
	sz = efi_loadopt_create(opt, opt_size, attributes,
				  (efidp)dp_buf, dp_size,
				  (uint8_t *)label,
				  (uint8_t *)loader_str, loader_sz);
	if (sz != opt_size)
		goto out;

	int set_entries[0x10000 / sizeof(int)] = {0,};
	efi_guid_t *guid = NULL;
	char *name = NULL;

	uint32_t boot_next = 0x10000;
	int found = 0;

	uint8_t *var_data = NULL;
	size_t var_data_size = 0;
	uint32_t attr;
	efi_load_option *loadopt = NULL;

	while ((rc = efi_get_next_variable_name(&guid, &name)) > 0) {
		if (efi_guid_cmp(guid, &efi_guid_global))
			continue;
		int scanned=0;
		uint16_t entry=0;
		rc = sscanf(name, "Boot%hX%n", &entry, &scanned);
		if (rc < 0)
			goto out;
		if (rc != 1)
			continue;
		if (scanned != 8)
			continue;

		int div = entry / (sizeof(set_entries[0]) * 8);
		int mod = entry % (sizeof(set_entries[0]) * 8);

		set_entries[div] |= 1 << mod;

		rc = efi_get_variable(*guid, name, &var_data, &var_data_size,
				      &attr);
		if (rc < 0)
			continue;

		loadopt = (efi_load_option *)var_data;
		if (!efi_loadopt_is_valid(loadopt, var_data_size)) {
do_next:
			free(var_data);
			continue;
		}

		sz = efi_loadopt_pathlen(loadopt, var_data_size);
		if (sz != efidp_size((efidp)dp_buf))
			goto do_next;

		efidp found_dp = efi_loadopt_path(loadopt, var_data_size);
		if (memcmp(found_dp, dp_buf, sz))
			goto do_next;

		if ((ssize_t)var_data_size != opt_size)
			goto do_next;
		if (memcmp(loadopt, opt, opt_size))
			goto do_next;
		if (memcmp(loadopt, opt, opt_size))
			goto do_next;

		found = 1;
		boot_next = entry;
		break;
	}
	if (rc < 0)
		goto out;

	if (found) {
		efi_loadopt_attr_set(loadopt, LOAD_OPTION_ACTIVE);
		rc = efi_set_variable(*guid, name, var_data,
				      var_data_size, attr, 0600);
		free(var_data);
		if (rc < 0)
			goto out;
	} else {
		char boot_next_name[] = "Boot####";
		for (uint32_t value = 0; value < 0x10000; value++) {
			int div = value / (sizeof(set_entries[0]) * 8);
			int mod = value % (sizeof(set_entries[0]) * 8);

			if (set_entries[div] & (1<<mod)) {
				continue;
			}
			boot_next = value;
			break;
		}

		if (boot_next >= 0x10000)
			goto out;

		sprintf(boot_next_name, "Boot%04X", boot_next);
		rc = efi_set_variable(efi_guid_global, boot_next_name, opt,
				      opt_size,
				      EFI_VARIABLE_NON_VOLATILE |
				      EFI_VARIABLE_BOOTSERVICE_ACCESS |
				      EFI_VARIABLE_RUNTIME_ACCESS,
				      0600);
		if (rc < 0)
			goto out;

	}

	uint16_t real_boot_next = boot_next;
	rc = efi_set_variable(efi_guid_global, "BootNext",
			      (uint8_t *)&real_boot_next, 2,
			      EFI_VARIABLE_NON_VOLATILE |
			      EFI_VARIABLE_BOOTSERVICE_ACCESS |
			      EFI_VARIABLE_RUNTIME_ACCESS,
			      0600);
	ret = rc;

out:
	saved_errno = errno;
	if (dp_buf)
		free(dp_buf);
	if (opt)
		free(opt);
	if (label)
		free(label);
	if (fwup_esp_path)
		free(fwup_esp_path);
	if (fwup_fs_path)
		free(fwup_fs_path);
	if (shim_fs_path)
		free(shim_fs_path);

	errno = saved_errno;
	return ret;
}

/**
 * get_existing_media_path:
 * @info: the #update_info
 *
 * Return a media path to use for the update which has already been used by
 * this specific GUID.
 *
 * Returns: a media path, or %NULL if no such path exists.
 */
static char *
get_existing_media_path(update_info *info)
{
	int rc;
	char *relpath = NULL;
	char *fullpath = NULL;
	uint16_t *ucs2file = NULL;
	uint16_t ucs2len = 0;

	/* never set */
	if (!info->dp_ptr)
		goto out;
	if (efidp_end_entire(info->dp_ptr))
		goto out;

	/* find UCS2 string */
	const_efidp idp = (const_efidp)info->dp_ptr;
	while (1) {
		if (efidp_type(idp) == EFIDP_END_TYPE &&
				efidp_subtype(idp) == EFIDP_END_ENTIRE)
			break;
		if (efidp_type(idp) != EFIDP_MEDIA_TYPE ||
				efidp_subtype(idp) !=EFIDP_MEDIA_FILE) {
			rc = efidp_next_node(idp, &idp);
			if (rc < 0)
				break;
			continue;
		}
		ucs2file = (uint16_t *)((uint8_t *)idp + 4);
		ucs2len = efidp_node_size(idp) - 4;
		break;
	}

	/* nothing found */
	if (!ucs2file || ucs2len <= 0)
		goto out;

	/* convert to something sane */
	relpath = ucs2_to_utf8(ucs2file, ucs2len / sizeof (uint16_t));
	if (!relpath)
		goto out;

	/* convert '\' to '/' */
	untilt_slashes(relpath);

	/* build a complete path */
	rc = asprintf(&fullpath, "/boot/efi%s", relpath);
	if (rc < 0)
		fullpath = NULL;

out:
	free(relpath);
	return fullpath;
}

/**
 * get_fd_and_media_path:
 * @info: the #update_info
 * @path: (out): the path
 *
 * Opens a suitable file descriptor and sets a media path to use for the update.
 *
 * Returns: a FD, or -1 for error
 */
static int
get_fd_and_media_path(update_info *info, char **path)
{
	char *fullpath = NULL;
	int fd = -1;
	int rc;

	/* look for an existing variable that we've used before for this
	 * update GUID, and reuse the filename so we don't wind up
	 * littering the filesystem with old updates */
	fullpath = get_existing_media_path (info);
	if (fullpath) {
		fd = open(fullpath, O_CREAT|O_TRUNC|O_CLOEXEC|O_RDWR, 0600);
		if (fd < 0) {
			warn("open of %s failed", fullpath);
			goto out;
		}
	} else {
		/* fall back to creating a new file from scratch */
		rc = asprintf(&fullpath,
			      "/boot/efi/EFI/%s/fw/fwupdate-XXXXXX.cap",
			      FWUP_EFI_DIR_NAME);
		if (rc < 0) {
			warn("asprintf failed");
			return fd;
		}
		fd = mkostemps(fullpath, 4, O_CREAT|O_TRUNC|O_CLOEXEC);
		if (fd < 0) {
			warn("mkostemps(%s) failed", fullpath);
			goto out;
		}
	}

	/* success, so take ownership of the string */
	if (path) {
		*path = fullpath;
		fullpath = NULL;
	}
out:
	free(fullpath);
	return fd;
}

/**
 * set_efidp_header:
 * @info: the #update_info
 * @path: the path
 *
 * Update the device path.
 *
 * Returns: a FD, or -1 for error
 */
static int
set_efidp_header(update_info *info, const char *path)
{
	int rc = 0;
	ssize_t req;
	ssize_t sz;
	uint8_t *dp_buf = NULL;

	/* get the size of the path first */
	req = efi_generate_file_device_path(NULL, 0, path,
				EFIBOOT_OPTIONS_IGNORE_FS_ERROR |
				EFIBOOT_ABBREV_HD);
	if (req < 0) {
		rc = -1;
		goto out;
	}
	if (req <= 4) { /* if we just have an end device path,
			  it's not going to work. */
		rc = EINVAL;
		goto out;
	}

	dp_buf = calloc(1, req);
	if (!dp_buf) {
		rc = -1;
		goto out;
	}

	/* actually get the path this time */
	efidp_header *dp = (efidp_header *)dp_buf;
	sz = efi_generate_file_device_path(dp_buf, req, path,
				EFIBOOT_OPTIONS_IGNORE_FS_ERROR |
				EFIBOOT_ABBREV_HD);
	if (sz < 0) {
		rc = -1;
		goto out;
	}

	/* @info owns this now */
	if (info->dp_ptr)
		free(info->dp_ptr);
	info->dp_ptr = dp;
	dp_buf = NULL;
out:
	free(dp_buf);
	return rc;
}

/**
 * fwup_set_up_update
 * @re: A %fwup_resource.
 * @hw_inst: A hardware instance -- currently unused.
 * @infd: file descriptor to the .cap binary
 *
 * Sets up a UEFI update using a file descriptor.
 *
 * Returns: -1 on error, @errno being set
 *
 * Since: 0.3
 */
int
fwup_set_up_update(fwup_resource *re,
		   uint64_t hw_inst __attribute__((__unused__)),
		   int infd)
{
	char *path = NULL;
	int outfd = -1;
	int rc;
	off_t offset;
	update_info *info = NULL;
	FILE *fin = NULL, *fout = NULL;
	int error;

	/* check parameters */
	if (infd < 0) {
		warn("fd invalid.\n");
		return -1;
	}

	offset = lseek(infd, 0, SEEK_CUR);

	/* get device */
	rc = get_info(&re->esre.guid, 0, &info);
	if (rc < 0) {
		warn("get_info failed.\n");
		goto out;
	}

	/* get destination */
	outfd = get_fd_and_media_path(info, &path);
	if (outfd < 0) {
		rc = -1;
		goto out;
	}

	fin = fdopen(infd, "r");
	if (!fin)
		goto out;

	fout = fdopen(outfd, "w");
	if (!fout)
		goto out;

	/* copy the input file to the new home */
	while (1) {
		int c;
		int rc;

		c = fgetc(fin);
		if (c == EOF) {
			if (feof(fin)) {
				break;
			} else if (ferror(fin)) {
				warn("read failed");
				rc = -1;
				goto out;
			} else {
				warnx("fgetc() == EOF but no error is set.");
				errno = EINVAL;
				rc = -1;
				goto out;
			}
		}

		rc = fputc(c, fout);
		if (rc == EOF) {
			if (feof(fout)) {
				break;
			} else if (ferror(fout)) {
				warn("write failed");
				rc = -1;
				goto out;
			} else {
				warnx("fputc() == EOF but no error is set.");
				errno = EINVAL;
				rc = -1;
				goto out;
			}
		}
	}

	/* set efidp header */
	rc = set_efidp_header(info, path);
	if (rc < 0)
		goto out;

	/* save this to the hardware */
	info->status = FWUPDATE_ATTEMPT_UPDATE;
	memset(&info->time_attempted, 0, sizeof(info->time_attempted));
	info->capsule_flags = re->esre.capsule_flags;
	rc = put_info(info);
	if (rc < 0) {
		warn("put_info failed.\n");
		goto out;
	}

	/* update the firmware before the bootloader runs */
	rc = set_up_boot_next();
	if (rc < 0)
		goto out;
out:
	error = errno;
	lseek(infd, offset, SEEK_SET);
	if (path)
		free(path);
	if (fin)
		fclose(fin);
	if (fout)
		fclose(fout);
	free_info(info);
	if (outfd >= 0) {
		fsync(outfd);
		close(outfd);
	}
	errno = error;
	return rc;
}

/**
 * fwup_set_up_update_with_buf
 * @re: A %fwup_resource.
 * @hw_inst: A hardware instance -- currently unused.
 * @buf: A memory buffer
 * @sz: Size of @buf
 *
 * Sets up a UEFI update using a pre-allocated buffer.
 *
 * Returns: -1 on error, @errno being set
 *
 * Since: 0.5
 */
int
fwup_set_up_update_with_buf(fwup_resource *re,
			    uint64_t hw_inst __attribute__((__unused__)),
			    const void *buf, size_t sz)
{
	char *path = NULL;
	int fd = -1;
	int rc;
	update_info *info = NULL;
	int error;
	off_t off = 0;

	/* check parameters */
	if (buf == NULL || sz == 0) {
		warn("buf invalid.\n");
		rc = -1;
		goto out;
	}

	/* get device */
	rc = get_info(&re->esre.guid, 0, &info);
	if (rc < 0) {
		warn("get_info failed.\n");
		goto out;
	}

	/* get destination */
	fd = get_fd_and_media_path(info, &path);
	if (fd < 0) {
		rc = -1;
		goto out;
	}

	/* write the buf to a new file */
	while (sz-off) {
		ssize_t wsz;
		wsz = write(fd, buf+off, sz-off);
		if (wsz < 0 &&
		    (errno == EAGAIN || errno == EINTR))
			continue;
		if (wsz < 0) {
			rc = wsz;
			warn("write failed");
			goto out;
		}
		off += wsz;
	}

	/* set efidp header */
	rc = set_efidp_header(info, path);
	if (rc < 0)
		goto out;

	/* save this to the hardware */
	info->status = FWUPDATE_ATTEMPT_UPDATE;
	memset(&info->time_attempted, 0, sizeof(info->time_attempted));
	info->capsule_flags = re->esre.capsule_flags;
	rc = put_info(info);
	if (rc < 0) {
		warn("put_info failed.\n");
		goto out;
	}

	/* update the firmware before the bootloader runs */
	rc = set_up_boot_next();
	if (rc < 0)
		goto out;
out:
	error = errno;
	free_info(info);
	if (fd >= 0)
		close(fd);
	errno = error;
	return rc;
}

/**
 * fwup_last_attempt_status_to_string:
 * @status: the status enum, e.g. %FWUP_LAST_ATTEMPT_STATUS_SUCCESS.
 *
 * Return a string representation of the last attempt status.
 *
 * Returns: A const string
 *
 * Since: 0.5
 */
const char *
fwup_last_attempt_status_to_string (uint64_t status)
{
	if (status == FWUP_LAST_ATTEMPT_STATUS_SUCCESS)
		return "Success";
	if (status == FWUP_LAST_ATTEMPT_STATUS_ERROR_UNSUCCESSFUL)
		return "Unsuccessful";
	if (status == FWUP_LAST_ATTEMPT_STATUS_ERROR_INSUFFICIENT_RESOURCES)
		return "Insufficient resources";
	if (status == FWUP_LAST_ATTEMPT_STATUS_ERROR_INCORRECT_VERSION)
		return "Incorrect version";
	if (status == FWUP_LAST_ATTEMPT_STATUS_ERROR_INVALID_FORMAT)
		return "Invalid firmware format";
	if (status == FWUP_LAST_ATTEMPT_STATUS_ERROR_AUTH_ERROR)
		return "Authentication signing error";
	if (status == FWUP_LAST_ATTEMPT_STATUS_ERROR_PWR_EVT_AC)
		return "AC power required";
	if (status == FWUP_LAST_ATTEMPT_STATUS_ERROR_PWR_EVT_BATT)
		return "Battery level is too low";
	return NULL;
}


/**
 * fwup_print_update_info:
 * Print the information of firmware update status.
 *
 * Returns: -1 on error, @errno being set
 *
 * Since: 0.5
 */
int
fwup_print_update_info(void)
{
	fwup_resource_iter *iter;
	int id;
	int rc;

	rc = fwup_resource_iter_create(&iter);
	if (rc < 0) {
		if (errno != ENOENT)
			warn(_("Could not create iterator"));
		return -1;
	}

	fwup_resource *re = NULL;
	id = 0;
	while ((rc = fwup_resource_iter_next(iter, &re)) > 0) {
		update_info *info = re->info;
		efi_guid_t *guid = &info->guid;
		char *id_guid = NULL;
		ssize_t dp_sz;
		char *path;

		rc = efi_guid_to_id_guid(guid, &id_guid);
		if (rc < 0)
			break;


		dp_sz = efidp_format_device_path(NULL, 0,
						 (const_efidp)info->dp_ptr,
						 0);
		if (dp_sz <= 0) {
			errno = EINVAL;
			rc = -1;
			free(id_guid);
			break;
		}

		path = malloc(dp_sz);
		if (!path) {
			rc = -1;
			free(id_guid);
			break;
		}

		if (efidp_format_device_path(path, dp_sz,
					     (const_efidp)info->dp_ptr, 0)
					     != dp_sz) {
			errno = EINVAL;
			rc = -1;
			free(path);
			free(id_guid);
			break;
		}

		printf("\nInformation for the update status entry %d:\n", id++);
		printf("  Information Version: %d\n", info->update_info_version);
		printf("  Firmware GUID: %s\n", id_guid);
		printf("  Capsule Flags: 0x%08x\n", info->capsule_flags);
		printf("  Hardware Instance: %" PRIu64 "\n", info->hw_inst);
		printf("  Update Status: %s\n",
		       info->status == FWUPDATE_ATTEMPT_UPDATE ? "Preparing"
		       : info->status == FWUPDATE_ATTEMPTED ? "Attempted"
		       : "Unknown");
		if (info->status == FWUPDATE_ATTEMPTED) {
			efi_time_t *time_attempted;
			struct tm tm;

			time_attempted = (efi_time_t *)&info->time_attempted;
			tm.tm_year = time_attempted->year - 1900;
			tm.tm_mon = time_attempted->month - 1;
			tm.tm_mday = time_attempted->day;
			tm.tm_hour = time_attempted->hour;
			tm.tm_min = time_attempted->minute;
			tm.tm_sec = time_attempted->second;
			tm.tm_isdst = time_attempted->daylight;

			printf("  Attempted Time: ");
			if (mktime(&tm) != (time_t)-1)
				printf("%s", asctime(&tm));
			else
				printf("Unknown\n");
		}
		printf("  Capsule File Path: %s\n", path);

		free(path);
		free(id_guid);
	}

	fwup_resource_iter_destroy(&iter);
	if (rc < 0)
		return -1;
	return 0;
}
