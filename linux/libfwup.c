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
#include <efivar/efiboot.h>
#include <efivar/efivar.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
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

static int verbose;
#include "error.h"

#include <dell-wmi-smi.h>
#ifdef FWUPDATE_HAVE_LIBSMBIOS__
#include <smbios_c/token.h>
#include <smbios_c/smi.h>
#endif

static char *arch_names_32[] = {
#if defined(__x86_64__) || defined(__i386__) || defined(__i686__)
	"ia32",
#endif
	EMPTY
	};

static int n_arches_32 = sizeof(arch_names_32) / sizeof(arch_names_32[0]);

static char *arch_names_64[] = {
#if defined(__x86_64__)
	"x64",
#elif defined(__aarch64__)
	"aa64",
#endif
	EMPTY
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

static char *esp_mountpoint = FWUP_ESP_MOUNTPOINT;

/**
 * fwup_set_esp_mountpoint:
 * @path: pointer to a string containing the path to the ESP mountpoint
 *
 * The string isn't copied so you should not free it after calling this function
 */
void
fwup_set_esp_mountpoint(char *path)
{
	esp_mountpoint = path;
}

/**
 * fwup_get_esp_mountpoint:
 *
 * Returns the path to the ESP mountpoint
 *
 * @returns: pointer to a string
 */
const char *
fwup_get_esp_mountpoint(void)
{
	return esp_mountpoint;
}

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

static int
wmi_supported(void)
{
	if (access(DELL_WMI_CHAR, F_OK) != -1)
		return 1;
	return 0;
}

static int
wmi_call_ioctl(struct dell_wmi_smbios_buffer *buffer)
{
	int fd, ret;
	int error;

	fd = open(DELL_WMI_CHAR, O_NONBLOCK);
	if (fd < 0)
		return fd;

	ret = ioctl(fd, DELL_WMI_SMBIOS_CMD, buffer);
	error = errno;
	close(fd);
	errno = error;
	return ret;
}

static int
wmi_read_buffer_size(uint64_t *buffer_size)
{
	FILE *f;

	f = fopen(DELL_WMI_CHAR, "rb");
	if (!f)
		return -1;
	fread(buffer_size, sizeof(uint64_t), 1, f);
	fclose(f);
	return 0;
}

static int
wmi_find_token(uint16_t token, uint32_t *location, uint32_t *value)
{
	char value_sysfs[sizeof("ffff_value")];
	char location_sysfs[sizeof("ffff_location")];

	sprintf(value_sysfs, "%04hhx_value", token);
	sprintf(location_sysfs, "%04hhx_location", token);

	*value = get_value_from_file_at_dir(TOKENS_SYSFS, value_sysfs);
	*location = get_value_from_file_at_dir(TOKENS_SYSFS, location_sysfs);

	if (*location)
		return 0;

	return -1;
}

static int
prepare_buffer_real(struct dell_wmi_smbios_buffer **buffer,
		    uint16_t class, uint16_t select, unsigned int count, ...)
{
	uint64_t buffer_size = 0;
	int ret;
	va_list ap;

	if (count > 4) {
		errno = EINVAL;
		return -errno;
	}

	ret = wmi_read_buffer_size(&buffer_size);
	if (ret < 0 || buffer_size < 1) {
		errno = ENODEV;
		return -errno;
	}

	*buffer = malloc(buffer_size);
	if (!buffer) {
		errno = ENOMEM;
		return -errno;
	}

	(*buffer)->length = buffer_size;
	(*buffer)->std.cmd_class = class;
	(*buffer)->std.cmd_select = select;
	va_start(ap, count);
	for (unsigned int i = 0; i < count; i++) {
		uint32_t arg = va_arg(ap, uint32_t);
		(*buffer)->std.input[i] = arg;
	}
	va_end(ap);
	return 0;
}

#define prepare_buffer(buffer, class, select, count, ...)		\
	({								\
		int ret_;						\
		ret_ = prepare_buffer_real(buffer, class, select,	\
					   count, ##__VA_ARGS__);	\
		if (ret_ >= 0)						\
			*(buffer) = onstack(*(buffer),			\
					    (*(buffer))->length);	\
		ret_;							\
	 })

static int
wmi_token_is_active(uint32_t *location, uint32_t *cmpvalue)
{
	struct dell_wmi_smbios_buffer *ioctl_buffer;
	int ret;

	ret = prepare_buffer(&ioctl_buffer, CLASS_TOKEN_READ,
			     SELECT_TOKEN_STD, 1, *location);
	if (ret < 0)
		return ret;

	ret = wmi_call_ioctl(ioctl_buffer);
	if (ret < 0 || ioctl_buffer->std.output[0] != 0)
		return ret;

	return (ioctl_buffer->std.output[1] == *cmpvalue);
}

static int
query_token(uint16_t token)
{
	if (wmi_supported()) {
		uint32_t location = 0;
		uint32_t cmpvalue = 0;

		/* locate token */
		if (wmi_find_token(token, &location, &cmpvalue) < 0)
			return -1;

		/* query actual token status */
		return wmi_token_is_active(&location, &cmpvalue);
	}
#ifdef FWUPDATE_HAVE_LIBSMBIOS__
	if (!token_is_bool(token))
		return -1;

	if (token_is_active(token) > 0)
		return 1;
#endif
	return -1;
}

static int
activate_token(uint16_t token)
{
	int ret;
	if (wmi_supported()) {
		struct dell_wmi_smbios_buffer *ioctl_buffer;
		uint32_t location;
		uint32_t cmpvalue;

		/* locate token */
		if (wmi_find_token(token, &location, &cmpvalue) < 0)
			return -1;

		ret = prepare_buffer(&ioctl_buffer, CLASS_TOKEN_WRITE,
				     SELECT_TOKEN_STD, 2, location, 1);
		if (ret < 0)
			return ret;

		ret = wmi_call_ioctl(ioctl_buffer);
		return ret;
	}
#ifdef FWUPDATE_HAVE_LIBSMBIOS__
	token_activate(token);
	ret = token_is_active(token);
	if (ret < 0) {
		efi_error("%d activation failed", token);
		return FWUPDATE_ADMIN_PASSWORD_SET;
	}
	return FWUPDATE_ESRT_DISABLED;
#else
	return FWUPDATE_NO_TOKENS_FOUND;
#endif
}

static int
admin_password_present()
{
	int ret;

	if (wmi_supported()) {
		struct dell_wmi_smbios_buffer *ioctl_buffer;
		ret = prepare_buffer(&ioctl_buffer, CLASS_ADMIN_PROP,
				     SELECT_ADMIN_PROP, 0);
		if (ret < 0)
			return ret;

		ret = wmi_call_ioctl(ioctl_buffer);
		if (ret < 0)
			return ret;

		if (ioctl_buffer->std.output[0] != 0 ||
		   (ioctl_buffer->std.output[1] & DELL_ADMIN_MASK) == DELL_ADMIN_INSTALLED)
			return FWUPDATE_ADMIN_PASSWORD_SET;

		return FWUP_SUPPORTED_STATUS_LOCKED_CAN_UNLOCK;
	}
#ifdef FWUPDATE_HAVE_LIBSMBIOS__
	uint32_t args[4] = { 0, }, out[4] = { 0, };

	if (dell_simple_ci_smi(CLASS_ADMIN_PROP,
			       SELECT_ADMIN_PROP, args, out))
		return FWUPDATE_LIBSMBIOS_FAILURE;

	if (out[0] != 0 || (out[1] & DELL_ADMIN_MASK) == DELL_ADMIN_INSTALLED)
		return FWUPDATE_ADMIN_PASSWORD_SET;

	return FWUP_SUPPORTED_STATUS_LOCKED_CAN_UNLOCK;
#else
	return FWUPDATE_NO_TOKENS_FOUND;
#endif

}

/*
	fwup_esrt_disabled
	tests if ESRT is disabled (but can be enabled)
	return codes:
		-1 : the tokens were not found. system is unsupported
		-2 : libsmbios failure, this scenario shouldn't be reached
		-3 : admin password is set
		 2 : ESRT is currently disabled and can be enabled.
		 3 : tokens were found, will be enabled next boot

 */
int
fwup_esrt_disabled(void)
{
	int ret;

	ret = query_token(CAPSULE_DIS_TOKEN);
	if (ret < 0) {
		ret = query_token(CAPSULE_EN_TOKEN);
		if (ret > 0)
			return FWUP_SUPPORTED_STATUS_LOCKED_CAN_UNLOCK_NEXT_BOOT;
		return FWUPDATE_LIBSMBIOS_FAILURE;
	}
	return admin_password_present();
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
	if (rc != FWUP_SUPPORTED_STATUS_LOCKED_CAN_UNLOCK) {
		efi_error("fwup_supported() returned %d", rc);
		return rc;
	}
	/* disabled in BIOS, but supported to be enabled via tool */
	rc = query_token(CAPSULE_EN_TOKEN);
	if (!rc) {
		efi_error
		    ("DELL_CAPSULE_FIRMWARE_UPDATES_ENABLED is unsupported");
		return FWUPDATE_LIBSMBIOS_FAILURE;
	}
	activate_token(CAPSULE_EN_TOKEN);

	return FWUPDATE_ESRT_DISABLED;
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
	if (rc < 0) {
		efi_error("ESRT is not present");
		/* check if we have the ability to turn on ESRT */
		rc = fwup_esrt_disabled();
		if (rc < 0) {
			efi_error("ESRT cannot be enabled");
			return FWUP_SUPPORTED_STATUS_UNSUPPORTED;
		}
		return rc;
	}
	if (buf.st_nlink < 3) {
		efi_error("ESRT has no entries.");
		return FWUP_SUPPORTED_STATUS_UNSUPPORTED;
	}
	return FWUP_SUPPORTED_STATUS_UNLOCKED;
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
	if (rc < 0) {
		efi_error("efi_guid_to_str() failed");
		return -1;
	}
	guidstr = onstack(guidstr, strlen(guidstr)+1);

	rc = asprintf(&varname, "fwupdate-%s-%"PRIx64, guidstr, hw_inst);
	if (rc < 0) {
		efi_error("asprintf() failed");
		return -1;
	}
	varname = onstack(varname, strlen(varname)+1);

	uint8_t *data = NULL;
	size_t data_size = 0;
	uint32_t attributes;

	rc = efi_get_variable(varguid, varname, &data, &data_size, &attributes);
	if (rc < 0) {
		if (errno != ENOENT) {
			efi_error("efi_get_variable() failed");
			return -1;
		}
		efi_error_clear();

		local = calloc(1, sizeof (*local));
		if (!local) {
			efi_error("calloc(1, %zd) failed", sizeof (*local));
			return -1;
		}

		local->update_info_version = UPDATE_INFO_VERSION;
		local->guid = *guid;
		local->hw_inst = hw_inst;

		local->dp_ptr = calloc(1, 1024);
		if (!local->dp_ptr) {
			efi_error("calloc(1, 1024) failed");
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
			efi_error("efidp_make_end_entire() failed");
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
		if (rc < 0) {
			efi_error("efi_del_variable() failed");
			return -1;
		}
		rc = get_info(guid, hw_inst, info);
		if (rc < 0)
			efi_error("get_info() failed");
		return rc;
	}
	local = (update_info *)data;

	if (local->update_info_version != UPDATE_INFO_VERSION) {
		efi_error("fwupdate saved state version mismatch");
		goto get_err;
	}

	ssize_t sz = efidp_size((efidp)local->dp_buf);
	if (sz < 0) {
		efi_error("efidp_size() failed");
		free(data);
		errno = EINVAL;
		return -1;
	}

	efidp_header *dp = malloc((size_t)sz);
	if (!dp) {
		efi_error("malloc(%zd) failed", (size_t)sz);
		free(data);
		errno = ENOMEM;
		return -1;
	}

	memcpy(dp, local->dp_buf, (size_t)sz);
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
		efi_error("efi_guid_to_str() failed");
err:
		return rc;
	}
	guidstr = onstack(guidstr, strlen(guidstr)+1);

	rc = asprintf(&varname, "fwupdate-%s-%"PRIx64, guidstr, info->hw_inst);
	if (rc < 0) {
		efi_error("asprintf() failed");
		goto err;
	}
	varname = onstack(varname, strlen(varname)+1);

	dps = efidp_size((efidp)info->dp_ptr);
	/* make sure dps is at least big enough to have our structure */
	if (dps < 0 || (size_t)dps < sizeof(*info)) {
		efi_error("device path size (%zd) was unreasonable", dps);
		errno = EINVAL;
		return -1;
	}
	/* Make sure sizeof(*info) + dps won't integer overflow */
	if (((size_t)dps >= SSIZE_MAX - sizeof(*info)) ||
	    /* Make sure extra hard by just picking an astonishingly large
	     * value that's merely very very unlikely... */
	    ((ssize_t)dps > sysconf(_SC_PAGESIZE) * 100)) {
		efi_error("device path size (%zd) would overflow", dps);
		errno = EOVERFLOW;
		return -1;
	}

	is = sizeof(*info) + dps - sizeof(info->dp_ptr);

	update_info *info2;
	info2 = malloc(is);
	if (!info2)
		return -1;

	memcpy(info2, info, sizeof(*info));
	memcpy(info2->dp_buf, info->dp_ptr, dps);

	uint32_t attributes = EFI_VARIABLE_NON_VOLATILE
			      | EFI_VARIABLE_BOOTSERVICE_ACCESS
			      | EFI_VARIABLE_RUNTIME_ACCESS;
	rc = efi_set_variable(varguid, varname, (uint8_t *)info2,
			      is, attributes, 0644);
	error = errno;
	if (rc < 0)
		efi_error("efi_set_variable(%s) failed", varname);
	free(info2);
	errno = error;
	return rc;
}

static int32_t fwup_screen_xsize;
static int32_t fwup_screen_ysize;

typedef struct fwup_resource_s
{
	esre esre;
	bool allocated; /* was this allocated *without* a fwup_resource_iter? */
	update_info *info;
} fwup_resource;

typedef struct fwup_resource_iter_s {
	DIR *dir;
	int dirfd;
	int add_ux_capsule;
	fwup_resource re;
} fwup_resource_iter;

int
fwup_resource_iter_create(fwup_resource_iter **iter)
{
	int error;
	char *path;
	uint32_t x, y;
	char *env;

	if (!iter) {
		efi_error("invalid iter");
		errno = EINVAL;
		return -1;
	}
	fwup_resource_iter *new = calloc(1, sizeof (fwup_resource_iter));
	if (!new) {
		efi_error("calloc(1, %zd) failed", sizeof (fwup_resource_iter));
		errno = ENOMEM;
		return -1;
	}

	path = get_esrt_dir(1);
	if (!path) {
		efi_error("get_esrt_dir(1) failed");
		goto err;
	}

	new->dir = opendir(path);
	if (!new->dir) {
		efi_error("opendir(path) failed");
		goto err;
	}

	new->dirfd = dirfd(new->dir);
	if (new->dirfd < 0) {
		efi_error("dirfd() failed");
		goto err;
	}

	new->add_ux_capsule = false;
	env = getenv("LIBFWUP_ADD_UX_CAPSULE");
	if (env && !strcmp(env, "1") && fwup_get_ux_capsule_info(&x, &y) >= 0)
		new->add_ux_capsule = true;

	*iter = new;
	return 0;
err:
	error = errno;
	if (new) {
		if (new->dir)
			closedir(new->dir);
		free(new);
	}
	errno = error;
	return -1;
}

static void
clear_res(fwup_resource *res)
{
	if (res) {
		bool allocated = res->allocated;
		if (res->info) {
			if (res->info->dp_ptr)
				free(res->info->dp_ptr);
			free(res->info);
		}
		memset(res, 0, sizeof (*res));
		res->allocated = allocated;
	}
}

void
fwup_resource_free(fwup_resource *res)
{
	if (!res)
		return;

	if (res->allocated != true)
		return;

	memset(res, '\0', sizeof(*res));
	free(res);
}

int
fwup_resource_iter_destroy(fwup_resource_iter **iterp)
{
	if (!iterp) {
		efi_error("invalid iter");
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

static fwup_resource fwup_ux_capsule = {
	.esre.fw_type = FWUP_RESOURCE_TYPE_SYSTEM_FIRMWARE,
	.esre.fw_version = 1,
	.esre.lowest_supported_fw_version = 1,
	.esre.capsule_flags = CAPSULE_FLAGS_PERSIST_ACROSS_RESET,
	.esre.last_attempt_version = 1,
	.esre.last_attempt_status = FWUP_LAST_ATTEMPT_STATUS_ERROR_UNSUCCESSFUL,
	.info = NULL
};

static fwup_resource *
make_ux_capsule_entry(void)
{
	int rc;
	fwup_ux_capsule.esre.guid = efi_guid_ux_capsule;

	if (fwup_ux_capsule.info == NULL) {
		rc = get_info(&fwup_ux_capsule.esre.guid, 0, &fwup_ux_capsule.info);
		if (rc < 0) {
			efi_error("get_info() failed");
			return NULL;
		}
	}
	return &fwup_ux_capsule;
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
			if (errno != 0) {
				efi_error("readdir failed");
				return -1;
			}
			if (iter->add_ux_capsule) {
				iter->add_ux_capsule = false;
				*re = make_ux_capsule_entry();
				if (*re)
					return 1;
			} else if (fwup_ux_capsule.info) {
				free_info(fwup_ux_capsule.info);
				fwup_ux_capsule.info = NULL;
			}

			return 0;
		}
		if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
			break;
	}

	int dfd = openat(iter->dirfd, entry->d_name, O_RDONLY|O_DIRECTORY);
	if (dfd < 0) {
		efi_error("openat() failed");
		return -1;
	}

	char *class = NULL;
	get_string_from_file(dfd, "fw_class", &class);
	int rc = efi_str_to_guid(class, &res->esre.guid);
	if (rc < 0) {
		efi_error("efi_str_to_guid() failed");
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
	if (rc < 0) {
		efi_error("get_info() failed");
		return rc;
	}

	res->info->capsule_flags = res->esre.capsule_flags;

	*re = res;

	return 1;
}

int
fwup_set_guid_forced(fwup_resource_iter *iter, fwup_resource **re,
		     const efi_guid_t *guid, bool force)
{
	fwup_resource *res;

	errno = 0;
	if (!iter && (!re && !force)) {
		efi_error("invalid argument '%s'", iter ? "iter" : "re");
		errno = EINVAL;
		return -1;
	}
	if (iter) {
		res = &iter->re;
		res->esre.guid = *guid;
		*re = res;
	} else if (force) {
		res = calloc(1, sizeof (*res));
		if (!res) {
			efi_error("couldn't allocate resource");
			errno = ENOMEM;
			return -1;
		}
		res->esre.guid = *guid;
		res->allocated = true;
		*re = res;
	} else {
		efi_error("No such guid");
		errno = ENOENT;
		return -1;
	}
	return 1;
}

int
fwup_set_guid(fwup_resource_iter *iter, fwup_resource **re,
	      const efi_guid_t *guid)
{
	return fwup_set_guid_forced(iter, re, guid, false);
}

int
fwup_clear_status(fwup_resource *re)
{
	if (!re) {
		efi_error("invalid resource");
		errno = EINVAL;
		return -1;
	}

	int rc;

	re->info->status = 0;

	rc = put_info(re->info);
	if (rc < 0)
		efi_error("put_info() failed");
	return rc;
}

int
fwup_get_guid(fwup_resource *re, efi_guid_t **guid)
{
	if (!re || !guid) {
		efi_error("invalid %s", guid ? "resource" : "guid");
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
		efi_error("invalid %s", version ? "resource" : "version");
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
		efi_error("invalid %s", type ? "resource" : "type");
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
		efi_error("invalid %s", version ? "resource" : "version");
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
		efi_error("invalid %s", status ? "resource" : "status");
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
		efi_error("invalid argument");
		errno = EINVAL;
		return -1;
	}

	if (!re->info->status) {
		efi_error("invalid status");
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
	int rc;

	char *shim_fs_path_tmpl = NULL;
	char *fwup_fs_path_tmpl = NULL;
	uint8_t fwup_esp_path_tmpl[] = "\\fwup";

	char *shim_fs_path_tmp = NULL;
	char *fwup_fs_path_tmp = NULL;
	char *fwup_esp_path_tmp = NULL;

	uint64_t firmware_bits = 0;

	rc = asprintf(&shim_fs_path_tmpl, "%s/EFI/%s/shim",
		      esp_mountpoint, FWUP_EFI_DIR_NAME);
	if (rc < 0) {
		efi_error("asprintf failed");
		goto out;
	}

	rc = asprintf(&fwup_fs_path_tmpl, "%s/EFI/%s/fwup",
		      esp_mountpoint, FWUP_EFI_DIR_NAME);
	if (rc < 0) {
		efi_error("asprintf failed");
		goto out;
	}

	firmware_bits = get_value_from_file_at_dir("/sys/firmware/efi/",
						   "fw_platform_size");
	char **arch_names = firmware_bits == 64 ? arch_names_64
						 : arch_names_32;
	int n_arches = firmware_bits == 64 ? n_arches_64 : n_arches_32;
	int i;

	*shim_fs_path = NULL;
	*fwup_fs_path = NULL;
	*fwup_esp_path = NULL;

	i = find_matching_file(shim_fs_path_tmpl, ".efi", arch_names,
			       n_arches, &shim_fs_path_tmp);

	i = find_matching_file(fwup_fs_path_tmpl, ".efi", arch_names,
				       n_arches, &fwup_fs_path_tmp);
	if (i < 0) {
		efi_error("could not find shim or fwup on ESP");
		errno = ENOENT;
		ret = i;
		goto out;
	}
	rc = asprintf(&fwup_esp_path_tmp, "%s%s.efi", fwup_esp_path_tmpl,
		      arch_names[i]);
	if (rc < 0) {
		efi_error("asprintf failed");
		goto out;
	}

	if (shim_fs_path_tmp) {
		*shim_fs_path = strdup(shim_fs_path_tmp);
		if (!*shim_fs_path) {
			efi_error("strdup failed");
			goto out;
		}
	}
	if (fwup_fs_path_tmp) {
		*fwup_fs_path = strdup(fwup_fs_path_tmp);
		if (!*fwup_fs_path) {
			efi_error("strdup failed");
			goto out;
		}
	}
	if (fwup_esp_path_tmp)
		*fwup_esp_path = fwup_esp_path_tmp;

	free(shim_fs_path_tmpl);
	free(fwup_fs_path_tmpl);

	return 0;
out:
	if (shim_fs_path_tmpl)
		free(shim_fs_path_tmpl);
	if (fwup_fs_path_tmpl)
		free(fwup_fs_path_tmpl);
	if (*shim_fs_path)
		free(*shim_fs_path);
	if (*fwup_fs_path)
		free(*fwup_fs_path);
	if (fwup_esp_path_tmp)
		free(fwup_esp_path_tmp);
	return ret;
}

static int
add_to_boot_order(uint16_t boot_entry)
{
	uint16_t *boot_order = NULL, *new_boot_order = NULL;
	size_t boot_order_size = 0;
	uint32_t attr = EFI_VARIABLE_NON_VOLATILE |
			EFI_VARIABLE_BOOTSERVICE_ACCESS |
			EFI_VARIABLE_RUNTIME_ACCESS;
	int rc;
	unsigned int i = 0;

	rc = efi_get_variable_size(efi_guid_global, "BootOrder",
				   &boot_order_size);
	if (rc == ENOENT) {
		boot_order_size = 0;
		rc = 0;
		efi_error_clear();
	} else if (rc < 0) {
		efi_error("efi_get_variable_size() failed");
		return rc;
	}

	if (boot_order_size != 0) {
		rc = efi_get_variable(efi_guid_global, "BootOrder",
				      (uint8_t **)&boot_order, &boot_order_size,
				      &attr);
		if (rc < 0) {
			efi_error("efi_get_variable() failed");
			goto out;
		}

		for (i = 0; i < boot_order_size / sizeof (uint16_t); i++) {
			uint16_t val = boot_order[i];
			if (val == boot_entry) {
				rc = 0;
				goto out;
			}
		}
	}

	new_boot_order = malloc(boot_order_size + sizeof (uint16_t));
	if (!new_boot_order) {
		efi_error("calloc(1, %zd) failed",
			  boot_order_size + sizeof (uint16_t));
		return -1;
	}
	if (boot_order_size != 0)
		memcpy(new_boot_order, boot_order, boot_order_size);

	i = boot_order_size / sizeof (uint16_t);
	new_boot_order[i] = boot_entry;
	boot_order_size += sizeof (uint16_t);

	rc = efi_set_variable(efi_guid_global, "BootOrder",
			      (uint8_t *)new_boot_order, boot_order_size,
			      attr, 0644);
	if (rc < 0)
		efi_error("efi_set_variable() failed");

out:
	if (boot_order)
		free(boot_order);
	if (new_boot_order)
		free(new_boot_order);
	return rc;
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

	uint8_t *opt=NULL;
	ssize_t opt_size=0;
	uint32_t attributes = LOAD_OPTION_ACTIVE;

	rc = get_paths(&shim_fs_path, &fwup_fs_path, &fwup_esp_path);
	if (rc < 0) {
		efi_error("could not find paths for shim and fwup");
		return -1;
	}

	if (!shim_fs_path)
		use_fwup_path = 1;

	sz = efi_generate_file_device_path(dp_buf, dp_size, use_fwup_path
							    ? fwup_fs_path
							    : shim_fs_path,
					   EFIBOOT_OPTIONS_IGNORE_FS_ERROR|
					   EFIBOOT_ABBREV_HD);
	if (sz < 0) {
		efi_error("efi_generate_file_device_path() failed");
		goto out;
	}

	dp_size=sz;
	dp_buf = calloc(1, dp_size);
	if (!dp_buf) {
		efi_error("calloc(1, %zd) failed", dp_size);
		goto out;
	}

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
	if (sz != dp_size) {
		efi_error("efi_generate_file_device_path() failed");
		goto out;
	}

	rc = asprintf(&label, "Linux-Firmware-Updater %s", fwup_esp_path);
	if (rc < 0) {
		efi_error("asprintf() failed");
		goto out;
	}

	sz = efi_loadopt_create(opt, opt_size, attributes,
				  (efidp)dp_buf, dp_size,
				  (uint8_t *)label,
				  (uint8_t *)loader_str, loader_sz);
	if (sz < 0) {
		efi_error("efi_loadopt_create() failed");
		goto out;
	}
	opt = calloc(1, sz);
	if (!opt) {
		efi_error("calloc(1, %zd) failed", sz);
		goto out;
	}
	opt_size = sz;
	sz = efi_loadopt_create(opt, opt_size, attributes,
				  (efidp)dp_buf, dp_size,
				  (uint8_t *)label,
				  (uint8_t *)loader_str, loader_sz);
	if (sz != opt_size) {
		efi_error("loadopt size was unreasonable.");
		goto out;
	}

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
		if (rc < 0) {
			efi_error("sscanf failed");
			goto out;
		}
		if (rc != 1)
			continue;
		if (scanned != 8)
			continue;

		int div = entry / (sizeof(set_entries[0]) * 8);
		int mod = entry % (sizeof(set_entries[0]) * 8);

		set_entries[div] |= 1 << mod;

		rc = efi_get_variable(*guid, name, &var_data, &var_data_size,
				      &attr);
		if (rc < 0) {
			efi_error("efi_get_variable() failed");
			continue;
		}

		loadopt = (efi_load_option *)var_data;
		if (!efi_loadopt_is_valid(loadopt, var_data_size)) {
			efi_error("load option was invalid");
do_next:
			free(var_data);
			continue;
		}

		sz = efi_loadopt_pathlen(loadopt, var_data_size);
		if (sz != efidp_size((efidp)dp_buf)) {
			efi_error("device path doesn't match");
			goto do_next;
		}

		efidp found_dp = efi_loadopt_path(loadopt, var_data_size);
		if (memcmp(found_dp, dp_buf, sz)) {
			efi_error("device path doesn't match");
			goto do_next;
		}

		if ((ssize_t)var_data_size != opt_size) {
			efi_error("variable data doesn't match");
			goto do_next;
		}

		if (memcmp(loadopt, opt, opt_size)) {
			efi_error("load option doesn't match");
			goto do_next;
		}

		found = 1;
		boot_next = entry;
		efi_error_clear();
		break;
	}
	if (rc < 0) {
		efi_error("failed to find boot variable");
		goto out;
	}

	if (found) {
		efi_loadopt_attr_set(loadopt, LOAD_OPTION_ACTIVE);
		rc = efi_set_variable(*guid, name, var_data,
				      var_data_size, attr, 0644);
		free(var_data);
		if (rc < 0) {
			efi_error("could not set boot variable active");
			goto out;
		}
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

		if (boot_next >= 0x10000) {
			efi_error("no free boot variables!");
			goto out;
		}

		sprintf(boot_next_name, "Boot%04hX", boot_next & 0xffff);
		rc = efi_set_variable(efi_guid_global, boot_next_name, opt,
				      opt_size,
				      EFI_VARIABLE_NON_VOLATILE |
				      EFI_VARIABLE_BOOTSERVICE_ACCESS |
				      EFI_VARIABLE_RUNTIME_ACCESS,
				      0644);
		if (rc < 0) {
			efi_error("could not set boot variable");
			goto out;
		}
	}

	/* XXX TODO: conditionalize this on the UEFI version. */
	rc = add_to_boot_order(boot_next);
	if (rc < 0)
		efi_error("could not set BootOrder");
	else
		efi_error_clear();

	uint16_t real_boot_next = boot_next;
	rc = efi_set_variable(efi_guid_global, "BootNext",
			      (uint8_t *)&real_boot_next, 2,
			      EFI_VARIABLE_NON_VOLATILE |
			      EFI_VARIABLE_BOOTSERVICE_ACCESS |
			      EFI_VARIABLE_RUNTIME_ACCESS,
			      0644);
	if (rc < 0)
		efi_error("could not set BootNext");
	else
		efi_error_clear();
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
	rc = asprintf(&fullpath, "%s%s", esp_mountpoint, relpath);
	if (rc < 0)
		fullpath = NULL;

out:
	free(relpath);
	return fullpath;
}

static bool use_existing_media_path = true;

/**
 * fwup_use_existing_media_path:
 * @use_existing_media_path_: 0 or 1
 *
 * set use_existing_media_path, used in get_fd_and_media_path
 * to know if we have to reuse the filename register for this
 * update GUID in the firmware.
 */
void
fwup_use_existing_media_path(int use_existing_media_path_)
{
	use_existing_media_path = use_existing_media_path_;
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
	char *directory = NULL;
	char *fullpath = NULL;
	int fd = -1;
	int rc;
	bool make_new_path = false;

	/* look for an existing variable that we've used before for this
	 * update GUID, and reuse the filename so we don't wind up
	 * littering the filesystem with old updates */
	if (use_existing_media_path)
		fullpath = get_existing_media_path (info);

	if (fullpath) {
		fd = open(fullpath, O_CREAT|O_TRUNC|O_CLOEXEC|O_RDWR, 0600);
		if (fd < 0) {
			efi_error("open of %s failed", fullpath);
			if (errno == ENOENT)
				make_new_path = true;
			else
				goto out;
		}
	} else {
		make_new_path = true;
	}

	if (make_new_path) {
		/* fall back to creating a new file from scratch */
		rc = asprintf(&directory,
			      "%s/EFI/%s/fw",
			      esp_mountpoint,
			      FWUP_EFI_DIR_NAME);
		if (rc < 0) {
			efi_error("asprintf directory failed");
			return fd;
		}
		rc = mkdir(directory, 0775);
		if (rc < 0 && errno != EEXIST) {
			efi_error("failed to make %s", directory);
			goto out;
		}
		rc = asprintf(&fullpath,
			      "%s/fwupdate-XXXXXX.cap",
			      directory);
		if (rc < 0) {
			efi_error("asprintf fullpath failed");
			goto out;
		}
		fd = mkostemps(fullpath, 4, O_CREAT|O_TRUNC|O_CLOEXEC);
		if (fd < 0) {
			efi_error("mkostemps(%s) failed", fullpath);
			goto out;
		}
		efi_error_clear();
	}

	/* success, so take ownership of the string */
	if (path) {
		*path = fullpath;
		fullpath = NULL;
	}
out:
	free(directory);
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

static int
get_bmp_size(uint8_t *buf, size_t buf_size, int *height, int *width)
{
	uint32_t ui32;

	if (buf_size < 26) {
invalid:
		errno = EINVAL;
		return -1;
	}

	if (memcmp(buf, "BM", 2) != 0)
		goto invalid;

	memcpy(&ui32, buf+10, 4);
	if (ui32 < 26)
		goto invalid;

	memcpy(&ui32, buf+14, 4);
	if (ui32 < 26 - 14)
		goto invalid;

	memcpy(width, buf+18, 4);
	memcpy(height, buf+22, 4);

	return 0;
}

#define fbdir "/sys/bus/platform/drivers/efi-framebuffer/efi-framebuffer.0"
static int
read_efifb_info(int *height, int *width)
{
	*height = get_value_from_file_at_dir(fbdir, "height");
	*width = get_value_from_file_at_dir(fbdir, "width");

	return 0;
}

typedef struct {
	efi_guid_t guid;
	uint32_t header_size;
	uint32_t flags;
	uint32_t capsule_image_size;
} efi_capsule_header_t;

static int
write_ux_capsule_header(FILE *fin, FILE *fout)
{
	int rc = -1;
	int bgrt_x, bgrt_y;
	int bgrt_height, bgrt_width;
	int screen_x, screen_y;
	int height, width;
	uint8_t *buf = NULL;
	size_t buf_size = 0;
	ux_capsule_header_t header;
	size_t size;
	int error;
	long header_pos;
	efi_capsule_header_t capsule_header = {
		.flags = CAPSULE_FLAGS_PERSIST_ACROSS_RESET,
		.guid = efi_guid_ux_capsule,
		.header_size = sizeof(efi_capsule_header_t),
		.capsule_image_size = 0
	};

	bgrt_x = get_value_from_file_at_dir("/sys/firmware/acpi/bgrt",
					    "xoffset");
	if (bgrt_x < 0) {
		rc = bgrt_x;
		goto out;
	}

	bgrt_y = get_value_from_file_at_dir("/sys/firmware/acpi/bgrt",
					    "yoffset");
	if (bgrt_y < 0) {
		rc = bgrt_y;
		goto out;
	}

	rc = read_file_at_dir("/sys/firmware/acpi/bgrt", "image",
			      &buf, &buf_size);
	if (rc < 0)
		return rc;

	rc = get_bmp_size(buf, buf_size, &bgrt_height, &bgrt_width);
	if (rc < 0)
		goto out;

	rc = read_efifb_info(&screen_x, &screen_y);
	if (rc < 0)
		goto out;

	header_pos = ftell(fin);
	if (header_pos < 0)
		goto out;
	buf_size = fread(buf, 1, 26, fin);
	if (buf_size < 26)
		goto out;

	rc = get_bmp_size(buf, buf_size, &height, &width);
	if (rc < 0)
		goto out;

	rc = fseek(fin, 0, SEEK_END);
	if (rc < 0)
		goto out;

	capsule_header.capsule_image_size =
		ftell(fin) +
		sizeof(efi_capsule_header_t) +
		sizeof(header);

	rc = fseek(fin, header_pos, SEEK_SET);
	if (rc < 0)
		goto out;

	memset(&header, '\0', sizeof(header));
	header.version = 1;
	header.image_type = 0;
	header.reserved = 0;
	header.x_offset = (screen_x / 2) - (width / 2);
	header.y_offset = bgrt_y + bgrt_height;

	size = fwrite(&capsule_header, capsule_header.header_size, 1, fout);
	if (size != 1) {
		rc = -1;
		goto out;
	}

	size = fwrite(&header, sizeof(header), 1, fout);
	if (size != 1) {
		rc = -1;
		goto out;
	}
	fflush(fout);

	size = fcopy_file(fin, fout);
	if (size == 0) {
		rc = -1;
		goto out;
	}
	fflush(fout);

	rc = 0;
out:
	error = errno;
	if (buf)
		free(buf);
	errno = error;
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
	if (!re) {
		efi_error("invalid resource");
		errno = EINVAL;
		return -1;
	}

	if (infd < 0) {
		efi_error("invalid file descriptor");
		errno = EINVAL;
		return -1;
	}

	offset = lseek(infd, 0, SEEK_CUR);
	if (offset < 0) {
		efi_error("lseek failed");
		return -1;
	}

	/* get device */
	rc = get_info(&re->esre.guid, 0, &info);
	if (rc < 0) {
		efi_error("get_info failed.");
		goto out;
	}

	/* get destination */
	rc = -1;
	outfd = get_fd_and_media_path(info, &path);
	if (outfd < 0) {
		goto out;
	}

	fin = fdopen(infd, "r");
	if (!fin)
		goto out;

	fout = fdopen(outfd, "w");
	if (!fout)
		goto out;

	if (!efi_guid_cmp(&re->esre.guid, &efi_guid_ux_capsule)) {
		rc = write_ux_capsule_header(fin, fout);
		if (rc < 0)
			goto out;
	}

	rc = fcopy_file(fin, fout);
	if (rc < 0)
		goto out;

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
		efi_error("put_info failed.");
		goto out;
	}

	/* update the firmware before the bootloader runs */
	rc = set_up_boot_next();
	if (rc < 0)
		goto out;

out:
	error = errno;
	if (path)
		free(path);
	if (fin)
		fclose(fin);
	if (fout) {
		fflush(fout);
		fclose(fout);
	}
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
	int rc = -1;
	update_info *info = NULL;
	int error;
	FILE *fin = NULL, *fout = NULL;

	/* check parameters */
	if (!re) {
		efi_error("invalid resource");
		errno = EINVAL;
		return -1;
	}

	if (buf == NULL || sz == 0) {
		efi_error("invalid %s", buf == NULL ? "buffer" : "size");
		errno = EINVAL;
		goto out;
	}

	/* get device */
	rc = get_info(&re->esre.guid, 0, &info);
	if (rc < 0) {
		efi_error("get_info() failed.");
		goto out;
	}

	/* get destination */
	fd = get_fd_and_media_path(info, &path);
	if (fd < 0) {
		efi_error("get_fd_and_media_path() failed");
		goto out;
	}

	rc = -1;
	fin = fmemopen((void *)buf, sz, "r");
	if (!fin)
		goto out;

	fout = fdopen(fd, "w");
	if (!fout)
		goto out;

	if (!efi_guid_cmp(&re->esre.guid, &efi_guid_ux_capsule)) {
		rc = write_ux_capsule_header(fin, fout);
		if (rc < 0)
			goto out;
	}

	rc = fcopy_file(fin, fout);
	if (rc < 0)
		goto out;

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
		efi_error("put_info failed.");
		goto out;
	}

	/* update the firmware before the bootloader runs */
	rc = set_up_boot_next();
	if (rc < 0)
		goto out;

	rc = 0;
out:
	error = errno;
	free_info(info);
	if (fout)
		fclose(fout);
	if (fin)
		fclose(fin);
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
			efi_error(_("Could not create iterator"));
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
						 4096);
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
					     (const_efidp)info->dp_ptr, 4096)
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

static int
check_bgrt_status(void)
{
	int version;
	int type;
	int status;

	status = get_value_from_file_at_dir("/sys/firmware/acpi/bgrt",
					    "status");
	if (status != 1) {
		errno = ENOSYS;
		return -1;
	}
	type = get_value_from_file_at_dir("/sys/firmware/acpi/bgrt", "type");
	if (type != 0) {
		errno = EINVAL;
		return -1;
	}
	version = get_value_from_file_at_dir("/sys/firmware/acpi/bgrt",
					     "version");
	if (version != 1) {
		errno = ENOTTY;
		return -1;
	}
	return 0;
}

int
fwup_get_ux_capsule_info(uint32_t *screen_x_size, uint32_t *screen_y_size)
{
	static bool once = false;
	int height, width;
	int rc;

	if (once == true) {
		if (fwup_screen_xsize <= 0 || fwup_screen_ysize <= 0) {
			errno = ENOSYS;
			return -1;
		}
		if (screen_x_size)
			*screen_x_size = fwup_screen_xsize;
		if (screen_y_size)
			*screen_y_size = fwup_screen_ysize;
		return 0;
	}

	rc = check_bgrt_status();
	if (rc < 0)
		return rc;

	rc = read_efifb_info(&height, &width);
	if (rc < 0)
		return rc;

	fwup_screen_xsize = width;
	fwup_screen_ysize = height;
	once = true;
	if (width <= 0 || height <= 0) {
		errno = ENOSYS;
		return -1;
	}

	if (screen_x_size)
		*screen_x_size = fwup_screen_xsize;
	if (screen_y_size)
		*screen_y_size = fwup_screen_ysize;

	return 0;
}

int
fwup_get_debug_log(char **utf8, size_t *size)
{
	int rc;
	efi_guid_t fwupdate_guid = FWUPDATE_GUID;
	uint16_t *data;
	size_t vsize;
	uint32_t attributes;
	char *udata;
	int error;

	if (!utf8 || !size) {
		errno = EINVAL;
		return -EINVAL;
	}

	rc = efi_get_variable(fwupdate_guid, "FWUPDATE_DEBUG_LOG",
			      (uint8_t **)&data, &vsize, &attributes);
	if (rc < 0)
		return rc;

	udata = ucs2_to_utf8(data, (vsize >> 1));
	error = errno;
	free(data);
	errno = error;
	if (!udata) {
		rc = -1;
		return rc;
	}

	*utf8 = udata;
	*size = vsize >> 1;
	return 0;
}
