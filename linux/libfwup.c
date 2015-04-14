/*
 * libfw - library interface to apply firmware updates
 *
 * Copyright 2015 Red Hat, Inc.
 *
 * See "COPYING" for license terms.
 *
 * Author: Peter Jones <pjones@redhat.com>
 */

#include <err.h>
#include <dirent.h>
#include <efivar.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define EFI_TIME efi_time_t

#include <fwup.h>
#include "util.h"
#include "ucs2.h"
#include "fwup-efi.h"
#include "disk.h"

static __thread int __fwup_error;

int *
__fwup_error_location(void)
{
	return &__fwup_error;
}

#define EOKAY	0
#define MAX_ERROR	35

static const char const *error_table[MAX_ERROR - ERANGE] = {
	[EOKAY] = "Okay",
};

static __thread char unknown[] = "Unknown error -2147483648";

const char const *
fwup_strerror(int error)
{
	if (error < 0 || error >= MAX_ERROR) {
		sprintf(unknown, "Unknown error %d\n", error);
		return unknown;
	}
	if (error > 0 && error <= ERANGE)
		return strerror(error);
	if (error == 0)
		return dgettext("libfwup", error_table[error]);
	return dgettext("libfwup", error_table[error - ERANGE]);
}

const char const *
fwup_strerror_r(int error, char *buf, size_t buflen)
{
	if (!buf || !buflen) {
		fwup_error = ERANGE;
		return NULL;
	}

	size_t n = 0;
	if (error < 0 || error >= MAX_ERROR) {
		return strerror_r(error, buf, buflen);
		n = snprintf(NULL, 0, "Unknown error %d", error);
		if (n < buflen) {
			fwup_error = EINVAL;
			return NULL;
		}
		snprintf(buf, buflen, "Unknown error %d", error);
		return buf;
	}

	if (error > 0 && error <= ERANGE)
		return strerror_r(error, buf, buflen);

	if (error == 0)
		return dgettext("libfwup", error_table[error]);

	n = strlen(dgettext("libfwup", error_table[error - ERANGE])) + 1;
	if (n < buflen) {
		fwup_error = EINVAL;
		return NULL;
	}
	strcpy(buf, dgettext("libfwup", error_table[error - ERANGE]));
	return buf;
}

static ssize_t
fwup_make_hd(uint8_t *buf, ssize_t size, char *disk, uint32_t partition)
{
	ssize_t rc;
	if (size == 0) {
		rc = efidp_make_hd(NULL, 0, 0, 0, 0, NULL, 0, 0);
		if (!rc)
			warn("efidp_make_hd(0) failed");
		return rc;
	}

	int fd;
	fd = open(disk, O_RDONLY);
	if (fd < 0) {
		warn("could not open %s", disk);
		return fd;
	}

	uint64_t start = 0;
	uint64_t part_size = 0;
	char signature[32] = "";
	uint8_t mbr_type = 0;
	uint8_t signature_type = -1;
	rc = disk_get_partition_info(fd, partition, &start, &part_size,
				     signature, &mbr_type, &signature_type);
	__typeof__(errno) saved_errno = errno;
	close(fd);
	errno = saved_errno;
	if (rc < 0) {
		warn("disk_get_partition_info failed");
		return rc;
	}

	rc = efidp_make_hd(buf, size, partition, start, part_size,
			   (uint8_t *)signature, mbr_type, signature_type);
	if (!rc)
		warn("efidp_make_hd() failed");
	return rc;
}

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

int
fwup_supported(void)
{
	struct stat buf;
	int rc;

	rc = stat(get_esrt_dir(1), &buf);
	if (rc < 0)
		return 0;
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

	rc = efi_guid_to_str(guid, &guidstr);
	if (rc < 0)
		goto err;
	guidstr = onstack(guidstr, strlen(guidstr)+1);

	rc = asprintf(&varname, "fwupdate-%s-%"PRIx64, guidstr, hw_inst);
	if (rc < 0)
		goto err;
	varname = onstack(varname, strlen(varname)+1);

	uint8_t *data = NULL;
	size_t data_size = 0;
	uint32_t attributes;

	rc = efi_get_variable(varguid, varname, &data, &data_size, &attributes);
	if (rc < 0) {
		if (errno != ENOENT)
			goto err;
		local = calloc(1, sizeof (*local));
		if (!local) {
			rc = -1;
			goto err;
		}

		local->update_info_version = UPDATE_INFO_VERSION;
		local->guid = *guid;
		local->hw_inst = hw_inst;

		local->dp_ptr = calloc(1, 1024);
		if (!local->dp_ptr) {
alloc_err:
			fwup_error = errno;
			free_info(local);
			return rc;
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

	if (data_size < sizeof (*local)) {
get_err:
		errno = EINVAL;
		free(local);
		return -1;
	}
	local = (update_info *)data;

	if (local->update_info_version != UPDATE_INFO_VERSION)
		goto get_err;

	efidp_header *dp = malloc(efidp_size((efidp)local->dp));
	if (!dp)
		goto get_err;

	memcpy(dp, local->dp, efidp_size((efidp)local->dp));
	local->dp_ptr = dp;

	*info = local;
	return 0;
err:
	fwup_error = errno;
	return -1;
}

static int
put_info(update_info *info)
{
	efi_guid_t varguid = FWUPDATE_GUID;
	ssize_t dps, is;
	char *guidstr = NULL;
	char *varname;
	int rc;

	rc = efi_guid_to_str(&info->guid, &guidstr);
	if (rc < 0) {
err:
		fwup_error = errno;
		return rc;
	}
	guidstr = onstack(guidstr, strlen(guidstr)+1);

	rc = asprintf(&varname, "fwupdate-%s-%"PRIx64, guidstr, info->hw_inst);
	if (rc < 0)
		goto err;
	varname = onstack(varname, strlen(varname)+1);

	dps = efidp_size((efidp)info->dp_ptr);
	is = (sizeof (*info)) + dps - (sizeof (info->dp_ptr));

	update_info *info2;
	info2 = alloca(is);
	if (!info2) {
		fwup_error = errno;
		return -1;
	}
	memcpy(info2, info, sizeof(*info));
	memcpy(info2->dp, info->dp_ptr, dps);

	uint32_t attributes = EFI_VARIABLE_NON_VOLATILE
			      | EFI_VARIABLE_BOOTSERVICE_ACCESS
			      | EFI_VARIABLE_RUNTIME_ACCESS;
	rc = efi_set_variable(varguid, varname, (uint8_t *)info2,
			      is, attributes);
	fwup_error = errno;
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
	if (!iter) {
		fwup_error = EINVAL;
		return -1;
	}
	fwup_resource_iter *new = calloc(1, sizeof (fwup_resource_iter));
	if (!new) {
		fwup_error = ENOMEM;
		return -1;
	}

	new->dir = opendir(get_esrt_dir(1));
	if (!new->dir) {
		fwup_error = errno;
		return -1;
	}
	new->dirfd = dirfd(new->dir);
	if (new->dirfd < 0) {
		fwup_error = errno;
		return -1;
	}

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
		fwup_error = EINVAL;
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
		fwup_error = EINVAL;
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
				fwup_error = errno;
				return -1;
			}
			return 0;
		}
		if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
			break;
	}

	int dfd = openat(iter->dirfd, entry->d_name, O_RDONLY|O_DIRECTORY);
	if (dfd < 0) {
		fwup_error = errno;
		return -1;
	}

	char *class = NULL;
	get_string_from_file(dfd, "fw_class", &class);
	int rc = efi_str_to_guid(class, &res->esre.guid);
	if (rc < 0) {
		fwup_error = errno;
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
		fwup_error = errno;
		return rc;
	}
	res->info->capsule_flags = res->esre.capsule_flags;

	*re = res;

	return 1;
}

#if 0
#ifdef pjones
static uint8_t test_data[] = {
  0x02, 0x01, 0x0c, 0x00, 0xd0, 0x41, 0x03, 0x0a, 0x00, 0x00, 0x00, 0x00,

  0x01, 0x01, 0x06, 0x00, 0x02, 0x1f,

  0x03, 0x12, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

  0x04, 0x01, 0x2a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x2a, 0x27, 0x84, 0x65, 0xb9, 0xd7, 0x2a, 0x44, 0xb8, 0xa4, 0x19, 0xb5,
  0xec, 0x45, 0x66, 0xf4, 0x02, 0x02,

  0x7f, 0xff, 0x04, 0x00,
};
static const_efidp test_dp = (const_efidp)test_data;
#else
static uint8_t test_data[] = {
  0x02, 0x01, 0x0c, 0x00, 0xd0, 0x41, 0x03, 0x0a, 0x00, 0x00, 0x00, 0x00,

  0x01, 0x01, 0x06, 0x00, 0x02, 0x1f,

  0x03, 0x12, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,

  0x04, 0x01, 0x2a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x48, 0x1f, 0x36, 0x65, 0x49, 0x87, 0xab, 0x44, 0xb2, 0x58, 0x03, 0x9d,
  0x6f, 0x4b, 0xdb, 0x5c, 0x02, 0x02,

  0x7f, 0xff, 0x04, 0x00
};
static const_efidp test_dp = (const_efidp)test_data;
#endif
#endif

int
fwup_clear_status(fwup_resource *re)
{
	if (!re) {
		fwup_error = EINVAL;
		return -1;
	}

	int rc;

	re->info->status = 0;

	rc = put_info(re->info);
	fwup_error = errno;
	return rc;
}

int
fwup_get_guid(fwup_resource *re, efi_guid_t **guid)
{
	if (!re || !guid) {
		fwup_error = EINVAL;
		return -1;
	}

	*guid = &re->esre.guid;
	return 0;
}

int
fwup_get_fw_version(fwup_resource *re, uint32_t *version)
{
	if (!re || !version) {
		fwup_error = EINVAL;
		return -1;
	}

	*version = re->esre.fw_version;
	return 0;
}

int
fwup_get_lowest_supported_fw_version(fwup_resource *re, uint32_t *version)
{
	if (!re || !version) {
		fwup_error = EINVAL;
		return -1;
	}

	*version = re->esre.lowest_supported_fw_version;
	return 0;
}

int
fwup_get_attempt_status(fwup_resource *re, uint32_t *status)
{
	if (!re || !status) {
		fwup_error = EINVAL;
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
		fwup_error = EINVAL;
		return -1;
	}

	if (!re->info->status) {
		fwup_error = ENOENT;
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

int
fwup_set_up_update(fwup_resource *re, uint64_t hw_inst, int infd)
{
	int rc;
	char *filename = NULL;
	int fd = -1;
	ssize_t sz;
	off_t offset;
	update_info *info = NULL;
	uint8_t *dp_buf = NULL;
	uint16_t *ucs2file = NULL;
	uint16_t ucs2len = 0;

	offset = lseek(infd, 0, SEEK_CUR);

	rc = get_info(&re->esre.guid, 0, &info);
	if (rc < 0) {
		warn("get_info failed.\n");
		goto err;
	}

	if (info->dp_ptr && !efidp_end_entire(info->dp_ptr)) {
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

		if (!ucs2file || ucs2len <= 0)
			goto new;

		char *filetmp = ucs2_to_utf8(ucs2file, ucs2len
						       / sizeof (uint16_t));
		if (!filetmp)
			goto new;
		filetmp = onstack(filetmp, ucs2len / sizeof (uint16_t) + 1);

		untilt_slashes(filetmp);

		rc = asprintf(&filename, "/boot/efi/%s", filetmp);
		if (rc < 0)
			goto new;

		rc = open(filename, O_CREAT|O_TRUNC|O_CLOEXEC|O_RDWR);
		if (rc < 0)
			goto new;
		fd = rc;
		rc = -1;
	} else {
new:
		rc = asprintf(&filename,
			      "/boot/efi/EFI/%s/fw/fwupdate-XXXXXX.cap",
			      FWUP_EFI_DIR_NAME);
		if (rc < 0) {
			warn("asprintf failed");
			goto err;
		}

		rc = mkostemps(filename, 4, O_CREAT|O_TRUNC|O_CLOEXEC|O_RDWR);
		if (rc < 0) {
			warn("mkostemps(%s) failed", filename);
			goto err;
		}
		fd = rc;
		rc = -1;
	}

	while (1) {
		char buf[4096];

		sz = read(infd, &buf, 4096);
		if (sz > 0) {
			ssize_t wsz;
			off_t off = 0;
			while (sz-off) {
				wsz = write(fd, buf+off, sz-off);
				if (wsz < 0 &&
				    (errno == EAGAIN || errno == EINTR))
					continue;
				if (wsz < 0) {
					rc = wsz;
					warn("write failed");
					goto err;
				}
				off += wsz;
			}
			continue;
		}
		rc = sz;
		if (sz < 0 && (errno == EAGAIN || errno == EINTR))
			continue;
		if (sz < 0) {
			warn("read failed");
			goto err;
		}
		if (sz == 0)
			break;
	}
	close(infd);
	infd = -1;
	close(fd);
	fd = -1;

	if (!info->dp_ptr || efidp_end_entire(info->dp_ptr)) {
		ssize_t s;
		ssize_t wsz;
		sz = 0;

		s = efidp_make_acpi_hid(NULL, 0, EFIDP_ACPI_PCI_ROOT_HID, 0);
		if (s < 0) {
			warn("efidp_make_acpi(0) failed");
			goto err;
		}
		sz += s;

		s = efidp_make_pci(NULL, 0, 0x1f, 0x02);
		if (s < 0) {
			warn("efidp_make_pci(0) failed");
			goto err;
		}
		sz += s;

		s = efidp_make_sata(NULL, 0, 0, 0, 0);
		if (s < 0) {
			warn("efidp_make_sata(0) failed");
			goto err;
		}
		sz += s;

		s = fwup_make_hd(NULL, 0, NULL, 0);
		if (s < 0) {
			warn("efidp_make_hd(0) failed");
			goto err;
		}
		sz += s;

		s = efidp_make_file(NULL, 0, filename + 9);
		if (s < 0) {
			warn("efidp_make_file(0) failed");
			goto err;
		}
		sz += s;

		s = efidp_make_end_entire(NULL, 0);
		if (s < 0) {
			warn("efidp_make_end_entire(0) failed");
			goto err;
		}
		sz += s;

		tilt_slashes(filename);
		dp_buf = calloc(1, sz);
		if (!dp_buf)
			goto err;
		wsz = 0;

		s = efidp_make_acpi_hid(dp_buf, sz, EFIDP_ACPI_PCI_ROOT_HID, 0);
		if (s < 0) {
			warn("efidp_make_acpi() failed");
			goto err;
		}
		wsz += s;

		s = efidp_make_pci(dp_buf+wsz, sz-wsz, 0x1f, 0x02);
		if (s < 0) {
			warn("efidp_make_pci() failed");
			goto err;
		}
		wsz += s;

		fd = open("/dev/sda", O_RDONLY);
		if (fd < 0) {
			warn("could not open /dev/sda");
			goto err;
		}

		uint8_t host, channel, id, lun;
		rc = efi_linux_scsi_idlun(fd, &host, &channel, &id, &lun);
		if (rc < 0) {
			warn("failed to detect id and lun");
			goto err;
		}

		close(fd);
		fd = -1;

		s = efidp_make_sata(dp_buf+wsz, sz-wsz, host, 0, 0);
		if (s < 0) {
			warn("efidp_make_sata() failed");
			goto err;
		}
		wsz += s;

		s = fwup_make_hd(dp_buf+wsz, sz-wsz, "/dev/sda", 1);
		if (s < 0) {
			warn("efidp_make_hd() failed");
			goto err;
		}
		wsz += s;

		s = efidp_make_file(dp_buf+wsz, sz-wsz, filename + 9);
		if (s < 0) {
			warn("efidp_make_file() failed");
			goto err;
		}
		wsz += s;

		s = efidp_make_end_entire(dp_buf+wsz, sz-wsz);
		if (s < 0) {
			warn("efidp_make_end_entire() failed");
			goto err;
		}
		wsz += s;

		efidp_header *dp = (efidp_header *)dp_buf;

		if (info->dp_ptr)
			free(info->dp_ptr);
		info->dp_ptr = dp;
	}

	info->status = FWUPDATE_ATTEMPT_UPDATE;

	rc = put_info(info);
	if (rc < 0) {
		warn("put_info failed.\n");
		goto err;
	}

	free_info(info);
	free(filename);
	return 1;
err:
	fwup_error = errno;
	lseek(infd, offset, SEEK_SET);
	if (dp_buf)
		free(dp_buf);
	if (filename)
		free(filename);
	if (info)
		free_info(info);
	if (fd > 0)
		close(fd);

	return rc;
}
