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
#include <efivar.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fwup.h>
#include "util.h"

static __thread int __fwup_error;

int *
__fwup_error_location(void)
{
	return &__fwup_error;
}


#define EOKAY		0
#define MAX_ERROR	35

static const char const *error_table[MAX_ERROR - ERANGE] = {
	[EOKAY] = "Okay",
};

static __thread char unknown[] = "Unknown error -2147483648";

char *
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

char *
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

#define FWUPDATE_GUID EFI_GUID(0x0abba7dc,0xe516,0x4167,0xbbf5,0x4d,0x9d,0x1c,0x73,0x94,0x16)

typedef struct fwup_resource_iter_s {
	DIR *dir;
	int dirfd;
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

int
fwup_resource_iter_destroy(fwup_resource_iter **iter)
{
	if (!iter) {
		fwup_error = EINVAL;
		return -1;
	}
	if (!*iter)
		return 0;

	if ((*iter)->dir)
		closedir((*iter)->dir);

	free(*iter);
	*iter = NULL;
	return 0;
}

static int
get_uint64_from_file(int dfd, char *file, uint64_t *value)
{
	uint64_t val = 0;
	uint8_t *buf = NULL;
	size_t bufsize = 0;
	int rc;

	rc = read_file_at(dfd, file, &buf, &bufsize);
	if (rc < 0) {
		fwup_error = errno;
		close(dfd);
		return -1;
	}

	val = strtoull((char *)buf, NULL, 0);
	if (val == ULLONG_MAX) {
		fwup_error = errno;
		close(dfd);
		free(buf);
		return -1;
	}
	free(buf);
	*value = val;
	return 0;
}

#define get_value_from_file(dfd, file)					\
	({								\
		uint64_t _val;						\
		int _rc;						\
									\
		_rc = get_uint64_from_file(dfd, file, &_val);		\
		if (_rc < 0)						\
			return -1;					\
		_val;							\
	})

#define get_string_from_file(dfd, file, str)				\
	({								\
		uint8_t *_buf = NULL;					\
		size_t _bufsize = 0;					\
		int _rc;						\
									\
		_rc = read_file_at(dfd, file, &_buf, &_bufsize);	\
		if (_rc < 0)						\
			return -1;					\
									\
		_buf[_bufsize] = '\0';					\
		*str = strndupa(_buf, _bufsize);			\
		free(_buf);						\
		*str;							\
	})

int
fwup_resource_iter_next(fwup_resource_iter *iter, fwup_resource *re)
{
	if (!iter || !re) {
		fwup_error = EINVAL;
		return -1;
	}

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
	int rc = efi_str_to_guid(class, &re->guid);
	if (rc < 0)
		return rc;
	re->fw_type = get_value_from_file(dfd, "fw_type");
	re->fw_version = get_value_from_file(dfd, "fw_version");
	re->last_attempt_status =
			get_value_from_file(dfd, "last_attempt_status");
	re->last_attempt_version =
			get_value_from_file(dfd, "last_attempt_version");
	re->lowest_supported_fw_version =
			get_value_from_file(dfd, "lowest_supported_fw_version");
	re->hardware_instance = get_value_from_file(dfd, "hardware_instance");

	uint8_t *buf = NULL;
	size_t bufsize = 0;

	rc = read_file_at(dfd, "fw_class", &buf, &bufsize);
	if (rc < 0) {
		fwup_error = errno;
		close(dfd);
		return -1;
	}
	close(dfd);
	rc = efi_str_to_guid((char *)buf, &re->guid);
	fwup_error = errno;
	free(buf);
	if (rc < 0)
		return rc;
	return 1;
}

int
fwup_set_up_update(efi_guid_t *guid, int fd)
{
	return 0;
}
