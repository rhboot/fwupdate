/*
 * libfw - library interface to apply firmware updates
 *
 * Copyright 2015 Red Hat, Inc.
 *
 * See "COPYING" for license terms.
 *
 * Author: Peter Jones <pjones@redhat.com>
 */

#include <efivar.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fwup.h"

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

int
fwup_supported(void)
{
	struct stat buf;
	int rc;

	rc = stat("/sys/firmware/efi/esrt/entries", &buf);
	if (rc < 0)
		return 0;
	if (buf.st_nlink < 3)
		return 0;
	return 1;
}

#define FWUPDATE_GUID EFI_GUID(0x0abba7dc,0xe516,0x4167,0xbbf5,0x4d,0x9d,0x1c,0x73,0x94,0x16)

typedef struct fwup_resource_iter {
	int a;
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

	DIR *dir;
	int dfd;

	dir = opendir("/sys/firmware/efi/esrt/");
	if (!dir) {
		fwup_error = errno;
		return -1;
	}

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

	free(*iter);
	*iter = NULL;
	return 0;
}
