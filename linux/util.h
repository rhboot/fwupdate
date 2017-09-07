/*
 * util.h - common include crud
 *
 * Copyright 2015 Red Hat, Inc.
 *
 * See "COPYING" for license terms.
 *
 * Author: Peter Jones <pjones@redhat.com>
 */
#ifndef LIBFW_UTIL_H
#define LIBFW_UTIL_H

#ifndef LOCALEDIR
#define LOCALEDIR "/usr/share/locale"
#endif

#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#define  _(String) gettext (String)
#define Q_(String) dgettext (NULL, String)
#define N_(String) (String)
#define C_(Context,String) dgettext (Context,String)
#define NC_(Context, String) (String)
#define EMPTY ""

#ifndef FWUP_ESP_MOUNTPOINT
#define FWUP_ESP_MOUNTPOINT "/boot/efi"
#endif

#ifndef FWUP_EFI_DIR_NAME
#define FWUP_EFI_DIR_NAME "fixme"
#endif

extern int quiet;

#define qprintf(fmt, args...) ({					\
		if (!quiet) {						\
			printf((fmt), ## args);				\
		}							\
	})

static inline int
__attribute__((unused))
read_file_at(int dfd, const char *name, uint8_t **buf, size_t *bufsize)
{
	int saved_errno;
	uint8_t *p;
	size_t size = 4096;
	size_t filesize = 0;
	ssize_t s = 0;

	int fd = openat(dfd, name, O_RDONLY);
	if (fd < 0)
		return -1;

	*buf = NULL;
	uint8_t *newbuf;
	if (!(newbuf = calloc(size, sizeof (uint8_t))))
		goto err;
	*buf = newbuf;

	do {
		p = *buf + filesize;
		/* size - filesize shouldn't exceed SSIZE_MAX because we're
		 * only allocating 4096 bytes at a time and we're checking that
		 * before doing so. */
		s = read(fd, p, size - filesize);
		if (s < 0 && errno == EAGAIN) {
			continue;
		} else if (s < 0) {
			goto err;
		}
		filesize += s;
		/* only exit for empty reads */
		if (s == 0)
			break;
		if (filesize >= size) {
			/* See if we're going to overrun and return an error
			 * instead. */
			if (size > (size_t)-1 - 4096) {
				errno = ENOMEM;
				goto err;
			}
			newbuf = realloc(*buf, size + 4096);
			if (newbuf == NULL)
				goto err;
			*buf = newbuf;
			memset(*buf + size, '\0', 4096);
			size += 4096;
		}
	} while (1);

	newbuf = realloc(*buf, filesize + 1);
	if (newbuf == NULL)
		goto err;
	newbuf[filesize] = '\0';
	*buf = newbuf;
	*bufsize = filesize + 1;
	close(fd);
	return 0;
err:
	saved_errno = errno;
	if (fd >= 0)
		close(fd);

	if (*buf) {
		free(*buf);
		*buf = NULL;
		*bufsize = 0;
	}

	errno = saved_errno;
	return -1;
}

static size_t
__attribute__((unused))
fcopy_file(FILE *fin, FILE *fout)
{
	int ret = 0;

	/* copy the input file to the new home */
	while (1) {
		int c;
		int rc;

		c = fgetc(fin);
		if (c == EOF) {
			if (feof(fin)) {
				break;
			} else if (ferror(fin)) {
				efi_error("read failed");
				ret = 0;
				goto out;
			} else {
				efi_error("fgetc() == EOF but no error is set.");
				errno = EINVAL;
				ret = 0;
				goto out;
			}
		}

		rc = fputc(c, fout);
		if (rc == EOF) {
			if (feof(fout)) {
				break;
			} else if (ferror(fout)) {
				efi_error("write failed");
				ret = 0;
				goto out;
			} else {
				efi_error("fputc() == EOF but no error is set.");
				errno = EINVAL;
				ret = 0;
				goto out;
			}
		} else {
			ret += 1;
		}
	}

out:
	return ret;
}

static int
__attribute__((unused))
read_file_at_dir(const char *dirname, const char *filename,
		 uint8_t **buf, size_t *buf_size)
{
	DIR *dir;
	int dfd;
	int rc;
	int error;

	dir = opendir(dirname);
	if (!dir)
		return -1;

	dfd = dirfd(dir);
	if (dfd < 0) {
		error = errno;
		closedir(dir);
		errno = error;
		return -1;
	}

	rc = read_file_at(dfd, filename, buf, buf_size);
	error = errno;
	close(dfd);
	closedir(dir);
	errno = error;
	return rc;
}

#define onstack(buf, len) ({						\
		char *__newbuf = alloca(len);				\
		memcpy(__newbuf, buf, len);				\
		free(buf);						\
		(void *)__newbuf;					\
	})

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

#define get_value_from_file_at_dir(dirname, file)			\
	({								\
		DIR *_dir;						\
		int _dfd;						\
		uint64_t _val;						\
		_dir = opendir(dirname);				\
		if (!_dir)						\
			return -1;					\
		_dfd = dirfd(_dir);					\
		if (_dfd < 0) {						\
			closedir(_dir);					\
			return -1;					\
		}							\
		_val = get_value_from_file(_dfd, (file));		\
		closedir(_dir);						\
		_val;							\
	})

#define find_matching_file(tmpl, suffix, items, n_items, outpath)	\
	({								\
		char *__path;						\
		int __rc;						\
		int __i;						\
		int __found = 0;					\
		for (__i = 0; __i < (n_items); __i++) {			\
			struct stat __statbuf;				\
			__rc = asprintf(&__path, "%s%s%s", tmpl,	\
					(items)[__i], suffix);		\
			if (__rc < 0)					\
				return -1;				\
			__rc = stat(__path, &__statbuf);		\
			if (__rc >= 0) {				\
				__found = 1;				\
				break;					\
			}						\
			free(__path);					\
			if (__rc < 0 && errno != ENOENT)		\
				return __rc;				\
		}							\
		if (__found) {						\
			*(outpath) = onstack(__path, strlen(__path)+1);	\
		} else {						\
			__i = -1;					\
		}							\
		__i;							\
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
		*str = strndupa((__typeof__(*str))_buf, _bufsize-1);	\
		(*str)[_bufsize-1] = '\0';				\
		free(_buf);						\
		*str;							\
	})

static int
__attribute__((__unused__))
get_uint64_from_file(int dfd, char *file, uint64_t *value)
{
	uint64_t val = 0;
	uint8_t *buf = NULL;
	size_t bufsize = 0;
	int rc;
	int error;

	rc = read_file_at(dfd, file, &buf, &bufsize);
	if (rc < 0) {
		error = errno;
		close(dfd);
		errno = error;
		return -1;
	}

	val = strtoull((char *)buf, NULL, 0);
	if (val == ULLONG_MAX) {
		error = errno;
		close(dfd);
		free(buf);
		errno = error;
		return -1;
	}
	free(buf);
	*value = val;
	return 0;
}

static char *
__attribute__((__unused__))
tilt_slashes(char *s)
{
	char *p;
	for (p = s; *p; p++)
		if (*p == '/')
			*p = '\\';
	return s;
}

static char *
__attribute__((__unused__))
untilt_slashes(char *s)
{
	char *p;
	for (p = s; *p; p++)
		if (*p == '\\')
			*p = '/';
	return s;
}

typedef struct {
	uint16_t year;
	uint8_t month;
	uint8_t day;
	uint8_t hour;
	uint8_t minute;
	uint8_t second;
	uint8_t pad1;
	uint32_t nanosecond;
	uint16_t timezone;
	uint8_t daylight;
	uint8_t pad2;
} efi_time_t;

#define CAPSULE_FLAGS_PERSIST_ACROSS_RESET    0x00010000
#define CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE   0x00020000
#define CAPSULE_FLAGS_INITIATE_RESET          0x00040000

#endif /* LIBFW_UTIL_H */
