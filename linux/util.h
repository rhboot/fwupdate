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

static inline int
__attribute__((unused))
read_file_at(int dfd, char *name, uint8_t **buf, size_t *bufsize)
{
	int saved_errno = errno;
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

#endif /* LIBFW_UTIL_H */
