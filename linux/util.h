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

#endif /* LIBFW_UTIL_H */
