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

#define  _(String) gettext (String)
#define Q_(String) dpgettext (NULL, String, 0)
#define N_(String) (String)
#define C_(Context,String) dpgettext (NULL, Context "\004" String, strlen (Context) + 1)
#define NC_(Context, String) (String)

#endif /* LIBFW_UTIL_H */
