/*
 * fwupdate.c - apply firmware updates
 *
 * Copyright 2015 Red Hat, Inc.
 *
 * See "COPYING" for license terms.
 *
 * Author: Peter Jones <pjones@redhat.com>
 */

#include <efivar.h>
#include <err.h>
#include <inttypes.h>
#include <libintl.h>
#include <locale.h>
#include <popt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <uchar.h>
#include <unistd.h>

#include <fwup.h>
#include "util.h"

#define CAPSULE_FLAGS_PERSIST_ACROSS_RESET    0x00010000
#define CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE   0x00020000
#define CAPSULE_FLAGS_INITIATE_RESET          0x00040000

static int
print_system_resources(void)
{
	fwup_resource_iter *iter;
	int rc;

	rc = fwup_resource_iter_create(&iter);
	if (rc < 0) {
		if (errno != ENOENT)
			warn(_("Could not create iterator"));
		return -1;
	}

	fwup_resource *re = NULL;
	while ((rc = fwup_resource_iter_next(iter, &re)) > 0) {
		efi_guid_t *guid = NULL;
		char *id_guid = NULL;
		uint32_t vers;
		uint32_t lowest;

		fwup_get_guid(re, &guid);
		rc = efi_guid_to_id_guid(guid, &id_guid);
		if (rc < 0)
			return -1;

		fwup_get_fw_version(re, &vers);
		fwup_get_lowest_supported_fw_version(re, &lowest);

		printf(_("%s version %d can be updated to any version above %d\n"),
			id_guid, vers, lowest-1);
		free(id_guid);
	}

	fwup_resource_iter_destroy(&iter);
	if (rc < 0)
		return -1;
	return 0;
}

#define ACTION_APPLY		0x01
#define ACTION_LIST		0x02
#define ACTION_SUPPORTED	0x04
#define ACTION_INFO		0x08

int
main(int argc, char *argv[]) {
	int action = 0;
	int quiet = 0;

	const char *guidstr = NULL;
	const char *filename = NULL;

	efi_guid_t guid;

	setlocale(LC_ALL, "");
	bindtextdomain("fwupdate", LOCALEDIR);
	textdomain("fwupdate");

	struct poptOption options[] = {
		{NULL, '\0', POPT_ARG_INTL_DOMAIN, "fwupdate" },
		{"apply", 'a', POPT_ARG_VAL|POPT_ARGFLAG_OR, &action,
			ACTION_APPLY, _("Apply firmware updates"),
			"<guid> <firmware.cap>"},
		{"list", 'l', POPT_ARG_VAL|POPT_ARGFLAG_OR, &action,
			ACTION_LIST, _("List supported firmware updates"),
			NULL},
		{"supported", 's', POPT_ARG_VAL|POPT_ARGFLAG_OR, &action,
			ACTION_SUPPORTED,
			_("Query for firmware update support"), NULL},
		{"info", 'i', POPT_ARG_VAL|POPT_ARGFLAG_OR, &action,
			ACTION_INFO,
			_("Show the information of firmware update status"),
			NULL},
		{"quiet", 'q', POPT_ARG_VAL, &quiet, 1, _("Work quietly"),
			NULL},
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	poptContext optcon;
	optcon = poptGetContext("fwupdate", argc, (const char **)argv, options, 0);

	int rc;
	rc = poptReadDefaultConfig(optcon, 0);
	if (rc < 0 && !(rc == POPT_ERROR_ERRNO && errno == ENOENT))
		errx(1, _("poptReadDefaultConfig failed: %s: %s"),
			poptBadOption(optcon, 0), poptStrerror(rc));

	while ((rc = poptGetNextOpt(optcon)) > 0)
		;

	if (action & ACTION_APPLY) {
		int rc;
		guidstr = poptGetArg(optcon);
		if (!guidstr) {
			warnx(_("missing argument: %s"), "guid");
			poptPrintUsage(optcon, stderr, 0);
			exit(1);
		}
		rc = efi_str_to_guid(guidstr, &guid);
		if (rc < 0)
			errx(1, _("Invalid guid: \"%s\""), guidstr);

		filename = poptGetArg(optcon);
		if (!filename) {
				warnx(_("missing argument: %s"),
				      "filename.cap");
			poptPrintUsage(optcon, stderr, 0);
			exit(1);
		}
	}

	if (rc < -1)
		errx(2, _("invalid argument: \"%s\": %s"),
			poptBadOption(optcon, 0), poptStrerror(rc));

	if (poptPeekArg(optcon))
		errx(3, _("invalid argument: \"%s\""),
			poptPeekArg(optcon));

	if (!action) {
		warnx(_("no action specified"));
		poptPrintUsage(optcon, stderr, 0);
		exit(4);
	}
	poptFreeContext(optcon);

	if (action & ACTION_SUPPORTED) {
		rc = fwup_supported();
		if (rc == 0) {
			if (!quiet)
				printf("%s", _("Firmware updates are not supported on this machine.\n"));
			return 1;
		} else if (rc == 1) {
			if (!quiet)
				printf("%s", _("Firmware updates are supported on this machine.\n"));
			return 0;
		}
	} else if (action & ACTION_LIST) {
		rc = print_system_resources();
		if (rc < 0 && errno != ENOENT)
			errx(5, _("Could not list system firmware resources"));
		return 0;
	} else if (action & ACTION_APPLY) {
		fwup_resource_iter *iter = NULL;
		fwup_resource_iter_create(&iter);
		fwup_resource *re = NULL;

		while (1) {
			rc = fwup_resource_iter_next(iter, &re);
			if (rc < 0)
				err(2, _("Could not iterate resources"));
			if (rc == 0)
				break;

			efi_guid_t *tmpguid = NULL;

			fwup_get_guid(re, &tmpguid);

			if (!efi_guid_cmp(tmpguid, &guid)) {
				int fd = open(filename, O_RDONLY);
				if (fd < 0)
					err(2, _("could not open \"%s\""),
					    filename);

				rc = fwup_set_up_update(re, 0, fd);
				if (rc < 0)
					err(2, _("Could not set up firmware update"));
				fwup_resource_iter_destroy(&iter);
				exit(0);
			}
		}
		errx(2, _("firmware resource not found"));
	} else if (action & ACTION_INFO) {
		rc = fwup_print_update_info();
		if (rc < 0)
			errx(6, _("Could not display firmware update status"));
		return 0;
	}

	return 0;
}
