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
#include "error.h"

#define CAPSULE_FLAGS_PERSIST_ACROSS_RESET    0x00010000
#define CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE   0x00020000
#define CAPSULE_FLAGS_INITIATE_RESET          0x00040000

int verbose = 0;
int quiet = 0;

static int
print_system_resources(void)
{
	fwup_resource_iter *iter;
	int rc;

	rc = fwup_resource_iter_create(&iter);
	if (rc < 0) {
		if (errno != ENOENT)
			efi_error(_("Could not create iterator"));
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
		if (rc < 0) {
			efi_error("efi_guid_to_id_guid failed");
			return -1;
		}

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
#define ACTION_ENABLE		0x10

int
main(int argc, char *argv[]) {
	int action = 0;
	int force = 0;

	const char *guidstr = NULL;
	const char *filename = NULL;

	efi_guid_t guid;

	setlocale(LC_ALL, EMPTY);
	bindtextdomain("fwupdate", LOCALEDIR);
	textdomain("fwupdate");

	struct poptOption options[] = {
		{.argInfo = POPT_ARG_INTL_DOMAIN,
		 .arg = "fwupdate" },
		{.longName = "apply",
		 .shortName = 'a',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_OR,
		 .arg = &action,
		 .val = ACTION_APPLY,
		 .descrip = _("Apply firmware updates"),
		 .argDescrip = "<guid> <firmware.cap>"},
		{.longName = "list",
		 .shortName = 'l',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_OR,
		 .arg = &action,
		 .val = ACTION_LIST,
		 .descrip = _("List supported firmware updates") },
		{.longName = "supported",
		 .shortName = 's',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_OR,
		 .arg = &action,
		 .val = ACTION_SUPPORTED,
		 .descrip = _("Query for firmware update support") },
		{.longName = "info",
		 .shortName = 'i',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_OR,
		 .arg = &action,
		 .val = ACTION_INFO,
		 .descrip =
			 _("Show the information of firmware update status")},
		{.longName = "enable",
		 .shortName = 'e',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_OR,
		 .arg = &action,
		 .val = ACTION_ENABLE,
		 .descrip = _("Enable firmware update support on supported systems (will require a reboot)") },
		{.longName = "quiet",
		 .shortName = 'q',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &quiet,
		 .val = 1,
		 .descrip = _("Work quietly") },
		{.longName = "force",
		 .shortName = 'f',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &force,
		 .val = 1,
		 .descrip = _("Forces flash even if GUID isn't in ESRT.") },
		{.longName = "verbose",
		 .shortName = 'v',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_OPTIONAL,
		 .arg = &verbose,
		 .val = 2,
		 .descrip = _("Be more verbose on errors"),
		},
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	poptContext optcon;
	optcon = poptGetContext("fwupdate", argc, (const char **)argv, options, 0);

	int rc;
	rc = poptReadDefaultConfig(optcon, 0);
	if (rc < 0 && !(rc == POPT_ERROR_ERRNO && errno == ENOENT))
		errorx(1, _("poptReadDefaultConfig failed: %s: %s"),
			poptBadOption(optcon, 0), poptStrerror(rc));

	while ((rc = poptGetNextOpt(optcon)) > 0)
		;

	if (action & ACTION_APPLY) {
		guidstr = poptGetArg(optcon);
		if (!guidstr) {
			warningx(_("missing argument: %s"), "guid");
			poptPrintUsage(optcon, stderr, 0);
			exit(1);
		}
		rc = efi_str_to_guid(guidstr, &guid);
		if (rc < 0)
			errorx(1, _("Invalid guid: \"%s\""), guidstr);

		filename = poptGetArg(optcon);
		if (!filename) {
				warningx(_("missing argument: %s"),
				      "filename.cap");
			poptPrintUsage(optcon, stderr, 0);
			exit(1);
		}
	}

	if (rc < -1)
		errorx(2, _("invalid argument: \"%s\": %s"),
			poptBadOption(optcon, 0), poptStrerror(rc));

	if (poptPeekArg(optcon))
		errorx(3, _("invalid argument: \"%s\""),
			poptPeekArg(optcon));

	if (!action) {
		warningx(_("no action specified"));
		poptPrintUsage(optcon, stderr, 0);
		exit(4);
	}
	poptFreeContext(optcon);

	if (action & ACTION_SUPPORTED) {
		rc = fwup_supported();
		if (rc == 0) {
			qprintf("%s\n",
			  _("Firmware updates are not supported on this machine."));
			return 1;
		} else if (rc == 1) {
			qprintf("%s\n",
			  _("Firmware updates are supported on this machine."));
			return 0;
		} else if (rc == 2) {
			qprintf("%s\n%s\n",
			  _("Firmware updates are supported on this machine."),
			  _("Support is currently disabled."));
			return 2;
		} else if (rc == 3) {
			qprintf("%s\n%s\n",
			  _("Firmware updates are supported on this machine."),
			  _("Support will be enabled on the next reboot."));
			return 2;
		}
	} else if (action & ACTION_LIST) {
		rc = print_system_resources();
		if (rc < 0 && errno != ENOENT)
			errorx(5,
			       _("Could not list system firmware resources"));
		return 0;
	} else if (action & ACTION_APPLY) {
		fwup_resource_iter *iter = NULL;
		fwup_resource_iter_create(&iter);
		fwup_resource *re = NULL;
		efi_guid_t *tmpguid = NULL;

		while (!force) {
			rc = fwup_resource_iter_next(iter, &re);
			if (rc < 0)
				error(2, _("Could not iterate resources"));
			if (rc == 0)
				break;

			fwup_get_guid(re, &tmpguid);

			if (!efi_guid_cmp(tmpguid, &guid))
				break;

			tmpguid = NULL;
		}

		if (!tmpguid && force) {
			rc = fwup_set_guid(iter, &re, &guid);
			if (rc < 0)
				error(2, _("Error configuring GUID"));
			tmpguid = &guid;
		}

		if (tmpguid) {
			int fd = open(filename, O_RDONLY);
			if (fd < 0)
				error(2, _("could not open \"%s\""), filename);

			rc = fwup_set_up_update(re, 0, fd);
			if (rc < 0)
				error(2, _("Could not set up firmware update"));

			fwup_resource_iter_destroy(&iter);
			exit(0);
		}
		errorx(2, _("firmware resource not found"));
	} else if (action & ACTION_INFO) {
		rc = fwup_print_update_info();
		if (rc < 0)
			errorx(6,
			       _("Could not display firmware update status"));
		return 0;
	} else if (action & ACTION_ENABLE) {
		if (geteuid() != 0) {
			qprintf("%s\n",
				_("To enable firmware updates, this tool must be launched as root."));
			return -1;
		}
		rc = fwup_enable_esrt();
		if (rc < 1) {
			qprintf("%s\n",
				_("Firmware updates can not be enabled on this machine from this tool."));
			return 1;
		} else if (rc == 1) {
			qprintf("%s\n",
				_("Firmware updates are already enabled."));
			return 1;
		} else if (rc == 2 || rc == 3) {
			qprintf("%s\n",
				_("Firmware updates will be enabled after the system is rebooted."));
			return 0;
		}
	}

	return 0;
}
