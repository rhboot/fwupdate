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
#include "ucs2.h"

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
		uint32_t type;
		char *str_type;

		fwup_get_guid(re, &guid);
		rc = efi_guid_to_id_guid(guid, &id_guid);
		if (rc < 0) {
			efi_error("efi_guid_to_id_guid failed");
			return -1;
		}

		fwup_get_fw_version(re, &vers);
		fwup_get_lowest_supported_fw_version(re, &lowest);
		fwup_get_fw_type(re, &type);
		switch (type) {
		case FWUP_RESOURCE_TYPE_UNKNOWN:
			str_type = "Unknown";
			break;
		case FWUP_RESOURCE_TYPE_SYSTEM_FIRMWARE:
			str_type = "System Firmware";
			break;
		case FWUP_RESOURCE_TYPE_DEVICE_FIRMWARE:
			str_type = "Device Firmware";
			break;
		case FWUP_RESOURCE_TYPE_UEFI_DRIVER:
			str_type = "UEFI Driver";
			break;
		default:
			str_type = EMPTY;
			break;
		}

		printf(_("%s type, %s version %d can be updated to any version above %d\n"),
			str_type , id_guid, vers, lowest-1);
		free(id_guid);
	}

	fwup_resource_iter_destroy(&iter);
	if (rc < 0)
		return -1;
	return 0;
}

static void
set_debug_flag(int8_t set_debug)
{
	int rc;
	uint8_t *data;
	size_t size;
	uint32_t attributes;
	const char *name = "FWUPDATE_VERBOSE";
	efi_guid_t fwupdate_guid = FWUPDATE_GUID;

	if (set_debug == -1)
		return;

	rc = efi_get_variable(fwupdate_guid, name, &data, &size, &attributes);
	if (rc >= 0) {
		if (size == 1 && *(int *)data == set_debug)
			return;
		efi_del_variable(fwupdate_guid, name);
		printf("Disabled fwupdate debugging\n");
	}

	if (set_debug <= 0)
		return;

	attributes = EFI_VARIABLE_NON_VOLATILE |
		     EFI_VARIABLE_BOOTSERVICE_ACCESS |
		     EFI_VARIABLE_RUNTIME_ACCESS;

	efi_set_variable(fwupdate_guid, name,
			 (uint8_t *)&set_debug, sizeof(set_debug),
			 attributes, 0644);
	printf("Enabled fwupdate debugging\n");
}

static void
dump_log(void)
{
	int rc;
	char *utf8 = NULL;
	size_t size = 0;

	rc = fwup_get_debug_log(&utf8, &size);
	if (rc < 0) {
		if (rc == ENOENT) {
			printf("No debug log found\n");
			return;
		}
		error(1, "Could not get debug log");
	}

	printf("%s", utf8);
	free(utf8);
}

#define ACTION_APPLY		0x01
#define ACTION_LIST		0x02
#define ACTION_SUPPORTED	0x04
#define ACTION_INFO		0x08
#define ACTION_ENABLE		0x10
#define ACTION_VERSION		0x20
#define ACTION_SHOW_LOG		0x40

int
main(int argc, char *argv[]) {
	int action = 0;
	int force = 0;
	int set_debug = 0;
	int use_existing_media_path = 1;
	char *esp_path = FWUP_ESP_MOUNTPOINT;

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
		{.longName = "log",
		 .shortName = 'L',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_OR,
		 .arg = &action,
		 .val = ACTION_SHOW_LOG,
		 .descrip = _("Show the debug log from the last attempted update"),
		},
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
		{.longName = "version",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_OPTIONAL,
		 .arg = &action,
		 .val = ACTION_VERSION,
		 .descrip = _("Display version"),
		},
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
		{.longName = "esp-path",
		 .shortName = 'p',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
		 .arg = &esp_path,
		 .val = 0,
		 .descrip = _("Override the default ESP path"),
		 .argDescrip = "<esp-path>"},
		{.longName = "dont-use-existing-media-path",
		 .shortName = 'F',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &use_existing_media_path,
		 .val = 0,
		 .descrip = _("Don't reuse the filename for this GUID from previous updates") },
		{.longName = "set-debug",
		 .shortName = 'd',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_OPTIONAL,
		 .arg = &set_debug,
		 .val = 1,
		 .descrip = _("Set the debugging flag during update"),
		},
		{.longName = "unset-debug",
		 .shortName = 'D',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_OPTIONAL,
		 .arg = &set_debug,
		 .val = 0,
		 .descrip = _("Set the debugging flag during update"),
		},
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

	fwup_set_esp_mountpoint(esp_path);

	set_debug_flag(set_debug);

	if (action & ACTION_SHOW_LOG)
		dump_log();

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

	if (!action && set_debug == -1) {
		warningx(_("no action specified"));
		poptPrintUsage(optcon, stderr, 0);
		exit(4);
	}
	poptFreeContext(optcon);

	if (action & ACTION_SUPPORTED) {
		rc = fwup_supported();
		if (rc == FWUP_SUPPORTED_STATUS_UNSUPPORTED) {
			qprintf("%s\n",
			  _("Firmware updates are not supported on this machine."));
			return 1;
		} else if (rc == FWUP_SUPPORTED_STATUS_UNLOCKED) {
			qprintf("%s\n",
			  _("Firmware updates are supported on this machine."));
			return 0;
		} else if (rc == FWUP_SUPPORTED_STATUS_LOCKED_CAN_UNLOCK) {
			qprintf("%s\n%s\n",
			  _("Firmware updates are supported on this machine."),
			  _("Support is currently disabled."));
			return 2;
		} else if (rc == FWUP_SUPPORTED_STATUS_LOCKED_CAN_UNLOCK_NEXT_BOOT) {
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

			fwup_use_existing_media_path(use_existing_media_path);
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
	} else if (action & ACTION_VERSION) {
		qprintf("fwupdate version: %d\n", LIBFWUP_VERSION);
		return 0;
	}

	return 0;
}
