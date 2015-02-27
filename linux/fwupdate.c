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

#include "util.h"
#include "fwup.h"

#define CAPSULE_FLAGS_PERSIST_ACROSS_RESET    0x00010000
#define CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE   0x00020000
#define CAPSULE_FLAGS_INITIATE_RESET          0x00040000

#if 0
#define INSYDE 1

struct fwupdate_entry {
	efi_guid_t guid;
	uint32_t version;
	uint32_t flags;
	char16_t path[1024];
};

int test(void)
{
	efi_guid_t fwupdate_guid = EFI_GUID(0x0abba7dc,0xe516,0x4167,0xbbf5,0x4d,0x9d,0x1c,0x73,0x94,0x16);
#if INSYDE == 1
	efi_guid_t fw_guid = EFI_GUID(0xffd4675e, 0xff47, 0x46d9,0xac24,0x8b,0x33,0x1f,0x93,0x77,0x37);
#else
	efi_guid_t fw_guid = EFI_GUID(0x819b858e,0xc52c,0x402f,0x80e1,0x5b,0x31,0x1b,0x6c,0x19,0x59);
#endif

	struct fwupdate_entry fwue = {
		.guid = fw_guid,
		.version = 1413742592,
#if INSYDE == 1
		.flags = (CAPSULE_FLAGS_PERSIST_ACROSS_RESET | CAPSULE_FLAGS_INITIATE_RESET) >> 16,
		.path = L"\\EFI\\fedora\\capsule\\isflash.bin",
#else
		.flags = 1
		.path = L"\\UEFIDevKit_S1200RP_vB2\\SDV_RP_B2_debug.cap",
#endif
	};
	void *data = &fwue;

	int rc;

	rc = efi_set_variable(fwupdate_guid, "FwUpdates",
			      data, sizeof (fwue),
			      EFI_VARIABLE_NON_VOLATILE |
			      EFI_VARIABLE_BOOTSERVICE_ACCESS |
			      EFI_VARIABLE_RUNTIME_ACCESS,
			      0600);
	printf("rc: %d\n", rc);
	return 0;
}
#endif

int
print_system_resources(void)
{
	fwup_resource_iter *iter;
	int rc;

	rc = fwup_resource_iter_create(&iter);
	if (rc < 0) {
		if (fwup_error != ENOENT)
			fwup_warn("Could not create iterator");
		return -1;
	}

	fwup_resource re = { {0}, 0 };
	while ((rc = fwup_resource_iter_next(iter, &re)) > 0) {
		char *id_guid = NULL;
		rc = efi_guid_to_id_guid(&re.guid, &id_guid);
		if (rc < 0)
			return -1;
		printf("%s version %d can be updated to any version above %d\n",
			id_guid, re.fw_version, re.lowest_supported_fw_version);
		free(id_guid);
	}
	if (rc < 0)
		return -1;
	return 0;
}

#define ACTION_APPLY		0x01
#define ACTION_LIST		0x02
#define ACTION_SUPPORTED	0x04

int
main(int argc, char *argv[]) {
	int action = 0;
	int quiet = 0;

	setlocale(LC_ALL, "");
	bindtextdomain("fwupdate", LOCALEDIR);
	textdomain("fwupdate");

	struct poptOption options[] = {
		{NULL, '\0', POPT_ARG_INTL_DOMAIN, "fwupdate" },
		{"apply", 'a', POPT_ARG_VAL|POPT_ARGFLAG_OR, &action,
			ACTION_APPLY, _("Apply firmware updates"), NULL},
		{"list", 'l', POPT_ARG_VAL|POPT_ARGFLAG_OR, &action,
			ACTION_LIST, _("List supported firmware updates"),
			NULL},
		{"supported", 's', POPT_ARG_VAL|POPT_ARGFLAG_OR, &action,
			ACTION_SUPPORTED,
			_("Query for firmware update support"), NULL},
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
				printf("Firmware updates are not supported on this machine.\n");
			return 1;
		} else if (rc == 1) {
			if (!quiet)
				printf("Firmware updates are supported on this machine.\n");
			return 0;
		}
	} else if (action & ACTION_LIST) {
		rc = print_system_resources();
		if (rc < 0 && fwup_error != ENOENT)
			errx(5, "Could not list system firmware resources");
		return 0;
	}

	return 0;
}
