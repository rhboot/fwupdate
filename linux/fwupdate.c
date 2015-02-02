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
#include <uchar.h>

#include "util.h"

#define CAPSULE_FLAGS_PERSIST_ACROSS_RESET    0x00010000
#define CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE   0x00020000
#define CAPSULE_FLAGS_INITIATE_RESET          0x00040000

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

#define ACTION_APPLY	0x01
#define ACTION_LIST	0x02

int main(int argc, char *argv[]) {
	int actions = 0;

	setlocale(LC_ALL, "");
	bindtextdomain("fwupdate", LOCALEDIR);
	textdomain("fwupdate");

	struct poptOption options[] = {
		{NULL, '\0', POPT_ARG_INTL_DOMAIN, "fwupdate" },
		{"apply", 'a', POPT_ARG_INT|POPT_ARGFLAG_OR, &actions,
			ACTION_APPLY, _("Apply firmware updates\n"), NULL},
		{"list", 'l', POPT_ARG_INT|POPT_ARGFLAG_OR, &actions,
			ACTION_LIST, _("List supported firmware updates\n"),
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
		errx(1, "fwupdate: poptReadDefaultConfig failed: %s: %s\n",
			poptBadOption(optcon, 0), poptStrerror(rc));

	while ((rc = poptGetNextOpt(optcon)) > 0)
		;

	if (rc < -1)
		errx(2, "fwupdate: invalid argument: \"%s\": %s\n",
			poptBadOption(optcon, 0), poptStrerror(rc));

	if (poptPeekArg(optcon))
		errx(3, "fwupdate: invalid argument: \"%s\"\n",
			poptPeekArg(optcon));

	poptFreeContext(optcon);
}
