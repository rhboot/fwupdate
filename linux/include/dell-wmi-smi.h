/*
 * dell-wmi-smi - kernel interface to SMI over WMI
 *
 * Copyright 2017 Dell, Inc.
 *
 * See "COPYING" for license terms.
 *
 * Author: Mario Limonciello <mario.limonciello@dell.com>
 */

#ifndef _DELL_WMI_SMI_H_
#define _DELL_WMI_SMI_H_

#include <sys/ioctl.h>

#define DELL_CAPSULE_FIRMWARE_UPDATES_ENABLED 0x0461
#define DELL_CAPSULE_FIRMWARE_UPDATES_DISABLED 0x0462

#define DELL_CLASS_READ_TOKEN 0
#define DELL_SELECT_READ_TOKEN 0
#define DELL_CLASS_WRITE_TOKEN 1
#define DELL_SELECT_WRITE_TOKEN 0

#define DELL_CLASS_ADMIN_PROP 10
#define DELL_SELECT_ADMIN_PROP 3
#define DELL_ADMIN_MASK 0xF
#define DELL_ADMIN_INSTALLED 0

struct calling_interface_buffer {
	uint16_t class;
	uint16_t select;
	volatile uint32_t input[4];
	volatile uint32_t output[4];
};

struct wmi_calling_interface_buffer {
	struct calling_interface_buffer smi;
	uint32_t argattrib;
	uint32_t blength;
	uint8_t data[32724];
};

#define DELL_WMI_CHAR "/dev/wmi/dell-smbios"
#define TOKENS_SYSFS "/sys/bus/wmi/devices/A80593CE-A997-11DA-B012-B622A1EF5492/tokens"

#define DELL_WMI_SMBIOS_IOC			'D'
/* run SMBIOS calling interface command
 * note - 32k is too big for size, so this can not be encoded in macro properly
 */
#define DELL_WMI_SMBIOS_CALL_CMD  	_IOWR(DELL_WMI_SMBIOS_IOC, 0, uint8_t)

#endif
