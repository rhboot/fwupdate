/*
 * libfw - library interface to apply firmware updates
 *
 * Copyright 2015 Red Hat, Inc.
 *
 * See "COPYING" for license terms.
 *
 * Author: Peter Jones <pjones@redhat.com>
 */
#ifndef LIBFWUP_H
#define LIBFWUP_H
#define LIBFWUP_H_INSIDE__

#include <dirent.h>
#include <efivar.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>

#include <fwup-version.h>

extern int fwup_supported(void);
extern int fwup_esrt_disabled(void);
extern int fwup_enable_esrt(void);

#define FWUP_SUPPORTED_STATUS_UNSUPPORTED			0
#define FWUP_SUPPORTED_STATUS_UNLOCKED				1
#define FWUP_SUPPORTED_STATUS_LOCKED_CAN_UNLOCK			2
#define FWUP_SUPPORTED_STATUS_LOCKED_CAN_UNLOCK_NEXT_BOOT	3

#define FWUP_RESOURCE_TYPE_UNKNOWN		0
#define FWUP_RESOURCE_TYPE_SYSTEM_FIRMWARE	1
#define FWUP_RESOURCE_TYPE_DEVICE_FIRMWARE	2
#define FWUP_RESOURCE_TYPE_UEFI_DRIVER		3
#define FWUP_RESOURCE_TYPE_FMP			4

#define FWUP_LAST_ATTEMPT_STATUS_SUCCESS			0x00000000
#define FWUP_LAST_ATTEMPT_STATUS_ERROR_UNSUCCESSFUL		0x00000001
#define FWUP_LAST_ATTEMPT_STATUS_ERROR_INSUFFICIENT_RESOURCES	0x00000002
#define FWUP_LAST_ATTEMPT_STATUS_ERROR_INCORRECT_VERSION	0x00000003
#define FWUP_LAST_ATTEMPT_STATUS_ERROR_INVALID_FORMAT		0x00000004
#define FWUP_LAST_ATTEMPT_STATUS_ERROR_AUTH_ERROR		0x00000005
#define FWUP_LAST_ATTEMPT_STATUS_ERROR_PWR_EVT_AC		0x00000006
#define FWUP_LAST_ATTEMPT_STATUS_ERROR_PWR_EVT_BATT		0x00000007

typedef struct fwup_resource_s fwup_resource;
typedef struct fwup_resource_iter_s fwup_resource_iter;

extern int fwup_resource_iter_next(fwup_resource_iter *iter,
				   fwup_resource **re);
extern int fwup_resource_iter_create(fwup_resource_iter **iter);
extern int fwup_resource_iter_destroy(fwup_resource_iter **iter);

extern void fwup_use_existing_media_path(int);
extern void fwup_set_esp_mountpoint(char *path);
const char *fwup_get_esp_mountpoint(void);

extern int fwup_set_up_update(fwup_resource *re, uint64_t hw_inst, int infd);
extern int fwup_set_up_update_with_buf(fwup_resource *re, uint64_t hw_inst,
				       const void *buf, size_t sz);
extern int fwup_set_guid(fwup_resource_iter *iter, fwup_resource **re,
			 const efi_guid_t *guid);
extern int fwup_clear_status(fwup_resource *re);
extern int fwup_get_guid(fwup_resource *re, efi_guid_t **guid);
extern int fwup_get_fw_type(fwup_resource *re, uint32_t *type);
extern int fwup_get_fw_version(fwup_resource *re, uint32_t *version);
extern int fwup_get_lowest_supported_fw_version(fwup_resource *re,
						uint32_t *version);
extern int fwup_get_last_attempt_info(fwup_resource *re, uint32_t *version,
			   uint32_t *status, time_t *when);
extern int fwup_get_ux_capsule_info(uint32_t *screen_x_size,
				    uint32_t *screen_y_size);
extern const char *fwup_last_attempt_status_to_string (uint64_t status);
extern int fwup_print_update_info(void);
extern int fwup_get_debug_log(char **utf8, size_t *size);

#undef LIBFWUP_H_INSIDE__
#endif /* LIBFWUP_H */
