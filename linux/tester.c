
#include <err.h>
#include <fwup.h>
#include <stdlib.h>
#include <stdio.h>

int main(void)
{
	setenv("LIBFWUP_ESRT_DIR", "sys/firmware/efi/esrt/", 1);

	fwup_resource_iter *iter;

	int rc;

	rc = fwup_resource_iter_create(&iter);
	if (rc < 0)
		err(1, "fwup_resource_iter_create");

	while (1) {
		fwup_resource re;
		rc = fwup_resource_iter_next(iter, &re);
		if (rc < 0)
			err(1, "fwup_resource_iter_next");
		if (rc == 0)
			break;
		printf("version: %d\n", re.fw_version);
	}
	fwup_resource_iter_destroy(&iter);
	return 0;
}
