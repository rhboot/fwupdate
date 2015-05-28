SRCDIR = .
TOPDIR = $(SRCDIR)/..

include $(TOPDIR)/Make.defaults

MAN1TARGETS = fwupdate.1
MAN3TARGETS = libfwup.h.3 \
	      libfwup.3 \
	      fwup_supported.3 \
	      fwup_resource_iter_next.3 \
	      fwup_resource_iter_create.3 \
	      fwup_resource_iter_destroy.3 \
	      fwup_set_up_update.3 \
	      fwup_clear_status.3 \
	      fwup_get_guid.3 \
	      fwup_get_fw_version.3 \
	      fwup_get_lowest_supported_version.3 \
	      fwup_get_last_attempt_info.3

all :

clean :

test :

install :
	$(INSTALL) -d -m 755 $(mandir)/man1
	$(foreach x, $(MAN1TARGETS), $(INSTALL) -m 644 $(x) $(mandir)/man1/;)
	$(INSTALL) -d -m 755 $(mandir)/man3
	$(foreach x, $(MAN3TARGETS), $(INSTALL) -m 644 $(x) $(mandir)/man3/;)

.PHONY: all clean test install
