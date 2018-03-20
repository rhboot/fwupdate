ifneq	($(origin TOPDIR),undefined)
TOP     := $(abspath $(TOPDIR))
else
TOP     := $(abspath ..)
endif
VPATH	= $(TOP)/docs

include $(TOP)/Make.defaults

MAN1TARGETS = fwupdate.1
MAN3TARGETS = libfwup.h.3 \
	      libfwup.3 \
	      fwup_supported.3 \
	      fwup_resource_iter_next.3 \
	      fwup_resource_iter_create.3 \
	      fwup_resource_iter_destroy.3 \
	      fwup_resource_free.3 \
	      fwup_set_up_update.3 \
	      fwup_clear_status.3 \
	      fwup_set_guid.3 \
	      fwup_set_guid_forced.3 \
	      fwup_get_guid.3 \
	      fwup_get_fw_version.3 \
	      fwup_get_lowest_supported_version.3 \
	      fwup_get_last_attempt_info.3 \
	      fwup_get_fw_type.3 \
	      fwup_get_ux_capsule_info.3

MANSECTIONS = 1 3

all clean test abidw abicheck :

mandirs :
	$(INSTALL) -d -m 755 $(DESTDIR)$(mandir)/man1/
	$(INSTALL) -d -m 755 $(DESTDIR)$(mandir)/man3/

install : | mandirs
install : | $(foreach x, $(MAN1TARGETS), $(DESTDIR)$(mandir)/man1/$(x))
install : | $(foreach x, $(MAN3TARGETS), $(DESTDIR)$(mandir)/man3/$(x))

$(DESTDIR)$(mandir)/man1/%.1 : | mandirs
$(DESTDIR)$(mandir)/man1/%.1 : %.1
	$(INSTALL) -m 644 $< $@

$(DESTDIR)$(mandir)/man3/%.3 : | mandirs
$(DESTDIR)$(mandir)/man3/%.3 : %.3
	$(INSTALL) -m 644 $< $@

.PHONY: all clean test install mandirs
