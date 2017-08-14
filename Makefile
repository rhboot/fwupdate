default : all

ifneq ($(origin TOPDIR),undefined)
TOP	:= $(abspath $(TOPDIR))
else
TOP	= $(abspath $(shell pwd))
endif

include $(TOP)/Make.version
include $(TOP)/Make.rules
include $(TOP)/Make.defaults
include $(TOP)/Make.coverity
SUBDIRS ?= efi linux docs include

all clean install : | check_efidir_error
	@set -e ; for x in $(SUBDIRS) ; do \
		if [ ! -d $${x} ]; then \
			install -m 0755 -d $${x} ; \
		fi ; \
		$(MAKE) DESTDIR=$(DESTDIR) TOPDIR=$(TOP) VERSION=$(VERSION) \
			LIBDIR=$(LIBDIR) bindir=$(bindir) mandir=$(mandir) \
			-C $$x/ -f $(TOP)/$$x/Makefile $@ ; \
	done

fwupdate.spec : | Makefile
fwupdate.spec : $(TOP)/fwupdate.spec.in
	@sed -e "s,@@VERSION@@,$(VERSION),g" $< > $@

GITTAG = $(VERSION)

test-archive: fwupdate.spec
	@rm -rf /tmp/fwupdate-$(VERSION) /tmp/fwupdate-$(VERSION)-tmp
	@mkdir -p /tmp/fwupdate-$(VERSION)-tmp
	@git archive --format=tar $(shell git branch | awk '/^*/ { print $$2 }') | ( cd /tmp/fwupdate-$(VERSION)-tmp/ ; tar x )
	@git diff | ( cd /tmp/fwupdate-$(VERSION)-tmp/ ; patch -s -p1 -b -z .gitdiff )
	@mv /tmp/fwupdate-$(VERSION)-tmp/ /tmp/fwupdate-$(VERSION)/
	@cp fwupdate.spec /tmp/fwupdate-$(VERSION)/
	@dir=$$PWD; cd /tmp; tar -c --bzip2 -f $$dir/fwupdate-$(VERSION).tar.bz2 fwupdate-$(VERSION)
	@rm -rf /tmp/fwupdate-$(VERSION)
	@echo "The archive is in fwupdate-$(VERSION).tar.bz2"

tag:
	git tag -s $(GITTAG) refs/heads/master

archive: tag fwupdate.spec
	@rm -rf /tmp/fwupdate-$(VERSION) /tmp/fwupdate-$(VERSION)-tmp
	@mkdir -p /tmp/fwupdate-$(VERSION)-tmp
	@git archive --format=tar $(GITTAG) | ( cd /tmp/fwupdate-$(VERSION)-tmp/ ; tar x )
	@mv /tmp/fwupdate-$(VERSION)-tmp/ /tmp/fwupdate-$(VERSION)/
	@cp fwupdate.spec /tmp/fwupdate-$(VERSION)/
	@dir=$$PWD; cd /tmp; tar -c --bzip2 -f $$dir/fwupdate-$(VERSION).tar.bz2 fwupdate-$(VERSION)
	@rm -rf /tmp/fwupdate-$(VERSION)
	@echo "The archive is in fwupdate-$(VERSION).tar.bz2"

.PHONY: $(SUBDIRS)
