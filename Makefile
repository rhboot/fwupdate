default : all

ifneq ($(origin TOPDIR),undefined)
TOP	:= $(abspath $(TOPDIR))
else
TOP	= $(abspath $(shell pwd))
endif

include $(TOP)/Make.defaults
include $(TOP)/Make.rules
include $(TOP)/Make.coverity
SUBDIRS ?= efi linux docs include

all abidw abicheck clean install : | check_efidir_error
	@set -e ; for x in $(SUBDIRS) ; do \
		if [ ! -d $${x} ]; then \
			install -m 0755 -d $${x} ; \
		fi ; \
		$(MAKE) DESTDIR=$(DESTDIR) TOPDIR=$(TOP) VERSION=$(VERSION) \
			LIBDIR=$(LIBDIR) bindir=$(bindir) mandir=$(mandir) \
			-C $$x/ -f $(TOP)/$$x/Makefile $@ ; \
	done

GITTAG = $(shell bash -c "echo $$(($(VERSION) + 1))")

fwupdate.spec : | Makefile
fwupdate.spec : $(TOP)/fwupdate.spec.in
	@sed -e "s,@@VERSION@@,$(VERSION),g" $< > $@

test-archive: abicheck fwupdate.spec
	@rm -rf /tmp/fwupdate-$(GITTAG) /tmp/fwupdate-$(GITTAG)-tmp
	@mkdir -p /tmp/fwupdate-$(GITTAG)-tmp
	@git archive --format=tar $(shell git branch | awk '/^*/ { print $$2 }') | ( cd /tmp/fwupdate-$(GITTAG)-tmp/ ; tar x )
	@git diff | ( cd /tmp/fwupdate-$(GITTAG)-tmp/ ; patch -s -p1 -b -z .gitdiff )
	@mv /tmp/fwupdate-$(GITTAG)-tmp/ /tmp/fwupdate-$(GITTAG)/
	@cp fwupdate.spec /tmp/fwupdate-$(GITTAG)/
	@dir=$$PWD; cd /tmp; tar -c --bzip2 -f $$dir/fwupdate-$(GITTAG).tar.bz2 fwupdate-$(GITTAG)
	@rm -rf /tmp/fwupdate-$(GITTAG)
	@echo "The archive is in fwupdate-$(GITTAG).tar.bz2"

bumpver:
	@echo VERSION=$(GITTAG) > Make.version
	@git add Make.version
	git commit -m "Bump version to $(GITTAG)" -s

tag:
	git tag -s $(GITTAG) refs/heads/master

archive: abicheck abidw bumpver tag fwupdate.spec
	@rm -rf /tmp/fwupdate-$(GITTAG) /tmp/fwupdate-$(GITTAG)-tmp
	@mkdir -p /tmp/fwupdate-$(GITTAG)-tmp
	@git archive --format=tar $(GITTAG) | ( cd /tmp/fwupdate-$(GITTAG)-tmp/ ; tar x )
	@mv /tmp/fwupdate-$(GITTAG)-tmp/ /tmp/fwupdate-$(GITTAG)/
	@cp fwupdate.spec /tmp/fwupdate-$(GITTAG)/
	@dir=$$PWD; cd /tmp; tar -c --bzip2 -f $$dir/fwupdate-$(GITTAG).tar.bz2 fwupdate-$(GITTAG)
	@rm -rf /tmp/fwupdate-$(GITTAG)
	@echo "The archive is in fwupdate-$(GITTAG).tar.bz2"

.PHONY: $(SUBDIRS)
