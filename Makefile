TOPDIR=$(shell pwd)
include $(TOPDIR)/Make.version
include $(TOPDIR)/Make.defaults
SUBDIRS = efi linux docs include

all clean install :
	@set -e ; for x in $(SUBDIRS) ; do \
		$(MAKE) DESTDIR=$(DESTDIR) TOPDIR=$(TOPDIR) VERSION=$(VERSION) \
			LIBDIR=$(LIBDIR) bindir=$(bindir) mandir=$(mandir) \
			-C $$x $@ ; \
	done

fwupdate.spec : fwupdate.spec.in Makefile
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
