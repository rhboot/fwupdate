default : all

TOPDIR=$(shell pwd)
include $(TOPDIR)/Make.version
include $(TOPDIR)/Make.rules
include $(TOPDIR)/Make.defaults
SUBDIRS ?= efi linux docs include

all install : | check_efidir_error
	@set -e ; for x in $(SUBDIRS) ; do \
		$(MAKE) DESTDIR=$(DESTDIR) TOPDIR=$(TOPDIR) VERSION=$(VERSION) \
			LIBDIR=$(LIBDIR) bindir=$(bindir) mandir=$(mandir) \
			-C $$x $@ ; \
	done

fwupdate.spec : fwupdate.spec.in Makefile
	@sed -e "s,@@VERSION@@,$(VERSION),g" $< > $@

COV_EMAIL=$(call get-config,coverity.email)
COV_TOKEN=$(call get-config,coverity.token)
COV_URL=$(call get-config,coverity.url)
COV_FILE=fwupdate-coverity-$(VERSION)-$(COMMIT_ID).tar.bz2
COMMIT_ID=$(shell git log -1 --pretty=%H 2>/dev/null || echo master)

clean :
	@set -e ; for x in $(SUBDIRS) ; do \
		$(MAKE) DESTDIR=$(DESTDIR) TOPDIR=$(TOPDIR) VERSION=$(VERSION) \
			LIBDIR=$(LIBDIR) bindir=$(bindir) mandir=$(mandir) \
			-C $$x $@ ; \
	done
	@rm -vrf cov-int fwupdate-coverity-*.tar.*

cov-int : clean
	cov-build --dir cov-int make all

$(COV_FILE) : cov-int
	tar caf $@ cov-int

cov-upload :
	@if [[ -n "$(COV_URL)" ]] &&					\
	    [[ -n "$(COV_TOKEN)" ]] &&					\
	    [[ -n "$(COV_EMAIL)" ]] ;					\
	then								\
		echo curl --form token=$(COV_TOKEN) --form email="$(COV_EMAIL)" --form file=@"$(COV_FILE)" --form version=$(VERSION).1 --form description="$(COMMIT_ID)" "$(COV_URL)" ; \
		curl --form token=$(COV_TOKEN) --form email="$(COV_EMAIL)" --form file=@"$(COV_FILE)" --form version=$(VERSION).1 --form description="$(COMMIT_ID)" "$(COV_URL)" ; \
	else								\
		echo Coverity output is in $(COV_FILE) ;		\
	fi

coverity : $(COV_FILE) cov-upload

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

.PHONY: $(SUBDIRS) coverity cov-upload
