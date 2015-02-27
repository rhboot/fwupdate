TOPDIR=$(shell pwd)

SUBDIRS = efi linux

all clean install :
	@for x in $(SUBDIRS) ; do \
		$(MAKE) DESTDIR=$(DESTDIR) TOPDIR=$(TOPDIR) -C $$x $@ ; \
	done

include $(TOPDIR)/Make.defaults
