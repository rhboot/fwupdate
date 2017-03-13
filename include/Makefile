TOPDIR	?= $(shell pwd)/..
include $(TOPDIR)/Make.version
include $(TOPDIR)/Make.defaults

all clean dep :

install :
	$(INSTALL) -d -m 755 $(DESTDIR)$(DEBUGSOURCE)/fwupdate-$(VERSION)/include
	$(foreach src,$(wildcard *.[chS]),$(INSTALL) -m 644 $(src) $(DESTDIR)$(DEBUGSOURCE)/fwupdate-$(VERSION)/include/$(src) ;)

