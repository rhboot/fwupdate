ifneq	($(origin TOPDIR),undefined)
TOP     := $(abspath $(TOPDIR))
else
TOP     := $(abspath ..)
endif
include $(TOP)/Make.defaults
include $(TOP)/Make.rules
VPATH	= $(TOP)/include

all clean dep abidw abicheck :

install :
	$(INSTALL) -d -m 755 $(DESTDIR)$(DEBUGSOURCE)/fwupdate-$(VERSION)$(DASHRELEASE)$(DOTARCH)/include
	$(foreach src,$(wildcard *.[chS]),$(INSTALL) -m 644 $(src) $(DESTDIR)$(DEBUGSOURCE)/fwupdate-$(VERSION)$(DASHRELEASE)$(DOTARCH)/include/$(src) ;)

