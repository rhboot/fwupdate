default : all

ifneq	($(origin TOPDIR),undefined)
TOP     := $(abspath $(TOPDIR))
else
TOP     := $(abspath ..)
endif
include $(TOP)/Make.version
include $(TOP)/Make.defaults
include $(TOP)/Make.rules
VPATH	= $(TOP)/linux

LIB_LIBS= pthread
BIN_LIBS= popt pthread
PKLIBS	= efivar efiboot
CFLAGS	?= -g3 -Og -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 \
	   -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 \
	   -grecord-gcc-switches
PJONES	=
BIN_CCLDFLAGS = $(foreach lib,$(BIN_LIBS),-l$(lib)) \
	$(foreach pklib,$(PKLIBS), \
		$(shell $(PKG_CONFIG) --libs-only-l --libs-only-other $(pklib))) \
	$(LDFLAGS) -pie -fPIE -Wl,-z,relro,-z,now -L.
LIB_CCLDFLAGS = $(foreach lib,$(LIB_LIBS),-l$(lib)) \
	$(foreach pklib,$(PKLIBS), \
		$(shell $(PKG_CONFIG) --libs-only-l --libs-only-other $(pklib))) \
	$(LDFLAGS) -shared -fPIC -Wl,-z,relro,-z,now

HAVE_LIBSMBIOS := $(shell $(PKG_CONFIG) --exists libsmbios_c && \
				echo yes || echo no)
ifeq ($(HAVE_LIBSMBIOS),yes)
	PKLIBS += libsmbios_c
	CFLAGS += -DFWUPDATE_HAVE_LIBSMBIOS__
endif
BUILDFLAGS := $(CFLAGS) -Wall -Wextra -Werror -Wno-error=cpp \
	-Wno-unused-result -Wno-unused-function \
	-Wsign-compare -Werror=sign-compare \
	-fshort-wchar --std=gnu11 \
	-DLOCALEDIR=\"$(localedir)\" -D_GNU_SOURCE \
	-DFWUP_EFI_DIR_NAME=\"$(EFIDIR)\"  \
	-DFWUP_ESP_MOUNTPOINT=\"$(ESPMOUNTPOINT)\"  \
	-I include -I $(TOP)/linux/include/ -iquote $(TOP)/include/ \
	$(foreach pklib,$(PKLIBS), $(shell $(PKG_CONFIG) --cflags $(pklib))) \
	$(PJONES)

BINTARGETS=fwupdate
INCTARGETS=include/fwup-version.h $(VPATH)/include/fwup.h
LIBTARGETS=libfwup.so
PCTARGETS=fwup.pc
POTARGETS = fwupdate.po libfwup.po
TARGETS=$(BINTARGETS) $(INCTARGETS) $(foreach x,$(LIBTARGETS),$(x) $(x).1 $(x).1.$(VERSION)) $(PCTARGETS) $(POTARGETS) libfwup.so cleanup.service cleanup

.SUFFIXES:

all : $(TARGETS)

fwupdate : libfwup.so

include-dir :
	if [ ! -d include ]; then \
		$(INSTALL) -d -m 755 include ; \
	fi

libfwup.c : | include/fwup.h
include/fwup.h : | include/fwup-version.h
include/fwup-version.h : | include-dir

abidw : $(patsubst %.so,%.abixml,$(LIBTARGETS))
	git add $^

abicheck : $(patsubst %.so,%.abicheck,$(LIBTARGETS))

% : %.o
	$(CC) $(BUILDFLAGS) -o $@ $(patsubst lib%.so,-l%,$^) $(BIN_CCLDFLAGS)

%.so.1.$(VERSION) : %.o
	$(CC) $(BUILDFLAGS) \
		-Wl,-soname,$(patsubst %.o,%.so.1,$<) \
		-o $@ $^ $(LIB_CCLDFLAGS)

%.so.1 : %.so.1.$(VERSION)
	ln -sf $< $@

%.so : %.so.1.$(VERSION)
	ln -sf $< $@

%.po : %.c
	$(XGETTEXT) -a --package-name=$(patsubst %.po,%,$@) --package-version=$(VERSION) -o $@ $^

%.o : %.c
	$(CC) $(BUILDFLAGS) -fPIC -c -o $@ $^

% : %.in
	sed -e "s,@@VERSION@@,$(VERSION),g" \
		-e "s,@@FWUP_MAJOR_VERSION@@,$(MAJOR_VERSION),g" \
		-e "s,@@FWUP_MINOR_VERSION@@,$(MINOR_VERSION),g" \
		-e "s,@@SHAREDSTATEDIR@@,$(statedir),g" \
		-e "s,@@ESPMOUNTPOINT@@,$(ESPMOUNTPOINT),g" \
		-e "s,@@EFIDIR@@,$(EFIDIR),g" \
		-e "s,@@LIBDIR@@,$(libdir),g" \
		-e "s,@@LIBEXECDIR@@,$(libexecdir),g" \
		$< > $@

tester : tester.c
	$(CC) -Wall -Werror -ggdb -L. -I./include -I/usr/include/efivar \
		-lefivar -lfwup -o $@ $^

test : tester
	LD_LIBRARY_PATH=$(shell pwd) ./tester

clean :
	@rm -vf $(BINTARGETS) $(LIBTARGETS) $(PCTARGETS) $(POTARGETS) *.o
	@rm -vf libfwup.so*
	@rm -vf cleanup.service cleanup
	@rm -vf include/fwup-version.h

install : check_efidir_error all
	$(INSTALL) -d -m 755 $(DESTDIR)$(libdir)
	$(foreach x, $(LIBTARGETS), $(INSTALL) -m 755 $(x).1.$(VERSION) $(DESTDIR)$(libdir);)
	$(INSTALL) -d -m 755 $(DESTDIR)$(pcdir)
	$(foreach x, $(PCTARGETS), $(INSTALL) -m 644 $(x) $(DESTDIR)$(pcdir) ;)
	$(INSTALL) -d -m 755 $(DESTDIR)$(includedir)/
	$(INSTALL) -m 644 $(INCTARGETS) $(DESTDIR)$(includedir)/
	$(INSTALL) -d -m 755 $(DESTDIR)$(localedir)/en/
	$(INSTALL) -m 644 $(POTARGETS) $(DESTDIR)$(localedir)/en/
	$(INSTALL) -d -m 755 $(DESTDIR)$(bindir)/
	$(foreach x, $(BINTARGETS), $(INSTALL) -m 755 $(x) $(DESTDIR)$(bindir);)
	$(foreach x, $(wildcard *.so.1.$(VERSION)), \
		ln -fs $(x) $(patsubst %.so.1.$(VERSION),%.so.1,$(DESTDIR)$(libdir)/$(x)) ;\
		ln -fs $(x) $(patsubst %.so.1.$(VERSION),%.so,$(DESTDIR)$(libdir)/$(x)) ;\
		)
	$(INSTALL) -d -m 755 $(DESTDIR)$(sharedstatedir)/fwupdate/
	$(INSTALL) -d -m 755 $(DESTDIR)$(libexecdir)/fwupdate/
	$(INSTALL) -m 755 cleanup $(DESTDIR)$(libexecdir)/fwupdate/cleanup
	$(INSTALL) -d -m 755 $(DESTDIR)$(libdatadir)/systemd/system
	$(INSTALL) -m 644 cleanup.service \
		$(DESTDIR)$(libdatadir)/systemd/system/fwupdate-cleanup.service
	$(INSTALL) -d -m 755 $(DESTDIR)/usr/share/bash-completion/completions/
	$(INSTALL) -m 755 $(VPATH)/bash-completion \
		$(DESTDIR)/usr/share/bash-completion/completions/fwupdate
