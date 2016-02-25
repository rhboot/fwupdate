TOPDIR	?= $(shell pwd)/..
include $(TOPDIR)/Make.version
include $(TOPDIR)/Make.defaults

LIB_LIBS= pthread
BIN_LIBS= popt pthread
PKLIBS	= efivar efiboot libsmbios_c
CFLAGS	?= -g -O0
PJONES  =
BIN_CCLDFLAGS = $(foreach lib,$(BIN_LIBS),-l$(lib)) \
	$(foreach pklib,$(PKLIBS), \
		$(shell pkg-config --libs-only-l --libs-only-other $(pklib))) \
	$(LDFLAGS) -pie -fPIE -Wl,-z,relro,-z,now -L.
LIB_CCLDFLAGS = $(foreach lib,$(LIB_LIBS),-l$(lib)) \
	$(foreach pklib,$(PKLIBS), \
		$(shell pkg-config --libs-only-l --libs-only-other $(pklib))) \
	$(LDFLAGS) -shared -fPIC -Wl,-z,relro,-z,now

BUILDFLAGS := $(CFLAGS) -Wall -Wextra -Werror \
	-Wno-unused-result -Wno-unused-function \
	-Wsign-compare -Werror=sign-compare \
	-fshort-wchar --std=gnu11 \
	-DLOCALEDIR=\"$(localedir)\" -D_GNU_SOURCE \
	-DFWUP_EFI_DIR_NAME=\"$(EFIDIR)\"  \
	-I$(TOPDIR)/linux/include -iquote$(TOPDIR)/include/ \
	$(foreach pklib,$(PKLIBS), $(shell pkg-config --cflags $(pklib))) \
	$(PJONES)

BINTARGETS=fwupdate
INCTARGETS=include/fwup.h
LIBTARGETS=libfwup.so.$(VERSION) libfwup.so.$(MAJOR_VERSION)
PCTARGETS=fwup.pc
POTARGETS = fwupdate.po libfwup.po
TARGETS=$(BINTARGETS) $(INCTARGETS) $(LIBTARGETS) $(PCTARGETS) $(POTARGETS) libfwup.so cleanup.service cleanup

.SUFFIXES:

all : $(TARGETS)

fwupdate : libfwup.so

% : %.o
	$(CC) $(BUILDFLAGS) -o $@ $(patsubst lib%.so,-l%,$^) $(BIN_CCLDFLAGS)

%.so.$(VERSION) : %.o
	$(CC) $(BUILDFLAGS) \
		-Wl,-soname,$(patsubst %.o,%.so.$(MAJOR_VERSION),$<) \
		-o $@ $^ $(LIB_CCLDFLAGS)

%.so.$(MAJOR_VERSION) : %.so.$(VERSION)
	ln -sf $< $@

%.so : %.so.$(VERSION)
	ln -sf $< $@

%.po : %.c
	$(XGETTEXT) -a --package-name=$(patsubst %.po,%,$@) --package-version=$(VERSION) -o $@ $^

%.o : %.c
	$(CC) $(BUILDFLAGS) -fPIC -c -o $@ $^

% : %.in
	sed -e "s,@@VERSION@@,$(VERSION),g" \
		-e "s,@@DATADIR@@,$(datadir),g" \
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

install : all
	$(INSTALL) -d -m 755 $(DESTDIR)/$(libdir)
	$(foreach x, $(LIBTARGETS), $(INSTALL) -m 755 $(x) $(DESTDIR)/$(libdir);)
	$(INSTALL) -d -m 755 $(DESTDIR)/$(pcdir)
	$(foreach x, $(PCTARGETS), $(INSTALL) -m 644 $(x) $(DESTDIR)/$(pcdir) ;)
	$(INSTALL) -d -m 755 $(DESTDIR)/$(includedir)/
	$(INSTALL) -m 644 $(INCTARGETS) $(DESTDIR)/$(includedir)/
	$(INSTALL) -d -m 755 $(DESTDIR)/$(localedir)/en/
	$(INSTALL) -m 644 $(POTARGETS) $(DESTDIR)/$(localedir)/en/
	$(INSTALL) -d -m 755 $(DESTDIR)/$(bindir)
	$(foreach x, $(BINTARGETS), $(INSTALL) -m 755 $(x) $(DESTDIR)/$(bindir);)
	$(foreach x, $(wildcard *.so.$(VERSION)), ln -fs $(x) $(patsubst %.so.$(VERSION),%.so,$(DESTDIR)/$(libdir)/$(x)); ln -fs $(x) $(patsubst %.so.$(VERSION),%.so.$(MAJOR_VERSION),$(DESTDIR)/$(libdir)/$(x));)
	$(INSTALL) -d -m 755 $(DESTDIR)$(datadir)/fwupdate/
	$(INSTALL) -d -m 755 $(DESTDIR)$(libexecdir)/fwupdate/
	$(INSTALL) -m 755 cleanup $(DESTDIR)$(libexecdir)/fwupdate/cleanup
	$(INSTALL) -d -m 755 $(DESTDIR)$(libdatadir)/systemd/system
	$(INSTALL) -m 644 cleanup.service \
		$(DESTDIR)$(libdatadir)/systemd/system/fwupdate-cleanup.service
	$(INSTALL) -d -m 755 $(DESTDIR)/usr/share/bash-completion/completions/
	$(INSTALL) -m 755 bash-completion \
		$(DESTDIR)/usr/share/bash-completion/completions/fwupdate
