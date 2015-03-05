TOPDIR	?= $(shell pwd)/..
include $(TOPDIR)/Make.defaults

LIB_LIBS= pthread
BIN_LIBS= popt pthread
PKLIBS	= efivar
CFLAGS	= -g -O0
BIN_CCLDFLAGS = $(foreach lib,$(BIN_LIBS),-l$(lib)) \
	$(foreach pklib,$(PKLIBS), \
		$(shell pkg-config --libs-only-l --libs-only-other $(pklib))) \
	-pie -fPIE -Wl,-z,relro,-z,now -L.
LIB_CCLDFLAGS = $(foreach lib,$(LIB_LIBS),-l$(lib)) \
	$(foreach pklib,$(PKLIBS), \
		$(shell pkg-config --libs-only-l --libs-only-other $(pklib))) \
	-shared -fPIC -Wl,-z,relro,-z,now

BUILDFLAGS := $(CFLAGS) -Wall -Wno-unused-result -Wno-unused-function \
	-Wsign-compare -Werror=sign-compare \
	-fshort-wchar --std=c11 \
	-DLOCALEDIR=\"$(localedir)\" -D_GNU_SOURCE \
	-I$(TOPDIR)/linux/include \
	$(foreach pklib,$(PKLIBS), $(shell pkg-config --cflags $(pklib)))

BINTARGETS=fwupdate
INCTARGETS=include/fwup.h
LIBTARGETS=libfwup.so.$(VERSION)
PCTARGETS=fwup.pc
POTARGETS = fwupdate.po libfwup.po
TARGETS=$(BINTARGETS) $(INCTARGETS) $(LIBTARGETS) $(PCTARGETS) $(POTARGETS) libfwup.so

.SUFFIXES:

all : $(TARGETS)

fwupdate : libfwup.so

% : %.o
	$(CC) $(BUILDFLAGS) $(BIN_CCLDFLAGS) -o $@ $(patsubst lib%.so,-l%,$^)

%.so.$(VERSION) : %.o
	$(CC) $(BUILDFLAGS) $(LIB_CCLDFLAGS) \
		-Wl,-soname,$@ \
		-o $@ $^

%.so : %.so.$(VERSION)
	ln -sf $^ $@

%.po : %.c
	$(XGETTEXT) -a --package-name=$(patsubst %.po,%,$@) --package-version=$(VERSION) -o $@ $^

%.o : %.c
	$(CC) $(BUILDFLAGS) -fPIC -c -o $@ $^

fwup.pc : fwup.pc.in
	sed -e "s,@@VERSION@@,$(VERSION),g" \
		-e "s,@@LIBDIR@@,$(libdir),g" \
		$< > $@

tester : tester.c
	$(CC) -Wall -Werror -ggdb -L. -I./include -I/usr/include/efivar \
		-lefivar -lfwup -o $@ $^

test : tester
	LD_LIBRARY_PATH=$(shell pwd) ./tester

clean :
	@rm -vf $(BINTARGETS) $(LIBTARGETS) $(PCTARGETS) $(POTARGETS) *.o

install : all
	$(INSTALL) -d -m 755 $(libdir)
	$(foreach x, $(LIBTARGETS), $(INSTALL) -m 755 $(x) $(libdir);)
	$(INSTALL) -d -m 755 $(pcdir)
	$(foreach x, $(PCTARGETS), $(INSTALL) -m 644 $(x) $(pcdir) ;)
	$(INSTALL) -d -m 755 $(includedir)/
	$(INSTALL) -m 644 $(INCTARGETS) $(includedir)/
	$(INSTALL) -d -m 755 $(localedir)/en/
	$(INSTALL) -m 644 $(POTARGETS) $(localedir)/en/
	$(INSTALL) -d -m 755 $(bindir)
	$(foreach x, $(BINTARGETS), $(INSTALL) -m 755 $(x) $(bindir);)
	ln -s libfwup.so.$(VERSION) $(libdir)/libfwup.so
	$(foreach x, $(wildcard *.so.$(VERSION)), ln -fs $(x) $(patsubst %.so.$(VERSION),%.so,$(libdir)/$(x));)


