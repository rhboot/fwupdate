CC	= gcc
LD	= ld
MAKE	= make
XGETTEXT = xgettext
PREFIX	= /usr
LIBDIR	= $(PREFIX)/lib64
DATADIR = $(PREFIX)/share
LOCALEDIR = $(DATADIR)/locale
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
	-DLOCALEDIR=\"$(LOCALEDIR)\" -D_GNU_SOURCE \

VERSION	= 0.1
TARGETS = fwupdate libfwup.so.$(VERSION) libfwup.so fwupdate.po libfwup.po

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

clean :
	@rm -vf $(TARGETS) *.o *.so *.po lib*.so.*
