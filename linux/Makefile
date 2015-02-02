CC	= gcc
LD	= ld
MAKE	= make
CFLAGS	= -g -O0
LIB_LIBS=
BIN_LIBS= popt
PKLIBS	= efivar
PREFIX	= /usr
LIBDIR	= $(PREFIX)/lib64
DATADIR = $(PREFIX)/share
LOCALEDIR = $(DATADIR)/locale
BIN_CCLDFLAGS = $(foreach lib,$(BIN_LIBS),-l$(lib)) $(foreach pklib,$(PKLIBS), $(shell pkg-config --libs-only-l --libs-only-other $(pklib))) \
	-pie -fPIE -Wl,-z,relro,-z,now
LIB_CCLDFLAGS = $(foreach lib,$(LIB_LIBS),-l$(lib)) $(foreach pklib,$(PKLIBS), $(shell pkg-config --libs-only-l --libs-only-other $(pklib))) \
	-shared -fPIC -Wl,-z,relro,-z,now

BUILDFLAGS := $(CFLAGS) -Wall -Wno-unused-result -Wno-unused-function \
	-Wsign-compare -Werror=sign-compare \
	-fshort-wchar --std=c11 \
	-DLOCALEDIR=\"$(LOCALEDIR)\" \
	-pie -fPIE

TARGETS = fwupdate libfwupdate.so
VERSION	= 0.1

.SUFFIXES:

all : $(TARGETS)

% : %.o
	$(CC) $(BUILDFLAGS) $(BIN_CCLDFLAGS) -o $@ $^

%.so : %.o
	$(CC) $(BUILDFLAGS) $(LIB_CCLDFLAGS) \
		-Wl,-soname,$@.so.$(VERSION) \
		-o $@ $^

%.o : %.c
	$(CC) $(BUILDFLAGS) -c -o $@ $^

clean :
	@rm -vf $(TARGETS) *.o *.so
