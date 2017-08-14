default : all

ifneq	($(origin TOPDIR),undefined)
TOP     := $(abspath $(TOPDIR))
else
TOP     := $(abspath ..)
endif
include $(TOP)/Make.version
include $(TOP)/Make.defaults
VPATH	= $(TOP)/efi

CFLAGS	?= -Og -g3 -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 \
	   -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 \
	   -grecord-gcc-switches
BUILDFLAGS	:= $(CFLAGS) -fpic -Werror -Wall -Wextra -fshort-wchar \
	-fno-merge-constants -ffreestanding \
	-fno-stack-protector -fno-stack-check --std=gnu11 -DCONFIG_$(ARCH) \
	-I/usr/include/efi/ -I/usr/include/efi/$(ARCH)/ \
	-iquote$(TOP)/include "-DDEBUGDIR=L\"$(DEBUGDIR)/\""
CCLDFLAGS	?= -nostdlib -Wl,--warn-common \
	-Wl,--no-undefined -Wl,--fatal-warnings \
	-Wl,-shared -Wl,-Bsymbolic -L$(LIBDIR) -L$(GNUEFIDIR) \
	-Wl,--build-id=sha1 -Wl,--hash-style=sysv \
	$(GNUEFIDIR)/crt0-efi-$(ARCH).o

define objcopy_version =
  $(OBJCOPY) --version |
    sed -e '/^GNU objcopy/! d;
	    : loop1; s/([^)(]*)//g;   t loop1;
	    : loop2; s/\[[^][]*\]//g; t loop2;
	    s/.* \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/;'
endef
OBJCOPY_GTE224 := $(shell expr `$(objcopy_version)` \>= 2.24)

FWUP = fwupdate

ifeq ($(ARCH),x86_64)
	FORMAT = --target efi-app-$(ARCH)
	BUILDFLAGS += -mno-mmx -mno-sse -mno-red-zone -nostdinc \
		-maccumulate-outgoing-args -DEFI_FUNCTION_WRAPPER \
		-DGNU_EFI_USE_MS_ABI -I$(shell $(CC) -print-file-name=include)
	FWUP = fwupx64
endif
ifeq ($(ARCH),ia32)
	FORMAT = --target efi-app-$(ARCH)
	BUILDFLAGS += -mno-mmx -mno-sse -mno-red-zone -nostdinc \
		-maccumulate-outgoing-args -m32 \
		-I$(shell $(CC) -print-file-name=include)
	FWUP = fwupia32
endif

ifeq ($(ARCH),aarch64)
	FORMAT = -O binary
	CCLDFLAGS += -Wl,--defsym=EFI_SUBSYSTEM=0xa
	BUILDFLAGS += -ffreestanding -I$(shell $(CC) -print-file-name=include)
	FWUP = fwupaa64
endif

ifeq ($(ARCH),arm)
	FORMAT = -O binary
	CCLDFLAGS += -Wl,--defsym=EFI_SUBSYSTEM=0xa
	BUILDFLAGS += -ffreestanding -I$(shell $(CC) -print-file-name=include)
	FWUP = fwuparm
endif

TARGETS = fakeesrt2.efi fakeesrt.efi dumpesrt.efi $(FWUP).efi mkvar.efi dumpf.efi mkvar2.efi

all : $(TARGETS)

.SECONDARY: $(foreach target,$(TARGETS),$(target).debug \
					$(target).build-id \
					$(target).so \
					)

$(FWUP).so : fwupdate.so
	ln -f $< $@

$(FWUP).efi : | $(FWUP).so

%.efi.signed : %.efi %.efi.debug %.efi.build-id
	pesign -s -i $< -o $@ --force -c 'Red Hat Test Certificate'

%.efi : %.so
ifneq ($(OBJCOPY_GTE224),1)
	$(error objcopy >= 2.24 is required)
endif
	$(OBJCOPY) -j .text -j .sdata -j .data -j .dynamic -j .dynsym \
		-j .rel* -j .rela* -j .reloc -j .eh_frame \
		$(FORMAT) $^ $@

%.efi.debug : %.so
ifneq ($(OBJCOPY_GTE224),1)
	$(error objcopy >= 2.24 is required)
endif
	$(OBJCOPY) -j .text -j .sdata -j .data -j .dynamic -j .dynsym \
		-j .rel* -j .rela* -j .reloc -j .eh_frame \
		-j .debug* -j .note.gnu.build-id \
		$^ $@

%.efi.build-id : %.so
	$(READELF) -n $^ | grep "Build ID:" | \
		sed -e 's/^.*Build ID: //' -e 's,^\(..\),\1/,' > $@

%.so : %.o
	$(CC) $(CCLDFLAGS) -o $@ $^ -lefi -lgnuefi \
		$(shell $(CC) -print-libgcc-file-name) \
		-T elf_$(ARCH)_efi.lds

%.o : %.c
	$(CC) $(BUILDFLAGS) -c -o $@ $^

clean :
	@rm -vf $(TARGETS) *.o *.so *.efi.signed *.efi *.efi.debug \
		*.efi.build-id

buildiddir = $(dir $(shell cat $(1).build-id))
buildidname = $(notdir $(shell cat $(1).build-id))
define inst =
 $(INSTALL) -d -m 755 $(DESTDIR)$(TARGETDIR)/
 $(INSTALL) -m 755 $(1) $(DESTDIR)$(TARGETDIR)/$(1)
 $(INSTALL) -d -m 755 $(DESTDIR)$(DEBUGINFO)$(TARGETDIR)/
 $(INSTALL) -m 755 $(1).debug $(DESTDIR)$(DEBUGINFO)$(TARGETDIR)/$(1).debug
 $(INSTALL) -d -m 755 $(DESTDIR)$(DEBUGINFO)/.build-id/$(buildiddir)
 ln -sf ../../../../$(TARGETDIR)/$(1) $(DESTDIR)$(DEBUGINFO)/.build-id/$(buildiddir)/$(buildidname)
 ln -sf ../../$(TARGETDIR)$(1).debug $(DESTDIR)$(DEBUGINFO)/.build-id/$(buildiddir)/$(buildidname).debug
endef

install : | check_efidir_error
install : $(FWUP).efi | $(FWUP).efi.debug $(FWUP).efi.build-id
	$(INSTALL) -d -m 755 $(DESTDIR)$(TARGETDIR)/fw/
	$(foreach prog,$^,$(call inst,$(prog)) ; )
	$(INSTALL) -d -m 755 $(DESTDIR)$(DEBUGSOURCE)/fwupdate-$(VERSION)$(DASHRELEASE)$(DOTARCH)/efi/
	$(foreach src,$(wildcard *.[chS]),$(INSTALL) -m 644 $(src) $(DESTDIR)$(DEBUGSOURCE)/fwupdate-$(VERSION)$(DASHRELEASE)$(DOTARCH)/efi/$(src) ;)
