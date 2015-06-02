TOPDIR	?= $(shell pwd)/..
include $(TOPDIR)/Make.version
include $(TOPDIR)/Make.defaults


CFLAGS		= -O0 -g3
BUILDFLAGS	:= $(CFLAGS) -fpic -Wall -fshort-wchar \
	-fno-strict-aliasing -fno-merge-constants -ffreestanding \
	-fno-stack-protector -fno-stack-check --std=c11 -DCONFIG_$(ARCH) \
	-D__KERNEL__ -I/usr/include/efi/ -I/usr/include/efi/$(ARCH)/ \
	-iquote$(TOPDIR)/include
LDFLAGS		= -nostdlib --warn-common --no-undefined --fatal-warnings \
	-shared -Bsymbolic -L$(LIBDIR) -L$(GNUEFIDIR) \
	$(GNUEFIDIR)/crt0-efi-$(ARCH).o

ifeq ($(ARCH),x86_64)
	FORMAT = --target efi-app-$(ARCH)
	BUILDFLAGS += -mno-mmx -mno-sse -mno-red-zone -nostdinc \
		-maccumulate-outgoing-args -DEFI_FUNCTION_WRAPPER \
		-DGNU_EFI_USE_MS_ABI -I$(shell $(CC) -print-file-name=include)
endif
ifeq ($(ARCH),ia32)
	FORMAT = --target efi-app-$(ARCH)
	BUILDFLAGS += -mno-mmx -mno-sse -mno-red-zone -nostdinc \
		-maccumulate-outgoing-args -m32 \
		-I$(shell $(CC) -print-file-name=include)
endif

ifeq ($(ARCH),aarch64)
	FORMAT = -O binary
	LDFLAGS += --defsym=EFI_SUBSYSTEM=0xa
	BUILDFLAGS += -ffreestanding -I$(shell $(CC) -print-file-name=include)
endif

ifeq ($(ARCH),arm)
	FORMAT = -O binary
	LDFLAGS += --defsym=EFI_SUBSYSTEM=0xa
	BUILDFLAGS += -ffreestanding -I$(shell $(CC) -print-file-name=include)
endif

MAME=make

TARGETS = fakeesrt2.efi fakeesrt.efi dumpesrt.efi fwupdate.efi mkvar.efi dumpf.efi mkvar2.efi

all : $(TARGETS)

%.efi : %.efi.unsigned
	pesign -s -i $< -o $@ --force -c 'Red Hat Test Certificate'

%.efi.unsigned : %.so
	$(OBJCOPY) -j .text -j .sdata -j .data -j .dynamic -j .dynsym \
		-j .rel* -j .rela* -j .reloc \
		$(FORMAT) $^ $@

%.so : %.o
	$(LD) $(LDFLAGS) -o $@ $^ -lefi -lgnuefi \
		$(shell gcc -print-libgcc-file-name) \
		-T $(GNUEFIDIR)/elf_$(ARCH)_efi.lds

%.o : %.c
	$(CC) $(BUILDFLAGS) -c -o $@ $^

clean :
	@rm -vf $(TARGETS) *.o *.so *.efi.unsigned *.efi

install : fwupdate.efi
	$(INSTALL) -d -m 755 $(DESTDIR)/boot/efi/EFI/$(EFIDIR)/fw/
	$(INSTALL) -m 755 fwupdate.efi $(DESTDIR)/boot/efi/EFI/$(EFIDIR)/fwupdate.efi
