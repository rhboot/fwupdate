CC=gcc
LD=ld
CFLAGS=-mno-red-zone -mno-mmx -mno-sse -O0 -fpic -Wall -fshort-wchar \
	-fno-strict-aliasing -fno-merge-constants -ffreestanding \
	-fno-stack-protector -fno-stack-check -DCONFIG_x86_64 \
	-DGNU_EFI_USE_MS_ABI -maccumulate-outgoing-args --std=c11 \
	-D__KERNEL__ -I/usr/include/efi/ -I/usr/include/efi/x86_64/
LDFLAGS=-nostdlib --warn-common --no-undefined --fatal-warnings -shared \
	-Bsymbolic -L/usr/lib64 -L/usr/lib64/gnuefi \
	/usr/lib64/gnuefi/crt0-efi-x86_64.o
MAME=make

TARGETS = fakeesrt.efi

all : $(TARGETS)

%.efi : %.efi.unsigned
	pesign -s -i $< -o $@ --force -c 'Red Hat Test Certificate'

%.efi.unsigned : %.so
	objcopy -j .text -j .sdata -j .data -j .dynamic -j .dynsym -j .rel* \
		-j .rela* -j .reloc --target efi-app-x86_64 $^ $@

%.so : %.o
	$(LD) $(LDFLAGS) -o $@ $^ -lefi -lgnuefi \
		/usr/lib/gcc/x86_64-redhat-linux/4.9.2/libgcc.a \
		-T /usr/lib64/gnuefi/elf_x86_64_efi.lds

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $^

clean :
	@rm -vf $(TARGETS) *.o *.so *.efi.unsigned *.efi
