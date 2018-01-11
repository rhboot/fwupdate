UEFI firmware capsules for Linux
--------
This project provides the pieces needed to flash an industry standard UEFI capsule in a Linux OS.
It also aims to be compatible with some implementation decisions that were made in Windows.

## Dependencies
The following dependencies are needed to compile:
 * libpopt
 * efivar (>=33)
 * gnu-efi (>= 3.0.2)
 * elfutils

Optionally if libsmbios is present some additional features on Dell systems can be enabled
as well.

## Compiling

Optionally set the EFI system partition mount point.  If not configured it will default to `/boot/efi`
```
# git config fwupdate.espmountdir
```

Set the EFI subdirectory directory that EFI binaries are installed into.
```
# git config fwupdate.efidir $DIRECTORY
```
This usually refers to the OS distributor.  For example on Ubuntu it's set to *ubuntu*

Run the build command
```
# make
```

Run the install command
```
# make install
```

## Other notes
Some distributions don't use the same paths for the dependencies as in Make.defaults.
For example on Debian and Ubuntu you need to override GNUEFIDIR to the correct path.
