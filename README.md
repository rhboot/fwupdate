UEFI firmware capsules for Linux
--------
This project provides the pieces needed to flash an industry standard UEFI capsule in a Linux OS.
It also aims to be compatible with some implementation decisions that were made in Windows.

The following binaries are produced:
 * `libfwup` library providing APIs to do UEFI updates for other applications
 * `fwupdate` reference command line tool
 * `fwup.efi` EFI application used for flashing the update from EFI.

## fwupd
[fwupd](https://github.com/hughsie/fwupd) is a project for managing firmware updates of many types of devices.  It has supported UEFI firmware update ever since its first release.
[fwupd](https://github.com/hughsie/fwupd) versions 1.0.x and earlier use `libfwupd` from this project for performing the flash
(following most of *Normal Flow* below).

[fwupd](https://github.com/hughsie/fwupd) versions 1.1.x and later have merged the code from this project directly into the
codebase and will manage boot assets directly at installation time.  This project is not needed when using a newer fwupd.

## Normal flow
UEFI capsule updates are _not_ actually flashed within Linux.  They're staged for update to
be installed on the next boot.

1. `fwupdate --apply` will be executed with the capsule payload as an argument
3. `libfwup` will copy the payload to the EFI system partition.
4. `libfwup` will create EFI NVRAM entries pointing to the correct payload on the EFI system partition.
5. `libfwup` will create a new EFI Boot entry to launch the firmware updating EFI application.
6. `libfwup` will set the `BootNext` variable to run that application on next boot.
7. The user will reboot the system.
8. The `fwup.efi` application will examine EFI NVRAM entries to find capsules previously staged.
9. The `fwup.efi` applciation will call the BIOS `UpdateCapsule()` method to flash the capsules.
10. The BIOS will flash the capsules and then reboot back into the OS.

## Usage
UEFI capsule updates are typically distributed by services such as [LVFS](https://fwupd.org) in _.CAB_ format.  The command line tool provided by this project works directly on the
payload stored in the *.CAB*.
Most users should apply UEFI capsule updates with a higher level tool such as [fwupd](https://github.com/hughsie/fwupd).

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
# git config fwupdate.espmountdir $DIRECTORY
```

Set the EFI subdirectory directory that EFI binaries are installed into.
```
# git config fwupdate.efidir $DIRECTORY
```
This usually refers to the OS distributor.  If not configured it will default to the value defined for `ID` in `/etc/os-release` or `/usr/lib/os-release`.

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
For example on Debian and Ubuntu you need to override `GNUEFIDIR` to the correct path.

## Command line
Checking if UEFI capsule updates are supported:
```
# fwupdate --supported
```

Checking which ESRT GUIDs are on the system:
```
# fwupdate --list
```

Display details of all ESRT entries:
```
# fwupdate --info
```

Applying a payload:
```
# fwupdate --apply=<guid> <payload>
```

Enable firmware updates on supported Dell systems (if compiled with libsmbios):
```
# fwupdate --enable
```

