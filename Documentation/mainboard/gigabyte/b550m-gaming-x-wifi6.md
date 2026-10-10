<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Gigabyte B550M GAMING X WIFI6: port investigation

**Status: investigation only. No working port, selectable build target,
bootable image, or hardware validation exists in this fork.**

## Source baseline and target

The investigation starts at upstream commit
cdd0aaaa8e0c2e52a57b515e801b339549e53283.

The target model was supplied by the project owner. No individual computer's
hardware inventory, processor identity, installed BIOS version, or board
revision is published in this branch. Confirm the printed PCB revision and
actual CPU during local development before choosing firmware.
Gigabyte provides separate downloads for revisions 1.0/1.1 and 1.2.

The manufacturer lists a B550 chipset and 128-Mbit (16-MiB) AMI UEFI flash.
The exact flash chip, voltage, Super I/O part, and board routing are unknown.

## Missing platform support

The baseline has no mainboard for this board and no B550 board identified
by the source audit. CPU support must be evaluated for the chosen processor.
An existing board cannot be renamed to supply these missing implementations.

For example, Picasso's AM4 detection path accepts Family 17h model-1x APUs;
it does not establish support for every AM4 processor. Sharing a socket or
family does not establish compatible initialization.

Useful source references:

- src/soc/amd/picasso/soc_util.c: silicon and AM4 detection.
- src/soc/amd/picasso/Kconfig: Picasso-specific FSP-M/FSP-S interfaces.
- src/vendorcode/amd/psp/psp_efs.h: firmware and Promontory pointers.
- src/vendorcode/amd/psp/psp_directory.h: PSP entry formats.
- src/vendorcode/amd/psp/bios_directory.h: BIOS entry formats.
- src/vendorcode/amd/psp/combo_directory.h: platform selector formats.
- util/amdfwtool: existing AMD image construction and inspection code.

Promontory pointers in upstream structures are not a B550 initialization
implementation. Common AMD blocks do not prove complete support for every CPU.

## Work required before an executable target

1. Confirm the printed PCB revision and measured processor CPUID.
2. Identify the SPI chip and voltage. Obtain two matching full-device reads
   and demonstrate external recovery on the actual board.
3. Map the stock flash layout, CPU selectors, reset entry, platform firmware,
   persistent stores, and board-specific data.
4. Establish a documented, compatible silicon initialization interface for
   the CPU, including memory training. A vendor UEFI image is not
   automatically a callable coreboot FSP binary.
5. Implement and verify chipset, Super I/O, UART, GPIO, DIMM/SPD wiring,
   PCIe topology, interrupts, ACPI, and power management.
6. Add Kconfig, devicetree, board code, and the measured ROM layout only when
   the initialization path is established. Test early debug output and RAM,
   then enumeration and OS boot on recoverable development hardware.

This change guesses no registers, GPIO routing, or memory parameters.
It adds no Kconfig selection or defconfig. Remaining work is physical
platform bring-up, not a completed image waiting to be flashed.

## Included evidence tools

The utilities collect selected Windows registry reports and inspect existing
raw ROM files. The inspector checks bounds and directory Fletcher checksums.
It never changes firmware or verifies executable signatures.

Tables can describe different CPU generations. A checksum match does not
identify the selected table, permit redistribution, or establish bootability.
Manufacturer update files are not backups of this board's unique contents.
Windows PCI registry records may include historical devices; they are not
live configuration-space or GPIO measurements.

Collected hardware evidence and vendor binaries remain outside version control.

## Initial stock-image findings

The official revision 1.0/1.1 F5a package contains a 16-MiB raw file,
B550MGAMINGXWIFI6.F5a. Its SHA-256 is
39a36c484506a0117f9b75caf34e481c0143fffd450a9ed68bdafcbb8738cf7e.
The downloaded ZIP SHA-256 is
7bb62c4a2de529d653d6d8659082bd4e036fa9c2b71ef84e49c1040b72af12d0.

The inspector found one embedded-firmware candidate at file offset 0x020000.
Its new PSP pointer references the combo selector at 0x0e7000; its BIOS3
pointer references the BIOS combo selector at 0x0e7800.
Of 39 signature occurrences, 16 form in-bounds directories with matching
Fletcher checksums; 23 fail structural checks. These rejected occurrences
are not evidence that the vendor image is corrupt.
The PSP combo selector has six entries, including platform ID 0xbc090000.
Mapping that ID to the actual CPU's boot path still needs verification.

Some BIOS reset-image entries are compressed and use a memory-region size,
not a stored-byte length. Treating that size as a flash span produces false
overrun findings, so the inspector leaves compressed lengths undetermined.
No AMD signature verification or firmware execution was performed.

## References

- [Gigabyte 1.0/1.1 support](https://www.gigabyte.com/Motherboard/B550M-GAMING-X-WIFI6-rev-10-11/support)
- [Gigabyte 1.2 specifications](https://www.gigabyte.com/us/Motherboard/B550M-GAMING-X-WIFI6-rev-12/sp)
- [AMD Family 17h background](https://doc.coreboot.org/soc/amd/family17h.html)
- [AMD PSP background](https://doc.coreboot.org/soc/amd/psp_integration.html)
