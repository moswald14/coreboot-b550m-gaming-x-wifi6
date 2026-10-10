<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# B550M GAMING X WIFI6 investigation tools

These tools prepare evidence; they do not implement firmware.
Python 3.10 or newer is sufficient for the offline inspector and tests.
No third-party Python packages are required.

## Collect Windows reports

From this directory in PowerShell:

~~~powershell
./collect_hardware.ps1
~~~

It reads named BIOS/CPU registry values and PCI hardware IDs, then writes
evidence/windows-hardware.json, ignored by Git. It collects no serial numbers,
account names, MAC/IP addresses, disks, files, or credentials.
It uploads nothing and rejects a different motherboard model.
PCI registry records may include historical devices; they do not give routing.

## Inspect a raw ROM

~~~text
python inspect_rom.py path/to/stock-image.bin > evidence/rom-report.json
python -m unittest discover -s tests -v
~~~

Input must be exactly 16 MiB, the published board capacity.
The inspector does not unwrap archives or capsules, choose a CPU, or change
the image. The report gives SHA-256, standard AMD embedded-firmware candidates,
PSP/BIOS/combo directory candidates, spans, and Fletcher checksums.
Partition-relative entries need a slot base and remain unresolved.
Inline values and RAM descriptors are distinguished from flash spans.
Compressed BIOS entries report memory-region size; the stored compressed
length cannot be inferred from that field. EFS and combo pointers have no
encoded address mode, so physical and image-offset interpretations are
labeled explicitly and must be checked against the referenced table.

The report always says flash_ready: false. Bounds and directory checksums
do not verify executable signatures or establish a usable boot chain.
