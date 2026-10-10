#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read-only AMD directory inspection for this board's 16-MiB raw ROMs."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROM_SIZE = 16 * 1024 * 1024
PHYSICAL_TOP = 1 << 32
ADDRESS_MASK = (1 << 62) - 1
EFS_ADDRESSES = (
    0xFFFA0000, 0xFFF20000, 0xFFE20000,
    0xFFC20000, 0xFF820000, 0xFF020000,
)
DIRECTORIES = {
    b"$PSP": (16, 16, "psp"),
    b"$PL2": (16, 16, "psp"),
    b"$BHD": (16, 24, "bios"),
    b"$BL2": (16, 24, "bios"),
    b"2PSP": (32, 16, "combo"),
    b"2BHD": (32, 16, "combo"),
}
EFS_POINTER_FIELDS = {
    "psp_directory": 0x10,
    "new_psp_directory": 0x14,
    "bios0": 0x18,
    "bios1": 0x1C,
    "bios2": 0x20,
    "bios3": 0x28,
    "psp_backup": 0x2C,
    "promontory_firmware": 0x30,
    "lp_promontory_firmware": 0x34,
    "promontory19_firmware": 0x38,
}


def fletcher32(data):
    """Match util/amdfwtool's little-endian Fletcher checksum."""
    if len(data) % 2:
        raise ValueError("Fletcher input must contain complete 16-bit words")
    words = struct.unpack(f"<{len(data) // 2}H", data)
    c0 = c1 = 0xFFFF
    for start in range(0, len(words), 359):
        for word in words[start:start + 359]:
            c0 += word
            c1 += c0
        c0 = (c0 & 0xFFFF) + (c0 >> 16)
        c1 = (c1 & 0xFFFF) + (c1 >> 16)
    c0 = (c0 & 0xFFFF) + (c0 >> 16)
    c1 = (c1 & 0xFFFF) + (c1 >> 16)
    return ((c1 << 16) | c0) & 0xFFFFFFFF


def resolve_address(encoded, table_offset, rom_size):
    """Return a file offset only for a supported, in-image address."""
    mode = encoded >> 62
    address = encoded & ADDRESS_MASK
    if mode == 0:
        offset = address - (PHYSICAL_TOP - rom_size)
    elif mode == 1:
        offset = address
    elif mode == 2:
        offset = table_offset + address
    else:
        return None, "partition-relative address requires the slot base"
    if not 0 <= offset < rom_size:
        return None, "address is outside the raw image"
    return offset, None


def resolve_unencoded_address(address, rom_size):
    """EFS/combo pointers have no encoded two-bit address-mode field."""
    if address in (0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
        return None, "absent or sentinel pointer"
    if PHYSICAL_TOP - rom_size <= address < PHYSICAL_TOP:
        return address - (PHYSICAL_TOP - rom_size), "physical-address interpretation"
    if 0 < address < rom_size:
        return address, "image-offset interpretation; verify against the target table"
    return None, "unencoded pointer has no supported in-image interpretation"


def parse_directory(data, offset, cookie):
    header_size, entry_size, kind = DIRECTORIES[cookie]
    if offset + header_size > len(data):
        return {"offset": offset, "cookie": cookie.decode(), "error": "truncated header"}
    _, stored_checksum, count, info = struct.unpack_from("<4I", data, offset)
    end = offset + header_size + count * entry_size
    if count > 4096 or end > len(data):
        return {"offset": offset, "cookie": cookie.decode(),
                "error": "entry count exceeds available data or inspection limit"}
    computed = fletcher32(data[offset + 8:end])
    result = {
        "offset": offset,
        "cookie": cookie.decode(),
        "kind": kind,
        "entry_count": count,
        "stored_checksum": f"0x{stored_checksum:08x}",
        "computed_checksum": f"0x{computed:08x}",
        "checksum_matches": stored_checksum == computed,
        "header_info": f"0x{info:08x}",
        "entries": [],
    }
    for index in range(count):
        position = offset + header_size + index * entry_size
        attributes, size_or_id, encoded = struct.unpack_from("<IIQ", data, position)
        resolved, reason = resolve_address(encoded, offset, len(data))
        entry = {"index": index, "encoded_address": f"0x{encoded:016x}",
                 "address_mode": encoded >> 62}
        if kind == "combo":
            resolved, reason = resolve_unencoded_address(encoded, len(data))
            entry = {"index": index, "raw_address": f"0x{encoded:016x}"}
            entry.update({"id_selector": attributes, "platform_id": f"0x{size_or_id:08x}",
                          "directory_offset": resolved, "resolution_note": reason})
        else:
            entry_type = attributes & 0xFF
            entry.update({"type": f"0x{entry_type:02x}", "size": size_or_id,
                          "attributes": f"0x{attributes:08x}"})
            if kind == "psp" and entry_type == 0x0B:
                entry.update({"storage": "inline_value", "value": f"0x{encoded:016x}"})
            elif kind == "bios" and entry_type in (0x61, 0x6B):
                entry.update({
                    "storage": "memory_descriptor",
                    "destination": f"0x{struct.unpack_from('<Q', data, position + 16)[0]:016x}",
                })
            elif kind == "bios" and attributes & (1 << 19):
                entry.update({
                    "storage": "compressed_image_candidate", "file_offset": resolved,
                    "size_semantics": "memory-region size; compressed stored length unknown",
                    "resolution_note": reason,
                    "destination": f"0x{struct.unpack_from('<Q', data, position + 16)[0]:016x}",
                })
            else:
                entry.update({
                    "storage": "flash_span_candidate", "file_offset": resolved,
                    "span_within_image": resolved is not None
                    and resolved + size_or_id <= len(data),
                    "resolution_note": reason,
                })
                if kind == "bios":
                    entry["destination"] = (
                        f"0x{struct.unpack_from('<Q', data, position + 16)[0]:016x}"
                    )
        result["entries"].append(entry)
    return result


def inspect(data, filename="raw-image"):
    if len(data) != ROM_SIZE:
        raise ValueError(f"Expected a raw {ROM_SIZE}-byte image; got {len(data)} bytes")
    report = {
        "schema_version": 1,
        "image_name": filename,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "flash_ready": False,
        "limitations": [
            "Directory candidates are not automatically selected for the installed CPU.",
            "No cryptographic signature, board compatibility, or bootability verification.",
            "Partition-relative addresses remain unresolved.",
            "Vendor update files are not backups of board-specific contents.",
        ],
        "embedded_firmware_candidates": [],
        "directory_candidates": [],
    }
    for physical in EFS_ADDRESSES:
        offset = physical - (PHYSICAL_TOP - len(data))
        if data[offset:offset + 4] != struct.pack("<I", 0x55AA55AA):
            continue
        pointers = {}
        for name, field_offset in EFS_POINTER_FIELDS.items():
            pointer = struct.unpack_from("<I", data, offset + field_offset)[0]
            resolved, reason = resolve_unencoded_address(pointer, len(data))
            pointers[name] = {"raw": f"0x{pointer:08x}", "file_offset": resolved,
                              "resolution_note": reason}
        report["embedded_firmware_candidates"].append(
            {"offset": offset, "physical_address": f"0x{physical:08x}", "pointers": pointers}
        )
    for cookie in DIRECTORIES:
        start = 0
        while True:
            offset = data.find(cookie, start)
            if offset < 0:
                break
            report["directory_candidates"].append(parse_directory(data, offset, cookie))
            start = offset + len(cookie)
    report["directory_candidates"].sort(key=lambda item: item["offset"])
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Existing 16-MiB raw ROM; opened read-only")
    args = parser.parse_args()
    try:
        with args.image.open("rb") as stream:
            data = stream.read(ROM_SIZE + 1)
        report = inspect(data, args.image.name)
    except (OSError, ValueError) as error:
        print(f"Inspection failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
