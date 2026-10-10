# SPDX-License-Identifier: GPL-2.0-only
"""Exercise malformed directory bounds and AMD pointer interpretations."""

import importlib.util
from pathlib import Path
import struct
import unittest

SPEC = importlib.util.spec_from_file_location(
    "inspect_rom", Path(__file__).resolve().parents[1] / "inspect_rom.py"
)
rom = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rom)


class RomInspectionTests(unittest.TestCase):
    def test_physical_address_does_not_wrap(self):
        self.assertEqual(rom.resolve_address(0xFF000000, 0, rom.ROM_SIZE), (0, None))
        self.assertEqual(rom.resolve_address(0xFFFFFFFF, 0, rom.ROM_SIZE)[0], rom.ROM_SIZE - 1)
        self.assertIsNone(rom.resolve_address(0xFEFFFFFF, 0, rom.ROM_SIZE)[0])
        self.assertIsNone(rom.resolve_address(0x100000000, 0, rom.ROM_SIZE)[0])

    def test_relative_address_modes(self):
        self.assertEqual(rom.resolve_address((1 << 62) | 0x20, 0x100, rom.ROM_SIZE)[0], 0x20)
        self.assertEqual(rom.resolve_address((2 << 62) | 0x20, 0x100, rom.ROM_SIZE)[0], 0x120)
        self.assertIsNone(rom.resolve_address((3 << 62) | 0x20, 0x100, rom.ROM_SIZE)[0])
        self.assertIsNone(
            rom.resolve_address((2 << 62) | rom.ROM_SIZE, 0x100, rom.ROM_SIZE)[0]
        )

    def test_truncated_directory_and_hostile_count(self):
        short = b"$PSP" + bytes(6)
        self.assertEqual(rom.parse_directory(short, 0, b"$PSP")["error"], "truncated header")
        hostile = struct.pack("<4I", 0x50535024, 0, 0xFFFFFFFF, 0)
        self.assertIn("error", rom.parse_directory(hostile, 0, b"$PSP"))

    def test_span_overrun_and_inline_value(self):
        data = bytearray(256)
        struct.pack_into("<4I", data, 0, 0x50535024, 0, 2, 0)
        struct.pack_into("<IIQ", data, 16, 1, 64, (1 << 62) | 240)
        struct.pack_into("<IIQ", data, 32, 0x0B, 0xFFFFFFFF, 0x1234)
        struct.pack_into("<I", data, 4, rom.fletcher32(data[8:48]))
        parsed = rom.parse_directory(data, 0, b"$PSP")
        self.assertTrue(parsed["checksum_matches"])
        self.assertFalse(parsed["entries"][0]["span_within_image"])
        self.assertEqual(parsed["entries"][1]["storage"], "inline_value")

    def test_checksum_known_vector_and_corruption(self):
        self.assertEqual(rom.fletcher32(bytes(8)), 0xFFFFFFFF)
        self.assertEqual(rom.fletcher32(struct.pack("<3H", 1, 2, 3)), 0x000A0006)
        data = bytearray(32)
        struct.pack_into("<4I", data, 0, 0x50535024, 0, 1, 0)
        struct.pack_into("<IIQ", data, 16, 1, 2, 1 << 62)
        struct.pack_into("<I", data, 4, rom.fletcher32(data[8:]))
        self.assertTrue(rom.parse_directory(data, 0, b"$PSP")["checksum_matches"])
        data[20] ^= 1
        self.assertFalse(rom.parse_directory(data, 0, b"$PSP")["checksum_matches"])

    def test_bios_memory_descriptor_and_combo_selector(self):
        bios = bytearray(40)
        struct.pack_into("<4I", bios, 0, 0x44484224, 0, 1, 0)
        struct.pack_into("<IIQQ", bios, 16, 0x61, 4096, 0, 0x12340000)
        struct.pack_into("<I", bios, 4, rom.fletcher32(bios[8:]))
        entry = rom.parse_directory(bios, 0, b"$BHD")["entries"][0]
        self.assertEqual(entry["storage"], "memory_descriptor")
        combo = bytearray(48)
        struct.pack_into("<4I", combo, 0, 0x50535032, 0, 1, 0)
        struct.pack_into("<IIQ", combo, 32, 1, 0xBC0A0000, 40)
        struct.pack_into("<I", combo, 4, rom.fletcher32(combo[8:]))
        parsed = rom.parse_directory(combo, 0, b"2PSP")
        self.assertTrue(parsed["checksum_matches"])
        self.assertEqual(parsed["entries"][0]["platform_id"], "0xbc0a0000")
        self.assertEqual(parsed["entries"][0]["directory_offset"], 40)
        self.assertNotIn("address_mode", parsed["entries"][0])

    def test_unencoded_relative_pointers_and_sentinels(self):
        self.assertEqual(rom.resolve_unencoded_address(0xE7000, rom.ROM_SIZE)[0], 0xE7000)
        self.assertEqual(rom.resolve_unencoded_address(0xFF0E7000, rom.ROM_SIZE)[0], 0xE7000)
        for address in (0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 1 << 62):
            self.assertIsNone(rom.resolve_unencoded_address(address, rom.ROM_SIZE)[0])

    def test_compressed_region_size_is_not_stored_length(self):
        data = bytearray(64)
        struct.pack_into("<4I", data, 0, 0x44484224, 0, 1, 0)
        struct.pack_into("<IIQQ", data, 16, 0x00080062, 4096, (1 << 62) | 48, 0xA000000)
        struct.pack_into("<I", data, 4, rom.fletcher32(data[8:40]))
        entry = rom.parse_directory(data, 0, b"$BHD")["entries"][0]
        self.assertEqual(entry["storage"], "compressed_image_candidate")
        self.assertEqual(entry["file_offset"], 48)
        self.assertNotIn("span_within_image", entry)

    def test_efs_image_offset_is_retained(self):
        data = bytearray(rom.ROM_SIZE)
        struct.pack_into("<I", data, 0x20000, 0x55AA55AA)
        struct.pack_into("<I", data, 0x20014, 0xE7000)
        struct.pack_into("<I", data, 0x2002C, 0xFFFFFFFF)
        pointers = rom.inspect(data)["embedded_firmware_candidates"][0]["pointers"]
        self.assertEqual(pointers["new_psp_directory"]["file_offset"], 0xE7000)
        self.assertIsNone(pointers["psp_backup"]["file_offset"])

    def test_wrong_size_is_rejected(self):
        for data in (b"", bytes(1024), bytes(rom.ROM_SIZE + 1)):
            with self.assertRaises(ValueError):
                rom.inspect(data)

    def test_empty_image_has_no_bootability_claim(self):
        report = rom.inspect(bytes(rom.ROM_SIZE))
        self.assertFalse(report["flash_ready"])
        self.assertEqual(report["directory_candidates"], [])


if __name__ == "__main__":
    unittest.main()
