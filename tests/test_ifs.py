"""Tests for the IFS image inspector and the synthetic image builder."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from qnx_buildfile_lint.ifs import parse_image
from qnx_buildfile_lint.ifsgen import BE, LE, build_filesystem, build_image


def codes(image, severity=None):
    return [d.code for d in image.report.diagnostics
            if severity is None or d.severity == severity]


class TestSyntheticImages(unittest.TestCase):
    def test_uncompressed_le_roundtrip(self):
        image = parse_image(build_image(LE, "none"), "test.ifs")
        self.assertEqual(codes(image, "error"), [])
        self.assertTrue(image.bootable)
        self.assertEqual(image.startup.machine, 62)
        self.assertEqual(image.startup.compress, "none")
        self.assertEqual(image.startup.endian, "little")
        self.assertEqual(image.image_header.mountpoint, "/")
        paths = {e.path for e in image.entries}
        self.assertIn("proc/boot/procnto", paths)
        self.assertIn("proc/boot/.script", paths)
        self.assertIn("bin/sh", paths)
        link = next(e for e in image.entries if e.path == "bin/sh")
        self.assertEqual(link.kind, "symlink")
        self.assertEqual(link.target, "/proc/boot/.script")
        script = next(e for e in image.entries
                      if e.path == "proc/boot/.script")
        self.assertEqual(script.kind, "file")
        self.assertEqual(image.image_header.script_ino, script.ino)

    def test_uncompressed_be_roundtrip(self):
        image = parse_image(build_image(BE, "none"), "test.ifs")
        self.assertEqual(codes(image, "error"), [])
        self.assertEqual(image.startup.endian, "big")
        self.assertEqual(image.image_header.endian, "big")
        paths = {e.path for e in image.entries}
        self.assertIn("proc/boot/procnto", paths)

    def test_zlib_roundtrip(self):
        image = parse_image(build_image(LE, "zlib"), "test.ifs")
        self.assertEqual(codes(image, "error"), [])
        self.assertEqual(image.startup.compress, "zlib")
        paths = {e.path for e in image.entries}
        self.assertIn("proc/boot/procnto", paths)

    def test_extra_files(self):
        image = parse_image(build_image(
            LE, "none", files={"etc/motd": b"hello\n", "usr/bin/tool": b"X"}),
            "test.ifs")
        self.assertEqual(codes(image, "error"), [])
        by_path = {e.path: e for e in image.entries}
        self.assertIn("etc/motd", by_path)
        self.assertIn("usr/bin/tool", by_path)

    def test_bare_filesystem(self):
        fs = build_filesystem(LE)
        image = parse_image(fs, "bare.ifs")
        self.assertEqual(codes(image, "error"), [])
        self.assertFalse(image.bootable)
        self.assertIsNone(image.startup)
        self.assertIn("proc/boot/procnto",
                      {e.path for e in image.entries})

    def test_file_bytes(self):
        from qnx_buildfile_lint.ifs import file_bytes
        image = parse_image(build_image(LE, "none"), "test.ifs")
        script = next(e for e in image.entries
                      if e.path == "proc/boot/.script")
        data = file_bytes(image, script)
        self.assertTrue(data.startswith(b"#!/bin/sh"))


class TestCorruption(unittest.TestCase):
    def test_not_an_ifs(self):
        image = parse_image(b"this is definitely not a qnx image" * 4,
                            "junk.bin")
        self.assertIn("QNX500", codes(image, "error"))

    def test_truncated_image(self):
        good = build_image(LE, "none")
        image = parse_image(good[:len(good) // 2], "cut.ifs")
        self.assertTrue(codes(image, "error"))

    def test_corrupt_file_data_breaks_image_checksum(self):
        good = bytearray(build_image(LE, "none"))
        # flip a byte inside the .script file data (last quarter)
        good[-12] ^= 0xFF
        image = parse_image(bytes(good), "corrupt.ifs")
        self.assertIn("QNX504", codes(image, "error"))

    def test_corrupt_startup_header(self):
        good = bytearray(build_image(LE, "none"))
        good[6] = 0xFF  # flags1: unknown compression selector bits
        image = parse_image(bytes(good), "corrupt.ifs")
        self.assertTrue(codes(image, "error"))

    def test_empty_file(self):
        image = parse_image(b"", "empty.ifs")
        self.assertIn("QNX500", codes(image, "error"))


if __name__ == "__main__":
    unittest.main()
