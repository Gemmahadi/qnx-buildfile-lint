"""Build synthetic, byte-accurate QNX IFS images.

Used by the test suite and the demo: a minimal bootable image (startup
header + startup program + imagefs with a handful of files, a symlink
and a device node), optionally zlib-compressed, in either byte order.

The layout mirrors the reference fixture builders of the MIT-licensed
``qnx-ifs`` crate, with one improvement: the trailer checksums are
written correctly (negated 32-bit word sum), so ``ifs`` verifies them.
"""

from __future__ import annotations

import struct
import zlib

from .ifs import _word_sum


def _align4(n: int) -> int:
    return (n + 3) & ~3


def _align8(n: int) -> int:
    return (n + 7) & ~7


class Endian:
    def __init__(self, big: bool = False):
        self.big = big
        self.prefix = ">" if big else "<"

    def u16(self, v: int) -> bytes:
        return struct.pack(self.prefix + "H", v)

    def u32(self, v: int) -> bytes:
        return struct.pack(self.prefix + "I", v)


LE = Endian(False)
BE = Endian(True)


def startup_header(endian: Endian, flags1: int, startup_size: int,
                   stored_size: int, imagefs_size: int,
                   machine: int = 62) -> bytes:
    """256-byte startup header (64 fixed bytes + zeroed info[48])."""
    out = bytearray()
    out += b"\x00\xff\x7e\xeb" if endian.big else b"\xeb\x7e\xff\x00"
    out += endian.u16(1)          # version
    out += bytes([flags1, 0])     # flags1, flags2
    out += endian.u16(256)        # header_size
    out += endian.u16(machine)    # machine (62 = EM_X86_64)
    out += endian.u32(0x00100000)  # startup_vaddr
    out += endian.u32(0)          # paddr_bias
    out += endian.u32(0x00100000)  # image_paddr
    out += endian.u32(0x00100000)  # ram_paddr
    out += endian.u32(0x1000)     # ram_size
    out += endian.u32(startup_size)
    out += endian.u32(stored_size)
    out += endian.u32(0)          # imagefs_paddr
    out += endian.u32(imagefs_size)
    out += endian.u16(0)          # preboot_size
    out += bytes(14)              # zero0 + zero[3]
    assert len(out) == 64
    out += bytes(192)             # info[48]
    assert len(out) == 256
    return bytes(out)


def _attr(endian: Endian, size: int, ino: int, mode: int, uid: int = 0,
          gid: int = 0, mtime: int = 1) -> bytes:
    return (endian.u16(size) + endian.u16(0) + endian.u32(ino)
            + endian.u32(mode) + endian.u32(gid) + endian.u32(uid)
            + endian.u32(mtime))


def _dirent(endian: Endian, kind_fixed: int, extra: bytes, path: str,
            target: str | None, ino: int, mode: int) -> bytes:
    raw = kind_fixed + len(path.encode()) + 1
    if target is not None:
        raw += len(target.encode()) + 1
    size = _align4(raw)
    out = bytearray()
    out += _attr(endian, size, ino, mode)
    out += extra
    out += path.encode() + b"\x00"
    if target is not None:
        out += target.encode() + b"\x00"
    out += bytes(size - len(out))
    assert len(out) == size
    return bytes(out)


def _file_extra(endian: Endian, offset: int, size: int) -> bytes:
    return endian.u32(offset) + endian.u32(size)


def _device_extra(endian: Endian, dev: int, rdev: int) -> bytes:
    return endian.u32(dev) + endian.u32(rdev)


def build_filesystem(endian: Endian, mountpoint: str = "/",
                     files: dict | None = None) -> bytes:
    """Build an imagefs blob.

    *files* maps target path -> bytes (regular files). The image always
    contains the root dir, procnto, a shell script and a symlink, plus
    the given extra files.
    """
    files = files or {}
    shell = b"#!/bin/sh\ndisplay_msg Booting QNX 8.0 demo\n"
    procnto = b"\x7fELF" + bytes(60)  # placeholder procnto image

    # entry list: (kind_fixed, extra, path, target, ino, mode, data)
    planned = []
    planned.append((24, b"", "", None, 1, 0o040755, None))            # root
    planned.append((24, b"", "proc", None, 2, 0o040755, None))
    planned.append((24, b"", "proc/boot", None, 3, 0o040755, None))
    planned.append((32, None, "proc/boot/procnto", None, 4, 0o100755, procnto))
    planned.append((32, None, "proc/boot/.script", None, 5, 0o100644, shell))
    planned.append((28, None, "bin/sh", "/proc/boot/.script", 6, 0o120777, None))
    ino = 10
    for target_path, data in sorted(files.items()):
        ino += 1
        planned.append((32, None, target_path, None, ino, 0o100644, data))

    header_len = _align4(88 + len(mountpoint.encode()) + 1)
    dir_area = sum(_align4(k + len(p.encode()) + 1
                           + (len(t.encode()) + 1 if t else 0))
                   for k, _, p, t, _, _, _ in planned)
    data_offset = header_len + dir_area + 4  # +4: chain terminator
    # lay out file data offsets
    cursor = data_offset
    blobs = []
    for item in planned:
        k, extra, p, t, i, mode, data = item
        if data is not None:
            blobs.append((p, cursor, data))
            cursor += len(data)
    image_size = _align4(cursor) + 4  # +4: image trailer
    hdr_dir_size = header_len + dir_area + 4

    fs = bytearray()
    fs += b"imagefs"
    fs += bytes([0x01 if endian.big else 0x00])
    fs += endian.u32(image_size)
    fs += endian.u32(hdr_dir_size)
    fs += endian.u32(header_len)
    for _ in range(4):
        fs += endian.u32(0)      # boot_ino
    fs += endian.u32(5)          # script_ino (.script)
    fs += endian.u32(0)          # chain_paddr
    for _ in range(10):
        fs += endian.u32(0)      # spare
    fs += endian.u32(0)          # mountflags
    fs += mountpoint.encode() + b"\x00"
    fs += bytes(header_len - len(fs))
    assert len(fs) == header_len

    data_by_path = {p: (off, d) for p, off, d in blobs}
    for k, extra, p, t, i, mode, data in planned:
        if data is not None:
            off, _ = data_by_path[p]
            extra = _file_extra(endian, off, len(data))
        elif t is not None:
            sym_off = len(p.encode()) + 1
            extra = endian.u16(sym_off) + endian.u16(len(t.encode()) + 1)
        fs += _dirent(endian, k, extra or b"", p, t, i, mode)
    fs += bytes(4)               # chain terminator
    assert len(fs) == data_offset
    for _, off, data in blobs:
        assert len(fs) == off
        fs += data
    fs += bytes(_align4(len(fs)) - len(fs))
    # image trailer: negated word sum over [0, image_size-4)
    trailer = _word_sum(bytes(fs), "big" if endian.big else "little")
    fs += endian.u32(trailer)
    assert len(fs) == image_size
    return bytes(fs)


def build_image(endian: Endian = LE, compress: str = "none",
                mountpoint: str = "/", files: dict | None = None,
                machine: int = 62) -> bytes:
    """Build a whole bootable .ifs image (startup header + imagefs)."""
    filesystem = build_filesystem(endian, mountpoint, files)
    flags1 = 0x02 if endian.big else 0x00
    if compress == "none":
        program = b"\x7fELF"
        startup_size = _align8(256 + len(program))
        trailer_off = startup_size - 4
        # startup region: header + program + trailer
        region = bytearray()
        region += program
        region += bytes(startup_size - 256 - len(program))
        # checksum over [header, trailer)
        header = startup_header(endian, flags1, startup_size,
                                startup_size + len(filesystem),
                                len(filesystem), machine)
        full_region = header + bytes(region)
        assert len(full_region) == startup_size
        cksum = _word_sum(full_region[:trailer_off],
                          "big" if endian.big else "little")
        full_region = (full_region[:trailer_off]
                       + endian.u32(cksum))
        assert len(full_region) == startup_size
        return full_region + filesystem
    if compress == "zlib":
        flags1 |= 0x04
        payload = zlib.compress(filesystem)
        startup_size = 260  # header + 4-byte startup trailer
        stored_size = 256 + len(payload) + 4
        header = startup_header(endian, flags1, startup_size, stored_size,
                                len(filesystem), machine)
        cksum = _word_sum(header, "big" if endian.big else "little")
        return header + endian.u32(cksum) + payload
    raise ValueError("unsupported compression: %s" % compress)
