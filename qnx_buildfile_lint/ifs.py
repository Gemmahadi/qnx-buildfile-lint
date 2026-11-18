"""Inspector for built QNX IFS images (the output of ``mkifs``).

Parses the on-disk structures documented in ``sys/startup.h`` and
``sys/image.h`` (see also the MIT-licensed ``qnx-ifs`` crate, whose
layout documentation this mirrors):

* startup header -- 256 bytes, signature 0x00FF7EEB, version 1, 64-byte
  fixed prefix: version u16, flags1 u8, flags2 u8, header_size u16,
  machine u16, startup_vaddr, paddr_bias, image_paddr, ram_paddr,
  ram_size, startup_size, stored_size, imagefs_paddr, imagefs_size
  (u32 each), preboot_size u16, 14 zero bytes, then info[48].
  flags1 bit 0x02 selects big-endian; bits 0x1c select compression
  (0x00 none, 0x04 zlib, 0x08 LZO1X, 0x0C UCL).
* image header -- signature "imagefs", flags u8 (0x01 big-endian),
  image_size, hdr_dir_size, dir_offset, boot_ino[4], script_ino,
  chain_paddr, spare[10], mountflags (u32 each), then the NUL-terminated
  mountpoint string.
* directory entries -- 24-byte image_attr (u16 size, u16 extattr_offset,
  u32 ino, u32 mode, u32 gid, u32 uid, u32 mtime), then per-type fields:
  file: u32 offset + u32 size + path; dir: path; symlink: u16 sym_offset
  + u16 sym_size + path + target; device: u32 dev + u32 rdev + path.
  A zero-size entry terminates the chain.
* trailers -- the last 4 bytes of the startup region and of the
  filesystem region hold a checksum: the negated sum of the 32-bit
  words of the region, in the image's byte order.

zlib-compressed images are decompressed with the standard library;
LZO1X/UCL images are reported but their contents are not listed.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field

from .diagnostics import Report
from .qnxdata import (
    ELF_MACHINES, IMAGE_FLAG_BIGENDIAN, IMAGE_HEADER_FIXED_SIZE,
    IMAGE_SIGNATURE, MODE_TYPE_NAMES, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO,
    S_IFLNK, S_IFMT, S_IFNAM, S_IFREG, S_IFSOCK, STARTUP_COMPRESS,
    STARTUP_HEADER_FIXED_SIZE, STARTUP_HEADER_SIZE, STARTUP_HDR_VERSION,
    STARTUP_MAGIC_BE, STARTUP_MAGIC_LE,
)


@dataclass
class StartupHeader:
    offset: int
    endian: str          # "little" | "big"
    version: int
    flags1: int
    flags2: int
    header_size: int
    machine: int
    startup_vaddr: int
    paddr_bias: int
    image_paddr: int
    ram_paddr: int
    ram_size: int
    startup_size: int
    stored_size: int
    imagefs_paddr: int
    imagefs_size: int
    preboot_size: int
    compress: str

    @property
    def machine_name(self) -> str:
        return ELF_MACHINES.get(self.machine, "unknown EM_%d" % self.machine)


@dataclass
class ImageHeader:
    offset: int
    endian: str
    flags: int
    image_size: int
    hdr_dir_size: int
    dir_offset: int
    boot_ino: tuple
    script_ino: int
    chain_paddr: int
    mountflags: int
    mountpoint: str


@dataclass
class Entry:
    path: str
    kind: str            # file | dir | symlink | char | block | fifo | named | socket
    ino: int
    mode: int
    uid: int
    gid: int
    mtime: int
    offset: int = 0      # file data offset (image-relative)
    size: int = 0
    target: str = ""     # symlink target
    dev: int = 0
    rdev: int = 0
    dirent_offset: int = 0

    @property
    def perms(self) -> str:
        return oct(self.mode & 0o7777)


@dataclass
class Image:
    data: bytes
    startup: StartupHeader | None = None
    image_header: ImageHeader | None = None
    entries: list = field(default_factory=list)
    omitted_dirents: list = field(default_factory=list)
    filesystem: bytes = b""      # decompressed imagefs region
    filesystem_offset: int = 0   # offset of imagefs region in the file
    bootable: bool = False
    report: Report = field(default_factory=Report)


def _word_sum(data: bytes, endian: str) -> int:
    """Negated sum of 32-bit words -- the QNX trailer checksum rule."""
    fmt = "<I" if endian == "little" else ">I"
    total = 0
    for off in range(0, len(data) - len(data) % 4, 4):
        total = (total + struct.unpack_from(fmt, data, off)[0]) & 0xFFFFFFFF
    return (-total) & 0xFFFFFFFF


def _read_u16(data: bytes, off: int, endian: str) -> int:
    return struct.unpack_from("<H" if endian == "little" else ">H",
                              data, off)[0]


def _read_u32(data: bytes, off: int, endian: str) -> int:
    return struct.unpack_from("<I" if endian == "little" else ">I",
                              data, off)[0]


def _parse_startup(data: bytes, off: int, report: Report,
                   path: str) -> StartupHeader | None:
    if off + STARTUP_HEADER_FIXED_SIZE > len(data):
        return None
    magic = data[off:off + 4]
    if magic == STARTUP_MAGIC_LE:
        endian = "little"
    elif magic == STARTUP_MAGIC_BE:
        endian = "big"
    else:
        return None
    version = _read_u16(data, off + 4, endian)
    flags1 = data[off + 6]
    flags2 = data[off + 7]
    header_size = _read_u16(data, off + 8, endian)
    machine = _read_u16(data, off + 10, endian)
    fields = [_read_u32(data, off + 12 + 4 * k, endian) for k in range(9)]
    (startup_vaddr, paddr_bias, image_paddr, ram_paddr, ram_size,
     startup_size, stored_size, imagefs_paddr, imagefs_size) = fields
    preboot_size = _read_u16(data, off + 48, endian)
    zeros = data[off + 50:off + 64]
    problems = []
    if version != STARTUP_HDR_VERSION:
        problems.append("version %d (expected %d)"
                        % (version, STARTUP_HDR_VERSION))
    if flags2 != 0:
        problems.append("flags2 is %#x (expected 0)" % flags2)
    if any(zeros):
        problems.append("reserved zero bytes are not zero")
    if header_size < STARTUP_HEADER_FIXED_SIZE:
        problems.append("header_size %d is smaller than %d"
                        % (header_size, STARTUP_HEADER_FIXED_SIZE))
    if startup_size < header_size:
        problems.append("startup_size %d is smaller than header_size %d"
                        % (startup_size, header_size))
    if stored_size < startup_size:
        problems.append("stored_size %d is smaller than startup_size %d"
                        % (stored_size, startup_size))
    if problems:
        report.error("QNX501", "Bad startup header at offset %#x: %s."
                     % (off, "; ".join(problems)), path, 0, 1)
        return None
    if machine not in ELF_MACHINES:
        report.warning("QNX502", "Unknown ELF machine %d in the startup "
                       "header." % machine, path, 0, 1)
    compress = STARTUP_COMPRESS.get(flags1 & 0x1C)
    if compress is None:
        report.error("QNX501", "Unknown compression selector %#x in "
                     "startup header flags1." % (flags1 & 0x1C), path, 0, 1)
        return None
    return StartupHeader(
        offset=off, endian=endian, version=version, flags1=flags1,
        flags2=flags2, header_size=header_size, machine=machine,
        startup_vaddr=startup_vaddr, paddr_bias=paddr_bias,
        image_paddr=image_paddr, ram_paddr=ram_paddr, ram_size=ram_size,
        startup_size=startup_size, stored_size=stored_size,
        imagefs_paddr=imagefs_paddr, imagefs_size=imagefs_size,
        preboot_size=preboot_size, compress=compress)


def _find_startup(data: bytes, report: Report, path: str):
    """Scan for a valid startup header; returns (offset, header)."""
    for off in range(0, max(0, len(data) - 4) + 1):
        if data[off:off + 4] not in (STARTUP_MAGIC_LE, STARTUP_MAGIC_BE):
            continue
        hdr = _parse_startup(data, off, report, path)
        if hdr is not None:
            return off, hdr
    return None, None


def _parse_image_header(fs: bytes, off: int, report: Report,
                        path: str) -> ImageHeader | None:
    if off + IMAGE_HEADER_FIXED_SIZE > len(fs):
        report.error("QNX507", "Truncated image header at offset %#x."
                     % off, path, 0, 1)
        return None
    if fs[off:off + 7] != IMAGE_SIGNATURE:
        return None
    flags = fs[off + 7]
    endian = "big" if flags & IMAGE_FLAG_BIGENDIAN else "little"
    image_size = _read_u32(fs, off + 8, endian)
    hdr_dir_size = _read_u32(fs, off + 12, endian)
    dir_offset = _read_u32(fs, off + 16, endian)
    boot_ino = tuple(_read_u32(fs, off + 20 + 4 * k, endian)
                     for k in range(4))
    script_ino = _read_u32(fs, off + 36, endian)
    chain_paddr = _read_u32(fs, off + 40, endian)
    mountflags = _read_u32(fs, off + 84, endian)
    end = fs.find(b"\x00", off + IMAGE_HEADER_FIXED_SIZE)
    if end == -1:
        mountpoint = ""
    else:
        mountpoint = fs[off + IMAGE_HEADER_FIXED_SIZE:end].decode(
            "utf-8", "replace")
    if image_size < IMAGE_HEADER_FIXED_SIZE or image_size > len(fs):
        report.error("QNX507", "image_size %d is out of range for a %d-byte "
                     "filesystem region." % (image_size, len(fs)), path, 0, 1)
        return None
    if dir_offset < IMAGE_HEADER_FIXED_SIZE or dir_offset > hdr_dir_size \
            or hdr_dir_size > image_size:
        report.error("QNX507", "Inconsistent image header: dir_offset=%d, "
                     "hdr_dir_size=%d, image_size=%d."
                     % (dir_offset, hdr_dir_size, image_size), path, 0, 1)
        return None
    return ImageHeader(offset=off, endian=endian, flags=flags,
                       image_size=image_size, hdr_dir_size=hdr_dir_size,
                       dir_offset=dir_offset, boot_ino=boot_ino,
                       script_ino=script_ino, chain_paddr=chain_paddr,
                       mountflags=mountflags, mountpoint=mountpoint)


def _parse_dirents(fs: bytes, hdr: ImageHeader, report: Report,
                   path: str) -> list:
    entries: list[Entry] = []
    omitted: list = []
    pos = hdr.offset + hdr.dir_offset
    end = hdr.offset + hdr.hdr_dir_size
    seen_paths: dict[str, int] = {}
    seen_inos: dict[int, str] = {}
    guard = 0
    while pos + 4 <= end:
        guard += 1
        if guard > 100000:
            report.error("QNX507", "Directory chain is too long; aborting.",
                         path, 0, 1)
            break
        size = _read_u16(fs, pos, hdr.endian)
        if size == 0:
            break  # chain terminator
        if size < 24 or pos + size > end:
            report.error("QNX507",
                         "Bad directory entry at offset %#x (size %d)."
                         % (pos, size), path, 0, 1)
            break
        extattr = _read_u16(fs, pos + 2, hdr.endian)
        ino = _read_u32(fs, pos + 4, hdr.endian)
        mode = _read_u32(fs, pos + 8, hdr.endian)
        gid = _read_u32(fs, pos + 12, hdr.endian)
        uid = _read_u32(fs, pos + 16, hdr.endian)
        mtime = _read_u32(fs, pos + 20, hdr.endian)
        kind_bits = mode & S_IFMT
        kind = MODE_TYPE_NAMES.get(kind_bits, "unknown")
        if ino == 0:
            omitted.append((pos, size, mode))
            pos += (size + 3) & ~3
            continue
        base = pos + 24
        entry = Entry(path="", kind=kind, ino=ino, mode=mode, uid=uid,
                      gid=gid, mtime=mtime, dirent_offset=pos)
        if kind_bits == S_IFREG:
            if base + 8 > pos + size:
                report.error("QNX507", "Truncated file entry at %#x." % pos,
                             path, 0, 1)
                break
            entry.offset = _read_u32(fs, base, hdr.endian)
            entry.size = _read_u32(fs, base + 4, hdr.endian)
            raw_path = fs[base + 8:pos + size].split(b"\x00", 1)[0]
            entry.path = raw_path.decode("utf-8", "replace")
            if entry.offset + entry.size > hdr.image_size:
                report.warning("QNX509",
                               "File '%s' data (offset %#x + size %#x) runs "
                               "past the end of the image."
                               % (entry.path, entry.offset, entry.size),
                               path, 0, 1)
        elif kind_bits == S_IFDIR:
            raw_path = fs[base:pos + size].split(b"\x00", 1)[0]
            entry.path = raw_path.decode("utf-8", "replace")
        elif kind_bits == S_IFLNK:
            if base + 4 > pos + size:
                report.error("QNX507", "Truncated symlink entry at %#x."
                             % pos, path, 0, 1)
                break
            sym_off = _read_u16(fs, base, hdr.endian)
            sym_size = _read_u16(fs, base + 2, hdr.endian)
            blob = fs[base + 4:pos + size]
            raw_path = blob.split(b"\x00", 1)[0]
            entry.path = raw_path.decode("utf-8", "replace")
            target = blob[sym_off:sym_off + sym_size].split(b"\x00", 1)[0]
            entry.target = target.decode("utf-8", "replace")
        elif kind_bits in (S_IFCHR, S_IFBLK, S_IFIFO, S_IFNAM, S_IFSOCK):
            if base + 8 > pos + size:
                report.error("QNX507", "Truncated device entry at %#x."
                             % pos, path, 0, 1)
                break
            entry.dev = _read_u32(fs, base, hdr.endian)
            entry.rdev = _read_u32(fs, base + 4, hdr.endian)
            raw_path = fs[base + 8:pos + size].split(b"\x00", 1)[0]
            entry.path = raw_path.decode("utf-8", "replace")
        else:
            report.warning("QNX507", "Unknown dirent type %#o at offset "
                           "%#x." % (kind_bits, pos), path, 0, 1)
            raw_path = fs[base:pos + size].split(b"\x00", 1)[0]
            entry.path = raw_path.decode("utf-8", "replace")
        if entry.path in seen_paths:
            report.warning("QNX508",
                           "Duplicate path '%s' in the image (first at "
                           "offset %#x)." % (entry.path, seen_paths[entry.path]),
                           path, 0, 1)
        else:
            seen_paths[entry.path] = pos
        if ino in seen_inos and seen_inos[ino] != entry.path:
            report.warning("QNX508",
                           "Inode %d is used by both '%s' and '%s'."
                           % (ino, seen_inos[ino], entry.path), path, 0, 1)
        else:
            seen_inos[ino] = entry.path
        entries.append(entry)
        pos += (size + 3) & ~3
    return entries, omitted


def parse_image(data: bytes, path: str = "<image>") -> Image:
    """Parse a whole .ifs file (bootable image or bare imagefs)."""
    report = Report()
    image = Image(data=data, report=report)

    off, startup = _find_startup(data, report, path)
    if startup is None:
        # maybe a bare imagefs filesystem (no startup header at all)
        if data[:7] == IMAGE_SIGNATURE:
            fs_off = 0
            image.filesystem = data
            image.filesystem_offset = 0
        else:
            report.error("QNX500",
                         "No QNX startup header (0x00FF7EEB) and no bare "
                         "'imagefs' header found.", path, 0, 1,
                         hint="This does not look like a QNX IFS image. "
                              "dumpifs cannot read srec-filtered images "
                              "either.")
            return image
    else:
        image.startup = startup
        image.bootable = True
        if startup.stored_size > len(data):
            report.error("QNX503",
                         "stored_size %d exceeds the actual file size %d; "
                         "the image is truncated."
                         % (startup.stored_size, len(data)), path, 0, 1)
            return image
        if startup.imagefs_size == 0:
            report.error("QNX503", "imagefs_size is 0.", path, 0, 1)
            return image
        # the imagefs region follows the startup program
        fs_start = off + startup.startup_size
        fs_end = fs_start + startup.imagefs_size
        if startup.compress == "none":
            if fs_end > len(data):
                report.error("QNX503",
                             "imagefs region runs past the end of the file.",
                             path, 0, 1)
                return image
            image.filesystem = data[fs_start:fs_end]
            image.filesystem_offset = fs_start
        elif startup.compress == "zlib":
            payload = data[fs_start:off + startup.stored_size]
            try:
                image.filesystem = zlib.decompress(payload)
            except zlib.error:
                try:
                    image.filesystem = zlib.decompress(payload, 47)  # gzip
                except zlib.error as exc:
                    report.error("QNX507",
                                 "zlib-compressed imagefs region cannot be "
                                 "decompressed: %s." % exc, path, 0, 1)
                    return image
            image.filesystem_offset = fs_start
        else:
            report.warning("QNX506",
                           "Image filesystem is compressed with %s; contents "
                           "are not listed (only zlib is decompressed by "
                           "this tool)." % startup.compress, path, 0, 1)
            image.filesystem = b""
            image.filesystem_offset = fs_start
            # still verify the startup trailer below
            _verify_startup_trailer(image, report, path)
            return image

    if not image.filesystem:
        return image
    fs_off = image.filesystem.find(IMAGE_SIGNATURE)
    if fs_off == -1:
        report.error("QNX507", "No 'imagefs' signature in the filesystem "
                     "region.", path, 0, 1)
        return image
    hdr = _parse_image_header(image.filesystem, fs_off, report, path)
    if hdr is None:
        return image
    image.image_header = hdr
    if hdr.endian != (image.startup.endian if image.startup else hdr.endian):
        report.warning("QNX507", "Image header byte order (%s) disagrees "
                       "with the startup header (%s)."
                       % (hdr.endian,
                          image.startup.endian if image.startup else "?"),
                       path, 0, 1)
    entries, omitted = _parse_dirents(image.filesystem, hdr, report, path)
    image.entries = entries
    image.omitted_dirents = omitted

    # trailer checksums
    _verify_image_trailer(image, report, path)
    if image.startup is not None:
        _verify_startup_trailer(image, report, path)

    # boot sanity summary
    if image.bootable:
        paths = {e.path for e in entries}
        has_procnto = any(p.rsplit("/", 1)[-1].startswith("procnto")
                          for p in paths)
        if not has_procnto:
            report.note("QNX510",
                        "Image has no procnto binary; it cannot boot as a "
                        "standalone image.", path, 0, 1)
        if hdr.script_ino == 0:
            report.note("QNX510",
                        "Image has no startup script (script_ino is 0).",
                        path, 0, 1)
    report.sort()
    return image


def _verify_image_trailer(image: Image, report: Report, path: str):
    hdr = image.image_header
    if hdr is None:
        return
    total = hdr.image_size
    if total < 8 or total % 4:
        return
    fs = image.filesystem
    start = hdr.offset
    data_end = start + total - 4
    if data_end + 4 > len(fs):
        return
    stored = _read_u32(fs, data_end, hdr.endian)
    computed = _word_sum(fs[start:data_end], hdr.endian)
    if stored != computed:
        report.error("QNX504",
                     "Image trailer checksum mismatch: stored %#010x, "
                     "computed %#010x." % (stored, computed), path, 0, 1,
                     hint="The image is corrupt or was truncated.")


def _verify_startup_trailer(image: Image, report: Report, path: str):
    st = image.startup
    if st is None or st.startup_size < 8 or st.startup_size % 4:
        return
    begin = st.offset
    data_end = begin + st.startup_size - 4
    if data_end + 4 > len(image.data):
        return
    stored = _read_u32(image.data, data_end, st.endian)
    computed = _word_sum(image.data[begin:data_end], st.endian)
    if stored != computed:
        report.error("QNX505",
                     "Startup trailer checksum mismatch: stored %#010x, "
                     "computed %#010x." % (stored, computed), path, 0, 1)


def file_bytes(image: Image, entry: Entry) -> bytes | None:
    """Raw bytes of a file entry (image-relative offsets)."""
    hdr = image.image_header
    if hdr is None or entry.kind != "file":
        return None
    start = hdr.offset + entry.offset
    return image.filesystem[start:start + entry.size]
