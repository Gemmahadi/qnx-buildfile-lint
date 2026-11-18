"""QNX 8.0 knowledge base for qnx-buildfile-lint.

Every fact here is taken from the QNX SDP 8.0 Utilities Reference
(``mkifs``) and the QNX SDP 8.0 *Building Embedded Systems* guide
("OS Image Buildfiles" / "The startup header" / "Making an OS Image"),
with the QNX 7.1 pages used only where the 8.0 text is identical.
Where the 8.0 docs differ from 7.1 the 8.0 behaviour wins and is noted.

New in QNX 8.0 (not present in 7.1):
  * ``+|-dupignore`` -- duplicate target-path handling.
  * ``ifs_csa={none|crc32c}`` -- IFS checksums array in front of the
    startup header.
  * ``sha512=<hex>`` -- 128-hex-digit expected hash.
  * default kept ELF sections also include ``.note.gnu.build-id`` and
    ``.qnx.srctrack``; bootstrap files keep ``QNX_info`` and
    ``.note.gnu.build-id``.
"""

# ---------------------------------------------------------------------------
# mkifs buildfile attributes
# ---------------------------------------------------------------------------

#: Boolean attributes: ``+name`` / ``-name`` only.
BOOLEAN_ATTRIBUTES = frozenset([
    "autolink",
    "big_pages",
    "bigendian",
    "compress",      # also accepts the value form compress=1|2|3
    "dupignore",     # QNX 8.0
    "followlink",
    "include",
    "keeplinked",
    "optional",
    "page_align",
    "raw",
    "script",
])

#: Value attributes: ``name=value`` only. ``compress`` is listed here too:
#: it has both a boolean form (``+compress``) and a value form
#: (``compress=1|2|3``).
VALUE_ATTRIBUTES = frozenset([
    "autoso",
    "cd",
    "chain",
    "cksum",
    "compress",
    "dperms",
    "drop",
    "filter",
    "gid",
    "ifs_csa",       # QNX 8.0
    "image",
    "keepsection",
    "linker",
    "module",
    "mount",
    "mtime",
    "pagesizes",
    "perms",
    "phys_align",
    "physical",
    "prefix",
    "ram",
    "search",
    "sha256",
    "sha512",        # QNX 8.0
    "type",
    "uid",
    "virtual",
])

#: ``compress`` is the one attribute with both a boolean and a value form.
DUAL_FORM_ATTRIBUTES = frozenset(["compress"])

ALL_ATTRIBUTES = BOOLEAN_ATTRIBUTES | VALUE_ATTRIBUTES

#: Attributes that only make sense on the bootstrap (virtual/physical) line.
BOOTSTRAP_ONLY_ATTRIBUTES = frozenset(["virtual", "physical"])

#: Default kept ELF sections (QNX 8.0 mkifs -s list).
DEFAULT_KEPT_SECTIONS = (
    "QNX_info",
    "QNX_usage",
    ".gnu_debuglink",
    ".note.gnu.build-id",
    ".qnx.srctrack",
)
#: Sections kept for bootstrap files (startup-*, procnto-*) in QNX 8.0.
BOOTSTRAP_KEPT_SECTIONS = ("QNX_info", ".note.gnu.build-id")

# ---------------------------------------------------------------------------
# Attribute value vocabularies
# ---------------------------------------------------------------------------

#: ``type=`` values.
FILE_TYPES = ("link", "fifo", "file", "dir")

#: ``autoso=`` values (prefix abbreviations allowed by mkifs).
AUTOSO_VALUES = {"n": "none", "none": "none",
                 "l": "list", "list": "list",
                 "a": "add", "add": "add"}

#: ``compress=`` algorithm numbers.
COMPRESS_ALGORITHMS = {"1": "ZLIB", "2": "LZO", "3": "UCL8"}

#: ``ifs_csa=`` values (QNX 8.0).
IFSCSA_VALUES = ("none", "crc32c")

#: ``module=`` procnto modules known to the linter.
KNOWN_MODULES = ("aps",)  # adaptive partitioning scheduler

#: CPU names accepted by ``virtual=[cpu,]bootfile``.
#: QNX 8.0 targets are aarch64le, armle-v7 and x86_64; the older names are
#: still recognised by mkifs for legacy buildfiles.
KNOWN_CPUS = ("aarch64le", "armle-v7", "armle", "x86_64", "ppcbe", "shle")
QNX8_CPUS = ("aarch64le", "armle-v7", "x86_64")

#: Bootfiles shipped in ${QNX_TARGET}/${PROCESSOR}/boot/sys and the CPUs
#: each one supports (QNX 8.0 mkifs "virtual" attribute table).
BOOTFILES = {
    "binary": ("aarch64le", "armle-v7", "x86_64"),
    "bios": ("x86_64",),
    "elf": ("aarch64le", "armle-v7", "x86_64"),
    "kpi": ("x86_64",),
    "multiboot": ("x86_64",),
    "raw": ("aarch64le", "armle-v7"),
    "srec": ("aarch64le", "armle-v7", "x86_64"),
    "uefi": ("x86_64",),
}

#: Variables mkifs expands from the host environment.
KNOWN_VARIABLES = (
    "QNX_TARGET", "QNX_HOST", "QNX_CONFIGURATION",
    "PROCESSOR", "PROCESSOR_BASE", "MKIFS_PATH",
    "PFS",  # path separator variable used in search lists
)

#: ELF machine numbers (EM_* from <sys/elf.h>) seen in startup headers.
ELF_MACHINES = {
    0: "EM_NONE", 1: "EM_M32", 2: "EM_SPARC", 3: "EM_386 (x86)",
    4: "EM_68K", 5: "EM_88K", 7: "EM_860", 8: "EM_MIPS",
    10: "EM_MIPS_RS3_LE", 20: "EM_PPC", 21: "EM_PPC64", 22: "EM_S390",
    40: "EM_ARM", 42: "EM_SH", 43: "EM_SPARCV9", 50: "EM_IA_64",
    62: "EM_X86_64", 183: "EM_AARCH64",
}

# ---------------------------------------------------------------------------
# Startup script (.script) grammar
# ---------------------------------------------------------------------------

#: Internal commands understood directly by procnto (no binary needed).
SCRIPT_INTERNAL_COMMANDS = ("display_msg", "procmgr_symlink", "reopen",
                            "waitfor")

#: Modifiers accepted in front of a script command line.
SCRIPT_MODIFIERS_BOOL = ("external", "session")
SCRIPT_MODIFIERS_VALUE = ("argv0", "cpu", "pri", "sched_aps")
SCRIPT_MODIFIERS = SCRIPT_MODIFIERS_BOOL + SCRIPT_MODIFIERS_VALUE

#: Scheduling policies for ``pri=<n><policy>``.
SCHED_POLICIES = {"f": "FIFO", "r": "round-robin", "o": "other (round-robin)"}

#: QNX process priority range.
PRI_MIN, PRI_MAX = 1, 255

#: Shell-only constructs that a QNX startup script cannot use.
SHELL_CONSTRUCTS = ("|", ">", "<", "`", "$(", ";", "&&", "||")

# ---------------------------------------------------------------------------
# Bootfile attributes (the [ ... ] block at the start of a .boot file)
# ---------------------------------------------------------------------------

BOOTFILE_ATTRIBUTES = (
    "attr", "big_pages", "default_image", "default_ram", "filter", "len",
    "notloaded", "paddr_bias", "pagesize", "pagesizes", "vboot",
)

# ---------------------------------------------------------------------------
# IFS on-disk format (sys/startup.h, sys/image.h; see qnx-ifs crate docs)
# ---------------------------------------------------------------------------

STARTUP_MAGIC_LE = bytes((0xEB, 0x7E, 0xFF, 0x00))
STARTUP_MAGIC_BE = bytes((0x00, 0xFF, 0x7E, 0xEB))
STARTUP_SIGNATURE = 0x00FF7EEB
STARTUP_HDR_VERSION = 1
STARTUP_HEADER_FIXED_SIZE = 64   # fixed prefix; full header is 256 bytes
STARTUP_HEADER_SIZE = 256

IMAGE_SIGNATURE = b"imagefs"
IMAGE_HEADER_FIXED_SIZE = 88     # mountpoint string follows

#: startup header flags1: compression selector is bits 0x1c.
STARTUP_COMPRESS = {0x00: "none", 0x04: "zlib", 0x08: "LZO1X", 0x0C: "UCL"}

#: image header flag bits.
IMAGE_FLAG_BIGENDIAN = 0x01
IMAGE_FLAG_READONLY = 0x02
IMAGE_FLAG_INO_BITS = 0x04

#: image_attr mode type bits (S_IFMT family).
S_IFMT = 0o170000
S_IFIFO = 0o010000
S_IFCHR = 0o020000
S_IFDIR = 0o040000
S_IFNAM = 0o050000
S_IFBLK = 0o060000
S_IFREG = 0o100000
S_IFLNK = 0o120000
S_IFSOCK = 0o140000
MODE_TYPE_NAMES = {
    S_IFIFO: "fifo", S_IFCHR: "char device", S_IFDIR: "directory",
    S_IFNAM: "named special", S_IFBLK: "block device",
    S_IFREG: "file", S_IFLNK: "symlink", S_IFSOCK: "socket",
}
