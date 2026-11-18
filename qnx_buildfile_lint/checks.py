"""Semantic checks for QNX mkifs buildfiles.

Works on the output of :mod:`qnx_buildfile_lint.parser`: per-attribute
value validation, bootstrap structure, duplicate detection (including the
QNX 8.0 ``+dupignore`` rules), startup-script checks, cross checks
between the script and the image contents, and optional host-file checks
(existence, sha256/sha512/cksum verification, [+include] expansion).
"""

from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime

from .diagnostics import Report
from .parser import Entry, parse
from .qnxdata import (
    AUTOSO_VALUES, BOOTFILES, COMPRESS_ALGORITHMS, DEFAULT_KEPT_SECTIONS,
    FILE_TYPES, IFSCSA_VALUES, KNOWN_CPUS, KNOWN_MODULES, KNOWN_VARIABLES,
    QNX8_CPUS,
)
from .script import check_script

_NUMBER = re.compile(r"^(0[xX][0-9a-fA-F]+|\d+)([kKmMgG])?$")
_VAR_REF = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_SIZE_SUFFIX = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}


# ---------------------------------------------------------------------------
# Small value parsers
# ---------------------------------------------------------------------------

def parse_number(text: str):
    """Parse a decimal/0x number with an optional k/m/g suffix."""
    m = _NUMBER.match(text)
    if not m:
        return None
    num, suffix = m.group(1), m.group(2)
    try:
        value = int(num, 16) if num.lower().startswith("0x") else int(num, 10)
    except ValueError:
        return None
    if suffix:
        value *= _SIZE_SUFFIX[suffix.lower()]
    return value


def is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def parse_addr_space(value: str):
    """Parse [start][-end][,maxsize][=totalsize][%align].

    Returns a dict or None when the syntax is wrong.
    """
    rest = value
    out = {"start": None, "end": None, "maxsize": None,
           "totalsize": None, "align": None}

    def take_number(s):
        m = re.match(r"^(0[xX][0-9a-fA-F]+|\d+[kKmMgG]?|\d+)", s)
        if not m:
            return None, s
        return parse_number(m.group(1)), s[m.end():]

    if rest and rest[0].isdigit():
        out["start"], rest = take_number(rest)
        if out["start"] is None:
            return None
    if rest.startswith("-"):
        out["end"], rest = take_number(rest[1:])
        if out["end"] is None:
            return None
    if rest.startswith(","):
        out["maxsize"], rest = take_number(rest[1:])
        if out["maxsize"] is None:
            return None
    if rest.startswith("="):
        out["totalsize"], rest = take_number(rest[1:])
        if out["totalsize"] is None:
            return None
    if rest.startswith("%"):
        out["align"], rest = take_number(rest[1:])
        if out["align"] is None:
            return None
    if rest != "":
        return None
    return out


def _valid_symbolic_mode(value: str, perms_chars: str) -> bool:
    """Validate a chmod-style symbolic mode string."""
    for clause in value.split(","):
        m = re.match(r"^([ugoa]*)([-+=])([%s]+)$" % re.escape(perms_chars),
                     clause)
        if not m:
            return False
    return True


def posix_cksum(data: bytes) -> int:
    """POSIX cksum (the algorithm of the QNX ``cksum`` utility).

    CRC-32 (poly 0x04c11db7, init 0) over the data plus the length in
    little-endian octets, as specified by POSIX.1.
    """
    crc = 0
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 \
                else (crc << 1) & 0xFFFFFFFF
    length = len(data)
    while length:
        crc ^= (length & 0xFF) << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 \
                else (crc << 1) & 0xFFFFFFFF
        length >>= 8
    return (~crc) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Per-attribute value validation
# ---------------------------------------------------------------------------

def _check_attr_value(attr, entry: Entry, path: str, report: Report,
                      defines: dict):
    name, value = attr.name, attr.value
    line, col = attr.line, attr.col

    def err(code, msg, hint=""):
        report.error(code, msg, path, line, col, hint=hint)

    def warn(code, msg, hint=""):
        report.warning(code, msg, path, line, col, hint=hint)

    if name in ("uid", "gid"):
        if value != "*":
            if not re.match(r"^\d+$", value):
                err("QNX203", "Invalid %s value '%s': a decimal number or "
                    "'*'." % (name, value))
            elif int(value) > 0xFFFFFFFF:
                err("QNX203", "%s value %s is out of range." % (name, value))
    elif name in ("perms", "dperms"):
        if value == "*":
            pass
        elif re.match(r"^[0-7]{1,4}$", value):
            pass
        elif _valid_symbolic_mode(value, "rwxstg"):
            pass
        else:
            err("QNX204",
                "Invalid %s value '%s'." % (name, value),
                hint="Use an octal number (e.g. 0755), '*', or a symbolic "
                     "mode such as 'u=rwx,go=rx'.")
    elif name == "type":
        if value not in FILE_TYPES:
            err("QNX205", "Invalid type= value '%s'." % value,
                hint="type= must be one of link, fifo, file or dir.")
    elif name == "autoso":
        if value.lower() not in AUTOSO_VALUES:
            err("QNX206", "Invalid autoso= value '%s'." % value,
                hint="autoso= must be none, list or add (n, l, a).")
    elif name == "compress":
        if value not in COMPRESS_ALGORITHMS:
            err("QNX207", "Invalid compress= value '%s'." % value,
                hint="compress= takes 1 (ZLIB), 2 (LZO) or 3 (UCL8, the "
                     "default).")
    elif name in ("image", "ram"):
        spec = parse_addr_space(value)
        if spec is None:
            err("QNX208", "Invalid %s value '%s'." % (name, value),
                hint="Expected [start][-end][,maxsize][=totalsize][%align], "
                     "numbers decimal or 0x hex with k/m/g suffix.")
        else:
            if (spec["start"] is not None and spec["end"] is not None
                    and spec["end"] < spec["start"]):
                err("QNX208", "%s end address %#x is below the start "
                    "address %#x." % (name, spec["end"], spec["start"]))
            if spec["align"] is not None and not is_power_of_two(spec["align"]):
                warn("QNX208", "%s alignment %d is not a power of two."
                     % (name, spec["align"]))
    elif name == "virtual":
        _check_virtual(value, attr, path, report)
    elif name == "physical":
        warn("QNX211", "physical= is not implemented; use virtual= instead.",
             hint="The QNX docs say to use the virtual attribute.")
        _check_virtual(value, attr, path, report)
    elif name == "mtime":
        if value != "*":
            m = re.match(r"^(\d{4})-(\d{2})-(\d{2})-(\d{2}):(\d{2}):(\d{2})$",
                         value)
            ok = False
            if m:
                try:
                    datetime(int(m.group(1)), int(m.group(2)),
                             int(m.group(3)), int(m.group(4)),
                             int(m.group(5)), int(m.group(6)))
                    ok = True
                except ValueError:
                    ok = False
            if not ok:
                err("QNX212", "Invalid mtime= value '%s'." % value,
                    hint="Use '*' or YYYY-MM-DD-HH:MM:SS (UTC), with all "
                         "six elements.")
    elif name in ("sha256", "sha512"):
        want = 64 if name == "sha256" else 128
        if not re.match(r"^[0-9a-fA-F]{%d}$" % want, value):
            err("QNX213", "Invalid %s value: exactly %d hex digits, no "
                "prefix or delimiters." % (name, want))
    elif name == "cksum":
        if parse_number(value) is None:
            err("QNX222", "Invalid cksum= value '%s'." % value,
                hint="cksum= takes a number (decimal or 0x hex).")
    elif name == "chain":
        if parse_number(value) is None:
            err("QNX222", "Invalid chain= value '%s'." % value,
                hint="chain= takes an address (decimal or 0x hex, with "
                     "k/m/g suffix).")
    elif name == "pagesizes":
        for part in value.split(","):
            size = parse_number(part)
            if size is None:
                err("QNX214", "Invalid pagesizes= value '%s'." % value,
                    hint="pagesizes= is a comma-separated list of sizes "
                         "with k/m/g suffix.")
                break
            if not is_power_of_two(size):
                warn("QNX214", "Page size %s is not a power of two." % part)
    elif name == "phys_align":
        parts = value.split(",")
        size = parse_number(parts[0]) if parts else None
        if size is None:
            err("QNX214", "Invalid phys_align= value '%s'." % value,
                hint="phys_align= takes a size with k/m/g suffix and an "
                     "optional ',group'.")
        else:
            if not is_power_of_two(size) and size != 0:
                warn("QNX214", "phys_align= size %s is not a power of two."
                     % parts[0])
            if len(parts) > 2 or (len(parts) == 2 and parts[1] != "group"):
                err("QNX214", "Invalid phys_align= value '%s'." % value,
                    hint="Only ',group' may follow the size.")
    elif name == "ifs_csa":
        if value not in IFSCSA_VALUES:
            err("QNX215", "Invalid ifs_csa= value '%s'." % value,
                hint="ifs_csa= (QNX 8.0) must be none or crc32c.")
    elif name == "module":
        if value not in KNOWN_MODULES:
            warn("QNX216", "Unknown procnto module '%s'." % value,
                 hint="The documented module is 'aps' (adaptive "
                      "partitioning scheduler).")
    elif name == "keepsection":
        bad = [s for s in value.split(",")
               if not re.match(r"^[A-Za-z0-9_.\-]+$", s)]
        if bad:
            err("QNX204", "Invalid keepsection= value '%s'." % value,
                hint="keepsection= is a comma-separated list of ELF "
                     "section names.")
        else:
            warn("QNX217",
                 "keepsection= keeps ONLY the listed sections; the "
                 "defaults (%s) will be stripped."
                 % ", ".join(DEFAULT_KEPT_SECTIONS),
                 hint="Add the defaults to the list if you still want "
                      "QNX_info / QNX_usage kept.")
    elif name == "linker":
        _check_linker(value, attr, path, report)
    elif name == "drop":
        for pat in value.split("|"):
            if not pat:
                err("QNX220", "Empty pattern in drop= value '%s'." % value)
            elif "/" in pat:
                err("QNX220",
                    "drop= pattern '%s' contains '/'; patterns are "
                    "compared to the filename only." % pat)
    elif name == "mount":
        if not value.startswith("/"):
            warn("QNX223", "mount= value '%s' is not an absolute path."
                 % value, hint="The mountpoint should start with '/'.")
    elif name == "search":
        if "" in value.split(":"):
            warn("QNX224", "search= value '%s' has an empty path element."
                 % value, hint="Remove the leading, trailing or doubled "
                               "':'.")
    elif name in ("cd", "prefix"):
        if "\\" in value:
            warn("QNX110", "Backslash in %s value '%s'; use forward "
                 "slashes." % (name, value))

    # variable references in this value
    for m in _VAR_REF.finditer(value):
        var = m.group(1) or m.group(2)
        if var not in KNOWN_VARIABLES and var not in defines \
                and var not in os.environ:
            warn("QNX219", "Undefined variable ${%s}." % var,
                 hint="Define it with --define %s=... or set it in the "
                      "environment." % var)


def _check_virtual(value: str, attr, path: str, report: Report):
    line, col = attr.line, attr.col
    parts = value.split()
    if not parts:
        report.error("QNX209", "Empty %s value." % attr.name,
                     path, line, col)
        return
    head = parts[0]
    cpu = None
    bootfile = head
    for sep in (",", "/"):
        if sep in head:
            cpu, bootfile = head.split(sep, 1)
            break
    if cpu is not None:
        if cpu not in KNOWN_CPUS:
            report.error("QNX209", "Unknown CPU '%s' in %s= value."
                         % (cpu, attr.name), path, line, col,
                         hint="QNX 8.0 CPUs: aarch64le, armle-v7, x86_64.")
            return
        if cpu not in QNX8_CPUS:
            report.warning("QNX209",
                           "CPU '%s' is not a QNX 8.0 target CPU."
                           % cpu, path, line, col,
                           hint="QNX 8.0 targets aarch64le, armle-v7 and "
                                "x86_64.")
    if bootfile not in BOOTFILES:
        report.error("QNX209", "Unknown bootfile '%s' in %s= value."
                     % (bootfile, attr.name), path, line, col,
                     hint="Bootfiles: binary, bios, elf, kpi, multiboot, "
                          "raw, srec, uefi.")
        return
    if cpu is not None and cpu in QNX8_CPUS \
            and cpu not in BOOTFILES[bootfile]:
        report.error("QNX210",
                     "Bootfile '%s' does not support CPU '%s'."
                     % (bootfile, cpu), path, line, col,
                     hint="%s supports: %s."
                     % (bootfile, ", ".join(BOOTFILES[bootfile])))


def _check_linker(value: str, attr, path: str, report: Report):
    line, col = attr.line, attr.col
    spec = value
    if spec.startswith("("):
        close = spec.find(")")
        if close == -1:
            report.error("QNX218", "Unterminated linker id '(...)' in "
                         "linker= value.", path, line, col)
            return
        idspec = spec[1:close]
        groups = idspec.split(";")
        if len(groups) != 3 or any(
                g and not re.match(r"^(\d+,)*\d+$", g) for g in groups):
            report.error("QNX218",
                         "Invalid linker id '(%s)': expected "
                         "(machine-list;type-list;segment-list) of ELF "
                         "numbers." % idspec, path, line, col)
            return
        spec = spec[close + 1:]
    missing = [code for code in ("%o", "%i") if code not in spec]
    if missing:
        report.warning("QNX218",
                       "linker= spec is missing %s."
                       % " and ".join(missing), path, line, col,
                       hint="The spec is a printf-like format: %o is the "
                            "output file, %i the input file.")

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

class LintOptions:
    def __init__(self, defines=None, check_host=False, host_roots=None,
                 search_roots=None):
        self.defines = dict(defines or {})
        self.check_host = check_host
        self.host_roots = list(host_roots or [])
        self.search_roots = list(search_roots or [])


def _effective_attrs(entry: Entry, sticky: dict, path: str,
                     report: Report) -> dict:
    """Attributes in effect for *entry*: sticky ones, overridden by the
    entry's own attributes. A '?' conditional attribute is skipped (with
    a QNX221 warning) when the attribute was already set."""
    eff = dict(sticky)
    for a in entry.attrs:
        if a.conditional and a.name in eff:
            report.warning(
                "QNX221",
                "Conditional attribute '?%s' has no effect: '%s' was "
                "already set." % (a.raw.lstrip("?"), a.name),
                path, a.line, a.col)
            continue
        eff[a.name] = a
    return eff


def _attr_value(eff: dict, name: str, default=None):
    a = eff.get(name)
    if a is not None and a.kind == "value":
        return a.value
    return default


def _bool_in_effect(eff: dict, name: str):
    """True/False/None for a boolean attribute in effect."""
    a = eff.get(name)
    if a is not None and a.kind == "bool":
        return a.sign == "+"
    return None


def _effective_target(entry: Entry, eff: dict, bootable: bool) -> str:
    """Target path as it will appear in the image.

    Bare names go under prefix (default proc/boot for a bootable image,
    empty otherwise) and mount (default /).
    """
    mount = _attr_value(eff, "mount", "/")
    prefix = _attr_value(eff, "prefix", "proc/boot" if bootable else "")
    target = entry.target
    if target.startswith("/"):
        full = target
    else:
        parts = [p for p in (mount, prefix, target) if p]
        full = "/" + "/".join(p.strip("/") for p in parts)
    while "//" in full:
        full = full.replace("//", "/")
    return full


def _is_bootstrap_line(line: str):
    """Return the executable word of a bootstrap line, or None for a
    pure environment-assignment line / blank / comment."""
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    words = text.split()
    idx = 0
    while idx < len(words) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[idx]):
        idx += 1
    if idx >= len(words):
        return None
    return words[idx]


def lint_parsed(parsed, path: str, options: LintOptions | None = None) -> Report:
    options = options or LintOptions()
    report = parsed.report
    entries = parsed.entries

    # -- expand [+include] when host checking is on -----------------------
    if options.check_host:
        entries = _expand_includes(entries, path, options, report)

    sticky: dict = {}
    file_entries: list[Entry] = []
    bootstrap_entries: list[Entry] = []
    has_image_attr = False
    has_ram_attr = False
    compress_one = False
    script_commands: list[str] = []
    uses_sched_aps = False
    sched_aps_created = False
    eff_by_entry: dict[int, dict] = {}

    for entry in entries:
        if entry.sticky:
            for a in entry.attrs:
                if a.conditional and a.name in sticky:
                    report.warning(
                        "QNX221",
                        "Conditional attribute '?%s' has no effect: '%s' "
                        "was already set." % (a.raw.lstrip("?"), a.name),
                        path, a.line, a.col)
                    continue
                sticky[a.name] = a
                if a.kind == "value":
                    _check_attr_value(a, entry, path, report,
                                      options.defines)
                if a.name == "image" and a.kind == "value":
                    has_image_attr = True
                elif a.name == "ram" and a.kind == "value":
                    has_ram_attr = True
                elif (a.name == "compress" and a.kind == "value"
                        and a.value == "1"):
                    compress_one = True
            continue
        file_entries.append(entry)
        eff = _effective_attrs(entry, sticky, path, report)
        eff_by_entry[id(entry)] = eff
        for a in entry.attrs:
            if a.kind == "value":
                _check_attr_value(a, entry, path, report, options.defines)
            if a.name == "image" and a.kind == "value":
                has_image_attr = True
            elif a.name == "ram" and a.kind == "value":
                has_ram_attr = True
            elif (a.name == "compress" and a.kind == "value"
                    and a.value == "1"):
                compress_one = True
        # variables in target/host
        for value in (entry.target, entry.host):
            for m in _VAR_REF.finditer(value):
                var = m.group(1) or m.group(2)
                if var not in KNOWN_VARIABLES and var not in options.defines \
                        and var not in os.environ:
                    report.warning("QNX219", "Undefined variable ${%s}." % var,
                                   path, entry.line, entry.col,
                                   hint="Define it with --define %s=... "
                                        % var)
        if "virtual" in eff or "physical" in eff:
            bootstrap_entries.append(entry)

    bootable = bool(bootstrap_entries)

    # -- bootstrap structure ----------------------------------------------
    if len(bootstrap_entries) > 1:
        for extra in bootstrap_entries[1:]:
            report.error("QNX300",
                         "More than one bootstrap (virtual/physical) in "
                         "one buildfile.", path, extra.line, extra.col,
                         hint="Only one virtual= or physical= attribute "
                              "may appear.")
    if bootstrap_entries:
        first = file_entries[0] if file_entries else None
        if first is not bootstrap_entries[0]:
            report.error("QNX301",
                         "The bootfile must be the first file in the "
                         "buildfile.", path, bootstrap_entries[0].line,
                         bootstrap_entries[0].col,
                         hint="Move the '[virtual=...] .bootstrap = { ... }' "
                              "line to the top.")
        boot = bootstrap_entries[0]
        boot_eff = eff_by_entry[id(boot)]
        if _bool_in_effect(boot_eff, "optional"):
            report.error("QNX304",
                         "+optional cannot be enabled for bootstrap "
                         "executables.", path, boot.line, boot.col)
        if boot.inline is not None:
            _check_bootstrap_contents(boot, path, report)
        if compress_one:
            report.error("QNX311",
                         "ZLIB compression (compress=1) is not bootable, "
                         "but this buildfile builds a bootable image.",
                         path, boot.line, boot.col,
                         hint="Use the default UCL8 (+compress) or LZO "
                              "(compress=2).")
    elif file_entries:
        report.note("QNX312",
                    "No [virtual=...] bootstrap: this image is not "
                    "bootable.", path, file_entries[0].line, 1)

    if has_image_attr != has_ram_attr:
        which = "image=" if has_image_attr else "ram="
        other = "ram=" if has_image_attr else "image="
        report.warning("QNX310",
                       "%s is set without %s." % (which, other),
                       path, file_entries[0].line if file_entries else 0, 1,
                       hint="Both image= and ram= are needed to create an "
                            "image in ROM/FLASH; otherwise procnto assumes "
                            "the image is in RAM.")

    # -- per-entry structural checks ---------------------------------------
    seen_targets: dict[str, Entry] = {}
    link_targets: dict[str, Entry] = {}
    for entry in file_entries:
        eff = eff_by_entry[id(entry)]
        effective = _effective_target(entry, eff, bootable)
        is_link = _attr_value(eff, "type") == "link"
        if is_link and not entry.host:
            report.error("QNX307",
                         "type=link entry '%s' has no link target."
                         % entry.target, path, entry.line, entry.col,
                         hint="Write '[type=link] %s=<link-target>'."
                         % entry.target)
        if is_link:
            link_targets[effective] = entry
        for link_path in link_targets:
            if effective != link_path and effective.startswith(link_path + "/"):
                report.error("QNX308",
                             "Path '%s' goes through the target symlink "
                             "'%s'." % (effective, link_path),
                             path, entry.line, entry.col,
                             hint="Symbolic links in the target filesystem "
                                  "are not resolved by mkifs; do not use "
                                  "them in other pathnames.")
        if _bool_in_effect(eff, "raw") and re.search(r"\.so(\.|$)",
                                                     entry.target):
            report.warning("QNX309",
                           "+raw is set on shared object '%s'."
                           % entry.target, path, entry.line, entry.col,
                           hint="Shared objects cannot be shared if +raw "
                                "is enabled.")
        dupignore = _bool_in_effect(eff, "dupignore") or False
        if effective in seen_targets:
            prev = seen_targets[effective]
            prev_dup = getattr(prev, "_dupignore", False)
            if not dupignore and not prev_dup:
                report.error("QNX305",
                             "Duplicate target path '%s' (first defined at "
                             "line %d)." % (effective, prev.line),
                             path, entry.line, entry.col,
                             hint="Remove one entry, or use [+dupignore] "
                                  "(QNX 8.0) to let one win.")
            elif dupignore and prev_dup:
                report.note("QNX306",
                            "Duplicate target path '%s': both entries have "
                            "+dupignore, so the earlier (line %d) wins and "
                            "this one is ignored." % (effective, prev.line),
                            path, entry.line, entry.col)
            else:
                winner = "the earlier entry" if dupignore else "this entry"
                report.note("QNX306",
                            "Duplicate target path '%s' resolved by "
                            "+dupignore: %s is used, the other is ignored."
                            % (effective, winner),
                            path, entry.line, entry.col)
        else:
            seen_targets[effective] = entry
        entry._dupignore = dupignore  # type: ignore[attr-defined]

        if _bool_in_effect(eff, "script"):
            if entry.inline is not None:
                cmds = check_script(entry.inline.lines, path,
                                    entry.inline.open_line, report)
                script_commands.extend(cmds)
            elif options.check_host and entry.host:
                host_path = _resolve_host(entry, options, path)
                if host_path and os.path.isfile(host_path):
                    with open(host_path, errors="replace") as fh:
                        content = [(n + 1, l) for n, l in
                                   enumerate(fh.read().splitlines())]
                    cmds = check_script(content, host_path, 1, report)
                    script_commands.extend(cmds)
        if entry.inline is not None:
            for _, text in entry.inline.lines:
                if "sched_aps=" in text:
                    uses_sched_aps = True
    for cmd in script_commands:
        if cmd == "sched_aps":
            sched_aps_created = True

    # -- cross checks: script commands vs image contents -------------------
    image_paths = {_effective_target(e, eff_by_entry[id(e)], bootable)
                   for e in file_entries}
    procmgr_links: list[str] = []
    for text in _script_lines(file_entries):
        m = re.match(r"^\s*(?:\[[^\]]*\]\s*)?procmgr_symlink\s+\S+\s+(\S+)",
                     text)
        if m:
            procmgr_links.append(m.group(1))
    if script_commands:
        image_basenames = {p.rsplit("/", 1)[-1] for p in image_paths}
        path_dirs = ["/proc/boot"]
        for text in _script_lines(file_entries):
            m = re.search(r"(?:^|\s)PATH=([^\s]+)", text)
            if m:
                path_dirs = m.group(1).split(":")
        for cmd in sorted(set(script_commands)):
            if cmd in ("display_msg", "procmgr_symlink", "reopen",
                       "waitfor", "sched_aps"):
                continue
            found = False
            if cmd.startswith("/"):
                found = cmd in image_paths or cmd in procmgr_links
            else:
                if cmd in image_basenames:
                    found = True
                else:
                    for d in path_dirs:
                        if d.rstrip("/") + "/" + cmd in image_paths:
                            found = True
                            break
                    if cmd in procmgr_links:
                        found = True
            if not found:
                report.warning(
                    "QNX313",
                    "Startup script starts '%s', but it is not in the "
                    "image (and not a procnto internal command)."
                    % cmd, path, 0, 1,
                    hint="Add '%s' to the buildfile, or fix the command "
                         "name." % cmd)
        if uses_sched_aps:
            has_aps = any(
                _attr_value(eff_by_entry[id(e)], "module") == "aps"
                for e in bootstrap_entries)
            if not has_aps:
                report.warning("QNX407",
                               "sched_aps is used but procnto has no "
                               "[module=aps].", path, 0, 1,
                               hint="Add [module=aps] to the procnto line.")
            if not sched_aps_created:
                report.warning("QNX407",
                               "sched_aps is used but no 'sched_aps <name> "
                               "<budget>' command creates the partition.",
                               path, 0, 1,
                               hint="Create the partition in the script "
                                    "before launching processes in it.")
    # -- runtime linker ------------------------------------------------------
    if bootable:
        ldqnx = [p for p in image_paths
                 if p in ("/usr/lib/ldqnx.so.2",
                          "/usr/lib/ldqnx-64.so.2")]
        link_to_ld = [l for l in procmgr_links
                      if l in ("/usr/lib/ldqnx.so.2",
                               "/usr/lib/ldqnx-64.so.2")]
        if not ldqnx and not link_to_ld:
            report.warning(
                "QNX314",
                "No runtime linker (/usr/lib/ldqnx.so.2 or "
                "/usr/lib/ldqnx-64.so.2) in the image.",
                path, 0, 1,
                hint="Dynamically linked programs need it; add "
                     "'/usr/lib/ldqnx-64.so.2=ldqnx-64.so.2' (64-bit) "
                     "or a procmgr_symlink to it.")

    # -- host file checks ----------------------------------------------------
    if options.check_host:
        _check_host_files(file_entries, eff_by_entry, bootable, path,
                          options, report)

    report.sort()
    return report


def _script_lines(file_entries):
    for e in file_entries:
        if e.inline is not None:
            for _, text in e.inline.lines:
                yield text


def _check_bootstrap_contents(boot: Entry, path: str, report: Report):
    from .script import _join_continuations
    joined = _join_continuations(boot.inline.lines)
    lines = [(ln, t) for ln, t in joined
             if t.strip() and not t.strip().startswith("#")]
    executables = []
    for lineno, text in lines:
        exe = _is_bootstrap_line(text)
        if exe is not None:
            executables.append((lineno, exe))
    if not executables:
        report.error("QNX302", "Bootstrap file is empty: the first "
                     "executable must be startup-*.",
                     path, boot.line, boot.col)
        return
    first_line, first_exe = executables[0]
    if not first_exe.startswith("startup-"):
        report.error("QNX302",
                     "First bootstrap executable is '%s', not startup-*."
                     % first_exe, path, first_line, 1,
                     hint="The first executable must be the QNX startup "
                          "program for the target board.")
    last_line, last_exe = executables[-1]
    if not last_exe.startswith("procnto"):
        report.error("QNX303",
                     "Last bootstrap executable is '%s', not procnto."
                     % last_exe, path, last_line, 1,
                     hint="The last executable must be procnto (procnto, "
                          "procnto-smp, procnto-smp-instr, ...).")


# ---------------------------------------------------------------------------
# [+include] expansion and host file checks
# ---------------------------------------------------------------------------

def _expand_includes(entries, path, options: LintOptions, report: Report):
    """Expand [+include] entries in place (recursive, cycle-safe).

    mkifs treats the top buildfile plus its includes as one stream, so
    attribute state carries across inclusions; this mirrors that.
    """
    out: list[Entry] = []
    state = {"include_mode": False}
    stack: list[str] = [os.path.abspath(path)]
    seen: set[str] = {os.path.abspath(path)}

    def resolve_include(name: str, from_path: str):
        base = os.path.dirname(os.path.abspath(from_path))
        candidates = [os.path.join(base, name)]
        for root in options.search_roots:
            candidates.append(os.path.join(root, name))
        qnx_target = os.environ.get("QNX_TARGET", "")
        proc = os.environ.get("PROCESSOR", "")
        if qnx_target and proc:
            candidates.append(os.path.join(qnx_target, proc, "boot", "build",
                                           name))
        for cand in candidates:
            if os.path.isfile(cand):
                return os.path.abspath(cand)
        return None

    def expand(entry_list, from_path, depth):
        for entry in entry_list:
            if entry.sticky:
                for a in entry.attrs:
                    if a.name == "include" and a.kind == "bool":
                        state["include_mode"] = (a.sign == "+")
                out.append(entry)
                continue
            is_include = entry.has_attr("include") and \
                _bool_in_effect(
                    {a.name: a for a in entry.attrs}, "include")
            if state["include_mode"] or is_include:
                inc_path = resolve_include(entry.target, from_path)
                if inc_path is None:
                    if _bool_in_effect(
                            {a.name: a for a in entry.attrs}, "optional"):
                        report.warning("QNX317",
                                       "Included buildfile '%s' not found; "
                                       "skipped because +optional is set."
                                       % entry.target, path, entry.line,
                                       entry.col)
                    else:
                        report.error("QNX317",
                                     "Included buildfile '%s' not found."
                                     % entry.target, path, entry.line,
                                     entry.col,
                                     hint="Check the path, the [search=] "
                                          "paths, or add +optional to skip "
                                          "it.")
                    continue
                if inc_path in stack:
                    report.error("QNX316",
                                 "Circular [+include]: '%s' includes itself "
                                 "through %s." % (entry.target, " -> ".join(
                                     os.path.basename(p) for p in stack)),
                                 path, entry.line, entry.col)
                    continue
                if inc_path in seen:
                    report.warning("QNX316",
                                   "Buildfile '%s' is included more than "
                                   "once; mkifs ignores the repeat."
                                   % entry.target, path, entry.line,
                                   entry.col)
                    continue
                if depth > 16:
                    report.error("QNX316",
                                 "Include nesting too deep (over 16).",
                                 path, entry.line, entry.col)
                    continue
                seen.add(inc_path)
                stack.append(inc_path)
                with open(inc_path, errors="replace") as fh:
                    sub = parse(fh.read(), inc_path)
                report.diagnostics.extend(sub.report.diagnostics)
                expand(sub.entries, inc_path, depth + 1)
                stack.pop()
                continue
            out.append(entry)

    expand(entries, path, 0)
    return out


def _resolve_host(entry: Entry, options: LintOptions, buildfile_path: str):
    """Resolve an entry's host file on this machine, or None."""
    host = entry.host or entry.target
    if os.path.isabs(host):
        return host if os.path.exists(host) else None
    base = os.path.dirname(os.path.abspath(buildfile_path))
    if "/" in host or "\\" in host:
        cand = os.path.join(base, host)
        return cand if os.path.exists(cand) else None
    search = list(options.search_roots)
    search.append(base)
    for root in options.host_roots:
        cand = os.path.join(root, host)
        if os.path.exists(cand):
            return cand
    for root in search:
        cand = os.path.join(root, host)
        if os.path.exists(cand):
            return cand
    return None


def _check_host_files(file_entries, eff_by_entry, bootable, path,
                      options: LintOptions, report: Report):
    for entry in file_entries:
        if entry.inline is not None:
            continue
        eff = eff_by_entry[id(entry)]
        if _attr_value(eff, "type") == "link":
            continue  # link target lives on the target, not the host
        host_path = _resolve_host(entry, options, path)
        optional = _bool_in_effect(eff, "optional")
        if host_path is None:
            if optional is False:
                report.error("QNX317",
                             "Host file '%s' not found (and -optional is "
                             "set)." % (entry.host or entry.target),
                             path, entry.line, entry.col,
                             hint="Check the [search=] paths or the "
                                  "file name.")
            elif optional is None:
                # default is +optional: mkifs warns and continues
                report.note("QNX317",
                            "Host file '%s' not found on this machine "
                            "(+optional is the default, so mkifs would warn "
                            "and continue)." % (entry.host or entry.target),
                            path, entry.line, entry.col)
            continue
        if not os.path.isfile(host_path):
            continue
        with open(host_path, "rb") as fh:
            data = fh.read()
        for a in entry.attrs:
            if a.name == "sha256":
                actual = hashlib.sha256(data).hexdigest()
                if actual.lower() != a.value.lower():
                    report.error("QNX213",
                                 "sha256 mismatch for '%s': expected %s, "
                                 "host file has %s."
                                 % (entry.target, a.value, actual),
                                 path, a.line, a.col)
            elif a.name == "sha512":
                actual = hashlib.sha512(data).hexdigest()
                if actual.lower() != a.value.lower():
                    report.error("QNX213",
                                 "sha512 mismatch for '%s': expected %s, "
                                 "host file has %s."
                                 % (entry.target, a.value, actual),
                                 path, a.line, a.col)
            elif a.name == "cksum":
                expected = parse_number(a.value)
                actual = posix_cksum(data)
                if expected is not None and expected != actual:
                    report.error("QNX222",
                                 "cksum mismatch for '%s': expected %s, "
                                 "host file has %s."
                                 % (entry.target, a.value, actual),
                                 path, a.line, a.col)


def lint_text(text: str, path: str = "<stdin>",
              options: LintOptions | None = None) -> Report:
    parsed = parse(text, path)
    return lint_parsed(parsed, path, options)


def lint_file(path: str, options: LintOptions | None = None) -> Report:
    with open(path, errors="replace") as fh:
        text = fh.read()
    return lint_text(text, path, options)
