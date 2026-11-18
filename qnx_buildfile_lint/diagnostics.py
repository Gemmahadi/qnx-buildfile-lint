"""Diagnostics: one finding, with a stable rule code, location and fix hint.

Severities mirror compilers: ``error`` (mkifs would fail, or the image
would not boot / would be wrong), ``warning`` (mkifs accepts it but it is
almost certainly not what was intended) and ``note`` (information that
helps the reader understand the buildfile).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Diagnostic:
    code: str
    severity: str  # "error" | "warning" | "note"
    message: str
    path: str = "<stdin>"
    line: int = 0
    col: int = 0
    end_col: int = 0
    hint: str = ""

    def gcc_style(self) -> str:
        loc = f"{self.path}:{self.line}:{self.col}" if self.line else self.path
        text = f"{loc}: {self.severity}: [{self.code}] {self.message}"
        if self.hint:
            text += f"\n{loc}: note: {self.hint}"
        return text

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "column": self.col,
            "end_column": self.end_col,
            "hint": self.hint,
        }


@dataclass
class Report:
    """All diagnostics for one lint run, plus a summary."""

    diagnostics: list = field(default_factory=list)

    def add(self, diag: Diagnostic) -> None:
        self.diagnostics.append(diag)

    def error(self, code, message, path="<stdin>", line=0, col=0, end_col=0,
              hint=""):
        self.add(Diagnostic(code, "error", message, path, line, col, end_col,
                            hint))

    def warning(self, code, message, path="<stdin>", line=0, col=0,
                end_col=0, hint=""):
        self.add(Diagnostic(code, "warning", message, path, line, col,
                            end_col, hint))

    def note(self, code, message, path="<stdin>", line=0, col=0, end_col=0,
             hint=""):
        self.add(Diagnostic(code, "note", message, path, line, col, end_col,
                            hint))

    @property
    def errors(self):
        return [d for d in self.diagnostics if d.severity == "error"]

    @property
    def warnings(self):
        return [d for d in self.diagnostics if d.severity == "warning"]

    @property
    def notes(self):
        return [d for d in self.diagnostics if d.severity == "note"]

    @property
    def has_errors(self):
        return bool(self.errors)

    def sort(self):
        self.diagnostics.sort(key=lambda d: (d.path, d.line, d.col,
                                             d.severity, d.code))


# ---------------------------------------------------------------------------
# Rule registry: every code the linter can emit, with documentation.
# ``rules`` subcommand prints this; docs/RULES.md is generated from it.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    code: str
    severity: str
    title: str
    body: str


RULES = [
    # --- syntax (QNX1xx) -------------------------------------------------
    Rule("QNX100", "error", "Unterminated attribute block",
         "A '[' opens an attribute list that never closes on this logical "
         "line. Attribute lists must close with ']' on the same line."),
    Rule("QNX101", "error", "Stray ']' outside an attribute block",
         "A ']' appears with no matching '['. Remove it, or open the "
         "attribute list with '[' first."),
    Rule("QNX102", "error", "Empty attribute block '[]'",
         "'[]' sets nothing. Remove the brackets or put attributes inside."),
    Rule("QNX103", "error", "Two attribute blocks on one line",
         "mkifs documents '[uid=5] [gid=5] filename' as the incorrect way: "
         "combine all attributes for a file inside one pair of brackets, "
         "e.g. '[uid=5 gid=5] filename'."),
    Rule("QNX104", "error", "Spaces around '=' in an attribute",
         "Value attributes must not have spaces around '=': write "
         "'[uid=0]', not '[uid = 0]'."),
    Rule("QNX105", "error", "Unterminated quoted string",
         "A '\"' opens a quoted filename or attribute value that never "
         "closes on this line."),
    Rule("QNX106", "error", "Unterminated inline file",
         "An inline file opened with 'target = {' never reaches a closing "
         "'}' before end of file. Close it with '}' on its own line."),
    Rule("QNX107", "error", "Inline-file content on the brace line",
         "The contents of an inline file cannot be on the same line as the "
         "opening or closing brace. Put '{' and '}' on lines of their own."),
    Rule("QNX108", "error", "Backslash line continuation inside an inline file",
         "Inside an inline file a backslash is an escape character, not a "
         "line continuation: the backslash and the newline become part of "
         "the file. Restructure the content instead."),
    Rule("QNX109", "warning", "Comment '#' must be preceded by a space",
         "mkifs only treats '#' as a comment when there is a space between "
         "the buildfile command and the '#'. 'foo#bar' is read as the "
         "filename 'foo#bar'."),
    Rule("QNX110", "warning", "Backslash in a host path",
         "Use forward slashes (/) as directory delimiters in buildfiles, "
         "even on Windows: backslashes may adversely affect the buildfile."),
    Rule("QNX111", "error", "Attribute used as a file specification",
         "A line that is only an attribute list is a global (sticky) "
         "attribute. 'virtual' and 'physical' cannot be used that way: "
         "they belong on the bootstrap file line."),
    Rule("QNX112", "error", "Missing file specification",
         "A file specification is expected after the attribute list, e.g. "
         "'[uid=0] myfile' or a 'target=host' mapping."),
    Rule("QNX113", "error", "Unescaped '}' inside an inline file",
         "A '}' inside an inline file ends the file. Escape literal "
         "braces and backslashes with a backslash ('\\}' and '\\\\')."),
    Rule("QNX114", "warning", "Unbalanced quotes in a file specification",
         "A quoted filename was not closed the way mkifs expects; check "
         "for a missing closing '\"'."),
    # --- attributes (QNX2xx) ----------------------------------------------
    Rule("QNX200", "error", "Unknown attribute",
         "mkifs does not know this attribute name. Check the spelling "
         "against the QNX 8.0 mkifs attribute list."),
    Rule("QNX201", "error", "Boolean attribute used with a value",
         "Boolean attributes take only '+' or '-': '[+raw]', not "
         "'[raw=1]'."),
    Rule("QNX202", "error", "Value attribute used as a boolean",
         "Value attributes need '=value': '[uid=0]', not '[+uid]'."),
    Rule("QNX203", "error", "Invalid uid/gid value",
         "uid/gid must be a decimal number or '*'."),
    Rule("QNX204", "error", "Invalid perms/dperms value",
         "perms/dperms must be an octal number (e.g. 0755), '*', or a "
         "symbolic mode string such as 'u=rwx,go=rx' / 'a+rx'."),
    Rule("QNX205", "error", "Invalid type= value",
         "type= must be one of link, fifo, file or dir."),
    Rule("QNX206", "error", "Invalid autoso= value",
         "autoso= must be none, list or add (prefixes n, l, a allowed)."),
    Rule("QNX207", "error", "Invalid compress= value",
         "compress= takes 1 (ZLIB), 2 (LZO) or 3 (UCL8). Note: a ZLIB "
         "compressed IFS is not bootable."),
    Rule("QNX208", "error", "Invalid image=/ram= address-space spec",
         "Expected [start][-end][,maxsize][=totalsize][%align], with "
         "numbers in decimal or 0x hex and an optional k/m/g suffix."),
    Rule("QNX209", "error", "Invalid virtual= value",
         "Expected virtual=[cpu,]bootfile [filter args]. The cpu must be "
         "a known QNX CPU (aarch64le, armle-v7, x86_64) and the bootfile "
         "one of binary, bios, elf, kpi, multiboot, raw, srec, uefi."),
    Rule("QNX210", "error", "Bootfile does not support this CPU",
         "e.g. bios/uefi/kpi/multiboot are x86_64 only; raw is "
         "aarch64le/armle-v7 only. Pick a bootfile from the mkifs "
         "virtual-attribute table for your CPU."),
    Rule("QNX211", "warning", "physical= is not implemented, use virtual=",
         "The QNX docs state the physical attribute is not currently "
         "implemented; use virtual= instead."),
    Rule("QNX212", "error", "Invalid mtime= value",
         "mtime= must be '*' or an ISO-8601 timestamp with all six "
         "elements: YYYY-MM-DD-HH:MM:SS (UTC)."),
    Rule("QNX213", "error", "Invalid sha256=/sha512= value",
         "sha256= needs exactly 64 hex digits, sha512= exactly 128, with "
         "no prefix or delimiters."),
    Rule("QNX214", "error", "Invalid pagesizes=/phys_align= value",
         "Sizes are integers with an optional k/m/g suffix. phys_align= "
         "may add ',group'. Page sizes should be powers of two."),
    Rule("QNX215", "error", "Invalid ifs_csa= value",
         "ifs_csa= (QNX 8.0) must be none or crc32c."),
    Rule("QNX216", "warning", "Unknown procnto module=",
         "Only 'aps' (adaptive partitioning scheduler) is a documented "
         "procnto module. Check the spelling."),
    Rule("QNX217", "warning", "keepsection= overrides the default kept sections",
         "Specifying keepsection= keeps ONLY the listed sections: the "
         "defaults (QNX_info, QNX_usage, .gnu_debuglink, "
         ".note.gnu.build-id, .qnx.srctrack) will be stripped."),
    Rule("QNX218", "error", "Invalid linker= value",
         "Expected linker=[(machine;type;segment)]spec with %o (output) "
         "and %i (input) in the spec."),
    Rule("QNX219", "warning", "Undefined ${VARIABLE}",
         "The variable is not defined by --define, the environment, or "
         "the known mkifs variables (QNX_TARGET, PROCESSOR, "
         "PROCESSOR_BASE, MKIFS_PATH). mkifs would expand it to empty."),
    Rule("QNX220", "error", "Invalid drop= pattern",
         "drop= patterns are filename wildcards ('?', '*' and '\\' to "
         "escape) separated by '|'."),
    Rule("QNX221", "warning", "Redundant conditional attribute",
         "A '?'-conditional attribute has no effect when the same "
         "attribute was already set unconditionally."),
    Rule("QNX222", "error", "Invalid chain=/cksum= value",
         "chain= takes an address and cksum= a number (decimal or 0x hex, "
         "with k/m/g suffix for chain=)."),
    Rule("QNX223", "warning", "mount= should be an absolute path",
         "The mountpoint of the image filesystem should start with '/'."),
    Rule("QNX224", "warning", "search= contains an empty path element",
         "A leading, trailing or doubled ':' in search= adds an empty "
         "search directory."),
    Rule("QNX225", "error", "Invalid filter= value",
         "filter= is a command string (quote it if it contains spaces) "
         "or 'none' to override a global filter."),
    # --- structure / boot (QNX3xx) ----------------------------------------
    Rule("QNX300", "error", "More than one bootstrap (virtual/physical)",
         "Only one virtual= or physical= attribute may appear in a "
         "buildfile."),
    Rule("QNX301", "error", "Bootstrap is not the first file",
         "The bootfile must be the first file specification in the "
         "buildfile."),
    Rule("QNX302", "error", "Bootstrap does not start with startup-*",
         "The first executable in the .bootstrap inline file must be the "
         "QNX startup program (startup-*)."),
    Rule("QNX303", "error", "Bootstrap does not end with procnto",
         "The last executable in the .bootstrap inline file must be "
         "procnto (procnto, procnto-smp, procnto-smp-instr, ...)."),
    Rule("QNX304", "error", "+optional on a bootstrap executable",
         "The optional attribute cannot be enabled for bootstrap "
         "executables (startup-*, procnto)."),
    Rule("QNX305", "error", "Duplicate target path in the image",
         "Two entries map to the same target path. mkifs reports this as "
         "an error unless +dupignore (QNX 8.0) resolves it."),
    Rule("QNX306", "note", "Duplicate resolved by +dupignore (QNX 8.0)",
         "Both entries had +dupignore, so the earlier entry wins and the "
         "later one is ignored by mkifs."),
    Rule("QNX307", "warning", "type=link without target=link-target",
         "A symbolic link needs the 'target=link-target' form, e.g. "
         "'[type=link] /bin/sh=/proc/boot/ksh'."),
    Rule("QNX308", "error", "Path goes through a target symlink",
         "Symbolic links in the target filesystem are not resolved by "
         "mkifs and must not be used in the pathnames of other items."),
    Rule("QNX309", "warning", "+raw on a shared object",
         "Shared objects cannot be shared if +raw is enabled; the file "
         "is treated as data and its debug info is kept."),
    Rule("QNX310", "warning", "image= without ram= (or vice versa)",
         "Both image= and ram= are needed to create an image in "
         "ROM/FLASH; otherwise procnto assumes the image is in RAM."),
    Rule("QNX311", "error", "ZLIB compression is not bootable",
         "An IFS compressed with zlib (compress=1) cannot boot. Use the "
         "default UCL8 compression (+compress / compress=3) or LZO."),
    Rule("QNX312", "note", "No bootstrap: image is not bootable",
         "Without [virtual=...] there is no startup/procnto, so the "
         "image cannot boot on its own."),
    Rule("QNX313", "warning", "Startup script command not in the image",
         "The script starts a command that is neither a procnto internal "
         "command nor a file included in this image (searched via the "
         "script PATH). It would fail at boot."),
    Rule("QNX314", "warning", "No runtime linker in the image",
         "Dynamically linked programs need /usr/lib/ldqnx.so.2 (32-bit) "
         "or /usr/lib/ldqnx-64.so.2 (64-bit) in the image, or a "
         "procmgr_symlink to it."),
    Rule("QNX315", "warning", "No procnto in the image",
         "A bootable image needs procnto; without it the system cannot "
         "start the process manager."),
    Rule("QNX316", "warning", "Include cycle / repeated include",
         "Circular [+include] inclusion is an error in mkifs; including "
         "the same buildfile twice is ignored with a diagnostic."),
    Rule("QNX317", "error", "Included buildfile not found",
         "With [+include], a missing buildfile is an error unless "
         "+optional is set."),
    # --- startup script (QNX4xx) ------------------------------------------
    Rule("QNX400", "error", "Unknown script modifier",
         "Script modifiers are argv0=, cpu=, +|-external, pri=, "
         "sched_aps= and +|-session."),
    Rule("QNX401", "error", "Invalid pri= value",
         "pri= takes a QNX priority (1-255) with an optional scheduling "
         "policy letter: f (FIFO), r (round-robin) or o (other)."),
    Rule("QNX402", "error", "Invalid cpu= value",
         "cpu= takes a zero-based processor number or '*'."),
    Rule("QNX403", "error", "Shell construct not supported in startup scripts",
         "Startup scripts are parsed by mkifs and run by procnto, not a "
         "shell: no branching, loops, redirection, piping, subshells, "
         "filename expansion or wildcards."),
    Rule("QNX404", "error", "Unknown internal command usage",
         "display_msg needs a message; procmgr_symlink needs two paths; "
         "reopen takes an optional filename; waitfor needs a pathname "
         "and an optional wait time (one decimal place)."),
    Rule("QNX405", "warning", "Foreground command blocks the rest of the script",
         "A foreground command that does not exit prevents the rest of "
         "the script from running. Add '&' or move it to the end."),
    Rule("QNX406", "error", "Unsupported shell keyword in startup script",
         "'export', 'if', 'for', 'while', 'case' and friends are shell "
         "features; startup scripts have none of them. Use plain "
         "'NAME=value' lines for environment variables."),
    Rule("QNX407", "warning", "sched_aps used without module=aps",
         "Adaptive partitioning needs [module=aps] on the procnto line "
         "and a 'sched_aps <name> <budget>' command in the script before "
         "any process is launched in the partition."),
    Rule("QNX408", "warning", "waitfor timeout looks wrong",
         "waitfor's wait time is in seconds and may have one decimal "
         "place; the default is 5.0."),
    # --- IFS image (QNX5xx) -----------------------------------------------
    Rule("QNX500", "error", "No QNX startup header found",
         "No 0x00FF7EEB startup-header signature was found in the file, "
         "and no bare 'imagefs' header either. This is not a QNX IFS "
         "image."),
    Rule("QNX501", "error", "Bad startup header",
         "Signature ok but version, flags2, zero fields or size "
         "relationships are invalid."),
    Rule("QNX502", "warning", "Unknown ELF machine in startup header",
         "The machine field is not a known EM_* value."),
    Rule("QNX503", "error", "Startup-header size mismatch",
         "stored_size disagrees with the actual file size, or "
         "imagefs_size runs past the end of the file."),
    Rule("QNX504", "error", "Image-header checksum mismatch",
         "The image trailer checksum does not match the recomputed "
         "value: the image is corrupt or was truncated."),
    Rule("QNX505", "error", "Startup trailer checksum mismatch",
         "The startup trailer checksum does not match the recomputed "
         "value."),
    Rule("QNX506", "warning", "Compressed IFS: contents not listed",
         "The image filesystem is compressed with LZO1X or UCL, which "
         "this tool cannot decompress with the Python standard library. "
         "zlib-compressed images are decompressed and listed."),
    Rule("QNX507", "error", "Bad image header / dirent chain",
         "The 'imagefs' header or a directory entry is malformed, "
         "truncated, or points outside the image."),
    Rule("QNX508", "warning", "Duplicate path / inode in IFS image",
         "Two directory entries share a path or an inode."),
    Rule("QNX509", "warning", "File data outside the image",
         "A file dirent's offset+size runs past the end of the image "
         "filesystem."),
    Rule("QNX510", "note", "IFS image has no procnto / no startup script",
         "The image lists no procnto binary (boot_ino) or no startup "
         "script (script_ino), so it cannot boot as a standalone image."),
]

RULES_BY_CODE = {r.code: r for r in RULES}
