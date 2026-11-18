"""qnx-buildfile-lint: a host linter/validator for QNX mkifs buildfiles
and IFS images (QNX SDP 8.0).

Usage:
    qnx-buildfile-lint [options] <buildfile>...
    qnx-buildfile-lint ifs [options] <image.ifs>
    qnx-buildfile-lint rules [--format text|json]
    qnx-buildfile-lint explain <CODE>
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .checks import LintOptions, lint_file, lint_text
from .diagnostics import RULES, RULES_BY_CODE
from .ifs import file_bytes, parse_image

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


# ---------------------------------------------------------------------------
# lint
# ---------------------------------------------------------------------------

def _build_lint_parser(sub):
    p = sub.add_parser("lint", help="lint one or more buildfiles")
    p.add_argument("buildfile", nargs="+",
                   help="buildfile(s) to lint ('-' reads stdin)")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="output format (default: text)")
    p.add_argument("--strict", action="store_true",
                   help="treat warnings as errors")
    p.add_argument("--define", "-D", action="append", default=[],
                   metavar="NAME=value",
                   help="define a ${VARIABLE} for expansion checks")
    p.add_argument("--check-host", action="store_true",
                   help="also check host files: existence, sha256/sha512/"
                        "cksum verification and [+include] expansion")
    p.add_argument("--host-root", action="append", default=[],
                   metavar="DIR",
                   help="extra directory to search for host files")
    p.add_argument("--search", action="append", default=[],
                   metavar="DIR",
                   help="extra directory to search for [+include] files")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="only print the summary line")
    return p


def _parse_defines(raw_list):
    defines = {}
    for item in raw_list:
        if "=" in item:
            name, value = item.split("=", 1)
            defines[name] = value
        else:
            defines[item] = ""
    return defines


def _print_report_text(report, quiet: bool):
    for d in report.diagnostics:
        if quiet and d.severity == "note":
            continue
        print(d.gcc_style())
    n_err = len(report.errors)
    n_warn = len(report.warnings)
    n_note = len(report.notes)
    if n_err or n_warn or n_note:
        print(f"qnx-buildfile-lint: {n_err} error(s), {n_warn} warning(s), "
              f"{n_note} note(s)")
    else:
        print("qnx-buildfile-lint: clean, no issues found")


def cmd_lint(args) -> int:
    options = LintOptions(
        defines=_parse_defines(args.define),
        check_host=args.check_host,
        host_roots=args.host_root,
        search_roots=args.search)
    all_diags = []
    for target in args.buildfile:
        if target == "-":
            text = sys.stdin.read()
            report = lint_text(text, "<stdin>", options)
        else:
            if not os.path.isfile(target):
                print(f"qnx-buildfile-lint: {target}: no such file",
                      file=sys.stderr)
                return EXIT_USAGE
            report = lint_file(target, options)
        all_diags.extend(report.diagnostics)
    from .diagnostics import Report as _Report
    combined = _Report(all_diags)
    if args.format == "json":
        print(json.dumps(
            {"tool": "qnx-buildfile-lint", "version": __version__,
             "diagnostics": [d.as_dict() for d in combined.diagnostics],
             "summary": {"errors": len(combined.errors),
                         "warnings": len(combined.warnings),
                         "notes": len(combined.notes)}},
            indent=2))
    else:
        _print_report_text(combined, args.quiet)
    if combined.errors:
        return EXIT_FINDINGS
    if args.strict and combined.warnings:
        return EXIT_FINDINGS
    return EXIT_OK


# ---------------------------------------------------------------------------
# ifs
# ---------------------------------------------------------------------------

def _build_ifs_parser(sub):
    p = sub.add_parser("ifs", help="inspect a built .ifs image")
    p.add_argument("image", help=".ifs image file to inspect")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--extract", metavar="DIR",
                   help="extract the image contents into DIR")
    p.add_argument("--strict", action="store_true",
                   help="treat warnings as errors")
    return p


def _print_ifs_text(image) -> None:
    st = image.startup
    hdr = image.image_header
    print(f"file: {len(image.data)} bytes")
    if st is not None:
        print("startup header:")
        print(f"  offset       : {st.offset} (boot prefix size)")
        print(f"  byte order   : {st.endian}")
        print(f"  version      : {st.version}")
        print(f"  machine      : {st.machine} ({st.machine_name})")
        print(f"  startup_vaddr: {st.startup_vaddr:#x}")
        print(f"  paddr_bias   : {st.paddr_bias:#x}")
        print(f"  image_paddr  : {st.image_paddr:#x}")
        print(f"  ram_paddr    : {st.ram_paddr:#x}  ram_size: {st.ram_size:#x}")
        print(f"  startup_size : {st.startup_size}  stored_size: {st.stored_size}")
        print(f"  imagefs_size : {st.imagefs_size}")
        print(f"  compression  : {st.compress}")
    if hdr is not None:
        print("image header:")
        print(f"  offset       : {image.filesystem_offset + hdr.offset}")
        print(f"  mountpoint   : {hdr.mountpoint or '(empty)'}")
        print(f"  image_size   : {hdr.image_size}")
        print(f"  hdr_dir_size : {hdr.hdr_dir_size}")
        print(f"  dir_offset   : {hdr.dir_offset}")
        print(f"  boot_ino     : {list(hdr.boot_ino)}")
        print(f"  script_ino   : {hdr.script_ino}")
        print(f"  flags        : {hdr.flags:#x}")
    if image.entries:
        print(f"entries ({len(image.entries)}):")
        print(f"  {'Offset':>8}  {'Size':>8}  {'Mode':>6}  Name")
        for e in image.entries:
            extra = ""
            if e.kind == "symlink":
                extra = " -> " + e.target
            elif e.kind in ("char", "block", "fifo", "named", "socket"):
                extra = f" (dev={e.dev:#x} rdev={e.rdev:#x})"
            size = e.size if e.kind == "file" else 0
            print(f"  {e.offset:8x}  {size:8x}  {e.perms:>6}  "
                  f"{e.path or '/'} [{e.kind}]{extra}")
    if image.omitted_dirents:
        print(f"omitted dirents (ino == 0, skipped by the kernel): "
              f"{len(image.omitted_dirents)}")


def _extract_image(image, outdir: str) -> list:
    extracted = []
    for e in image.entries:
        if e.kind == "dir":
            os.makedirs(os.path.join(outdir, e.path), exist_ok=True)
            continue
        dest = os.path.join(outdir, e.path)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if e.kind == "symlink":
            try:
                os.symlink(e.target, dest)
            except FileExistsError:
                pass
            extracted.append(dest)
        elif e.kind == "file":
            data = file_bytes(image, e)
            if data is None:
                continue
            with open(dest, "wb") as fh:
                fh.write(data)
            try:
                os.chmod(dest, e.mode & 0o7777)
            except OSError:
                pass
            extracted.append(dest)
    return extracted


def cmd_ifs(args) -> int:
    if not os.path.isfile(args.image):
        print(f"qnx-buildfile-lint: {args.image}: no such file",
              file=sys.stderr)
        return EXIT_USAGE
    with open(args.image, "rb") as fh:
        data = fh.read()
    image = parse_image(data, args.image)
    if args.format == "json":
        out = {
            "file": args.image,
            "size": len(data),
            "bootable": image.bootable,
            "startup": None,
            "image_header": None,
            "entries": [],
            "diagnostics": [d.as_dict()
                            for d in image.report.diagnostics],
        }
        if image.startup is not None:
            st = image.startup
            out["startup"] = {
                "offset": st.offset, "endian": st.endian,
                "version": st.version, "machine": st.machine,
                "machine_name": st.machine_name,
                "startup_vaddr": st.startup_vaddr,
                "paddr_bias": st.paddr_bias,
                "image_paddr": st.image_paddr,
                "ram_paddr": st.ram_paddr, "ram_size": st.ram_size,
                "startup_size": st.startup_size,
                "stored_size": st.stored_size,
                "imagefs_size": st.imagefs_size,
                "compress": st.compress,
            }
        if image.image_header is not None:
            h = image.image_header
            out["image_header"] = {
                "mountpoint": h.mountpoint, "image_size": h.image_size,
                "hdr_dir_size": h.hdr_dir_size,
                "dir_offset": h.dir_offset,
                "boot_ino": list(h.boot_ino), "script_ino": h.script_ino,
                "flags": h.flags,
            }
        for e in image.entries:
            out["entries"].append({
                "path": e.path, "kind": e.kind, "ino": e.ino,
                "mode": oct(e.mode), "uid": e.uid, "gid": e.gid,
                "mtime": e.mtime, "offset": e.offset, "size": e.size,
                "target": e.target, "dev": e.dev, "rdev": e.rdev,
            })
        print(json.dumps(out, indent=2))
    else:
        _print_ifs_text(image)
        for d in image.report.diagnostics:
            print(d.gcc_style())
        n_err = len(image.report.errors)
        n_warn = len(image.report.warnings)
        print(f"qnx-buildfile-lint ifs: {n_err} error(s), "
              f"{n_warn} warning(s)")
    if args.extract:
        extracted = _extract_image(image, args.extract)
        print(f"extracted {len(extracted)} entries to {args.extract}")
    if image.report.errors:
        return EXIT_FINDINGS
    if args.strict and image.report.warnings:
        return EXIT_FINDINGS
    return EXIT_OK


# ---------------------------------------------------------------------------
# rules / explain
# ---------------------------------------------------------------------------

def cmd_rules(args) -> int:
    if args.format == "json":
        print(json.dumps(
            [{"code": r.code, "severity": r.severity, "title": r.title,
              "body": r.body} for r in RULES], indent=2))
    else:
        for r in RULES:
            print(f"{r.code} [{r.severity}] {r.title}\n    {r.body}\n")
    return EXIT_OK


def cmd_explain(args) -> int:
    code = args.code.upper()
    rule = RULES_BY_CODE.get(code)
    if rule is None:
        print(f"qnx-buildfile-lint: unknown rule {code}", file=sys.stderr)
        print("Run 'qnx-buildfile-lint rules' for the full list.",
              file=sys.stderr)
        return EXIT_USAGE
    print(f"{rule.code} [{rule.severity}] {rule.title}\n\n{rule.body}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# top level
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="qnx-buildfile-lint",
        description="Lint QNX mkifs buildfiles and inspect QNX IFS images "
                    "(QNX SDP 8.0).")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command")
    _build_lint_parser(sub)
    _build_ifs_parser(sub)
    rp = sub.add_parser("rules", help="list all lint rules")
    rp.add_argument("--format", choices=["text", "json"], default="text")
    ep = sub.add_parser("explain", help="explain one rule code")
    ep.add_argument("code", help="rule code, e.g. QNX305")
    return p


def main(argv=None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in ("lint", "ifs", "rules", "explain",
                                "--version", "-h", "--help"):
        # default subcommand: lint, so bare file arguments work:
        # `qnx-buildfile-lint foo.build`
        argv = ["lint"] + argv
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return EXIT_OK
    if args.command == "lint":
        return cmd_lint(args)
    if args.command == "ifs":
        return cmd_ifs(args)
    if args.command == "rules":
        return cmd_rules(args)
    if args.command == "explain":
        return cmd_explain(args)
    parser.print_help()
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
