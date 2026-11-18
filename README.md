# qnx-buildfile-lint

A host-based linter and validator for **QNX mkifs buildfiles** and **QNX IFS
images** — the files that define what goes into a QNX 8.0 boot image and how
the system starts.

`mkifs` fails late: a typo in a buildfile is usually discovered only when
the image build breaks, or worse, when the target does not boot. This tool
catches the mistake on the host, before `mkifs` ever runs, with the exact
line, a rule code, and a fix hint. It also inspects built `.ifs` images the
way `dumpifs` does — headers, directory entries, and both trailer
checksums — so a corrupt or truncated image is caught before it is flashed.

## Why this is a QNX tool, not a generic linter

* It parses the real `mkifs` buildfile grammar: attribute blocks (`[uid=0
  gid=0]`), sticky (global) attributes, `target=host` mappings, inline
  files (`target = { ... }`), backslash continuation rules that differ
  inside and outside inline files, `?`-conditional attributes, and
  `${VARIABLE}` expansion.
* It validates every QNX 8.0 `mkifs` attribute value: `virtual=[cpu,]bootfile`
  (including the CPU/bootfile compatibility table — `bios` is x86_64-only,
  `raw` is aarch64le/armle-v7-only), `image=`/`ram=` address-space specs,
  `perms=`/`dperms=` (octal and symbolic modes), `mtime=`, `sha256=`/
  `sha512=`, `autoso=`, `compress=` (and the fact that zlib compression is
  not bootable), `type=`, `keepsection=`, `linker=`, `drop=`, `ifs_csa=`,
  and the QNX 8.0 `+dupignore` duplicate rules.
* It understands the boot sequence: the bootstrap must be first, start
  with `startup-*` and end with `procnto`; `+optional` is illegal there;
  `image=` without `ram=` (or vice versa) means the image is assumed to be
  in RAM.
* It parses QNX startup scripts (`.script`) as `mkifs`/`procnto` do — not
  as shell: no redirection, pipes, loops, branching or wildcards — and
  checks that every command the script starts is actually in the image.
* It parses the IFS on-disk format (`sys/startup.h`, `sys/image.h`):
  startup header (signature `0x00FF7EEB`), image header (`imagefs`),
  directory entries, and both trailer checksums (negated 32-bit word
  sum). zlib-compressed images are decompressed and listed.

## Quick start

```sh
# no installation needed — Python 3.8+, standard library only
./qnx-buildfile-lint examples/x86_64-bios.build
# qnx-buildfile-lint: clean, no issues found

./qnx-buildfile-lint examples/bad/bad-duplicate.build
# examples/bad/bad-duplicate.build:3:9: error: [QNX305] Duplicate target path '/myapp' (first defined at line 2).
# ...

./qnx-buildfile-lint ifs demo/demo.ifs
# startup header: ... machine: 62 (EM_X86_64) ... compression: none
# entries (8): ... proc/boot/procnto ... bin/sh [symlink] -> /proc/boot/.script
# qnx-buildfile-lint ifs: 0 error(s), 0 warning(s)
```

Or install it:

```sh
pip install .
qnx-buildfile-lint --help
```

## Usage

```
qnx-buildfile-lint [options] <buildfile>...     # lint (default command)
qnx-buildfile-lint lint [options] <buildfile>...
qnx-buildfile-lint ifs [options] <image.ifs>     # inspect a built image
qnx-buildfile-lint rules [--format text|json]    # list all rules
qnx-buildfile-lint explain <CODE>               # explain one rule
```

### Lint options

| Option | Meaning |
| ------ | ------- |
| `--format text\|json` | Human (GCC-style) or machine-readable output |
| `--strict` | Warnings fail the run (exit 1) — for CI |
| `-D NAME=value` / `--define` | Define a `${VARIABLE}` for expansion checks |
| `--check-host` | Also check the host: file existence, `sha256=`/`sha512=`/`cksum=` verification, `[+include]` expansion and cycle detection |
| `--host-root DIR` | Extra directory to search for host files |
| `--search DIR` | Extra directory to search for `[+include]` files |
| `-q` / `--quiet` | Summary only |

Exit codes: `0` clean (or warnings only), `1` errors (or warnings with
`--strict`), `2` usage error. Without `--check-host` the linter needs no
QNX installation at all — it works purely from the buildfile text.

### IFS inspection options

| Option | Meaning |
| ------ | ------- |
| `--format text\|json` | Human listing or machine-readable output |
| `--extract DIR` | Extract the image contents into DIR |
| `--strict` | Warnings fail the run |

## Examples

* `examples/x86_64-bios.build` — minimal bootable x86_64/BIOS image (from
  the QNX SDP 8.0 mkifs documentation).
* `examples/aarch64-rpi4.build` — Raspberry Pi 4 (BCM2711) raw-boot image
  with `image=`/`ram=`, a serial console, and an inline `/etc/hosts`.
* `examples/minimal.build` — a non-bootable data-only IFS.
* `examples/bad/*.build` — one file per error class; every file fails the
  linter for exactly the reason its name says. See `docs/RULES.md`.
* `demo/*.ifs` — synthetic but byte-accurate IFS images built by the
  tool's own generator (`qnx_buildfile_lint/ifsgen.py`): uncompressed
  little-endian, zlib-compressed, and big-endian.

## Rules

79 rules, `QNX100`–`QNX510`, in five groups: buildfile syntax, attributes,
structure/boot image, startup script, IFS image. Full list:
[`docs/RULES.md`](docs/RULES.md), or run `qnx-buildfile-lint rules`.

## Building and running for QNX 8.0

This is a **host tool** — it runs on Linux (also macOS/Windows with Python
3.8+) and needs no QNX installation, no target hardware, and no QNX
license. It targets buildfiles written for **QNX SDP 8.0 / QNX Everywhere
(8.0.x)**, for the QNX 8.0 CPUs `aarch64le`, `armle-v7` and `x86_64`, built
with `mkifs` from the QNX SDP 8.0 toolchain (host `qcc`/`mkifs`, target
QEMU or hardware such as Raspberry Pi 4/5).

To validate a real image end to end:

```sh
# on a machine with QNX SDP 8.0 installed and sourced (qnxsdp-env.sh):
mkifs -v examples/x86_64-bios.build /tmp/test.ifs
./qnx-buildfile-lint examples/x86_64-bios.build   # lint the source
./qnx-buildfile-lint ifs /tmp/test.ifs            # inspect the product
```

Without an SDP installed, `qnx-buildfile-lint --check-host` still verifies
host files against a local staging tree, and `ifs` works on any `.ifs`
file, including the synthetic ones in `demo/`.

## Tests

```sh
./run_tests.sh        # 87 tests, stdlib unittest, no dependencies
```

The suite covers: the parser (comments, quoting, continuation, inline
files), every attribute validator, bootstrap/script structure, duplicate
handling including QNX 8.0 `+dupignore`, host checks (sha256/cksum against
real files, `[+include]` cycles), IFS round-trips (little/big-endian,
uncompressed/zlib, bare `imagefs`), checksum-mismatch and truncation
detection, and the CLI (exit codes, JSON output, extraction).

## How it was verified

* The three valid examples lint clean; each of the 20 `examples/bad/`
  files fails with the expected rule.
* `demo/demo.ifs` (and the zlib and big-endian variants) parse with zero
  errors: startup header, image header, 6–8 entries, and both trailer
  checksums verify. Flipping one byte in the file data makes `ifs`
  report `QNX504` (image checksum mismatch); truncating the file makes it
  report `QNX503`.
* The POSIX `cksum` implementation is checked against the system `cksum`
  binary in the test suite.

## Tutorial

[`docs/CODELAB.md`](docs/CODELAB.md) walks through writing a buildfile for
a Raspberry Pi 4, linting it, fixing each finding, and inspecting the
resulting image — about 20 minutes, no QNX installation required.

## References

* QNX SDP 8.0 Utilities Reference — `mkifs` (attribute list, buildfile
  grammar, script files, bootfiles, image format, patch files).
* QNX SDP 8.0 *Building Embedded Systems* — "OS Image Buildfiles", "The
  startup header", "Making an OS Image".
* `sys/startup.h` / `sys/image.h` on-disk structures, as documented by the
  MIT-licensed [`qnx-ifs`](https://docs.rs/qnx-ifs/0.1.1) crate, whose
  fixture builders the synthetic-image generator mirrors.

## License

MIT — see [LICENSE](LICENSE).
