# Codelab: catch a broken QNX boot image before you build it

**Time:** ~20 minutes. **You need:** Python 3.8+ and this repository. No QNX
installation, no target hardware, no license. (One optional step runs real
`mkifs`, and needs QNX SDP 8.0.)

You will write a QNX 8.0 buildfile for a Raspberry Pi 4, lint it, fix every
finding the linter reports, and then inspect the image that `mkifs` would
produce — learning the three things that break most first buildfiles along
the way.

## 0. Get the tool

```sh
git clone https://github.com/gemmaworks/qnx-buildfile-lint.git
cd qnx-buildfile-lint
./qnx-buildfile-lint --help
```

## 1. Start from a buildfile that looks right — but isn't

Create `rpi4.build`:

```text
[image=0x80000-0x8000000,16m]
[virtual=aarch64le,bios] .bootstrap = {
    startup-bcm2711-rpi4 -v
    PATH=/proc/boot procnto-smp-instr
}

[+script] .script = {
    devc-ser8250 -e -b 115200 0xfe201000,153 &
    ls > /tmp/boot.log
    [+session] esh &
}

libc.so
devc-ser8250
esh
```

Run the linter:

```sh
./qnx-buildfile-lint rpi4.build
```

You get three findings. Read each one — they are the three classic
first-buildfile mistakes:

1. **`QNX210` — `Bootfile 'bios' does not support CPU 'aarch64le'`.**
   The `virtual=` attribute picks a *bootfile* (the code that wraps the
   image for the board's loader) and a CPU. `bios` only exists for
   x86_64 PCs. A Pi 4 is loaded by U-Boot, so it wants `raw`: a plain
   binary image with a jump instruction at the front. Fix:
   `[virtual=aarch64le,raw]`.
2. **`QNX403` — `Shell construct '>' is not supported`.** A startup
   script is parsed by `mkifs` and executed by `procnto` — it is not a
   shell. There is no redirection, no piping, no loops, no wildcards.
   Delete the `ls > /tmp/boot.log` line (use `display_msg` for boot
   diagnostics instead).
3. **`QNX310` — `image= is set without ram=`.** `image=` says where the
   image lives; `ram=` says where its read-write memory lives. If you
   want the image in ROM/FLASH you need both, otherwise `procnto`
   assumes the image is in RAM. Add `[ram=0x1000000-0x40000000]`.

There is a fourth finding hiding behind the first three: after fixing
them, the linter also reports **`QNX314` — no runtime linker**. The
image has `libc.so` but no `/usr/lib/ldqnx-64.so.2`, and dynamically
linked programs cannot start without it. Add:

```text
/usr/lib/ldqnx-64.so.2=ldqnx-64.so.2
```

## 2. The fixed buildfile

Your file should now look like `examples/aarch64-rpi4.build` in this
repository (which adds a serial console symlink and an inline
`/etc/hosts` on top of the same skeleton). Lint it:

```sh
./qnx-buildfile-lint examples/aarch64-rpi4.build
# qnx-buildfile-lint: clean, no issues found
```

## 3. See what each rule means

Every finding has a code and a fix hint. Ask the tool to explain one:

```sh
./qnx-buildfile-lint explain QNX305
./qnx-buildfile-lint rules | head -30
```

`docs/RULES.md` lists all 79 rules, grouped: syntax (`QNX1xx`),
attributes (`QNX2xx`), structure and boot image (`QNX3xx`), startup
script (`QNX4xx`), IFS image (`QNX5xx`).

## 4. Break things on purpose

The `examples/bad/` directory has one file per error class. Try a few and
watch the diagnostics change:

```sh
./qnx-buildfile-lint examples/bad/bad-duplicate.build
# error: [QNX305] Duplicate target path '/myapp' ...

./qnx-buildfile-lint examples/bad/bad-script.build
# error: [QNX403] Shell construct '>' ...
# error: [QNX401] Priority 999 is outside the QNX range 1-255.
# warning: [QNX313] Startup script starts 'missing-driver', but it is
#   not in the image ...

./qnx-buildfile-lint examples/bad/bad-dupignore.build
# note: [QNX306] Duplicate target path '/myapp' resolved by +dupignore ...
```

That last one is a QNX 8.0 feature: when two entries map to the same
target path, `+dupignore` decides which one wins instead of failing the
build. The linter models the exact rule — both `+dupignore` (earlier
wins), one-sided `+dupignore` (the other wins), neither (error).

## 5. Inspect a built image

A buildfile is only half the story; the other half is the `.ifs` file
`mkifs` produces. This repository ships byte-accurate synthetic images
in `demo/` (built by `qnx_buildfile_lint/ifsgen.py` from the documented
`sys/startup.h` / `sys/image.h` layout), so you can practise inspection
without an SDP:

```sh
./qnx-buildfile-lint ifs demo/demo.ifs
```

You will see the startup header (`0x00FF7EEB`, machine 62 = x86_64,
`stored_size`, compression), the image header (`imagefs`, mountpoint,
`image_size`), and the directory entries — including the symlink
`bin/sh -> /proc/boot/.script` and the script's inode. The last line
says `0 error(s), 0 warning(s)`: both trailer checksums verified.

Now corrupt it and watch the inspector catch it:

```sh
python3 -c "
data = bytearray(open('demo/demo.ifs','rb').read())
data[-12] ^= 0xFF
open('corrupt.ifs','wb').write(data)"
./qnx-buildfile-lint ifs corrupt.ifs
# error: [QNX504] Image trailer checksum mismatch: stored 0x..., computed 0x...
```

Try the other variants: `demo/demo-zlib.ifs` is zlib-compressed (the
inspector decompresses it with the standard library and lists its
contents), and `demo/demo-be.ifs` is a big-endian image.

Extract an image the way `dumpifs -d` would:

```sh
./qnx-buildfile-lint ifs --extract ./unpacked demo/demo.ifs
find ./unpacked -type f -o -type l
```

## 6. (Optional) Run the real thing

If you have QNX SDP 8.0 installed (QNX Everywhere, free for
non-commercial use) and sourced `qnxsdp-env.sh`:

```sh
mkifs -v examples/x86_64-bios.build /tmp/test.ifs
./qnx-buildfile-lint examples/x86_64-bios.build
./qnx-buildfile-lint ifs /tmp/test.ifs
qemu-system-x86_64 -kernel /tmp/test.ifs -m 512 -serial stdio
```

The linter also checks host files when you ask it to — file existence,
`sha256=`/`sha512=`/`cksum=` verification, and `[+include]` expansion
with cycle detection:

```sh
./qnx-buildfile-lint --check-host examples/x86_64-bios.build
```

## 7. Put it in CI

Linting is fast and needs no QNX installation, so it belongs in the
pipeline before `mkifs` runs:

```yaml
- run: ./qnx-buildfile-lint --strict --format json build/*.build
- run: mkifs -v build/rpi4.build out/rpi4.ifs
- run: ./qnx-buildfile-lint --strict ifs out/rpi4.ifs
```

`--strict` turns warnings into failures; `--format json` is for
machine-readable reports. Exit codes: `0` clean, `1` findings,
`2` usage error.

## What you learned

* A buildfile is a small language with its own grammar — attribute
  blocks, sticky attributes, inline files, conditional attributes —
  and most of its mistakes are invisible until boot time.
* `virtual=` couples a CPU to a bootfile; the wrong pair is the most
  common first error on a new board.
* Startup scripts are not shell scripts, and a foreground command in
  the middle of one blocks everything after it.
* An IFS image is a checkable artefact: startup header, image header,
  directory entries, and two checksums — verify them before flashing.
