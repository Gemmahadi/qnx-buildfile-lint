"""Tests for the buildfile linter: parser + semantic checks.

Run:  python3 -m unittest discover -s tests -v
"""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from qnx_buildfile_lint.checks import LintOptions, lint_text, posix_cksum
from qnx_buildfile_lint.parser import parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def codes(report, severity=None):
    out = [d.code for d in report.diagnostics
           if severity is None or d.severity == severity]
    return out


def lint(text, **kwargs):
    return lint_text(text, "<test>", LintOptions(**kwargs))


GOOD_X86 = """\
[virtual=x86_64,bios] .bootstrap = {
    startup-x86
    PATH=/proc/boot procnto-smp-instr
}

[+script] .script = {
    devc-con -n9 &
    reopen /dev/con1
    [+session] esh &
}

libc.so
libgcc_s.so.1
/usr/lib/ldqnx-64.so.2=ldqnx-64.so.2
devc-con
esh
"""


class TestValidBuildfiles(unittest.TestCase):
    def test_good_x86_is_clean(self):
        self.assertEqual(codes(lint(GOOD_X86)), [])

    def test_example_files_are_clean(self):
        from qnx_buildfile_lint.checks import lint_file
        for name in ("x86_64-bios.build", "aarch64-rpi4.build"):
            report = lint_file(os.path.join(ROOT, "examples", name))
            self.assertEqual(codes(report, "error"), [], name)
            self.assertEqual(codes(report, "warning"), [], name)

    def test_minimal_is_only_a_note(self):
        from qnx_buildfile_lint.checks import lint_file
        report = lint_file(os.path.join(ROOT, "examples", "minimal.build"))
        self.assertEqual(codes(report, "error"), [])
        self.assertEqual(codes(report, "warning"), [])
        self.assertIn("QNX312", codes(report, "note"))


class TestParserErrors(unittest.TestCase):
    def test_unterminated_attribute_block(self):
        self.assertIn("QNX100", codes(lint("[uid=0\nfoo\n"), "error"))

    def test_stray_bracket(self):
        self.assertIn("QNX101", codes(lint("foo ]\n"), "error"))

    def test_empty_brackets(self):
        self.assertIn("QNX102", codes(lint("[] foo\n"), "error"))

    def test_two_bracket_groups(self):
        self.assertIn("QNX103", codes(lint("[uid=5] [gid=5] f\n"), "error"))

    def test_spaces_around_equals(self):
        rep = lint("[uid = 0] foo\n")
        self.assertIn("QNX104", codes(rep, "error"))

    def test_unterminated_inline(self):
        rep = lint("/etc/x = {\nnever closed\n")
        self.assertIn("QNX106", codes(rep, "error"))

    def test_content_on_brace_line(self):
        rep = lint("/etc/x = { content\n}\n")
        self.assertIn("QNX107", codes(rep, "error"))

    def test_backslash_continuation_joins_lines(self):
        parsed = parse("[uid=0] some\\\nfile\n")
        self.assertEqual(len(parsed.entries), 1)
        self.assertEqual(parsed.entries[0].target, "somefile")

    def test_comment_needs_space(self):
        rep = lint("foo#bar\n")
        self.assertIn("QNX109", codes(rep, "warning"))
        # '#bar' stays part of the filename
        self.assertEqual(parse("foo#bar\n").entries[0].target, "foo#bar")

    def test_comment_after_space_is_stripped(self):
        parsed = parse("foo # comment\n")
        self.assertEqual(parsed.entries[0].target, "foo")

    def test_quoted_filename_with_space(self):
        parsed = parse('[uid=0] "my file.bin"\n')
        self.assertEqual(parsed.entries[0].target, "my file.bin")

    def test_inline_file_lines_recorded(self):
        parsed = parse("/etc/hosts = {\n127.0.0.1 localhost\n}\n")
        entry = parsed.entries[0]
        self.assertIsNotNone(entry.inline)
        self.assertEqual(entry.inline.lines[0][1], "127.0.0.1 localhost")


class TestAttributeValues(unittest.TestCase):
    def test_unknown_attribute(self):
        self.assertIn("QNX200", codes(lint("[frobnicate=1] f\n"), "error"))

    def test_boolean_with_value(self):
        self.assertIn("QNX201", codes(lint("[raw=1] f\n"), "error"))

    def test_value_as_boolean(self):
        self.assertIn("QNX202", codes(lint("[+uid] f\n"), "error"))

    def test_bad_uid(self):
        self.assertIn("QNX203", codes(lint("[uid=abc] f\n"), "error"))
        self.assertNotIn("QNX203", codes(lint("[uid=*] f\n"), "error"))
        self.assertNotIn("QNX203", codes(lint("[uid=1000] f\n"), "error"))

    def test_perms_forms(self):
        for good in ("0755", "644", "*", "u=rwx,go=rx", "a+rx", "u+s"):
            self.assertNotIn("QNX204",
                             codes(lint("[perms=%s] f\n" % good), "error"),
                             good)
        for bad in ("9999", "abc", "u=rwx,go=", "888"):
            self.assertIn("QNX204",
                          codes(lint("[perms=%s] f\n" % bad), "error"), bad)

    def test_type_values(self):
        self.assertIn("QNX205", codes(lint("[type=banana] f\n"), "error"))
        for good in ("link", "fifo", "file", "dir"):
            self.assertNotIn("QNX205",
                             codes(lint("[type=%s] f=x\n" % good), "error"),
                             good)

    def test_autoso(self):
        self.assertIn("QNX206", codes(lint("[autoso=sometimes] f\n"), "error"))
        for good in ("none", "list", "add", "n", "l", "a"):
            self.assertNotIn("QNX206",
                             codes(lint("[autoso=%s] f\n" % good), "error"),
                             good)

    def test_compress_values(self):
        self.assertIn("QNX207", codes(lint("[compress=9] f\n"), "error"))
        for good in ("1", "2", "3"):
            self.assertNotIn("QNX207",
                             codes(lint("[compress=%s] f\n" % good), "error"),
                             good)

    def test_addr_space(self):
        good = ["0x400000", "0x1400000", "0x80000-0x8000000,16m",
                ",16m", "0x1000000=0x2000000%4096", "4m"]
        for value in good:
            self.assertNotIn("QNX208",
                             codes(lint("[image=%s] f\n" % value), "error"),
                             value)
        for bad in ("xyz", "0x100-0x50", "1x", "0x10,,5"):
            rep = lint("[image=%s] f\n" % bad)
            self.assertIn("QNX208", codes(rep, "error"), bad)

    def test_virtual(self):
        self.assertIn("QNX210",
                      codes(lint("[virtual=aarch64le,bios] .bootstrap = {\n"
                                 "startup-x\nPATH=/proc/boot procnto\n}\n"),
                            "error"))
        self.assertIn("QNX209",
                      codes(lint("[virtual=x86_64,magic] .bootstrap = {\n"
                                 "startup-x\nPATH=/proc/boot procnto\n}\n"),
                            "error"))
        self.assertIn("QNX209",
                      codes(lint("[virtual=sparc,elf] .bootstrap = {\n"
                                 "startup-x\nPATH=/proc/boot procnto\n}\n"),
                            "error"))
        ok = lint("[virtual=aarch64le,raw] .bootstrap = {\n"
                  "startup-x\nPATH=/proc/boot procnto\n}\n")
        self.assertNotIn("QNX209", codes(ok, "error"))
        self.assertNotIn("QNX210", codes(ok, "error"))

    def test_physical_is_not_implemented(self):
        rep = lint("[physical=x86_64,bios] .bootstrap = {\n"
                   "startup-x\nPATH=/proc/boot procnto\n}\n")
        self.assertIn("QNX211", codes(rep, "warning"))

    def test_mtime(self):
        self.assertIn("QNX212",
                      codes(lint("[mtime=2026-13-01-00:00:00] f\n"), "error"))
        self.assertIn("QNX212",
                      codes(lint("[mtime=2026-01-01] f\n"), "error"))
        self.assertNotIn("QNX212",
                         codes(lint("[mtime=2026-01-02-03:04:05] f\n"),
                               "error"))
        self.assertNotIn("QNX212", codes(lint("[mtime=*] f\n"), "error"))

    def test_sha(self):
        self.assertIn("QNX213",
                      codes(lint("[sha256=abcd] f\n"), "error"))
        self.assertNotIn("QNX213",
                         codes(lint("[sha256=%s] f\n" % ("ab" * 32)), "error"))
        self.assertNotIn("QNX213",
                         codes(lint("[sha512=%s] f\n" % ("cd" * 64)), "error"))

    def test_ifs_csa(self):
        self.assertIn("QNX215", codes(lint("[ifs_csa=md5] f\n"), "error"))
        self.assertNotIn("QNX215", codes(lint("[ifs_csa=crc32c] f\n"),
                                         "error"))
        self.assertNotIn("QNX215", codes(lint("[ifs_csa=none] f\n"), "error"))

    def test_module(self):
        self.assertIn("QNX216",
                      codes(lint("[module=banana] f\n"), "warning"))
        self.assertNotIn("QNX216", codes(lint("[module=aps] f\n"), "warning"))

    def test_pagesizes_and_phys_align(self):
        self.assertNotIn("QNX214",
                         codes(lint("[pagesizes=4k,64k] f\n"), "error"))
        self.assertIn("QNX214",
                      codes(lint("[pagesizes=3k] f\n"), "warning"))
        self.assertNotIn("QNX214",
                         codes(lint("[phys_align=16M,group] f\n"), "error"))
        self.assertNotIn("QNX214",
                         codes(lint("[phys_align=16M,group] f\n"), "warning"))
        self.assertIn("QNX214",
                      codes(lint("[phys_align=16M,other] f\n"), "error"))

    def test_linker(self):
        # a value with spaces must be quoted, otherwise mkifs reads the
        # rest as further attributes
        self.assertIn("QNX218",
                      codes(lint('[linker="(40;1;2)qcc -o%o"] f\n'), "warning"))
        self.assertNotIn("QNX218",
                         codes(lint('[linker="qcc -o%o %i"] f\n'), "warning"))

    def test_drop(self):
        self.assertIn("QNX220",
                      codes(lint("[drop=*.sym|] f\n"), "error"))
        self.assertNotIn("QNX220",
                         codes(lint("[drop=*.sym|*.a] f\n"), "error"))

    def test_mount_search(self):
        self.assertIn("QNX223", codes(lint("[mount=ifs] f\n"), "warning"))
        self.assertIn("QNX224",
                      codes(lint("[search=/a::/b] f\n"), "warning"))

    def test_undefined_variable(self):
        rep = lint("[search=/opt/${NO_SUCH_VAR}/bin]\nfoo\n")
        self.assertIn("QNX219", codes(rep, "warning"))
        rep2 = lint("[search=/opt/${MY_VAR}/bin]\nfoo\n",
                    defines={"MY_VAR": "/x"})
        self.assertNotIn("QNX219", codes(rep2, "warning"))


class TestStructure(unittest.TestCase):
    def test_two_bootstraps(self):
        rep = lint("[virtual=x86_64,bios] .bootstrap = {\nstartup-x\n"
                   "PATH=/proc/boot procnto\n}\n"
                   "[virtual=x86_64,elf] .bootstrap2 = {\nstartup-x\n"
                   "PATH=/proc/boot procnto\n}\n")
        self.assertIn("QNX300", codes(rep, "error"))

    def test_bootstrap_not_first(self):
        rep = lint("libc.so\n[virtual=x86_64,bios] .bootstrap = {\n"
                   "startup-x\nPATH=/proc/boot procnto\n}\n")
        self.assertIn("QNX301", codes(rep, "error"))

    def test_bootstrap_contents(self):
        bad_first = lint("[virtual=x86_64,bios] .bootstrap = {\n"
                         "procnto\nstartup-x\n}\n")
        self.assertIn("QNX302", codes(bad_first, "error"))
        self.assertIn("QNX303", codes(bad_first, "error"))

    def test_optional_on_bootstrap(self):
        rep = lint("[+optional virtual=x86_64,bios] .bootstrap = {\n"
                   "startup-x\nPATH=/proc/boot procnto\n}\n")
        self.assertIn("QNX304", codes(rep, "error"))

    def test_duplicate_target(self):
        rep = lint("[uid=0] app\n[uid=1] app\n")
        self.assertIn("QNX305", codes(rep, "error"))

    def test_dupignore_resolves(self):
        rep = lint("[+dupignore] app=/a/app\n[+dupignore] app=/b/app\n")
        self.assertNotIn("QNX305", codes(rep, "error"))
        self.assertIn("QNX306", codes(rep, "note"))

    def test_dupignore_one_sided(self):
        rep = lint("[+dupignore] app=/a/app\napp=/b/app\n")
        self.assertNotIn("QNX305", codes(rep, "error"))
        self.assertIn("QNX306", codes(rep, "note"))

    def test_link_without_target(self):
        self.assertIn("QNX307",
                      codes(lint("[type=link] /bin/sh\n"), "error"))

    def test_path_through_symlink(self):
        rep = lint("[type=link] mylink=mydir\nmylink/file=x\n")
        self.assertIn("QNX308", codes(rep, "error"))

    def test_raw_on_shared_object(self):
        self.assertIn("QNX309",
                      codes(lint("[+raw] libfoo.so\n"), "warning"))

    def test_image_without_ram(self):
        rep = lint("[image=0x1400000]\nfoo\n")
        self.assertIn("QNX310", codes(rep, "warning"))

    def test_zlib_not_bootable(self):
        rep = lint("[virtual=x86_64,bios] .bootstrap = {\nstartup-x\n"
                   "PATH=/proc/boot procnto\n}\n[compress=1] libc.so\n")
        self.assertIn("QNX311", codes(rep, "error"))

    def test_no_bootstrap_note(self):
        rep = lint("foo\n")
        self.assertIn("QNX312", codes(rep, "note"))

    def test_conditional_redundant(self):
        rep = lint("[+bigendian]\n[?+bigendian] foo\n")
        self.assertIn("QNX221", codes(rep, "warning"))


class TestScript(unittest.TestCase):
    def _script_build(self, script_body):
        return ("[virtual=x86_64,bios] .bootstrap = {\n"
                "    startup-x86\n"
                "    PATH=/proc/boot procnto-smp-instr\n}\n\n"
                "[+script] .script = {\n" + script_body + "}\n\n"
                "libc.so\nlibgcc_s.so.1\n"
                "/usr/lib/ldqnx-64.so.2=ldqnx-64.so.2\n"
                "devc-con\nesh\ndevc-pty\n")

    def test_shell_redirect_rejected(self):
        rep = lint(self._script_build("    ls > /tmp/x\n"))
        self.assertIn("QNX403", codes(rep, "error"))

    def test_pipe_rejected(self):
        rep = lint(self._script_build("    ls | grep x\n"))
        self.assertIn("QNX403", codes(rep, "error"))

    def test_export_rejected(self):
        rep = lint(self._script_build("    export FOO=bar\n"))
        self.assertIn("QNX406", codes(rep, "error"))

    def test_bad_priority(self):
        rep = lint(self._script_build("    [pri=999] devc-con &\n"))
        self.assertIn("QNX401", codes(rep, "error"))
        rep2 = lint(self._script_build("    [pri=20f] devc-con &\n"))
        self.assertNotIn("QNX401", codes(rep2, "error"))

    def test_unknown_modifier(self):
        rep = lint(self._script_build("    [bogus=1] esh &\n"))
        self.assertIn("QNX400", codes(rep, "error"))

    def test_foreground_blocks(self):
        rep = lint(self._script_build("    devc-con &\n    devc-pty\n"
                                      "    esh &\n"))
        self.assertIn("QNX405", codes(rep, "warning"))

    def test_missing_command(self):
        rep = lint(self._script_build("    devc-con &\n    nosuchdrv &\n"
                                      "    esh &\n"))
        self.assertIn("QNX313", codes(rep, "warning"))

    def test_waitfor_bad_time(self):
        rep = lint(self._script_build("    waitfor /dev/pci 1.25\n"
                                      "    esh &\n"))
        self.assertIn("QNX408", codes(rep, "error"))

    def test_procmgr_symlink_wrong_args(self):
        rep = lint(self._script_build("    procmgr_symlink /only-one\n"
                                      "    esh &\n"))
        self.assertIn("QNX404", codes(rep, "error"))

    def test_sched_aps_without_module(self):
        rep = lint(self._script_build("    [sched_aps=Debug] esh &\n"))
        self.assertIn("QNX407", codes(rep, "warning"))


class TestHostChecks(unittest.TestCase):
    def test_posix_cksum_matches_system(self):
        data = b"hello qnx\n"
        got = posix_cksum(data)
        proc = subprocess.run(["cksum"], input=data, capture_output=True)
        if proc.returncode == 0:
            want = int(proc.stdout.split()[0])
            self.assertEqual(got, want)

    def test_sha256_mismatch(self):
        import hashlib
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            host = os.path.join(tmp, "myapp")
            with open(host, "wb") as fh:
                fh.write(b"real bytes")
            wrong = hashlib.sha256(b"other bytes").hexdigest()
            text = ("[sha256=%s] myapp=%s\n" % (wrong, host))
            rep = lint(text, check_host=True)
            self.assertIn("QNX213", codes(rep, "error"))
            right = hashlib.sha256(b"real bytes").hexdigest()
            rep2 = lint("[sha256=%s] myapp=%s\n" % (right, host),
                        check_host=True)
            self.assertNotIn("QNX213", codes(rep2, "error"))

    def test_cksum_match(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            host = os.path.join(tmp, "myapp")
            with open(host, "wb") as fh:
                fh.write(b"cksum me\n")
            value = posix_cksum(b"cksum me\n")
            rep = lint("[cksum=%d] myapp=%s\n" % (value, host),
                       check_host=True)
            self.assertNotIn("QNX222", codes(rep, "error"))
            rep2 = lint("[cksum=%d] myapp=%s\n" % (value + 1, host),
                        check_host=True)
            self.assertIn("QNX222", codes(rep2, "error"))

    def test_include_cycle(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            a = os.path.join(tmp, "a.build")
            b = os.path.join(tmp, "b.build")
            with open(a, "w") as fh:
                fh.write("[+include] b.build\nfoo\n")
            with open(b, "w") as fh:
                fh.write("[+include] a.build\nbar\n")
            from qnx_buildfile_lint.checks import lint_file
            rep = lint_file(a, LintOptions(check_host=True))
            self.assertIn("QNX316", codes(rep, "error"))


class TestBadExamples(unittest.TestCase):
    """Every file in examples/bad must produce at least one error or
    warning (dupignore is the exception: it resolves to notes)."""

    def test_bad_examples(self):
        from qnx_buildfile_lint.checks import lint_file
        bad_dir = os.path.join(ROOT, "examples", "bad")
        for name in sorted(os.listdir(bad_dir)):
            if not name.endswith(".build"):
                continue
            report = lint_file(os.path.join(bad_dir, name))
            # dupignore resolves to notes by design; everything else must
            # produce at least one error or warning
            total = len(report.errors) + len(report.warnings) \
                + len(report.notes)
            self.assertGreater(total, 0, name)


if __name__ == "__main__":
    unittest.main()
