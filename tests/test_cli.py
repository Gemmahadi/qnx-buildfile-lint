"""End-to-end CLI tests."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TOOL = os.path.join(ROOT, "qnx-buildfile-lint")


def run(*args, input_text=None):
    proc = subprocess.run([sys.executable, TOOL, *args],
                          input=input_text, capture_output=True, text=True)
    return proc


class TestCli(unittest.TestCase):
    def test_good_file_exit_0(self):
        proc = run(os.path.join(ROOT, "examples", "x86_64-bios.build"))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("clean", proc.stdout)

    def test_bad_file_exit_1(self):
        proc = run(os.path.join(ROOT, "examples", "bad",
                                "bad-duplicate.build"))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("QNX305", proc.stdout)

    def test_warnings_do_not_fail_by_default(self):
        proc = run(os.path.join(ROOT, "examples", "bad",
                                "bad-image-ram.build"))
        self.assertEqual(proc.returncode, 0)

    def test_strict_fails_on_warnings(self):
        proc = run("--strict", os.path.join(
            ROOT, "examples", "bad", "bad-image-ram.build"))
        self.assertEqual(proc.returncode, 1)

    def test_json_output(self):
        proc = run("--format", "json", os.path.join(
            ROOT, "examples", "bad", "bad-duplicate.build"))
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["tool"], "qnx-buildfile-lint")
        self.assertEqual(payload["summary"]["errors"], 1)
        err_codes = [d["code"] for d in payload["diagnostics"]
                     if d["severity"] == "error"]
        self.assertEqual(err_codes, ["QNX305"])

    def test_stdin(self):
        proc = run("-", input_text="[frobnicate=1] foo\n")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("QNX200", proc.stdout)

    def test_missing_file_exit_2(self):
        proc = run("no-such-file.build")
        self.assertEqual(proc.returncode, 2)

    def test_rules_lists_all(self):
        proc = run("rules")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("QNX305", proc.stdout)
        self.assertIn("QNX500", proc.stdout)

    def test_explain(self):
        proc = run("explain", "QNX210")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("x86_64 only", proc.stdout)

    def test_ifs_subcommand(self):
        sys.path.insert(0, ROOT)
        from qnx_buildfile_lint.ifsgen import LE, build_image
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "demo.ifs")
            with open(path, "wb") as fh:
                fh.write(build_image(LE, "none"))
            proc = run("ifs", path)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("proc/boot/procnto", proc.stdout)
            self.assertIn("startup header:", proc.stdout)

    def test_ifs_json(self):
        sys.path.insert(0, ROOT)
        from qnx_buildfile_lint.ifsgen import LE, build_image
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "demo.ifs")
            with open(path, "wb") as fh:
                fh.write(build_image(LE, "zlib"))
            proc = run("ifs", "--format", "json", path)
            self.assertEqual(proc.returncode, 0)
            payload = json.loads(proc.stdout)
            self.assertTrue(payload["bootable"])
            self.assertEqual(payload["startup"]["compress"], "zlib")
            self.assertGreater(len(payload["entries"]), 0)

    def test_ifs_extract(self):
        sys.path.insert(0, ROOT)
        from qnx_buildfile_lint.ifsgen import LE, build_image
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "demo.ifs")
            with open(path, "wb") as fh:
                fh.write(build_image(LE, "none"))
            outdir = os.path.join(tmp, "out")
            proc = run("ifs", "--extract", outdir, path)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertTrue(os.path.isfile(
                os.path.join(outdir, "proc/boot/.script")))


if __name__ == "__main__":
    unittest.main()
