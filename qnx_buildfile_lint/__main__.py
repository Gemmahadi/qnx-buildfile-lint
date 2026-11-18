#!/usr/bin/env python3
"""Entry point for qnx-buildfile-lint (installed as a console script)."""

from qnx_buildfile_lint.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
