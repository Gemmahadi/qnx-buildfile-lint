"""Checks for QNX startup scripts (the [+script] inline/host file).

A startup script is parsed by mkifs and executed by procnto -- it is
NOT a shell script: no branching, loops, redirection, piping, subshells,
filename expansion or wildcards. Each line is::

    [modifiers] command_line [&]

with modifiers argv0=, cpu=, +|-external, pri=, sched_aps=, +|-session,
and internal commands display_msg, procmgr_symlink, reopen, waitfor.
"""

from __future__ import annotations

import re

from .diagnostics import Report
from .qnxdata import (
    PRI_MAX, PRI_MIN, SCHED_POLICIES, SCRIPT_INTERNAL_COMMANDS,
    SCRIPT_MODIFIERS, SCRIPT_MODIFIERS_BOOL, SCRIPT_MODIFIERS_VALUE,
    SHELL_CONSTRUCTS,
)

_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_SHELL_KEYWORDS = ("if", "then", "else", "elif", "fi", "for", "while",
                   "until", "do", "done", "case", "esac", "export",
                   "source", ".")
_WAITFOR_TIME = re.compile(r"^\d+(\.\d)?$")


def _join_continuations(lines):
    """Join backslash-continued lines, as mkifs does when it parses
    bootstrap and script contents. Returns [(first_lineno, text)]."""
    out = []
    buf = None
    buf_line = 0
    for lineno, text in lines:
        stripped = text.rstrip("\r")
        trailing = 0
        for ch in reversed(stripped):
            if ch == "\\":
                trailing += 1
            else:
                break
        if buf is None:
            buf, buf_line = stripped, lineno
        else:
            buf += stripped
        if trailing % 2 == 1:
            buf = buf[:-1]
            continue
        out.append((buf_line, buf))
        buf = None
    if buf is not None:
        out.append((buf_line, buf))
    return out


def check_script(lines, path: str, base_line: int, report: Report,
                 *, in_bootstrap: bool = False) -> list:
    """Check one script's lines.

    *lines* is a list of (lineno, text). Returns a list of command names
    started by the script (for the "command not in the image" check).
    """
    lines = _join_continuations(lines)
    commands: list[str] = []
    n = len(lines)
    for idx, (lineno, raw) in enumerate(lines):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # shell keywords / control flow
        first_word = line.split(None, 1)[0]
        if first_word in _SHELL_KEYWORDS:
            report.error(
                "QNX406",
                "Shell keyword '%s' is not supported in a QNX startup "
                "script." % first_word, path, lineno, 1,
                hint="Startup scripts have no branching, loops or "
                     "'export'; use plain 'NAME=value' lines for "
                     "environment variables.")
            continue
        # shell-only constructs
        bad = None
        for construct in SHELL_CONSTRUCTS:
            if construct in line:
                bad = (construct, line.index(construct) + 1)
                break
        if bad is not None:
            report.error(
                "QNX403",
                "Shell construct '%s' is not supported in a QNX "
                "startup script." % bad[0], path, lineno, bad[1],
                hint="Scripts are parsed by mkifs and run by procnto, "
                     "not a shell: no redirection, piping, subshells "
                     "or wildcards.")
            continue

        # modifiers: leading [ ... ]
        rest = line
        if rest.startswith("["):
            close = rest.find("]")
            if close == -1:
                report.error("QNX100", "Unterminated modifier block '['.",
                             path, lineno, 1)
                continue
            for token in rest[1:close].split():
                _check_modifier(token, path, lineno, report)
            rest = rest[close + 1:].strip()
            if not rest:
                continue

        # wildcard / glob characters in the command part (no filename
        # expansion in startup scripts)
        if re.search(r"(?<!\\)[*?]", rest):
            report.error(
                "QNX403",
                "Wildcard is not supported in a QNX startup script "
                "(no filename expansion).",
                path, lineno, 1,
                hint="Spell out the full pathname.")
            continue

        # environment assignment lines: every word is NAME=value
        words = rest.split()
        if words and all(_ENV_ASSIGN.match(w) for w in words):
            continue
        # 'NAME=value command ...' prefix form
        while True:
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(\S+)\s+", rest)
            if not m:
                break
            rest = rest[m.end():]

        if not rest:
            continue
        background = rest.rstrip().endswith("&")
        if background:
            rest = rest.rstrip()[:-1].strip()
        if not rest:
            continue
        parts = rest.split()
        cmd = parts[0]
        args = parts[1:]
        commands.append(cmd)

        if cmd in SCRIPT_INTERNAL_COMMANDS:
            _check_internal(cmd, args, path, lineno, report)
        # foreground blocking check: a non-background, non-internal
        # command that is not the last real command blocks the script.
        if not background and cmd not in SCRIPT_INTERNAL_COMMANDS:
            if idx < n - 1 and any(
                    l.strip() and not l.strip().startswith("#")
                    for _, l in lines[idx + 1:]):
                report.warning(
                    "QNX405",
                    "Foreground command '%s' blocks the rest of the "
                    "startup script until it exits." % cmd,
                    path, lineno, 1,
                    hint="Add '&' to run it in the background, or move it "
                         "to the end of the script (a shell is usually "
                         "last).")
    return commands


def _check_modifier(token: str, path: str, lineno: int, report: Report):
    body = token
    if body.startswith("?"):
        body = body[1:]
    if body.startswith(("+", "-")):
        name = body[1:]
        if name not in SCRIPT_MODIFIERS_BOOL and name not in SCRIPT_MODIFIERS:
            report.error("QNX400", "Unknown script modifier '%s'." % token,
                         path, lineno, 1,
                         hint="Modifiers: argv0=, cpu=, +|-external, pri=, "
                              "sched_aps=, +|-session.")
        elif name in SCRIPT_MODIFIERS_VALUE:
            report.error("QNX400",
                         "Modifier '%s' needs a value: '[%s=<value>]'."
                         % (name, name), path, lineno, 1)
        return
    if "=" in body:
        name, value = body.split("=", 1)
        if name not in SCRIPT_MODIFIERS_VALUE:
            report.error("QNX400", "Unknown script modifier '%s'." % token,
                         path, lineno, 1,
                         hint="Modifiers: argv0=, cpu=, +|-external, pri=, "
                              "sched_aps=, +|-session.")
            return
        if name == "pri":
            _check_pri(value, path, lineno, report)
        elif name == "cpu":
            if value != "*" and not value.isdigit():
                report.error("QNX402",
                             "Invalid cpu= value '%s': a zero-based "
                             "processor number or '*'." % value,
                             path, lineno, 1)
        elif name == "sched_aps":
            if not value:
                report.error("QNX400", "sched_aps= needs a partition name.",
                             path, lineno, 1)
        return
    report.error("QNX400", "Unknown script modifier '%s'." % token,
                 path, lineno, 1,
                 hint="Modifiers: argv0=, cpu=, +|-external, pri=, "
                      "sched_aps=, +|-session.")


def _check_pri(value: str, path: str, lineno: int, report: Report):
    m = re.match(r"^(\d+)([fro])?$", value)
    if not m:
        report.error("QNX401",
                     "Invalid pri= value '%s'." % value, path, lineno, 1,
                     hint="pri= takes a priority 1-255 with an optional "
                          "policy letter f (FIFO), r (round-robin) or o "
                          "(other).")
        return
    pri = int(m.group(1))
    if not PRI_MIN <= pri <= PRI_MAX:
        report.error("QNX401",
                     "Priority %d is outside the QNX range %d-%d."
                     % (pri, PRI_MIN, PRI_MAX), path, lineno, 1)


def _check_internal(cmd: str, args: list, path: str, lineno: int,
                    report: Report):
    if cmd == "display_msg":
        if not args:
            report.error("QNX404", "display_msg needs a message.",
                         path, lineno, 1)
    elif cmd == "procmgr_symlink":
        if len(args) != 2:
            report.error("QNX404",
                         "procmgr_symlink needs exactly two paths: "
                         "procmgr_symlink <target> <link-name>.",
                         path, lineno, 1)
    elif cmd == "reopen":
        if len(args) > 1:
            report.error("QNX404",
                         "reopen takes at most one filename.",
                         path, lineno, 1)
    elif cmd == "waitfor":
        if not args or len(args) > 2:
            report.error("QNX404",
                         "waitfor needs a pathname and an optional wait "
                         "time: waitfor <pathname> [<seconds>].",
                         path, lineno, 1)
        elif len(args) == 2:
            if not _WAITFOR_TIME.match(args[1]):
                report.error("QNX408",
                             "waitfor wait time '%s' is not a number of "
                             "seconds with at most one decimal place."
                             % args[1], path, lineno, 1,
                             hint="The default wait is 5.0 seconds.")
