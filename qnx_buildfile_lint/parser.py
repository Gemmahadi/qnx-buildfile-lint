"""Buildfile lexer/parser for QNX mkifs buildfiles.

Grammar (QNX SDP 8.0 mkifs Utilities Reference, "Buildfiles")::

    logical_line := [attributes] file_specification
    attributes   := '[' attr_token ... ']'        # one block per line
    attr_token   := ['?'] ('+'|'-') name | ['?'] name '=' value
    file_spec    := path | target '=' host | target '=' '{' inline '}'
    inline       := lines ... '}'                  # braces/backslashes escaped

Comments start at '#' preceded by a space (or at line start); inside an
inline file '#' is literal. Outside inline files a backslash at end of
line continues the logical line; inside an inline file it is an escape
and does NOT continue the line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .diagnostics import Report
from .qnxdata import ALL_ATTRIBUTES, BOOLEAN_ATTRIBUTES, VALUE_ATTRIBUTES


@dataclass
class Attr:
    name: str
    kind: str            # "bool" | "value" | "bare" (no +/- and no =)
    sign: str = ""       # "+" | "-" for booleans
    value: str = ""      # value for value attributes (unquoted)
    conditional: bool = False
    line: int = 0
    col: int = 0
    end_col: int = 0
    raw: str = ""


@dataclass
class InlineFile:
    """Content lines of an inline file, with their physical line numbers."""
    lines: list = field(default_factory=list)  # [(lineno, text)]
    open_line: int = 0
    close_line: int = 0


@dataclass
class Entry:
    target: str = ""
    host: str = ""            # "" when the entry is a bare path (== target)
    inline: InlineFile | None = None
    attrs: list = field(default_factory=list)   # Attr, this line only
    sticky: bool = False      # True for attribute-only (global) lines
    line: int = 0
    col: int = 0
    raw: str = ""

    @property
    def is_bare_path(self) -> bool:
        return not self.host and self.inline is None

    @property
    def attr_map(self) -> dict:
        return {a.name: a for a in self.attrs}

    def has_attr(self, name: str) -> bool:
        return any(a.name == name for a in self.attrs)


@dataclass
class ParsedBuildfile:
    entries: list = field(default_factory=list)
    report: Report = field(default_factory=Report)
    path: str = "<stdin>"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_comment(text: str):
    """Return (code_part, comment_start_index or None).

    '#' starts a comment only at the start of the line or after a space,
    and never inside double quotes.
    """
    in_quote = False
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '"' and (i == 0 or text[i - 1] != "\\"):
            in_quote = not in_quote
        elif ch == "#" and not in_quote:
            if i == 0 or text[i - 1] in " \t":
                return text[:i], i
            return text, ("attached", i)
        i += 1
    return text, None


def _split_tokens(text: str):
    """Split on whitespace, honouring double quotes and \\ escapes
    anywhere in a token.

    Returns (tokens, error) where error is ('unterminated-quote', pos) or
    None. Each token is (value, start_col, end_col, was_quoted, raw_text).
    """
    tokens = []
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] in " \t":
            i += 1
        if i >= n:
            break
        start = i
        buf: list[str] = []
        quoted_any = False
        while i < n:
            ch = text[i]
            if ch in " \t":
                break
            if ch == "\\" and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                quoted_any = True
                i += 1
                closed = False
                while i < n:
                    ch2 = text[i]
                    if ch2 == "\\" and i + 1 < n:
                        buf.append(text[i + 1])
                        i += 2
                    elif ch2 == '"':
                        closed = True
                        i += 1
                        break
                    else:
                        buf.append(ch2)
                        i += 1
                if not closed:
                    return tokens, ("unterminated-quote", start)
                continue
            buf.append(ch)
            i += 1
        tokens.append(("".join(buf), start, i, quoted_any,
                       text[start:i]))
    return tokens, None


def _split_first_equals(text: str):
    """Split on the first '=' outside double quotes. Returns (left, right)
    or (text, None) when there is no such '='."""
    in_quote = False
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '"' and (i == 0 or text[i - 1] != "\\"):
            in_quote = not in_quote
        elif ch == "=" and not in_quote:
            return text[:i].strip(), text[i + 1:].strip()
        i += 1
    return text.strip(), None


def _find_attr_close(text: str, start: int):
    """Find the matching ']' for the '[' at *start*, honouring \\] and
    quotes. Returns the index of ']' or None."""
    in_quote = False
    i = start + 1
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            i += 2
            continue
        if ch == '"' and (i == 0 or text[i - 1] != "\\"):
            in_quote = not in_quote
        elif ch == "]" and not in_quote:
            return i
        i += 1
    return None


# ---------------------------------------------------------------------------
# Attribute token parsing
# ---------------------------------------------------------------------------

def _parse_attr_token(raw: str, line_no: int, col: int, path: str,
                      report: Report) -> Attr | None:
    conditional = False
    body = raw
    if body.startswith("?"):
        conditional = True
        body = body[1:]
    if not body:
        report.error("QNX200", "Empty attribute token.", path, line_no, col,
                     hint="Remove the stray '?' or fill in the attribute.")
        return None
    if body[0] in "+-":
        sign, name = body[0], body[1:]
        if not name:
            report.error("QNX200", "Missing attribute name after '%s'." % sign,
                         path, line_no, col)
            return None
        if "=" in name:
            report.error("QNX201",
                         "Boolean attribute '+%s' used with a value." % name.split("=")[0],
                         path, line_no, col,
                         hint="Write '[+%s]' instead." % name.split("=")[0])
            return Attr(name.split("=")[0], "bool", sign, "",
                        conditional, line_no, col, col + len(raw), raw)
        if name not in ALL_ATTRIBUTES:
            report.error("QNX200", "Unknown attribute '+%s'." % name,
                         path, line_no, col,
                         hint="See the QNX 8.0 mkifs attribute list.")
            return Attr(name, "bool", sign, "", conditional, line_no, col,
                        col + len(raw), raw)
        if name in VALUE_ATTRIBUTES and name not in BOOLEAN_ATTRIBUTES:
            report.error("QNX202",
                         "Value attribute '%s' used as a boolean." % name,
                         path, line_no, col,
                         hint="Write '[%s=<value>]' instead." % name)
        return Attr(name, "bool", sign, "", conditional, line_no, col,
                    col + len(raw), raw)
    if "=" in body:
        name, value = body.split("=", 1)
        if not name:
            report.error("QNX104", "Attribute value without a name.",
                         path, line_no, col)
            return None
        # a quoted value: strip the quotes (e.g. prefix="" or
        # virtual="aarch64le,srec -b")
        if len(value) >= 2 and value.startswith('"') \
                and value.endswith('"'):
            value = value[1:-1]
        if name not in ALL_ATTRIBUTES:
            report.error("QNX200", "Unknown attribute '%s'." % name,
                         path, line_no, col,
                         hint="See the QNX 8.0 mkifs attribute list.")
            return Attr(name, "value", "", value, conditional, line_no, col,
                        col + len(raw), raw)
        if name in BOOLEAN_ATTRIBUTES and name not in VALUE_ATTRIBUTES:
            report.error("QNX201",
                         "Boolean attribute '%s' used with a value." % name,
                         path, line_no, col,
                         hint="Write '[+%s]' or '[-%s]' instead." % (name, name))
        return Attr(name, "value", "", value, conditional, line_no, col,
                    col + len(raw), raw)
    # bare name: neither +/- nor =
    name = body
    if name not in ALL_ATTRIBUTES:
        report.error("QNX200", "Unknown attribute '%s'." % name,
                     path, line_no, col,
                     hint="See the QNX 8.0 mkifs attribute list.")
    elif name in VALUE_ATTRIBUTES:
        report.error("QNX202",
                     "Value attribute '%s' used as a boolean." % name,
                     path, line_no, col,
                     hint="Write '[%s=<value>]' instead." % name)
    else:
        report.error("QNX201",
                     "Boolean attribute '%s' needs '+' or '-'." % name,
                     path, line_no, col,
                     hint="Write '[+%s]' or '[-%s]'." % (name, name))
    return Attr(name, "bare", "", "", conditional, line_no, col,
                col + len(raw), raw)


def _parse_attr_block(block: str, line_no: int, base_col: int, path: str,
                      report: Report) -> list:
    """Parse the inside of '[ ... ]' into Attr objects."""
    attrs = []
    tokens, err = _split_tokens(block)
    if err:
        report.error("QNX105", "Unterminated quoted string in attribute list.",
                     path, line_no, base_col)
        return attrs
    # Detect 'name = value' with spaces around '=': the '=' becomes its
    # own token (or a token ending/starting with it).
    skip_next = False
    for idx, (tok, start, end, quoted, raw) in enumerate(tokens):
        col = base_col + start
        if skip_next:
            skip_next = False
            continue
        if raw == "=":
            report.error("QNX104",
                         "Spaces around '=' in an attribute ('%s = ...')."
                         % (tokens[idx - 1][0] if idx else "?"),
                         path, line_no, col,
                         hint="Write '[name=value]' with no spaces around '='.")
            skip_next = True  # the following token is the detached value
            continue
        if raw.endswith("=") and raw != "=" and re.match(
                r"^\??[+-]?[A-Za-z_][A-Za-z0-9_]*=$", raw):
            # a bare 'name =' with the value detached by spaces
            report.error("QNX104",
                         "Spaces around '=' in attribute '%s'." % raw[:-1],
                         path, line_no, col,
                         hint="Write '[%s=value]' with no spaces around '='."
                         % raw[:-1])
            continue
        if tok.startswith("="):
            report.error("QNX104", "Attribute value without a name.",
                         path, line_no, col)
            continue
        attr = _parse_attr_token(tok, line_no, col, path, report)
        if attr is not None:
            attrs.append(attr)
    return attrs


def _ends_with_continuation(line: str) -> bool:
    """True when *line* ends with an odd number of backslashes: the last
    one escapes the newline and continues the logical line."""
    stripped = line.rstrip("\r")
    count = 0
    for ch in reversed(stripped):
        if ch == "\\":
            count += 1
        else:
            break
    return count % 2 == 1


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse(text: str, path: str = "<stdin>") -> ParsedBuildfile:
    report = Report()
    parsed = ParsedBuildfile(report=report, path=path)
    physical = text.splitlines()

    i = 0
    n = len(physical)
    while i < n:
        # --- build one logical line (backslash continuation, normal mode)
        start_line = i + 1
        parts = [physical[i]]
        while (_ends_with_continuation(parts[-1])
               and i + 1 < n):
            # backslash-newline continues the logical line
            parts[-1] = parts[-1].rstrip("\r")[:-1]
            i += 1
            parts.append(physical[i])
        logical = "".join(parts)
        logical_first_line = start_line

        # --- comment handling
        code, comment = _find_comment(logical)
        if isinstance(comment, tuple) and comment[0] == "attached":
            report.warning(
                "QNX109",
                "Comment '#' must be preceded by a space; '%s' is read as "
                "part of the preceding token." % logical[comment[1]:].split()[0][:20],
                path, logical_first_line, comment[1] + 1,
                hint="Put a space before '#'.")
        stripped = code.strip()
        if not stripped:
            i += 1
            continue

        # --- attribute block(s) at the start of the line
        attrs: list[Attr] = []
        rest = code
        rest_col = len(code) - len(code.lstrip())
        if code.lstrip().startswith("["):
            open_idx = code.index("[")
            close_idx = _find_attr_close(code, open_idx)
            if close_idx is None:
                report.error("QNX100", "Unterminated attribute block '['.",
                             path, logical_first_line, open_idx + 1,
                             hint="Close the list with ']' on the same line.")
                i += 1
                continue
            block = code[open_idx + 1:close_idx]
            if not block.strip():
                report.error("QNX102", "Empty attribute block '[]'.",
                             path, logical_first_line, open_idx + 1)
            attrs = _parse_attr_block(block, logical_first_line,
                                      open_idx + 2, path, report)
            rest = code[close_idx + 1:]
            rest_col = close_idx + 1
            # a second '[' before the file spec is the documented error
            stripped_rest = rest.lstrip()
            if stripped_rest.startswith("["):
                second = _find_attr_close(rest, rest.index("["))
                report.error(
                    "QNX103",
                    "Two attribute blocks on one line; combine them into "
                    "one pair of brackets.",
                    path, logical_first_line, rest.index("[") + 1,
                    hint="Write '[uid=5 gid=5] filename', not "
                         "'[uid=5] [gid=5] filename'.")
                if second is not None:
                    rest = rest[second + 1:]
                    rest_col = close_idx + 1 + second + 1
        elif "]" in code:
            report.error("QNX101", "Stray ']' with no matching '['.",
                         path, logical_first_line, code.index("]") + 1)

        file_spec = rest.strip()
        file_col = rest_col + (len(rest) - len(rest.lstrip())) + 1
        if not file_spec:
            # attribute-only line: sticky (global) attributes
            if attrs:
                if any(a.name in ("virtual", "physical") for a in attrs):
                    report.error(
                        "QNX111",
                        "'virtual'/'physical' cannot stand alone; they "
                        "belong on the bootstrap file line.",
                        path, logical_first_line, 1,
                        hint="Write '[virtual=x86_64,bios] .bootstrap = { ... }'.")
                parsed.entries.append(Entry(attrs=attrs, sticky=True,
                                            line=logical_first_line,
                                            col=1, raw=logical))
            i += 1
            continue

        # --- file specification: target = host | target = { ... } | path
        target, host = _split_first_equals(file_spec)
        inline = None
        if host is not None and host.strip() == "{":
            # Inline files whose contents mkifs *parses* (.bootstrap and
            # +script files) accept backslash-newline continuation -- the
            # official mkifs examples use it in .bootstrap. For plain data
            # inline files the backslash becomes literal content.
            parsed_content = any(
                a.name in ("virtual", "physical") for a in attrs) or any(
                a.name == "script" and a.kind == "bool" and a.sign == "+"
                for a in attrs)
            # inline file: consume physical lines until a '}' line
            inline_lines: list = []
            open_line = logical_first_line
            j = i + 1
            closed = False
            close_line = 0
            while j < n:
                raw_line = physical[j]
                # backslash-newline inside an inline file is NOT a
                # continuation: it becomes part of the file.
                if _ends_with_continuation(raw_line) and not parsed_content:
                    report.warning(
                        "QNX108",
                        "Backslash at end of line inside an inline file "
                        "does not continue the line; it becomes part of "
                        "the file.",
                        path, j + 1, len(raw_line.rstrip("\r")),
                        hint="Restructure the content instead of "
                             "continuing the line.")
                stripped_j = raw_line.strip()
                if stripped_j.startswith("}") and not stripped_j.startswith("\\}"):
                    after = stripped_j[1:].strip()
                    if after and not after.startswith("#"):
                        report.error(
                            "QNX107",
                            "Content after the closing brace of an inline "
                            "file on the same line.",
                            path, j + 1, raw_line.index("}") + 2,
                            hint="Put '}' on a line of its own.")
                    close_line = j + 1
                    closed = True
                    j += 1
                    break
                inline_lines.append((j + 1, raw_line))
                j += 1
            if not closed:
                report.error("QNX106",
                             "Unterminated inline file opened at line %d."
                             % open_line,
                             path, open_line, 1,
                             hint="Close the inline file with '}' on its "
                                  "own line.")
                i = n
            else:
                i = j
            inline = InlineFile(lines=inline_lines, open_line=open_line,
                                close_line=close_line)
            host = ""
        elif host is not None and host.strip().startswith("{"):
            report.error("QNX107",
                         "Inline-file content cannot be on the same line "
                         "as the opening brace.",
                         path, logical_first_line, file_col,
                         hint="Write 'target = {' and put the contents on "
                              "the following lines.")
            host = host.strip()[1:].strip()
            i += 1
        else:
            i += 1

        # unquote target/host
        target_clean = _unquote(target, path, logical_first_line, report)
        host_clean = _unquote(host, path, logical_first_line, report) if host else ""

        # backslash in a host path (outside inline files)
        for label, value in (("target", target_clean), ("host", host_clean)):
            if "\\" in value:
                report.warning(
                    "QNX110",
                    "Backslash in %s path '%s'; use forward slashes."
                    % (label, value),
                    path, logical_first_line, file_col,
                    hint="mkifs recommends '/' even on Windows hosts.")

        parsed.entries.append(Entry(target=target_clean, host=host_clean,
                                    inline=inline, attrs=attrs,
                                    line=logical_first_line, col=file_col,
                                    raw=logical))
    return parsed


def _unquote(value: str, path: str, line_no: int, report: Report) -> str:
    value = value.strip()
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value.startswith('"'):
        report.error("QNX105", "Unterminated quoted string in '%s'." % value,
                     path, line_no, 1)
        return value.strip('"')
    return value
