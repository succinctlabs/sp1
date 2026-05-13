#!/usr/bin/env python3
"""Re-bucket GitHub's auto-generated release notes by Conventional Commit prefix.

Reads the body of a release (produced by `gh release create --generate-notes`)
from stdin and writes a categorized version to stdout. Each "* <title> by @user
in <url>" line is sorted into a section based on the leading conventional commit
prefix in the PR title (e.g. `feat:`, `fix(sdk):`, `perf!:`). The "New
Contributors" and "Full Changelog" footers, if present, are preserved verbatim.
"""

from __future__ import annotations

import re
import sys
from collections import OrderedDict

# Ordered map of section title -> list of conventional commit types that land in it.
SECTIONS: "OrderedDict[str, list[str]]" = OrderedDict(
    [
        ("Breaking Changes", []),  # populated dynamically from `!` marker
        ("New Features", ["feat"]),
        ("Bug Fixes", ["fix"]),
        ("Performance", ["perf"]),
        ("Refactoring", ["refactor", "refac"]),
        ("Documentation", ["docs"]),
        ("CI & Build", ["ci", "build"]),
        ("Chores", ["chore", "test", "style"]),
    ]
)
OTHER_SECTION = "Other Changes"

# Matches "* <title> by @<author> in <url>" — GitHub's standard line format.
ENTRY_RE = re.compile(r"^\*\s+(?P<title>.*?)\s+by\s+@[\w\-\[\]]+\s+in\s+https?://\S+\s*$")

# Conventional commit prefix at the start of a PR title:
#   type(optional-scope)!?: rest
PREFIX_RE = re.compile(r"^(?P<type>[a-zA-Z]+)(?:\([^)]*\))?(?P<bang>!?):\s*(?P<rest>.*)$")


def bucket_for(title: str) -> tuple[str, str]:
    """Return (section, rendered_line_body) for a PR title."""
    m = PREFIX_RE.match(title)
    if not m:
        return OTHER_SECTION, title

    ctype = m.group("type").lower()
    breaking = m.group("bang") == "!"
    # Strip the leading "type:" / "type(scope):" so the section header isn't redundant,
    # but promote a parenthesised scope into a bold "**scope**: " prefix.
    rest_with_scope = re.sub(
        rf"^{re.escape(m.group('type'))}(\(([^)]*)\))?!?:\s*",
        lambda mm: f"**{mm.group(2)}**: " if mm.group(2) else "",
        title,
        count=1,
    )

    if breaking:
        return "Breaking Changes", rest_with_scope

    for section, types in SECTIONS.items():
        if ctype in types:
            return section, rest_with_scope

    return OTHER_SECTION, title


def main() -> int:
    body = sys.stdin.read()
    lines = body.splitlines()

    buckets: "OrderedDict[str, list[str]]" = OrderedDict()
    for section in SECTIONS:
        buckets[section] = []
    buckets[OTHER_SECTION] = []

    footer_lines: list[str] = []
    in_footer = False

    for line in lines:
        stripped = line.strip()
        # Recognise the start of footer sections produced by GitHub.
        if stripped.startswith("## New Contributors") or stripped.startswith("**Full Changelog**"):
            in_footer = True
        if in_footer:
            footer_lines.append(line)
            continue

        # Skip the auto-generated "## What's Changed" header — we render our own.
        if stripped.startswith("## What's Changed"):
            continue

        m = ENTRY_RE.match(line)
        if not m:
            continue

        title = m.group("title").strip()
        section, rendered_title = bucket_for(title)
        # Reconstruct the line, keeping the "by @user in <url>" suffix intact.
        suffix = line[line.find(title) + len(title):]
        buckets[section].append(f"* {rendered_title}{suffix}")

    out: list[str] = ["## What's Changed", ""]
    any_section = False
    for section, entries in buckets.items():
        if not entries:
            continue
        any_section = True
        out.append(f"### {section}")
        out.extend(entries)
        out.append("")

    if not any_section:
        # Nothing parsed — fall back to the original body so we never ship an empty release.
        sys.stdout.write(body)
        return 0

    if footer_lines:
        # Strip leading blank lines between body and footer, but keep one separator.
        while footer_lines and not footer_lines[0].strip():
            footer_lines.pop(0)
        out.extend(footer_lines)

    sys.stdout.write("\n".join(out).rstrip() + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
