#!/usr/bin/env python3
"""Normalise the [5-E*] oracle lines of a Playwright transcript for diffing.

The (5-E*, live Restlet) describes log the actual bytes they measured, so a
transcript of one full-suite run is the pre-flip capture criterion 13 asks for
(docs/migration/restlet/phase-5d-1.md). Two raw transcripts do not diff: workers
interleave nondeterministically, and several lines embed per-run values.

    python3 e2e/tools/e2e-oracle-extract.py e2e-pre-flip.txt  > /tmp/pre
    python3 e2e/tools/e2e-oracle-extract.py e2e-post-flip.txt > /tmp/post
    diff -u /tmp/pre /tmp/post

Blanks only what varies regardless of the flip; everything a divergence row
rides on -- status, error code, error_description, headers, Content-Type,
Content-Length, Allow, cache headers -- is preserved verbatim.
"""
import re
import sys

UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\d*\b")
# ETags are hashCode()s of the stored description: signed, and long. Some rows
# log them inside a JSON-escaped label, so the quotes may be backslashed.
WEAK_ETAG = re.compile(r'W/(\\?)"-?\d+(\\?)"')
QUOTED_ETAG = re.compile(r'(\\?)"-?\d{6,}(\\?)"')
# Fixture names carry a random 8-char suffix; require a digit so words like
# "resource" are left alone.
SUFFIX = re.compile(r"\b(?=[a-z0-9]{8}\b)[a-z]*\d[a-z0-9]*\b")
# ...but the suffix is base-36, so roughly one name in 17 draws no digit at all and
# the rule above misses it, putting a PHANTOM row in the byte-diff -- measured
# 2026-08-05, when `cejdvhxu` made 5-E4 row 7 look like a flip divergence it was not.
# Dropping the digit guard outright would eat English words; inside a quoted fixture
# name the token is unambiguous, so anchor on the closing quote instead.
QUOTED_SUFFIX = re.compile(r"(?<= )[a-z0-9]{8}(?=')")
ID_COUNT = re.compile(r"\b\d+ ids\b")
TEARDOWN = re.compile(r"teardown: \d+/\d+ deleted; \d+ could not be removed")


def normalise(line):
    line = UUID.sub("<uuid>", line)
    line = WEAK_ETAG.sub(r'W/\1"<etag>\2"', line)
    line = QUOTED_ETAG.sub(r'\1"<etag>\2"', line)
    line = SUFFIX.sub("<sfx>", line)
    line = QUOTED_SUFFIX.sub("<sfx>", line)
    line = ID_COUNT.sub("<n> ids", line)
    line = TEARDOWN.sub("teardown: <n>/<n> deleted; <n> could not be removed", line)
    return line


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: e2e-oracle-extract.py <playwright-transcript>")
    with open(sys.argv[1], encoding="utf-8", errors="replace") as fh:
        rows = [normalise(ln.strip()) for ln in fh if ln.lstrip().startswith("[5-E")]
    if not rows:
        sys.exit("no [5-E*] lines found -- was this a full-suite run?")
    print(f"# {len(rows)} oracle rows")
    for row in sorted(rows):
        print(row)


if __name__ == "__main__":
    main()
