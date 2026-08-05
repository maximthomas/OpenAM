#!/usr/bin/env python3
"""Verify every internal markdown link in this directory resolves.

Broken markdown anchors fail silently — nothing renders an error, the link just
lands at the top of the file. Run this after editing headings or adding a doc.

    python3 docs/migration/restlet/check-links.py

Exits non-zero if anything is broken. Recognises both heading-derived anchors
(GitHub's rules, including the -1/-2 suffix on duplicates) and the explicit
<a id="..."> anchors these docs use for stable short ids like #d10.
"""
import os
import re
import sys
from collections import Counter

DIR = os.path.dirname(os.path.abspath(__file__))


def heading_anchor(text):
    text = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', text)   # [label](url) -> label
    text = text.replace('`', '')
    text = re.sub(r'<[^>]+>', '', text)
    return re.sub(r'[^\w\s-]', '', text.strip().lower()).replace(' ', '-')


_cache = {}


def anchors(path):
    if path not in _cache:
        with open(path, errors='replace') as fh:
            body = fh.read()
        found, seen = set(), Counter()
        for line in body.splitlines():
            m = re.match(r'^#{1,6}\s+(.*?)\s*$', line)
            if not m:
                continue
            base = heading_anchor(m.group(1))
            found.add(base if seen[base] == 0 else f'{base}-{seen[base]}')
            seen[base] += 1
        found |= set(re.findall(r'<a\s+(?:id|name)="([^"]*)"', body))
        _cache[path] = found
    return _cache[path]


def main():
    os.chdir(DIR)
    checked, broken = 0, []
    for name in sorted(f for f in os.listdir('.') if f.endswith('.md')):
        with open(name, errors='replace') as fh:
            body = fh.read()
        for m in re.finditer(r'\[([^\]]*)\]\(([^)]+)\)', body):
            target = m.group(2)
            if target.startswith(('http', 'mailto')):
                continue
            if not (target.endswith('.md') or '.md#' in target or target.startswith('#')):
                # Not a doc link. If it is not a real path either, it is almost
                # certainly an anchor that lost its '#' — which every other check
                # here would skip in silence. That is the failure mode this file
                # exists to prevent, so it is an error, not a skip.
                if not os.path.exists(target.partition('#')[0]):
                    checked += 1
                    broken.append((name, target, "not a file and not an anchor "
                                                 "— missing '#'?"))
                continue
            checked += 1
            path, _, frag = target.partition('#')
            path = path or name
            if not os.path.exists(path):
                broken.append((name, target, 'no such file'))
            elif frag and frag not in anchors(path):
                broken.append((name, target, 'no such anchor'))

    print(f'{checked} internal links checked — {len(broken)} broken')
    current = None
    for name, target, why in sorted(set(broken)):
        if name != current:
            print(f'\n{name}:')
            current = name
        print(f'   {target}   <- {why}')
    return 1 if broken else 0


if __name__ == '__main__':
    sys.exit(main())
