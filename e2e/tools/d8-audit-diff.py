#!/usr/bin/env python3
"""D8 step 4: render a capture as a stable, diffable field dump.

    ./d8-audit-diff.py artefacts/d8-audit-pre-flip.csv > /tmp/pre
    ./d8-audit-diff.py artefacts/d8-audit-post-flip.csv > /tmp/post
    diff -u /tmp/pre /tmp/post

Every field that varies run to run regardless of the flip -- ids, timestamps, ports, elapsed time, issued
token and resource-set ids -- is replaced by a placeholder, so a clean diff means "nothing changed but the
things that always change" and any remaining line is a real behavioural difference.

Deliberately NOT normalised, because a change in them is exactly what the smoke is looking for:
response.detail (bar embedded ids), response.status, response.statusCode, http.request.method/path/
queryParameters, eventName, component, realm.
"""

import csv
import re
import sys

# Volatile whole columns: the value carries no signal, only its presence/absence does.
VOLATILE = {
    "_id", "timestamp", "transactionId", "trackingIds", "client.ip", "client.port",
    "server.ip", "server.port", "response.elapsedTime",
}
# Columns worth diffing, in a fixed order so the dump is stable.
FIELDS = [
    "eventName", "component", "realm", "userId",
    "http.request.secure", "http.request.method", "http.request.path", "http.request.queryParameters",
    "request.detail", "response.status", "response.statusCode", "response.detail",
]
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[0-9a-f]*")


def scrub(value):
    """Replaces issued identifiers inside a JSON detail blob, keeping its shape and key order."""
    if not value:
        return value
    return UUID.sub("<id>", value)


def dump(path):
    with open(path) as handle:
        rows = list(csv.DictReader([l for l in handle if not l.startswith("#")], delimiter=";"))
    for n, row in enumerate(rows, 1):
        print(f"--- row {n} ---")
        for field in FIELDS:
            # userId is a token subject for client_credentials and a DN for a user session; both are stable,
            # but an issued id inside a detail blob is not.
            print(f"{field}={scrub(row.get(field) or '')}")
        for field in sorted(set(row) - set(FIELDS) - VOLATILE - {None}):
            value = row.get(field) or ""
            if value:
                print(f"{field}={scrub(value)}")
        print()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <capture.csv>")
    dump(sys.argv[1])
