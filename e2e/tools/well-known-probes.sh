#!/bin/bash
#
# Copyright 2026 3A Systems LLC.
#
# The D2 oracle probes for /.well-known (phase 5d-2a, docs/migration/restlet/phase-5d-2.md#d2).
# Emits a markdown capture on stdout: status + headers + raw body bytes + md5 for every probe.
#
# Run it three times against the same deployment settings, and diff the results:
#   - pre-flip  (5d-2a-i step 2)  -> artefacts/well-known-probes-pre-flip.md   [criterion 5]
#   - dormant   (5d-2a-i step 6)  -> must be byte-identical to pre-flip        [criterion 7]
#   - post-flip (5d-2a-ii)        -> artefacts/well-known-probes-post-flip.md  [criterion 8]
# Only the Date: header may differ between runs.
#
# Usage: e2e/tools/well-known-probes.sh [base-url] [label]
#   e2e/tools/well-known-probes.sh http://openam.example.org:8080/openam pre-flip > out.md
#
set -u
BASE="${1:-http://openam.example.org:8080/openam}"
LABEL="${2:-pre-flip}"
ISSUER='http://openid.net/specs/connect/1.0/issuer'
RESOURCE='acct:demo@example.com'
TMP=$(mktemp -d)

probe() {  # probe <id> <name> <method> <path> [curl args...]
  local id="$1" name="$2" method="$3" path="$4"; shift 4
  local hdr="$TMP/$id.h" body="$TMP/$id.b"
  local url rc
  # HEAD needs -I: -X HEAD leaves curl expecting a body and it aborts mid-transfer (rc=18).
  if [ "$method" = HEAD ]; then
    url=$(curl -sS --max-time 25 -I -o "$hdr" -w '%{url_effective}' --get "$@" "$BASE$path" 2>"$TMP/$id.err")
    rc=$?; : >"$body"
  else
    url=$(curl -sS --max-time 25 -o "$body" -D "$hdr" -w '%{url_effective}' \
          -X "$method" --get "$@" "$BASE$path" 2>"$TMP/$id.err")
    rc=$?
  fi
  echo "### $id — $name"
  echo
  echo '```'
  echo "$method ${url#"$BASE"}"
  echo '```'
  if [ $rc -ne 0 ]; then
    echo
    echo "**curl failed (rc=$rc):** \`$(tr -d '\n' <"$TMP/$id.err")\`"
    echo
    return
  fi
  echo
  echo "**Status + headers**"
  echo
  echo '```http'
  tr -d '\r' <"$hdr"
  echo '```'
  echo
  local n md5
  n=$(wc -c <"$body" | tr -d ' ')
  md5=$(md5sum <"$body" | cut -d' ' -f1)
  echo "**Body** — $n bytes, md5 \`$md5\`"
  echo
  if [ "$n" = "0" ]; then
    echo '_(empty)_'
  else
    echo '```'
    cat "$body"; echo
    echo '```'
  fi
  echo
}

cat <<EOF
# \`/.well-known\` oracle capture — $LABEL

Driven against \`$BASE\`.

EOF

probe 01 "success: issuer lookup, explicit realm=/ (the e2e spec's row)" GET /.well-known/webfinger \
  --data-urlencode "resource=$RESOURCE" --data-urlencode "rel=$ISSUER" --data-urlencode 'realm=/'
probe 02 "success: issuer lookup, no realm parameter" GET /.well-known/webfinger \
  --data-urlencode "resource=$RESOURCE" --data-urlencode "rel=$ISSUER"
probe 03 "missing resource (rel only)" GET /.well-known/webfinger \
  --data-urlencode "rel=$ISSUER"
probe 04 "missing rel (resource only)" GET /.well-known/webfinger \
  --data-urlencode "resource=$RESOURCE"
probe 05 "wrong rel" GET /.well-known/webfinger \
  --data-urlencode "resource=$RESOURCE" --data-urlencode 'rel=http://example.com/not-the-issuer-rel'
probe 06 "unknown user" GET /.well-known/webfinger \
  --data-urlencode 'resource=acct:nobody@example.com' --data-urlencode "rel=$ISSUER"
probe 07 "no parameters at all" GET /.well-known/webfinger
probe 08 "bad realm via ?realm=" GET /.well-known/webfinger \
  --data-urlencode "resource=$RESOURCE" --data-urlencode "rel=$ISSUER" --data-urlencode 'realm=/bogus'
probe 09 "unrouted child" GET /.well-known/nonsense
probe 10 "bare /.well-known/" GET /.well-known/
probe 11 "realms/{realm} path spelling" GET /.well-known/realms/root/webfinger \
  --data-urlencode "resource=$RESOURCE" --data-urlencode "rel=$ISSUER"
probe 12 "legacy subrealm path spelling, unresolvable realm" GET /.well-known/bogusrealm/webfinger \
  --data-urlencode "resource=$RESOURCE" --data-urlencode "rel=$ISSUER"
probe 13 "HEAD on the success URL" HEAD /.well-known/webfinger \
  --data-urlencode "resource=$RESOURCE" --data-urlencode "rel=$ISSUER" --data-urlencode 'realm=/'
probe 14 "POST on the success URL" POST /.well-known/webfinger \
  --data-urlencode "resource=$RESOURCE" --data-urlencode "rel=$ISSUER" --data-urlencode 'realm=/'
probe 15 "R-5d2.4: does /.well-known serve openid-configuration at the context root?" \
  GET /.well-known/openid-configuration
probe 16 "control: the same document under /oauth2 (already CHF-served)" \
  GET /oauth2/.well-known/openid-configuration
probe 17 "/.well-known with no trailing slash" GET /.well-known
probe 18 "extra path element after webfinger" GET /.well-known/webfinger/extra \
  --data-urlencode "resource=$RESOURCE" --data-urlencode "rel=$ISSUER"
probe 19 "deep unrouted child" GET /.well-known/a/b/c

rm -rf "$TMP"
