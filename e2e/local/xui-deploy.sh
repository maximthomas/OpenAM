#!/usr/bin/env bash
#
# The contents of this file are subject to the terms of the Common Development and
# Distribution License (the License). You may not use this file except in compliance with the
# License.
#
# You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
# specific language governing permission and limitations under the License.
#
# When distributing Covered Software, include this CDDL Header Notice in each file and include
# the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
# Header, with the fields enclosed by brackets [] replaced by your own identifying
# information: "Portions copyright [year] [name of copyright owner]".
#
# Copyright 2026 3A Systems, LLC.
#
# Replace the deployed /XUI in the running container with a freshly built one, without
# rebuilding the war or restarting Tomcat.
#
# Two reasons this exists:
#   - the XUI is static content, so a redeploy is a file copy; going through `mvn install` and an
#     image rebuild to see a UI change costs minutes for no gain;
#   - the migration needs to point the same Playwright suite at a Grunt-built and then a
#     Vite-built /XUI and get identical results. That comparison is only cheap if swapping the
#     build output is cheap.
#
# Usage:
#   ./xui-deploy.sh                    # deploy openam-ui-ria/target/openam-ui-ria-<version>-www.zip
#   ./xui-deploy.sh path/to/www.zip    # deploy a specific zip
#   ./xui-deploy.sh path/to/dir        # deploy a directory (e.g. a Vite outDir)

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd docker

XUI_PATH="/usr/local/tomcat/webapps/${AM_PATH}/XUI"

docker inspect "$AM_CONTAINER" >/dev/null 2>&1 \
    || die "${AM_CONTAINER} is not running. Start it with ./openam-up.sh"

SOURCE="${1:-}"
if [ -z "$SOURCE" ]; then
    VERSION="$(am_version)"
    SOURCE="${REPO_ROOT}/openam-ui/openam-ui-ria/target/openam-ui-ria-${VERSION}-www.zip"
    [ -f "$SOURCE" ] || die "no built XUI at ${SOURCE}

Build it first:
    cd ${REPO_ROOT}/openam-ui/openam-ui-ria && mvn -DskipTests package
"
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

if [ -d "$SOURCE" ]; then
    log "deploying directory ${SOURCE}"
    cp -R "${SOURCE}/." "${STAGE}/"
elif [ -f "$SOURCE" ]; then
    require_cmd unzip
    log "deploying ${SOURCE}"
    unzip -q "$SOURCE" -d "$STAGE"
else
    die "not a file or directory: ${SOURCE}"
fi

# The zip unpacks with no top-level directory (see src/main/assembly/zip.xml -- baseDirectory is
# "/"), so its contents map straight onto /XUI. Guard against being handed something else.
[ -f "${STAGE}/index.html" ] \
    || die "${SOURCE} does not look like an XUI build -- no index.html at its root"

# Replace rather than merge: a stale file left behind by the previous build is exactly the kind
# of thing that makes a migration comparison lie.
# Each docker exec here runs as root (-u 0) rather than exec's default openam. See the chown
# below for why the tree can end up owned by a UID the container does not know: once it is,
# openam can neither unlink those files nor write into their directories, so `rm -rf` fails
# partway and `set -e` aborts leaving a half-deleted /XUI that Tomcat then serves as 404s.
log "replacing ${XUI_PATH}"
docker exec -u 0 "$AM_CONTAINER" rm -rf "$XUI_PATH"
docker exec -u 0 "$AM_CONTAINER" mkdir -p "$XUI_PATH"
docker cp "${STAGE}/." "${AM_CONTAINER}:${XUI_PATH}/"

# `docker cp` preserves the staging files' host ownership. On native Linux that is the invoking
# host UID verbatim (typically 1000), while the container runs as openam (1001) -- so the copied
# tree lands owned by nobody the container knows. Tomcat still serves it, which is why this went
# unnoticed, but specs that write into the deployed /XUI through `docker exec` (the theme and
# operator-module ones) fail with EACCES. Docker Desktop's VM maps UIDs on copy and hides this;
# native Linux does not. Tomcat's own war-expanded /XUI is openam-owned, so this restores what
# the tests were written against.
docker exec -u 0 "$AM_CONTAINER" chown -R openam:root "$XUI_PATH"

log "deployed. ${AM_BASE}/XUI/ now serves $(find "$STAGE" -type f | wc -l | tr -d ' ') files"
