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

# Shared settings and helpers for the local OpenAM e2e instance.
#
# The values here deliberately mirror the "Docker test with an external OpenDJ identity store"
# job in .github/workflows/build.yml. When that job changes, change this file with it -- the
# whole point of the local harness is that a green run here predicts a green run there.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

NETWORK="test-openam"
AM_CONTAINER="openam-idp"
DJ_CONTAINER="opendj-idp"
DJ_IMAGE="openidentityplatform/opendj:latest"
IMAGE="openam-e2e:local"

AM_HOST="openam.example.org"
AM_PORT="8080"
AM_PATH="openam"
AM_BASE="http://${AM_HOST}:${AM_PORT}/${AM_PATH}"

ADMIN_USER="amadmin"
ADMIN_PASS="ampassword"
DEMO_USER="demo"
DEMO_PASS="changeit"

# Where the staged Docker build context is assembled. Under target/ so `mvn clean` removes it.
BUILD_CONTEXT="${REPO_ROOT}/target/e2e-docker-context"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m warn\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror\033[0m %s\n' "$*" >&2; exit 1; }

# Resolve the project version from the reactor root pom, so the harness follows a version bump
# without being edited. The root pom declares no <parent>, so its first <version> is the project's.
am_version() {
    sed -n 's/.*<version>\(.*\)<\/version>.*/\1/p' "${REPO_ROOT}/pom.xml" | head -1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# AM refuses to run on a bare hostname -- it needs an FQDN so it can set a cookie domain.
require_hosts_entry() {
    if ! grep -qE "^[^#]*[[:space:]]${AM_HOST}([[:space:]]|$)" /etc/hosts; then
        die "missing /etc/hosts entry. Run:

    echo '127.0.0.1 ${AM_HOST}' | sudo tee -a /etc/hosts
"
    fi
}

container_healthy() {
    [ "$(docker inspect --format '{{.State.Health.Status}}' "$1" 2>/dev/null || true)" = "healthy" ]
}

wait_healthy() {
    local name="$1" limit="${2:-300}" waited=0
    log "waiting for ${name} to report healthy (up to ${limit}s)"
    until container_healthy "$name"; do
        [ "$waited" -ge "$limit" ] && die "${name} did not become healthy within ${limit}s. Try: docker logs ${name}"
        sleep 5
        waited=$((waited + 5))
    done
}

admin_token() {
    curl -sf -X POST \
        -H "Content-Type: application/json" \
        -H "X-OpenAM-Username: ${ADMIN_USER}" \
        -H "X-OpenAM-Password: ${ADMIN_PASS}" \
        -H "Accept-API-Version: resource=2.0, protocol=1.0" \
        --data "{}" \
        "${AM_BASE}/json/authenticate" | sed -n 's/.*"tokenId":"\([^"]*\)".*/\1/p'
}
