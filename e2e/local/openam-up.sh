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
# Bring up a configured OpenAM instance, serving the XUI built by THIS working tree, for the
# Playwright suite to target. See README.md.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd docker
require_cmd curl
require_hosts_entry

VERSION="$(am_version)"
[ -n "$VERSION" ] || die "could not resolve the project version from ${REPO_ROOT}/pom.xml"
log "project version: ${VERSION}"

WAR="${REPO_ROOT}/openam-server/target/OpenAM-${VERSION}.war"
ADMIN_TOOLS="${REPO_ROOT}/openam-distribution/openam-distribution-ssoadmintools/target/SSOAdminTools-${VERSION}.zip"
CONFIG_TOOLS="${REPO_ROOT}/openam-distribution/openam-distribution-ssoconfiguratortools/target/SSOConfiguratorTools-${VERSION}.zip"

for artifact in "$WAR" "$ADMIN_TOOLS" "$CONFIG_TOOLS"; do
    [ -f "$artifact" ] || die "missing build artifact: ${artifact}

Build it first:
    cd ${REPO_ROOT} && mvn -DskipTests install
"
done

if docker inspect "$AM_CONTAINER" >/dev/null 2>&1; then
    die "${AM_CONTAINER} already exists. Run ./openam-down.sh first, or ./openam-reset.sh to recreate."
fi

# ── Stage a build context ───────────────────────────────────────────────────────────────────
# The distribution Dockerfile ships its COPY lines commented out and CI un-comments them; we do
# the same rather than maintaining a second Dockerfile that could drift from the one that
# actually ships. Its COPY sources are globs, so the context holds exactly one match each --
# target/ normally contains several versions and a glob matching two files fails the build.
# Hard links keep the ~300MB war from being copied.
log "staging Docker build context in ${BUILD_CONTEXT}"
rm -rf "$BUILD_CONTEXT"
mkdir -p "${BUILD_CONTEXT}/openam-server/target" \
         "${BUILD_CONTEXT}/openam-distribution/openam-distribution-ssoadmintools/target" \
         "${BUILD_CONTEXT}/openam-distribution/openam-distribution-ssoconfiguratortools/target"

ln -f "$WAR"          "${BUILD_CONTEXT}/openam-server/target/$(basename "$WAR")" 2>/dev/null \
    || cp "$WAR"      "${BUILD_CONTEXT}/openam-server/target/$(basename "$WAR")"
ln -f "$ADMIN_TOOLS"  "${BUILD_CONTEXT}/openam-distribution/openam-distribution-ssoadmintools/target/$(basename "$ADMIN_TOOLS")" 2>/dev/null \
    || cp "$ADMIN_TOOLS" "${BUILD_CONTEXT}/openam-distribution/openam-distribution-ssoadmintools/target/$(basename "$ADMIN_TOOLS")"
ln -f "$CONFIG_TOOLS" "${BUILD_CONTEXT}/openam-distribution/openam-distribution-ssoconfiguratortools/target/$(basename "$CONFIG_TOOLS")" 2>/dev/null \
    || cp "$CONFIG_TOOLS" "${BUILD_CONTEXT}/openam-distribution/openam-distribution-ssoconfiguratortools/target/$(basename "$CONFIG_TOOLS")"

sed -E '/^#COPY openam-(server|distribution)\//s/^#//' \
    "${REPO_ROOT}/openam-distribution/openam-distribution-docker/Dockerfile" \
    > "${BUILD_CONTEXT}/Dockerfile"

grep -q '^COPY openam-server/' "${BUILD_CONTEXT}/Dockerfile" \
    || die "the COPY lines in openam-distribution-docker/Dockerfile no longer match the pattern this script un-comments"

# VERSION is passed so the image build does not reach out to the GitHub releases API to discover
# a version it will not use -- every artifact it needs is already in the context.
log "building ${IMAGE} (this takes a few minutes on a cold cache)"
docker build --build-arg "VERSION=${VERSION}" -t "$IMAGE" "$BUILD_CONTEXT"

# ── Start the containers ────────────────────────────────────────────────────────────────────
docker network inspect "$NETWORK" >/dev/null 2>&1 || docker network create "$NETWORK"

log "starting ${DJ_CONTAINER} (external identity store)"
docker run --rm -d --hostname "$DJ_CONTAINER" --name "$DJ_CONTAINER" --network "$NETWORK" "$DJ_IMAGE" >/dev/null

log "starting ${AM_CONTAINER}"
docker run --rm -d -p "${AM_PORT}:8080" --memory=2g \
    -h "$AM_HOST" --name "$AM_CONTAINER" --network "$NETWORK" "$IMAGE" >/dev/null

wait_healthy "$DJ_CONTAINER"
wait_healthy "$AM_CONTAINER"

# ── Configure ───────────────────────────────────────────────────────────────────────────────
log "running the configurator"
docker exec -w /usr/openam/ssoconfiguratortools "$AM_CONTAINER" bash -c \
'echo "ACCEPT_LICENSES=true
SERVER_URL=http://'"${AM_HOST}"':8080
DEPLOYMENT_URI=/$OPENAM_PATH
BASE_DIR=$OPENAM_DATA_DIR
locale=en_US
PLATFORM_LOCALE=en_US
AM_ENC_KEY=
ADMIN_PWD='"${ADMIN_PASS}"'
AMLDAPUSERPASSWD=password
COOKIE_DOMAIN=example.org
DATA_STORE=embedded
DIRECTORY_SSL=SIMPLE
DIRECTORY_SERVER=localhost
DIRECTORY_PORT=1389
DIRECTORY_ADMIN_PORT=5444
DIRECTORY_JMX_PORT=1689
ROOT_SUFFIX=dc=openam,dc=openidentityplatform,dc=org
DS_DIRMGRDN=cn=Directory Manager
DS_DIRMGRPASSWD=password
USERSTORE_TYPE=LDAPv3ForOpenDS
USERSTORE_SSL=SIMPLE
USERSTORE_HOST='"${DJ_CONTAINER}"'
USERSTORE_PORT=1389
USERSTORE_SUFFIX=dc=example,dc=com
USERSTORE_MGRDN=cn=Directory Manager
USERSTORE_PASSWD=password
" > conf.file && java -jar openam-configurator-tool*.jar --file conf.file'

log "installing ssoadm tools"
docker exec -w /usr/openam/ssoadmintools "$AM_CONTAINER" bash -c './setup -p /usr/openam/config --acceptLicense'
docker exec -w /usr/openam/ssoadmintools/openam/bin "$AM_CONTAINER" bash -c \
    "echo ${ADMIN_PASS} > pwd.txt && chmod 400 pwd.txt"

# ── Seed the baseline the suite expects ─────────────────────────────────────────────────────
log "creating the ${DEMO_USER} user"
TOKEN="$(admin_token)"
[ -n "$TOKEN" ] || die "could not authenticate as ${ADMIN_USER} after configuration"

curl -sS -f -X POST \
    -H "iPlanetDirectoryPro: ${TOKEN}" \
    -H "Content-Type: application/json" \
    -H "Accept-API-Version: resource=3.0, protocol=2.1" \
    -d "{
      \"username\": \"${DEMO_USER}\",
      \"userpassword\": \"${DEMO_PASS}\",
      \"mail\": \"${DEMO_USER}@example.com\",
      \"sn\": \"Demo\",
      \"givenName\": \"Demo\",
      \"cn\": \"Demo Demo\"
    }" \
    "${AM_BASE}/json/realms/root/users?_action=create" >/dev/null

log "verifying ${DEMO_USER} can authenticate"
curl -sf -X POST \
    -H "Content-Type: application/json" \
    -H "X-OpenAM-Username: ${DEMO_USER}" \
    -H "X-OpenAM-Password: ${DEMO_PASS}" \
    -H "Accept-API-Version: resource=2.0, protocol=1.0" \
    --data "{}" "${AM_BASE}/json/authenticate" >/dev/null \
    || die "${DEMO_USER} could not authenticate"

cat <<EOF

$(log "ready")

  XUI            ${AM_BASE}/XUI/
  admin          ${ADMIN_USER} / ${ADMIN_PASS}
  end user       ${DEMO_USER} / ${DEMO_PASS}

  run the suite  cd ${REPO_ROOT}/e2e && npm run test:xui
  reset          ./openam-reset.sh
  tear down      ./openam-down.sh

EOF
