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
# Tear down the local OpenAM e2e instance. Both containers run with --rm, so stopping them
# destroys their state, which is what makes openam-up.sh reproducible.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_cmd docker

for container in "$AM_CONTAINER" "$DJ_CONTAINER"; do
    if docker inspect "$container" >/dev/null 2>&1; then
        log "stopping ${container}"
        docker stop "$container" >/dev/null
    fi
done

# Leaving the network behind would make a later `docker network create` noisy, but removing it
# while another compose project still uses it would not be ours to do -- so only remove it if
# nothing is attached.
if docker network inspect "$NETWORK" >/dev/null 2>&1; then
    attached="$(docker network inspect "$NETWORK" --format '{{len .Containers}}')"
    if [ "$attached" = "0" ]; then
        log "removing network ${NETWORK}"
        docker network rm "$NETWORK" >/dev/null
    else
        warn "network ${NETWORK} still has ${attached} container(s) attached; leaving it"
    fi
fi

log "down"
