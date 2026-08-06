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
# Reset the instance to its post-configuration baseline.
#
# This is the authoritative reset: it destroys both containers and rebuilds from scratch, so it
# cannot leave residue behind whatever a failed test did -- including changes written directly
# into the deployed /XUI by xui-deploy.sh. It costs a few minutes.
#
# The image layer is cached, so a reset only re-runs the configurator, not the image build. If
# the war changed, openam-up.sh rebuilds the image; that is the slow path and it is meant to be.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${HERE}/openam-down.sh"
"${HERE}/openam-up.sh"
