/**
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2025 3A Systems LLC.
 */

(function () {
    var TEST_REGEXP = /(spec|test)\.js$/i,
        allTestFiles = Object.keys(window.__karma__.files).filter(function (file) {
            return TEST_REGEXP.test(file);
        });

    require.config({
        baseUrl: "/base/target/compiled",

        map: {
            "*": {
                // TODO: Remove this when there are no longer any references to the "underscore" dependency
                "underscore": "lodash"
            }
        },
        paths: {
            // TASK 4.7. These seven used to be read straight out of target/dependencies/libs,
            // the maven-assembly output that the retired commons.ui.libs dependencySet blocks
            // filled. Task 4.8 removed that directory entirely. The libraries are staged
            // from npm and shipped into target/compiled/libs, which is already baseUrl above,
            // so they are addressed relatively - and for libs/ the harness now exercises the SAME
            // bytes the build ships rather than a second copy of them.
            //
            // SCOPE OF THAT CLAIM: libs/ only. It does NOT mean this harness runs against a Vite
            // target/compiled - it cannot, because 4.1 stopped emitting an org/ tree there and
            // baseUrl points at it. `npm run test:karma` is documented as running against a Grunt
            // tree, where these relative paths resolve. The harness has been dormant since 4.1
            // and group 9 (D12) replaces it with Vitest; 4.7 repointed it off the two retired
            // Maven-fed directories so it stays coherent, and verified every path here exists,
            // but no Karma run confirms it.
            "backbone": "libs/backbone-1.1.2-min",
            "chai": "/base/node_modules/chai/chai",
            "handlebars": "libs/handlebars-4.7.7",
            "i18next": "libs/i18next-1.7.3-min",
            "jquery": "libs/jquery-3.7.1-min",
            "lodash": "libs/lodash-3.10.1-min",
            "moment": "libs/moment-2.28.0-min",
            "redux": "libs/redux-3.5.2-min",
            "sinon-chai": "/base/node_modules/sinon-chai/lib/sinon-chai",
            // sinon and squire were the last two commons.ui.libs test artifacts, copied into
            // target/test-classes/libs by the copy-dependencies-test execution 4.7 removes.
            // sinon was already a devDependency, at 1.17.6 rather than the artifact's 1.15.4;
            // squirejs@0.2.0 is the same release as the artifact. The other two artifacts,
            // qunit js and css, are NOT replaced: nothing in this module references QUnit at
            // all - the frameworks here are mocha and requirejs - so they were dead weight.
            "sinon": "/base/node_modules/sinon/pkg/sinon",
            "squire": "/base/node_modules/squirejs/src/Squire"
        },
        shim: {
            "lodash": {
                exports: "_"
            }
        }
    });

    require(["chai", "sinon-chai"].concat(allTestFiles), function (chai, chaiSinon) {
        chai.use(chaiSinon);

        window.expect = chai.expect;
        window.__karma__.start();
    });
}());
