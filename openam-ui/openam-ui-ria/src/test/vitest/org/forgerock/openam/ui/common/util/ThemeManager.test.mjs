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
 * Portions copyright 2026 3A Systems, LLC.
 */

/*
 * ES module port of src/test/js/org/forgerock/openam/ui/common/util/ThemeManagerTest.js -- same
 * tests, same names, same order. Task 9.2 (D12). The largest and most entangled of the ten:
 * six mocked ids, one of them jquery, one of them a bare `Router`, and 24 cases.
 *
 * ONE SUBSTITUTION MOVED TO A DIFFERENT SEAM, and it is the only thing here that is not a
 * transcription. The original's beforeEach did `sandbox.stub(require, "toUrl", url => baseUrl +
 * url)`, which is how every expected value in this file acquires its "toUrl:" prefix. That
 * cannot be reproduced: Vitest gives each SSR-transformed module its OWN Node CJS require
 * (vite-node mints it per module, `require: createRequire(href)`), so the require this file sees
 * and the require the subject sees are different objects and neither is globalThis.require --
 * measured, and it is why resolveAssetUrl.test.mjs has four cases left failing.
 *
 * The seam it stubbed, though, has moved anyway. ThemeManager no longer calls require.toUrl; it
 * calls resolveAssetUrl, which delegates to require.toUrl only when nothing has configured it.
 * So the substitution is applied one module further out, as a vi.mock of the resolveAssetUrl id
 * -- the same mechanism as the other five mocks in this file, rather than a global reach-around.
 * Every assertion, every expected `toUrl:`-prefixed value and every test name is unchanged. What
 * this file no longer does is exercise the real resolveAssetUrl; that module has its own test.
 *
 * `sandbox` GOES WITH IT. It existed in the original for that one stub and nothing else, so the
 * sinon sandbox and its afterEach restore have no remaining subject.
 *
 * jquery IS MOCKED AND THE REAL $.Deferred IS STILL NEEDED. ThemeManager reads exactly one thing
 * off the module default -- `$.Deferred()` -- while the test asserts on `$` as a spy for the
 * `$("link")` and `$("<link/>", {...})` calls. The original solved this with
 * `mock$.Deferred = _.bind($.Deferred, $)` against the real jQuery it had as a define dependency.
 * Here the mock covers the test file's own imports too, so the real one comes from
 * vi.importActual at the top. Everything else the subject touches -- .remove(), .appendTo() --
 * hangs off the spy's RETURN value, which is the spy itself, exactly as before.
 *
 * THE MOCK OBJECTS HAVE FILE LIFETIME, THEIR CONTENTS HAVE CASE LIFETIME (D3): vi.mock factories
 * are hoisted above every import and run once, so they forward to a vi.hoisted holder whose
 * contents beforeEach replaces. `mock$` is the awkward one -- it is a function, not an object, so
 * the factory publishes a small forwarder that calls whatever spy the holder currently carries,
 * and the assertions read the spy itself. `baseUrl` is declared twice for the same reason: the
 * factory needs a hoisted copy, and the body keeps its own so the 24 cases read as written.
 *
 * "returns a promise" TOOK MOCHA'S `done` AND NOW RETURNS ITS PROMISE. Vitest does not implement
 * the callback -- the case would have passed unconditionally, before its own assertion ran. This
 * is the same correction task 9.1 made to PromiseTest's four whenPassed cases; the assertion and
 * the name are untouched. It was the one `done` inside an `it` that the recon flagged as still
 * open in this file.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import _ from "lodash";
import sinon from "sinon";
import Constants from "org/forgerock/openam/ui/common/util/Constants";

/*
 * The real jQuery, fetched inside beforeEach rather than at the top of the file: a
 * top-level await is ES2022 and this module lints with ESLint 3.8.1, whose parser stops at
 * ES2018. It has to be vi.importActual, because the vi.mock above covers this file too.
 */
let $;

const mocks = vi.hoisted(() => ({
    baseUrl: "toUrl:",
    $: null,
    themeConfig: {},
    URIUtils: {},
    Configuration: {},
    EventManager: {},
    Router: {}
}));

vi.mock("jquery", () => ({
    "default": Object.assign((...args) => mocks.$(...args), {
        Deferred: (...args) => mocks.$.Deferred(...args)
    })
}));
vi.mock("config/ThemeConfiguration", () => ({ "default": mocks.themeConfig }));
vi.mock("org/forgerock/commons/ui/common/util/URIUtils", () => ({ "default": mocks.URIUtils }));
vi.mock("org/forgerock/commons/ui/common/main/Configuration", () => ({ "default": mocks.Configuration }));
vi.mock("org/forgerock/commons/ui/common/main/EventManager", () => ({ "default": mocks.EventManager }));
vi.mock("Router", () => ({ "default": mocks.Router }));
vi.mock("org/forgerock/openam/ui/common/util/resolveAssetUrl", () => ({
    "default": (url) => mocks.baseUrl + url
}));

const baseUrl = "toUrl:";
let ThemeManager;
let Configuration;
let EventManager;
let URIUtils;
let Router;
let mock$;
let themeConfig;
let urlParams;
describe("org/forgerock/openam/ui/common/util/ThemeManager", () => {
    beforeEach(async () => {
        $ = (await vi.importActual("jquery")).default;

        themeConfig = mocks.themeConfig;
        Configuration = mocks.Configuration;
        EventManager = mocks.EventManager;
        URIUtils = mocks.URIUtils;
        Router = mocks.Router;

        Object.keys(themeConfig).forEach((key) => delete themeConfig[key]);
        Object.keys(Configuration).forEach((key) => delete Configuration[key]);
        Object.keys(EventManager).forEach((key) => delete EventManager[key]);
        Object.keys(URIUtils).forEach((key) => delete URIUtils[key]);
        Object.keys(Router).forEach((key) => delete Router[key]);

        themeConfig.themes = {
            "default": {
                path: "",
                icon: "icon.png",
                stylesheets: ["a.css", "c.css"]
            },
            other: {
                name: "other",
                path: "",
                icon: "otherIcon.png",
                stylesheets: ["b.css"]
            }
        };
        themeConfig.mappings = [
            { theme: "other", realms: ["/b"] }
        ];

        urlParams = {};

        mock$ = sinon.spy(function () { return mock$; });
        mock$.remove = sinon.spy();
        mock$.appendTo = sinon.spy();
        mock$.Deferred = _.bind($.Deferred, $);

        mocks.$ = mock$;

        Configuration.globalData = {
            theme: undefined,
            realm: "/"
        };

        EventManager.sendEvent = sinon.stub();

        URIUtils.getCurrentCompositeQueryString = sinon.stub().returns("");
        URIUtils.parseQueryString = sinon.stub().returns(urlParams);

        Router.currentRoute = {};

        vi.resetModules();
        ThemeManager = (await import("org/forgerock/openam/ui/common/util/ThemeManager")).default;
    });

    describe("#getTheme", () => {
        it("sends EVENT_THEME_CHANGED event", () =>
            ThemeManager.getTheme().then(() => {
                expect(EventManager.sendEvent).to.be.calledOnce.calledWith(Constants.EVENT_THEME_CHANGED);
            })
        );
        it("throws if theme configuration does not contain a theme object", () => {
            delete themeConfig.themes;
            expect(() => {
                ThemeManager.getTheme();
            }).to.throw();
        });
        it("throws if theme configuration does specify a default theme", () => {
            delete themeConfig.themes.default;
            expect(() => {
                ThemeManager.getTheme();
            }).to.throw();
        });
        it("returns a promise", () => {
            var result = ThemeManager.getTheme();
            expect(result.then).to.not.be.undefined;
            return result;
        });
        it("places the selected theme onto the global data object", () =>
            ThemeManager.getTheme().then(() => {
                expect(Configuration.globalData.theme).to.deep.equal(themeConfig.themes.default);
            })
        );
        it("selects the correct theme based on the realm", () => {
            Configuration.globalData.realm = "/b";
            return ThemeManager.getTheme().then(() => {
                expect(Configuration.globalData.theme).to.deep.equal(themeConfig.themes.other);
            });
        });
        it("selects the correct theme based on the realm", () => {
            Configuration.globalData.realm = "/b";
            return ThemeManager.getTheme().then(() => {
                expect(Configuration.globalData.theme).to.deep.equal(themeConfig.themes.other);
            });
        });
        it("selects the default theme if no realms match", () => {
            Configuration.globalData.realm = "/c";
            return ThemeManager.getTheme().then(() => {
                expect(Configuration.globalData.theme).to.deep.equal(themeConfig.themes.default);
            });
        });
        it("allows mappings to specify regular expressions to match realms", () => {
            themeConfig.mappings[0].realms[0] = /^\/hello.*/;
            Configuration.globalData.realm = "/hello/world";
            return ThemeManager.getTheme().then(() => {
                expect(Configuration.globalData.theme).to.deep.equal(themeConfig.themes.other);
            });
        });
        it("selects the correct theme based on the authentication chain", () => {
            urlParams.service = "test";
            themeConfig.mappings.push({
                theme: "other",
                authenticationChains: ["test"]
            });
            return ThemeManager.getTheme().then(() => {
                expect(Configuration.globalData.theme).to.deep.equal(themeConfig.themes.other);
            });
        });
        it("selects the default theme if no authentication chains match", () => {
            urlParams.service = "tester";
            themeConfig.mappings.push({
                theme: "other",
                authenticationChains: ["test"]
            });
            return ThemeManager.getTheme().then(() => {
                expect(Configuration.globalData.theme).to.deep.equal(themeConfig.themes.default);
            });
        });
        it("allows mappings to specify regular expressions to match authentication chains", () => {
            urlParams.service = "tester";
            themeConfig.mappings.push({
                theme: "other",
                authenticationChains: [/test/]
            });
            return ThemeManager.getTheme().then(() => {
                expect(Configuration.globalData.theme).to.deep.equal(themeConfig.themes.other);
            });
        });
        it("matches realms and authentication chains if both are specified in a mapping", () => {
            Configuration.globalData.realm = "/a";
            urlParams.service = "test";
            // No match - wrong realm
            themeConfig.mappings.push({
                theme: "default",
                realms: ["/b"],
                authenticationChains: ["test"]
            });
            // No match - wrong authentication chain
            themeConfig.mappings.push({
                theme: "default",
                realms: ["/a"],
                authenticationChains: ["tester"]
            });
            // Match
            themeConfig.mappings.push({
                theme: "other",
                realms: ["/a"],
                authenticationChains: ["test"]
            });
            return ThemeManager.getTheme().then(() => {
                expect(Configuration.globalData.theme).to.deep.equal(themeConfig.themes.other);
            });
        });
        it("won't match a mapping that needs an authentication chain if none is present", () => {
            Configuration.globalData.realm = "/a";
            // No match - wants an authentication chain but none is present
            themeConfig.mappings.push({
                theme: "default",
                realms: ["/a"],
                authenticationChains: ["test"]
            });
            // Match
            themeConfig.mappings.push({
                theme: "other",
                realms: ["/a"]
            });
            return ThemeManager.getTheme().then(() => {
                expect(Configuration.globalData.theme).to.deep.equal(themeConfig.themes.other);
            });
        });
        it("matches a mapping that has an empty authentication chain if none is present", () => {
            themeConfig.mappings.push({
                theme: "other",
                authenticationChains: [""]
            });
            return ThemeManager.getTheme().then(() => {
                expect(Configuration.globalData.theme).to.deep.equal(themeConfig.themes.other);
            });
        });
        it("fills in any missing properties from selected theme with the default theme", () => {
            Configuration.globalData.realm = "/b";
            delete themeConfig.themes.other.stylesheets;
            return ThemeManager.getTheme().then(() => {
                expect(Configuration.globalData.theme.stylesheets)
                    .to.deep.equal(themeConfig.themes.default.stylesheets);
            });
        });
        it("doesn't try to merge arrays in the selected theme with the default theme", () => {
            Configuration.globalData.realm = "/b";
            return ThemeManager.getTheme().then(() => {
                expect(Configuration.globalData.theme.stylesheets)
                    .to.deep.equal(themeConfig.themes.other.stylesheets);
            });
        });
        it("updates src fields in the theme to be relative to the entry point", () => {
            themeConfig.themes.default.settings = {
                logo: {
                    src: "foo"
                },
                loginLogo: {
                    src: "bar"
                }
            };
            return ThemeManager.getTheme().then(() => {
                expect(Configuration.globalData.theme.settings).to.deep.equal({
                    logo: {
                        src: `${baseUrl}foo`
                    },
                    loginLogo: {
                        src: `${baseUrl}bar`
                    }
                });
            });
        });
        it("removes any existing CSS and favicons from the page", () =>
            ThemeManager.getTheme().then(() => {
                expect(mock$).to.be.calledWith("link");
                sinon.assert.calledOnce(mock$.remove);
            })
        );
        it("adds the favicon to the page", () =>
            ThemeManager.getTheme().then(() => {
                expect(mock$).to.be.calledWith("<link/>", {
                    rel: "icon",
                    type: "image/x-icon",
                    href: `${baseUrl}icon.png`
                });
                expect(mock$.appendTo).to.be.calledWith("head");
            })
        );
        it("adds the alternate favicon to the page", () =>
            ThemeManager.getTheme().then(() => {
                expect(mock$).to.be.calledWith("<link/>", {
                    rel: "shortcut icon",
                    type: "image/x-icon",
                    href: `${baseUrl}icon.png`
                });
                expect(mock$.appendTo).to.be.calledWith("head");
            })
        );
        it("adds any stylesheets to the page", () =>
            ThemeManager.getTheme().then(() => {
                expect(mock$).to.be.calledWith("<link/>", {
                    rel: "stylesheet",
                    type: "text/css",
                    href: `${baseUrl}a.css`
                });
                expect(mock$).to.be.calledWith("<link/>", {
                    rel: "stylesheet",
                    type: "text/css",
                    href: `${baseUrl}c.css`
                });
                expect(mock$.appendTo).to.be.calledWith("head");
            })
        );
        it("doesn't update the page if the theme hasn't changed since the last call", () =>
            ThemeManager.getTheme().then(() => {
                mock$.reset();
                return ThemeManager.getTheme();
            }).then(() => {
                expect(mock$).to.not.be.called;
            })
        );
        it("overrides the theme's stylesheets if the user is on an admin page", () => {
            Router.currentRoute.navGroup = "admin";
            return ThemeManager.getTheme().then(() => {
                expect(mock$).to.be.calledWith("<link/>", {
                    rel: "stylesheet",
                    type: "text/css",
                    href: baseUrl + Constants.DEFAULT_STYLESHEETS[0]
                });
                expect(mock$).to.be.calledWith("<link/>", {
                    rel: "stylesheet",
                    type: "text/css",
                    href: baseUrl + Constants.DEFAULT_STYLESHEETS[1]
                });
            });
        });
    });
});
