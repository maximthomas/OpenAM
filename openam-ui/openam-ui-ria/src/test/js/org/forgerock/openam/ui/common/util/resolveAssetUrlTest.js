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
 * Copyright 2026 3A Systems, LLC.
 */

define([
    "squire",
    "sinon"
], (Squire, sinon) => {
    describe("org/forgerock/openam/ui/common/util/resolveAssetUrl", () => {
        const stubbedBase = "toUrl:";
        let resolveAssetUrl;
        let sandbox;

        beforeEach((done) => {
            sandbox = sinon.sandbox.create();
            /*
             * A fresh injector per test, because the module holds `urlArgs` and `resolved` at
             * module scope. Squire gives each injector its own RequireJS context, so this is a
             * new instance rather than the one the previous test configured.
             */
            new Squire().require(
                ["org/forgerock/openam/ui/common/util/resolveAssetUrl"],
                (subject) => {
                    resolveAssetUrl = subject;
                    done();
                });
        });

        afterEach(() => {
            sandbox.restore();
        });

        describe("unconfigured", () => {
            it("delegates to require.toUrl, which is what applies urlArgs under RequireJS", () => {
                sandbox.stub(require, "toUrl", (url) => stubbedBase + url);

                expect(resolveAssetUrl("templates/common/LoginBaseTemplate.html"))
                    .to.equal(`${stubbedBase}templates/common/LoginBaseTemplate.html`);
            });

            it("throws when there is no require.toUrl to delegate to", () => {
                const original = require.toUrl;
                require.toUrl = undefined;

                try {
                    expect(() => resolveAssetUrl("templates/common/LoginBaseTemplate.html"))
                        .to.throw(/called before configure\(\)/);
                } finally {
                    require.toUrl = original;
                }
            });
        });

        describe("configured", () => {
            it("appends urlArgs after a ? when the url carries no query", () => {
                resolveAssetUrl.configure({ urlArgs: "v=14.8.4" });

                expect(resolveAssetUrl("templates/common/LoginBaseTemplate.html"))
                    .to.equal("templates/common/LoginBaseTemplate.html?v=14.8.4");
            });

            it("appends urlArgs after an & when the url already carries a query", () => {
                resolveAssetUrl.configure({ urlArgs: "v=14.8.4" });

                expect(resolveAssetUrl("templates/common/Foo.html?a=1"))
                    .to.equal("templates/common/Foo.html?a=1&v=14.8.4");
            });

            it("resolves without a cache-buster when urlArgs is empty", () => {
                resolveAssetUrl.configure({ urlArgs: "" });

                expect(resolveAssetUrl("css/structure.css")).to.equal("css/structure.css");
            });

            it("does not consult require.toUrl once configured", () => {
                const toUrl = sandbox.stub(require, "toUrl", (url) => stubbedBase + url);
                resolveAssetUrl.configure({ urlArgs: "v=14.8.4" });

                resolveAssetUrl("images/login-logo.png");

                expect(toUrl.called).to.be.false;
            });

            it("leaves a library's unexpanded placeholders untouched", () => {
                // i18next hands resGetPath through verbatim and substitutes __lng__/__ns__ itself,
                // so the string this receives is not yet a valid url and must not be parsed.
                resolveAssetUrl.configure({ urlArgs: "v=14.8.4" });

                expect(resolveAssetUrl("locales/__lng__/__ns__.json"))
                    .to.equal("locales/__lng__/__ns__.json?v=14.8.4");
            });

            it("appends to a theme-prefixed path, which is what compileTemplate passes", () => {
                resolveAssetUrl.configure({ urlArgs: "v=14.8.4" });

                expect(resolveAssetUrl("themes/acme/templates/common/FooterTemplate.html"))
                    .to.equal("themes/acme/templates/common/FooterTemplate.html?v=14.8.4");
            });
        });

        describe("configure", () => {
            it("rejects a missing options object", () => {
                expect(() => resolveAssetUrl.configure())
                    .to.throw(/requires \{ urlArgs: <string> \}/);
            });

            it("rejects a non-string urlArgs", () => {
                expect(() => resolveAssetUrl.configure({ urlArgs: 14 }))
                    .to.throw(/requires \{ urlArgs: <string> \}/);
            });

            it("throws when it lands after a url has already been resolved", () => {
                // The ordering hazard recorded in NOTES-resolve-asset-url.md section 4b: urls
                // already written into a <link href> cannot be recalled, so a late configure
                // would leave those without a cache-buster while every later url carried one.
                sandbox.stub(require, "toUrl", (url) => stubbedBase + url);
                resolveAssetUrl("themes/acme/favicon.ico");

                expect(() => resolveAssetUrl.configure({ urlArgs: "v=14.8.4" }))
                    .to.throw(/after the first URL was already resolved/);
            });
        });

        describe("reset", () => {
            it("restores the unconfigured state so a later configure is accepted", () => {
                sandbox.stub(require, "toUrl", (url) => stubbedBase + url);
                resolveAssetUrl("css/structure.css");

                resolveAssetUrl.reset();
                resolveAssetUrl.configure({ urlArgs: "v=14.8.4" });

                expect(resolveAssetUrl("css/structure.css")).to.equal("css/structure.css?v=14.8.4");
            });
        });
    });
});
