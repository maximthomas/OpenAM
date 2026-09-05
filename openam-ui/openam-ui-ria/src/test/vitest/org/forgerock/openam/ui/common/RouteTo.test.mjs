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
 * Portions copyright 2026 3A Systems, LLC.
 */

/*
 * ES module port of src/test/js/org/forgerock/openam/ui/common/RouteToTest.js -- same tests,
 * same names, same order. Task 9.2 (D12).
 *
 * THE REPRESENTATIVE SHAPE OF THIS TASK: four bare aliased AMD ids mocked at once, mock objects
 * built in a beforeEach, a fresh subject per case, and sinon-chai and plain chai side by side.
 * Seven of the ten Squire files are some subset of this.
 *
 * THE MOCK OBJECTS HAVE FILE LIFETIME, THEIR CONTENTS HAVE CASE LIFETIME, and that split is the
 * whole structural difference between Squire and vi.mock. vi.mock is hoisted above every import
 * and its factories run once per file, so a factory cannot close over an object beforeEach
 * rebuilds -- it would keep serving case 1's object for the rest of the file while the test's own
 * handles pointed at newer ones. Keeping one identity and replacing the contents is the shape
 * that works, and it is also what survives the vi.resetModules() below, which would otherwise
 * swap the mocks out from under the handles this file asserts on.
 *
 * THE SUBJECT IS PULLED IN WITH A DYNAMIC IMPORT, not a static one, because a static import
 * binds once and this file needs a new RouteTo per case: the #logout block spies on
 * RouteTo.setGoToUrlProperty, a method of the subject's own default export. The spy is restored
 * in afterEach, so a shared instance would probably survive -- but Squire gave a fresh module per
 * case and reproducing that costs one line here.
 *
 * `sinon.spy(RouteTo, "setGoToUrlProperty")` WORKS ONLY BECAUSE RouteTo.logout CALLS IT AS
 * `obj.setGoToUrlProperty()` rather than through the local binding. That is true of the source
 * today (checked); if it is ever changed to call the local function, this spy becomes silently
 * ineffective and "invokes #setGoToUrlProperty" starts passing for the wrong reason.
 *
 * Constants is imported for real, unmocked, exactly as the original had it.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import $ from "jquery";
import sinon from "sinon";
import Constants from "org/forgerock/openam/ui/common/util/Constants";

const context = describe;

const mocks = vi.hoisted(() => ({
    Configuration: {},
    EventManager: {},
    Router: {},
    SessionManager: {}
}));

vi.mock("org/forgerock/commons/ui/common/main/Configuration", () => ({ "default": mocks.Configuration }));
vi.mock("org/forgerock/commons/ui/common/main/EventManager", () => ({ "default": mocks.EventManager }));
vi.mock("org/forgerock/commons/ui/common/main/Router", () => ({ "default": mocks.Router }));
vi.mock("org/forgerock/commons/ui/common/main/SessionManager", () => ({ "default": mocks.SessionManager }));

let Configuration;
let EventManager;
let Router;
let RouteTo;
let SessionManager;
describe("org/forgerock/openam/ui/common/RouteTo", () => {
    beforeEach(async () => {
        Configuration = mocks.Configuration;
        EventManager = mocks.EventManager;
        Router = mocks.Router;
        SessionManager = mocks.SessionManager;

        Object.keys(Configuration).forEach((key) => delete Configuration[key]);
        Object.keys(EventManager).forEach((key) => delete EventManager[key]);
        Object.keys(Router).forEach((key) => delete Router[key]);
        Object.keys(SessionManager).forEach((key) => delete SessionManager[key]);

        Configuration.globalData = {
            authorizationFailurePending: true
        };
        Configuration.setProperty = sinon.stub();

        EventManager.sendEvent = sinon.stub();

        Router.configuration = {
            routes: {
                login: {
                    url: "loginUrl"
                }
            }
        };
        Router.getCurrentHash = sinon.stub().returns("page");

        SessionManager.logout = sinon.stub();

        vi.resetModules();
        RouteTo = (await import("org/forgerock/openam/ui/common/RouteTo")).default;
    });

    describe("#setGoToUrlProperty", () => {
        context("when a gotoURL is not set and the current hash does not match the login route's URL", () => {
            it("sets the gotoURL to be the current hash", () => {
                RouteTo.setGoToUrlProperty();

                expect(Configuration.setProperty).to.be.calledOnce.calledWith("gotoURL", "#page");
            });
        });
    });

    describe("#forbiddenPage", () => {
        it("deletes \"authorizationFailurePending\" attribute Configuration.globalData", () => {
            RouteTo.forbiddenPage();

            expect(Configuration.globalData).to.not.have.ownProperty("authorizationFailurePending");
        });
        it("sends EVENT_CHANGE_VIEW event", () => {
            RouteTo.forbiddenPage();

            expect(EventManager.sendEvent).to.be.calledOnce.calledWith(Constants.EVENT_CHANGE_VIEW, {
                route: {
                    view: "org/forgerock/openam/ui/common/views/error/ForbiddenView",
                    url: /.*/
                },
                fromRouter: true
            });
        });
    });

    describe("#forbiddenError", () => {
        it("sends EVENT_DISPLAY_MESSAGE_REQUEST event", () => {
            RouteTo.forbiddenError();

            expect(EventManager.sendEvent).to.be.calledOnce.calledWith(Constants.EVENT_DISPLAY_MESSAGE_REQUEST,
                "unauthorized");
        });
    });

    describe("#logout", () => {
        let promise;

        beforeEach(() => {
            promise = $.Deferred();
            SessionManager.logout = sinon.stub().returns(promise);
            sinon.spy(RouteTo, "setGoToUrlProperty");
        });

        afterEach(() => {
            RouteTo.setGoToUrlProperty.restore();
        });

        it("invokes #setGoToUrlProperty", () => {
            RouteTo.logout();

            expect(RouteTo.setGoToUrlProperty).to.be.calledOnce;
        });

        context("when logout is successful", () => {
            it("sends EVENT_AUTHENTICATION_DATA_CHANGED event", () => {
                const p = promise.resolve();

                return p.then(() => {
                    RouteTo.logout().then(() => {
                        expect(EventManager.sendEvent).to.be
                            .calledWith(Constants.EVENT_AUTHENTICATION_DATA_CHANGED, {
                                anonymousMode: true
                            });
                    });
                });
            });

            it("sends EVENT_CHANGE_VIEW event", () => {
                const p = promise.resolve();
                return p.then(() => {
                    return RouteTo.logout().then(() => {
                        expect(EventManager.sendEvent).to.be.calledWith(Constants.EVENT_CHANGE_VIEW, {
                            route: Router.configuration.routes.login
                        });
                    });
                });
            });
        });

        context("when logout is unsuccessful", () => {
            it("sends no events", () => {
                promise.fail();

                RouteTo.logout();

                expect(EventManager.sendEvent).to.not.be.called;
            });
        });
    });

    describe("#loginDialog", () => {
        it("sends EVENT_SHOW_LOGIN_DIALOG event", () => {
            RouteTo.loginDialog();

            expect(EventManager.sendEvent).to.be.calledOnce.calledWith(Constants.EVENT_SHOW_LOGIN_DIALOG);
        });
    });
});
