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
 * Portions copyright 2026 3A Systems, LLC.
 */

/*
 * ============================================================================================
 * What src/test/js/test-main.js did for Karma, minus the globals.
 * ============================================================================================
 *
 * test-main.js did two things: `chai.use(sinonChai)` and `window.expect = chai.expect`. Only the
 * first survives. The second is deliberately not reproduced -- every ported file imports
 * `expect` from "vitest" explicitly, which is the house style commons/ui/commons/src/test/vitest
 * sets, and it is the reason a reader of one of these files can tell where its assertions come
 * from without knowing this file exists.
 *
 * WHY sinon-chai IS STILL HERE
 *
 * Vitest's own `expect` IS chai, so every plain-chai assertion in the ported suite -- `.to.eql`,
 * `.to.be.an.instanceOf`, `.and.be.empty`, `.to.contain.keys`, `.to.not.have.ownProperty`,
 * `.to.throw` -- works unchanged and needs nothing from this file. The suite's sinon assertions
 * do not. 46 of them across 5 files use sinon-chai's short forms (`.to.be.called`,
 * `.to.be.calledOnce`, `.to.be.calledWith(...)`, and the chained
 * `.to.be.calledOnce.calledWith(...)`), and those properties are registered by sinon-chai, not
 * by chai. Vitest's own toHaveBeenCalled* family is not a substitute: it looks for a `.mock`
 * property that sinon spies do not have.
 *
 * Dropping this file would therefore mean rewriting 46 assertions, which is the opposite of a
 * transcription. It fails loudly rather than silently if it is ever removed -- chai 4+ proxies
 * Assertion and throws on an unknown property -- so there is no green-but-vacuous hazard here.
 *
 * THE VERSION PAIRING IS UNENFORCED. sinon-chai 2.8.0 declares
 * `peerDependencies: { chai: ">=1.9.2 <4", sinon: ">=1.4.0 <2" }` and Vitest 2.1.9 bundles chai
 * 5, so it is in use two majors outside its declared range. It works; the plugin API did not
 * change. Upgrading is not a free fix: sinon-chai 4.x requires sinon >= 9, and this suite uses
 * sinon 1.x APIs that sinon 2 removed (`sinon.sandbox.create()`, three-argument
 * `sandbox.stub(obj, "m", fn)`, `sinon.test`). Keep sinon 1.17.6 and sinon-chai 2.8.0 together.
 */

import { chai } from "vitest";
import sinonChai from "sinon-chai";

chai.use(sinonChai);
