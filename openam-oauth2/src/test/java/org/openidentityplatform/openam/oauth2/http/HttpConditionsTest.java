/*
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
 * Copyright 2026 3A Systems LLC.
 */
package org.openidentityplatform.openam.oauth2.http;

import static org.assertj.core.api.Assertions.assertThat;

import org.forgerock.http.protocol.Request;
import org.testng.annotations.Test;

/**
 * Unit coverage for the conditional-request helper.
 * <p>
 * Every row here is either measured against live Restlet (the {@code If-Match} parsing table in the
 * <a href="../../../../../../../../../docs/migration/restlet/phase-5c.md">5-E4 as-built</a>) or read off the
 * fork's own bytecode -- the parser ({@code TagReader} -&gt; {@code HeaderReader.readRawValue} -&gt;
 * {@code Tag.parse}) <em>and</em> the comparator ({@code Conditions.getStatus}), recorded in chf-patterns 21a
 * and 21b. The distinction matters: the oracle dies at 5d-1, so a row that merely looks reasonable is
 * worthless -- each one below traces to an observation or to bytecode.
 * <p>
 * ⚠ Reading only the parser is how the first cut of this class shipped two divergences that all 21 of its
 * rows passed: it matched {@code *} anywhere in an {@code If-Match} list rather than at position 0 only, and
 * it ignored weakness in {@code If-None-Match}, where Restlet compares it. Neither header form appears in the
 * measured table, so the oracle would not have caught either.
 */
public class HttpConditionsTest {

    /** The tag the endpoint would have computed; the exact wire form 5-E4 row 5 recorded. */
    private static final String CURRENT = "W/\"-1234567\"";

    /**
     * Restlet's {@code checkWeakness} argument to the {@code If-None-Match} comparison, which is literally
     * {@code GET.equals(method) || HEAD.equals(method)}. 5-E4 row 21 measured it varying: the strong form of
     * this endpoint's weak tag is a 200 on a {@code GET} and a 412 on a {@code PUT}.
     */
    private static final boolean ON_GET = true;
    private static final boolean ON_WRITE = false;

    private static HttpConditions ifMatch(String headerValue) {
        Request request = new Request();
        request.getHeaders().put("If-Match", headerValue);
        return HttpConditions.of(request);
    }

    private static HttpConditions ifNoneMatch(String headerValue) {
        Request request = new Request();
        request.getHeaders().put("If-None-Match", headerValue);
        return HttpConditions.of(request);
    }

    // ---------------------------------------------------------- If-Match: the measured parsing table

    @Test
    public void wildcardMatches() {
        assertThat(ifMatch("*").hasIfMatch()).isTrue();
        assertThat(ifMatch("*").matches(CURRENT)).isTrue();
    }

    @Test
    public void theVerbatimWeakTagMatches() {
        assertThat(ifMatch(CURRENT).matches(CURRENT)).isTrue();
    }

    @Test
    public void theStrongFormOfTheSameTagMatches() {
        // Tag.equals(o, checkWeakness=false): names only.
        assertThat(ifMatch("\"-1234567\"").matches(CURRENT)).isTrue();
    }

    @Test
    public void aCommaListMatchesWhicheverPositionTheTagIsIn() {
        assertThat(ifMatch("W/\"nope\", " + CURRENT).matches(CURRENT)).isTrue();
        assertThat(ifMatch(CURRENT + ", W/\"nope\"").matches(CURRENT)).isTrue();
        assertThat(ifMatch("W/\"nope\"," + CURRENT).matches(CURRENT)).isTrue();
    }

    @Test
    public void aCommaListOfNonMatchingTagsParsesAndLoses() {
        HttpConditions conditions = ifMatch("W/\"nope\", W/\"nope2\"");
        assertThat(conditions.hasIfMatch()).isTrue();     // parsed -> 412, not the missing-header 400
        assertThat(conditions.matches(CURRENT)).isFalse();
    }

    @Test
    public void aQuotedEmptyStringParsesAsATagAndLoses() {
        HttpConditions conditions = ifMatch("\"\"");
        assertThat(conditions.hasIfMatch()).isTrue();
        assertThat(conditions.matches(CURRENT)).isFalse();
    }

    // ---------------------------------------------------------- If-Match: the wildcard is positional

    /*
     * Restlet computes one flag, `all = getMatch().get(0).equals(Tag.ALL)`, and only then falls back to
     * comparing names. So the wildcard is a property of the first parsed element, not of the list -- and the
     * comparison that establishes it is the weakness-checked equals, while every other comparison in the
     * If-Match branch is not. A helper that answered "does the list contain `*`" would accept both headers
     * below, applying an update Restlet refuses with a 412: the lost-update hole this class exists to close.
     */

    @Test
    public void theWildcardCountsOnlyAsTheFirstElement() {
        HttpConditions conditions = ifMatch("W/\"nope\", *");

        assertThat(conditions.hasIfMatch()).isTrue();       // parsed -> 412, not the missing-header 400
        assertThat(conditions.matches(CURRENT)).isFalse();  // `*` here is just a tag named `*`
    }

    @Test
    public void aWeakWildcardIsNotTheWildcard() {
        // Tag.ALL is Tag.parse("*"), i.e. strong, and `all` is the one comparison that checks weakness.
        HttpConditions conditions = ifMatch("W/*");

        assertThat(conditions.hasIfMatch()).isTrue();
        assertThat(conditions.matches(CURRENT)).isFalse();
    }

    @Test
    public void theWildcardFirstCarriesTheWholeList() {
        assertThat(ifMatch("*, W/\"nope\"").matches(CURRENT)).isTrue();
    }

    @Test
    public void aQuotedWildcardIsTheSameWildcard() {
        // Not measured: Tag.parse tests the quoted form first, so `"*"` is a tag named `*` -- strong, at
        // position 0, and therefore Tag.ALL. The parser's one genuine conflation.
        assertThat(ifMatch("\"*\"").matches(CURRENT)).isTrue();
    }

    // ---------------------------------------------------------- If-Match: unparseable == absent

    @Test
    public void anUnquotedTagDoesNotParseAndSoReadsAsAbsent() {
        // The trap: "present but unmatched" would answer 412 where Restlet answers the missing-header 400.
        assertThat(ifMatch("-1234567").hasIfMatch()).isFalse();
    }

    @Test
    public void anEmptyHeaderReadsAsAbsent() {
        assertThat(ifMatch("").hasIfMatch()).isFalse();
    }

    @Test
    public void garbageReadsAsAbsent() {
        assertThat(ifMatch("!!!").hasIfMatch()).isFalse();
    }

    @Test
    public void aLoneQuoteReadsAsAbsent() {
        // Restlet's Tag.parse does substring(1, 0) here and throws; we drop it as invalid instead.
        assertThat(ifMatch("\"").hasIfMatch()).isFalse();
    }

    @Test
    public void anAbsentHeaderReadsAsAbsent() {
        assertThat(HttpConditions.of(new Request()).hasIfMatch()).isFalse();
    }

    @Test
    public void oneGarbageMemberDoesNotPoisonTheRestOfTheList() {
        assertThat(ifMatch("!!!, " + CURRENT).matches(CURRENT)).isTrue();
    }

    // ---------------------------------------------------------- If-Match: the splitter is not quote-aware

    @Test
    public void aCommaInsideQuotesStillSplitsAndSoTheWholeHeaderIsDropped() {
        // readRawValue reads to the next comma with no quote tracking: "a,b" -> ["a and b"], neither parses.
        assertThat(ifMatch("\"a,b\"").hasIfMatch()).isFalse();
    }

    @Test
    public void aTagWhoseNameContainsACommaCanNeverMatch() {
        assertThat(ifMatch("\"x,y\"").matches("W/\"x,y\"")).isFalse();
    }

    // ---------------------------------------------------------- If-None-Match

    @Test
    public void ifNoneMatchOnTheCurrentTagMatches() {
        assertThat(ifNoneMatch(CURRENT).noneMatches(CURRENT, ON_GET)).isTrue();
    }

    @Test
    public void ifNoneMatchOnAStaleTagDoesNotMatch() {
        assertThat(ifNoneMatch("W/\"stale\"").noneMatches(CURRENT, ON_GET)).isFalse();
    }

    @Test
    public void ifNoneMatchWildcardDoesNotMatch() {
        // Measured: If-None-Match: * answers 200, not the 304 RFC 7232 3.2 asks for.
        assertThat(ifNoneMatch("*").noneMatches(CURRENT, ON_GET)).isFalse();
    }

    /**
     * The asymmetry, and the reason this helper cannot share one comparison. {@code If-Match} is always
     * compared with {@code Tag.equals(actual, false)}; {@code If-None-Match} with
     * {@code Tag.equals(actual, GET || HEAD)}. This endpoint's tag is weak, so on a {@code GET} the strong
     * form of it never produces a 304 and a client that stored the tag without its {@code W/} gets the full
     * representation. <b>5-E4 row 21 measured exactly this</b> -- it was a bytecode-only claim until S4.
     */
    @Test
    public void onAGetIfNoneMatchComparesWeaknessSoTheStrongFormOfTheWeakTagDoesNotMatch() {
        assertThat(ifNoneMatch("\"-1234567\"").noneMatches(CURRENT, ON_GET)).isFalse();
    }

    /**
     * ...and the same header on any other verb compares <em>names only</em>, so it does match -- and a
     * match there is a 412, not a 304 (row 18). The one argument carries that whole difference, which is why
     * it has no default: a helper with one weakness rule cannot produce both wire answers.
     */
    @Test
    public void onAWriteIfNoneMatchComparesNamesOnlySoTheStrongFormDoesMatch() {
        assertThat(ifNoneMatch("\"-1234567\"").noneMatches(CURRENT, ON_WRITE)).isTrue();
    }

    @Test
    public void theVerbatimWeakTagMatchesIfNoneMatchOnEitherVerb() {
        assertThat(ifNoneMatch(CURRENT).noneMatches(CURRENT, ON_WRITE)).isTrue();
    }

    @Test
    public void anAbsentIfNoneMatchNeverMatches() {
        assertThat(HttpConditions.of(new Request()).noneMatches(CURRENT, ON_GET)).isFalse();
        assertThat(HttpConditions.of(new Request()).hasIfNoneMatch()).isFalse();
    }

    @Test
    public void hasIfNoneMatchIsAlsoDidItParse() {
        // The same rule hasIfMatch() follows -- and the caller needs it, because on a write "no If-None-Match"
        // and "one that did not match" take different paths: the second falls through to the missing-If-Match
        // rejection, the first was never conditional at all.
        assertThat(ifNoneMatch(CURRENT).hasIfNoneMatch()).isTrue();
        assertThat(ifNoneMatch("!!!").hasIfNoneMatch()).isFalse();
        assertThat(ifNoneMatch("").hasIfNoneMatch()).isFalse();
    }

    // ---------------------------------------------------------- no current tag: only the wildcard is left

    @Test
    public void withNoCurrentTagOnlyTheWildcardMatches() {
        // Restlet: `matched = all` when the representation has no tag. Previously this NPE'd.
        assertThat(ifMatch("*").matches(null)).isTrue();
        assertThat(ifMatch(CURRENT).matches(null)).isFalse();
    }

    @Test
    public void withNoCurrentTagIfNoneMatchReachesItsWildcardTest() {
        // The one place Restlet's noneMatch wildcard is live -- which is why `*` loses against a real tag.
        // ⚠ Not hypothetical: this IS the collection url, whose representation carries no tag. Measured on
        // both sides by 5-E4 row 20 -- `GET /resource_set` with If-None-Match: * answers 304, and a POST
        // carrying it answers 412, where the same header against an item answers 200.
        assertThat(ifNoneMatch("*").noneMatches(null, ON_GET)).isTrue();
        assertThat(ifNoneMatch("*").noneMatches(null, ON_WRITE)).isTrue();
        assertThat(ifNoneMatch(CURRENT).noneMatches(null, ON_GET)).isFalse();
    }

    @Test
    public void theWeakWildcardIsNotTheWildcardForIfNoneMatchEither() {
        // Row 21's third case: a POST carrying `If-None-Match: W/*` creates, where `*` would have 412'd.
        assertThat(ifNoneMatch("W/*").noneMatches(null, ON_WRITE)).isFalse();
    }

    // ---------------------------------------------------------- the two headers are independent

    @Test
    public void ifNoneMatchDoesNotMakeTheRequestConditionalForIfMatchPurposes() {
        // hasIfMatch() is Restlet's isConditionalRequest() as this endpoint uses it: getMatch(), not hasSome().
        assertThat(ifNoneMatch(CURRENT).hasIfMatch()).isFalse();
    }

    @Test
    public void ifMatchIsNotConsultedByNoneMatches() {
        assertThat(ifMatch(CURRENT).noneMatches(CURRENT, ON_GET)).isFalse();
    }

    /**
     * ⚠ Both headers on one request are evaluated independently and <em>both</em> can fail it -- a winning
     * {@code If-Match} does not stop {@code If-None-Match} being consulted. Measured by 5-E4 row 18: a
     * {@code PUT} carrying the current tag in both headers is a 412, not the update the client meant.
     */
    @Test
    public void bothHeadersAreEvaluatedIndependently() {
        Request request = new Request();
        request.getHeaders().put("If-Match", CURRENT);
        request.getHeaders().put("If-None-Match", CURRENT);
        HttpConditions conditions = HttpConditions.of(request);

        assertThat(conditions.matches(CURRENT)).isTrue();
        assertThat(conditions.noneMatches(CURRENT, ON_WRITE)).isTrue();
    }
}
