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
        assertThat(ifNoneMatch(CURRENT).noneMatches(CURRENT)).isTrue();
    }

    @Test
    public void ifNoneMatchOnAStaleTagDoesNotMatch() {
        assertThat(ifNoneMatch("W/\"stale\"").noneMatches(CURRENT)).isFalse();
    }

    @Test
    public void ifNoneMatchWildcardDoesNotMatch() {
        // Measured: If-None-Match: * answers 200, not the 304 RFC 7232 3.2 asks for.
        assertThat(ifNoneMatch("*").noneMatches(CURRENT)).isFalse();
    }

    /**
     * The asymmetry, and the reason this helper cannot share one comparison. {@code If-Match} is compared
     * with {@code Tag.equals(actual, false)}; {@code If-None-Match} with
     * {@code Tag.equals(actual, GET || HEAD)}, and GET/HEAD are the only verbs that consult it -- so weakness
     * <em>is</em> compared. This endpoint's tag is weak, so the strong form of it never produces a 304, and a
     * client that stores the tag without its {@code W/} gets the full representation, not an empty 304.
     */
    @Test
    public void ifNoneMatchComparesWeaknessSoTheStrongFormOfTheWeakTagDoesNotMatch() {
        assertThat(ifNoneMatch("\"-1234567\"").noneMatches(CURRENT)).isFalse();
    }

    @Test
    public void anAbsentIfNoneMatchNeverMatches() {
        assertThat(HttpConditions.of(new Request()).noneMatches(CURRENT)).isFalse();
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
        assertThat(ifNoneMatch("*").noneMatches(null)).isTrue();
        assertThat(ifNoneMatch(CURRENT).noneMatches(null)).isFalse();
    }

    // ---------------------------------------------------------- the two headers are independent

    @Test
    public void ifNoneMatchDoesNotMakeTheRequestConditionalForIfMatchPurposes() {
        // hasIfMatch() is Restlet's isConditionalRequest() as this endpoint uses it: getMatch(), not hasSome().
        assertThat(ifNoneMatch(CURRENT).hasIfMatch()).isFalse();
    }

    @Test
    public void ifMatchIsNotConsultedByNoneMatches() {
        assertThat(ifMatch(CURRENT).noneMatches(CURRENT)).isFalse();
    }
}
