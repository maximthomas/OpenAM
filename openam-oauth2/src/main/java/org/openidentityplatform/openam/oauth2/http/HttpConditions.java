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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.forgerock.http.protocol.Header;
import org.forgerock.http.protocol.Request;

/**
 * The {@code If-Match} / {@code If-None-Match} preconditions of a request, parsed and compared the way Restlet
 * parsed and compared them.
 * <p>
 * CHF has no conditional-request support at all -- {@code Endpoints.from} dispatches on verb alone -- while
 * Restlet's {@code ServerResource} evaluated preconditions itself, before the annotated method ran. An
 * endpoint whose Java only asked "is this request conditional?" therefore still had full {@code If-Match}
 * enforcement, and porting only the visible half is a silent loss of lost-update protection. This class is the
 * missing half, for the one endpoint in the migration that needs it.
 *
 * <h2>Why the rules are quirky on purpose</h2>
 * The rules below are Restlet's, not RFC 7232's, and every one of them is either measured against a live
 * container or read off the fork's bytecode -- the parser ({@code TagReader} -&gt;
 * {@code HeaderReader.readRawValue} -&gt; {@code Tag.parse}) and, for the comparisons, {@code
 * Conditions.getStatus}. The Restlet oracle dies when {@code /oauth2} moves to CHF, so "more correct" here
 * would be an unreviewable behaviour change:
 * <ul>
 * <li><b>{@code If-Match} ignores weakness</b> ({@code tag.equals(actual, false)}), so {@code W/"x"} and
 *     {@code "x"} are the same tag -- but <b>{@code If-None-Match} compares it on {@code GET}/{@code HEAD}
 *     and not on any other verb</b>, because Restlet passes {@code checkWeakness = GET || HEAD}. The
 *     endpoint's own tag is weak, so the strong form of it answers <b>200 on a {@code GET} and 412 on a
 *     {@code PUT}</b> -- measured, 5-E4 row 21. That is the whole reason
 *     {@link #noneMatches(String, boolean)} takes the flag rather than assuming it.</li>
 * <li><b>{@code *} counts only as the first parsed element, and only in its strong form.</b> The wildcard is
 *     {@code getMatch().get(0).equals(Tag.ALL)} -- one positional test, with weakness checked. Elsewhere in
 *     the list a {@code *} is just a tag named {@code *}, which no real tag is called, so
 *     {@code If-Match: "stale", *} and {@code If-Match: W/*} both <em>fail</em>.</li>
 * <li><b>Unparseable reads as absent.</b> An element Restlet cannot parse is dropped, so a header of nothing
 *     but garbage leaves an <em>empty</em> list and {@link #hasIfMatch()} answers {@code false}. Reporting
 *     "present but unmatched" instead would answer 412 where Restlet answers whatever the endpoint does with
 *     a missing header.</li>
 * <li><b>The splitter is not quote-aware.</b> A comma always ends an element, so a tag name containing one
 *     can never be expressed -- and never matches.</li>
 * <li><b>{@code *} does not satisfy {@code If-None-Match}</b> against a real tag. RFC 7232 3.2 asks for 304
 *     when a representation exists; Restlet reaches its wildcard test only when the current tag is
 *     {@code null}, so it answers 200, measured. ⚠ The tag-less case is not theoretical -- it is this
 *     endpoint's <em>collection</em> URL, where the very same header answers <b>304</b> (row 20).</li>
 * </ul>
 *
 * <h2>⚠ The caller decides nothing about <em>which</em> verbs are conditional</h2>
 * Restlet's {@code doConditionalHandle} runs before the annotated method <b>whatever the verb is</b>, so both
 * headers are evaluated on {@code POST}, {@code PUT} and {@code DELETE} exactly as on {@code GET} -- and both
 * are evaluated on the same request, so a winning {@code If-Match} does not stop {@code If-None-Match} failing
 * it (5-E4 rows 18-20). Only the <em>consequence</em> of a match differs: 304 on {@code GET}/{@code HEAD},
 * 412 everywhere else. A caller that attaches these checks per verb reproduces none of that.
 *
 * <p>One deliberate divergence: {@code If-Match: "} (a lone quote) makes Restlet's {@code Tag.parse} do
 * {@code substring(1, 0)} and throw, which escapes its reader. We drop it as invalid.
 */
public final class HttpConditions {

    private final List<Tag> ifMatch;
    private final List<Tag> ifNoneMatch;

    private HttpConditions(List<Tag> ifMatch, List<Tag> ifNoneMatch) {
        this.ifMatch = ifMatch;
        this.ifNoneMatch = ifNoneMatch;
    }

    public static HttpConditions of(Request request) {
        return new HttpConditions(tags(request, "If-Match"), tags(request, "If-None-Match"));
    }

    /**
     * Whether the request carries an {@code If-Match} that <em>parsed</em> -- Restlet's
     * {@code isConditionalRequest()} as this endpoint used it.
     */
    public boolean hasIfMatch() {
        return !ifMatch.isEmpty();
    }

    /**
     * Whether {@code If-Match} is satisfied by the current tag: the wildcard, else a name match with weakness
     * ignored. A {@code null} or unparseable current tag leaves only the wildcard, as it does in Restlet.
     */
    public boolean matches(String currentEtag) {
        if (isAll(ifMatch)) {
            return true;
        }
        Tag current = Tag.parse(currentEtag);
        if (current == null) {
            return false;
        }
        for (Tag tag : ifMatch) {
            // Restlet's If-Match loop passes checkWeakness = false, unconditionally.
            if (tag.matches(current, false)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether the request carries an {@code If-None-Match} that <em>parsed</em>. Same rule as
     * {@link #hasIfMatch()}, and a caller on a write verb needs it: "no {@code If-None-Match}" and "one that
     * did not match" are different requests, only the first of which was never conditional.
     */
    public boolean hasIfNoneMatch() {
        return !ifNoneMatch.isEmpty();
    }

    /**
     * Whether {@code If-None-Match} is satisfied by the current tag -- a 304 on a {@code GET}, a 412 on
     * anything else.
     * <p>
     * The wildcard test Restlet has here is reached <em>only</em> when the current tag is {@code null}, which
     * is why {@code *} loses against a real tag and wins against the tag-less collection representation.
     *
     * @param checkWeakness Restlet's second comparison argument, literally
     *     {@code GET.equals(method) || HEAD.equals(method)}. It has no default on purpose: 5-E4 row 21
     *     measured the strong form of this endpoint's weak tag answering <b>200 on a {@code GET} and 412 on a
     *     {@code PUT}</b>, so a caller that does not say which verb it is cannot be given a right answer.
     *     {@link #matches} takes no such parameter because {@code If-Match} passes {@code false} always.
     */
    public boolean noneMatches(String currentEtag, boolean checkWeakness) {
        Tag current = Tag.parse(currentEtag);
        if (current == null) {
            return isAll(ifNoneMatch);
        }
        for (Tag tag : ifNoneMatch) {
            if (tag.matches(current, checkWeakness)) {
                return true;
            }
        }
        return false;
    }

    /** Restlet's {@code all}: {@code list.get(0).equals(Tag.ALL)}, so position 0 only and weakness checked. */
    private static boolean isAll(List<Tag> tags) {
        return !tags.isEmpty() && tags.get(0).isAll();
    }

    private static List<Tag> tags(Request request, String headerName) {
        Header header = request.getHeaders().get(headerName);
        if (header == null) {
            return Collections.emptyList();
        }
        List<Tag> tags = new ArrayList<>();
        for (String value : header.getValues()) {
            // A comma always ends an element, quoted or not -- HeaderUtil.split would honour the quotes.
            for (String element : value.split(",", -1)) {
                Tag tag = Tag.parse(element.trim());
                // canAdd drops nulls and duplicates, and its duplicate test is the weakness-checked equals.
                if (tag != null && !tags.contains(tag)) {
                    tags.add(tag);
                }
            }
        }
        return tags;
    }

    /** An entity tag, reduced to the two fields Restlet's comparisons read. */
    private static final class Tag {

        private final String name;
        private final boolean weak;

        private Tag(String name, boolean weak) {
            this.name = name;
            this.weak = weak;
        }

        /** {@code Tag.parse} minus the lone-quote crash: {@code null} for an element Restlet would discard. */
        private static Tag parse(String element) {
            if (element == null) {
                return null;
            }
            boolean weak = element.startsWith("W/");
            String tag = weak ? element.substring(2) : element;
            if (tag.length() >= 2 && tag.startsWith("\"") && tag.endsWith("\"")) {
                return new Tag(tag.substring(1, tag.length() - 1), weak);
            }
            // The quoted form is tested first, so `*` and `"*"` both arrive here as a tag named `*`.
            return "*".equals(tag) ? new Tag("*", weak) : null;
        }

        /** {@code Tag.ALL} is {@code Tag.parse("*")}, i.e. strong, and the wildcard test checks weakness. */
        private boolean isAll() {
            return !weak && "*".equals(name);
        }

        /** {@code Tag.equals(Object other, boolean checkWeakness)} -- names always, weakness only if asked. */
        private boolean matches(Tag that, boolean checkWeakness) {
            return name.equals(that.name) && (!checkWeakness || weak == that.weak);
        }

        /** {@code Tag.equals(Object)}, which is {@code equals(o, checkWeakness = true)}. */
        @Override
        public boolean equals(Object object) {
            return object instanceof Tag && matches((Tag) object, true);
        }

        @Override
        public int hashCode() {
            return name.hashCode() * 31 + (weak ? 1 : 0);
        }
    }
}
