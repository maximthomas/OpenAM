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
 *     {@code "x"} are the same tag -- but <b>{@code If-None-Match} does not</b>: Restlet compares it with
 *     {@code checkWeakness = GET || HEAD}, and GET/HEAD are the only verbs that consult it. The endpoint's
 *     own tag is weak, so only the {@code W/} form of it can produce a 304.</li>
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
 *     {@code null}, so it answers 200, measured.</li>
 * </ul>
 * One deliberate divergence: {@code If-Match: "} (a lone quote) makes Restlet's {@code Tag.parse} do
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
            if (tag.name.equals(current.name)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether {@code If-None-Match} is satisfied by the current tag, i.e. whether to answer 304.
     * <p>
     * Weakness <em>is</em> compared here, unlike {@link #matches}: Restlet passes
     * {@code checkWeakness = GET || HEAD} and only GET/HEAD ever ask. The wildcard test it does have is
     * reached only when the current tag is {@code null}.
     */
    public boolean noneMatches(String currentEtag) {
        Tag current = Tag.parse(currentEtag);
        if (current == null) {
            return isAll(ifNoneMatch);
        }
        for (Tag tag : ifNoneMatch) {
            if (tag.equals(current)) {
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

        /** {@code Tag.equals(Object)}, which is {@code equals(o, checkWeakness = true)}. */
        @Override
        public boolean equals(Object object) {
            if (!(object instanceof Tag)) {
                return false;
            }
            Tag that = (Tag) object;
            return weak == that.weak && name.equals(that.name);
        }

        @Override
        public int hashCode() {
            return name.hashCode() * 31 + (weak ? 1 : 0);
        }
    }
}
