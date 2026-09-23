/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

/**
 * Strips the parts of a configured URL that can carry a secret, for messages that report one.
 *
 * <p>Every OIDC URL property is operator-supplied, and a value the library warns about lands in
 * application logs like anything else — and, unlike a one-off startup failure, keeps landing there
 * on every later attempt, since the application starts and keeps running with it. {@code
 * https://user:password@idp.example.com/token} puts credentials there, and a query string can carry
 * a token or a tracking value; the library's logging rules forbid either at any level. Scheme, host
 * and path survive, which is what identifies the endpoint and locates a typo — the reason for
 * naming the value at all.
 *
 * <p>A value does not have to be well-formed to carry a credential, and the messages that quote one
 * are mostly quoting something the library considers unusable, but keeps and uses regardless.
 * User-info is therefore found by shape rather than by parsing: see {@link #authorityStart}.
 *
 * <p>A fragment keeps its {@code '#'} and loses its contents. Several of these messages exist
 * <em>because</em> a value carries a fragment — a redirect URI and a post-logout redirect URI may
 * both have none — so removing it entirely would hide the very thing the operator has to go and
 * delete. Keeping what follows is not safe either: OAuth returns tokens in fragments, and nothing
 * stops one being pasted into configuration. The marker says where the problem is without repeating
 * what it holds.
 *
 * <p>Control characters are replaced rather than passed through. CR and LF let an otherwise
 * unremarkable-looking value forge a second line in the log the message lands in, unescaped.
 *
 * <p>Trimmed as a string rather than parsed as a {@link java.net.URI}: these values may hold
 * unexpanded {@code {placeholder}} templates, whose braces are not legal URI characters, and this
 * runs on values the library considers unparseable precisely for that reason.
 */
public final class UrlRedaction {

  private static final String ELLIPSIS = "…";

  /** {@code LINE SEPARATOR} (U+2028) and {@code PARAGRAPH SEPARATOR} (U+2029). */
  private static final int LINE_SEPARATOR = 0x2028;

  private static final int PARAGRAPH_SEPARATOR = 0x2029;

  private UrlRedaction() {}

  /**
   * The URL with its user-info, query string and fragment contents replaced by an ellipsis, and any
   * control character replaced by a printable escape.
   *
   * @param url the configured value, possibly blank, a template, or malformed
   * @return the redacted value, or the input unchanged when there is nothing to strip
   */
  public static String redact(final String url) {
    if (url == null || url.isEmpty()) {
      return url;
    }
    return escapeControlCharacters(withoutFragment(withoutQuery(withoutUserInfo(url))));
  }

  private static String withoutUserInfo(final String url) {
    final var authorityStart = authorityStart(url);
    final var authorityEnd = endOfAuthority(url, authorityStart);
    // lastIndexOf so a '@' in the credentials themselves does not end the user-info early.
    final var at = url.lastIndexOf('@', authorityEnd - 1);
    return at < authorityStart
        ? url
        : url.substring(0, authorityStart) + ELLIPSIS + "@" + url.substring(at + 1);
  }

  private static String withoutQuery(final String url) {
    final var queryStart = url.indexOf('?');
    if (queryStart < 0) {
      return url;
    }
    final var fragmentStart = url.indexOf('#', queryStart);
    return fragmentStart < 0
        ? url.substring(0, queryStart) + ELLIPSIS
        : url.substring(0, queryStart) + ELLIPSIS + url.substring(fragmentStart);
  }

  /**
   * Where the authority begins.
   *
   * <p>Three forms reach these messages, and all three can carry credentials. {@code
   * scheme://user:pw@host} is the obvious one. A scheme-relative {@code //user:pw@host/path} is an
   * authority too. So is a value that has lost its scheme altogether — {@code
   * user:pw@idp.example.com/token}, an {@code issuer-uri} typed without its {@code https://}, which
   * {@code URI} happily parses as scheme {@code user}, which {@code warnIfNotAbsoluteHttpUrl} then
   * flags, and which the warning quotes.
   *
   * <p>The last form has no delimiter to find, so the value is treated as beginning with its
   * authority. That costs nothing when there is none: {@link #withoutUserInfo} looks for an {@code
   * '@'} before the first {@code '/'}, {@code '?'} or {@code '#'} and leaves the value alone when
   * there is not one, so a path like {@code /goodbye} and a bare word like {@code goodbye} pass
   * through untouched.
   */
  private static int authorityStart(final String url) {
    final var schemeEnd = url.indexOf("://");
    if (schemeEnd >= 0) {
      return schemeEnd + 3;
    }
    return url.startsWith("//") ? 2 : 0;
  }

  /** Keeps the {@code '#'} so the message can still point at it, drops what it carries. */
  private static String withoutFragment(final String url) {
    final var fragmentStart = url.indexOf('#');
    if (fragmentStart < 0 || fragmentStart == url.length() - 1) {
      return url;
    }
    return url.substring(0, fragmentStart + 1) + ELLIPSIS;
  }

  /**
   * Escapes a control character (for example CR or LF), or the line/paragraph separators {@code
   * Character#isISOControl} does not cover (U+2028, U+2029), to its 4-digit unicode escape form —
   * the one place this logic lives, so a value forging a log line this way cannot be fixed in one
   * caller and missed in another, the way U+2028 was across two review rounds. Used both for a URL
   * value here and for {@code ScopedClientRegistrationFactory#sanitizeForLog}'s registrationId,
   * which is never a URL and so does not otherwise go through this class.
   */
  static String escapeControlCharacters(final String value) {
    if (value == null || value.chars().noneMatch(UrlRedaction::mustBeEscaped)) {
      return value;
    }
    final var escaped = new StringBuilder(value.length());
    value
        .chars()
        .forEach(c -> escaped.append(mustBeEscaped(c) ? String.format("\\u%04x", c) : (char) c));
    return escaped.toString();
  }

  private static boolean mustBeEscaped(final int c) {
    return Character.isISOControl(c) || c == LINE_SEPARATOR || c == PARAGRAPH_SEPARATOR;
  }

  private static int endOfAuthority(final String url, final int from) {
    final var end = firstIndexOf(url, from, '/', '?', '#');
    return end < 0 ? url.length() : end;
  }

  private static int firstIndexOf(final String value, final int from, final char... delimiters) {
    var found = -1;
    for (final char delimiter : delimiters) {
      final var at = value.indexOf(delimiter, from);
      if (at >= 0 && (found < 0 || at < found)) {
        found = at;
      }
    }
    return found;
  }
}
