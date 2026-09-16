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
 * <p>Every OIDC URL property is operator-supplied, and a startup failure naming one lands in
 * application logs like anything else. {@code https://user:password@idp.example.com/token} puts
 * credentials there, and a query string can carry a token or a tracking value; the library's
 * logging rules forbid either at any level. Scheme, host and path survive, which is what identifies
 * the endpoint and locates a typo — the reason for naming the value at all.
 *
 * <p>A fragment keeps its {@code '#'} and loses its contents. Several of these messages exist
 * <em>because</em> a value carries a fragment — a redirect URI and a post-logout redirect URI may
 * both have none — so removing it entirely would hide the very thing the operator has to go and
 * delete. Keeping what follows is not safe either: OAuth returns tokens in fragments, and nothing
 * stops one being pasted into configuration. The marker says where the problem is without repeating
 * what it holds.
 *
 * <p>Control characters are replaced rather than passed through. CR and LF are rejected values, and
 * a rejected value is exactly what these messages quote — unescaped, it would forge a second line
 * in the log the message lands in.
 *
 * <p>Trimmed as a string rather than parsed as a {@link java.net.URI}: these values may hold
 * unexpanded {@code {placeholder}} templates, whose braces are not legal URI characters, and this
 * runs on values that were rejected precisely for being unparseable.
 */
public final class UrlRedaction {

  private static final String ELLIPSIS = "…";

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
    return withoutControlCharacters(withoutFragment(withoutQuery(withoutUserInfo(url))));
  }

  private static String withoutUserInfo(final String url) {
    final var schemeEnd = url.indexOf("://");
    if (schemeEnd < 0) {
      return url;
    }
    final var authorityStart = schemeEnd + 3;
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

  /** Keeps the {@code '#'} so the message can still point at it, drops what it carries. */
  private static String withoutFragment(final String url) {
    final var fragmentStart = url.indexOf('#');
    if (fragmentStart < 0 || fragmentStart == url.length() - 1) {
      return url;
    }
    return url.substring(0, fragmentStart + 1) + ELLIPSIS;
  }

  private static String withoutControlCharacters(final String url) {
    if (url.chars().noneMatch(Character::isISOControl)) {
      return url;
    }
    final var escaped = new StringBuilder(url.length());
    url.chars()
        .forEach(
            c ->
                escaped.append(Character.isISOControl(c) ? String.format("\\u%04x", c) : (char) c));
    return escaped.toString();
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
