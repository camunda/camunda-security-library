/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.spi;

import java.net.URI;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * What the failed-login page tells the user, as supplied by an {@link OidcLoginFailurePort}. All
 * text is rendered HTML-escaped, so it is plain text, not markup. It is shown to the user, so it
 * must never carry token claims, error descriptions or other values copied from the failure.
 *
 * @param status the response status: {@code 401} when the login itself failed, {@code 403} when the
 *     user signed in but is not allowed into this application
 * @param title a short heading
 * @param message the explanation, one or two sentences
 * @param link an optional link offering the user a way forward, such as switching account
 * @param language the language the text is written in, rendered as the page's {@code lang} so
 *     assistive technology pronounces it correctly; {@code null} means {@link #DEFAULT_LANGUAGE}
 * @param retryText the label of the page's retry control, in {@code language}; {@code null} means
 *     {@link #DEFAULT_RETRY_TEXT}
 */
public record OidcLoginFailureNotice(
    int status, String title, String message, Link link, Locale language, String retryText) {

  public static final Locale DEFAULT_LANGUAGE = Locale.ENGLISH;
  public static final String DEFAULT_RETRY_TEXT = "Try again";

  public OidcLoginFailureNotice {
    if (status != 401 && status != 403) {
      throw new IllegalArgumentException("status must be 401 or 403, was " + status);
    }
    requireText(title, "title");
    requireText(message, "message");
    language = language == null ? DEFAULT_LANGUAGE : language;
    if (language.getLanguage().isEmpty()) {
      throw new IllegalArgumentException("language must name a language, was " + language);
    }
    retryText = retryText == null ? DEFAULT_RETRY_TEXT : retryText;
    requireText(retryText, "retryText");
  }

  /** An English notice without a link. */
  public OidcLoginFailureNotice(final int status, final String title, final String message) {
    this(status, title, message, null);
  }

  /** An English notice with an optional link. */
  public OidcLoginFailureNotice(
      final int status, final String title, final String message, final Link link) {
    this(status, title, message, link, null, null);
  }

  /**
   * This notice, declared as written in {@code language} with the retry control labelled {@code
   * retryText}. Both are set together so a translated notice never sits next to an English control.
   */
  public OidcLoginFailureNotice withLanguage(final Locale language, final String retryText) {
    Objects.requireNonNull(language, "language");
    Objects.requireNonNull(retryText, "retryText");
    return new OidcLoginFailureNotice(status, title, message, link, language, retryText);
  }

  public Optional<Link> optionalLink() {
    return Optional.ofNullable(link);
  }

  private static void requireText(final String value, final String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
  }

  /**
   * A link on the failed-login page.
   *
   * @param text the link text
   * @param target an absolute {@code http}/{@code https} URI, or a host-relative path starting with
   *     a single {@code /}; anything else, such as a {@code javascript:} URI, is rejected
   */
  public record Link(String text, URI target) {

    public Link {
      requireText(text, "link text");
      Objects.requireNonNull(target, "target");
      if (!isSafeTarget(target)) {
        throw new IllegalArgumentException(
            "link target must be an absolute http(s) URI or a host-relative path");
      }
    }

    private static boolean isSafeTarget(final URI target) {
      final String scheme = target.getScheme();
      if (scheme == null) {
        final String path = target.toString();
        // "//host" is protocol-relative and would leave the host, so only a single slash counts.
        return path.startsWith("/") && !path.startsWith("//");
      }
      return ("https".equalsIgnoreCase(scheme) || "http".equalsIgnoreCase(scheme))
          && target.getHost() != null;
    }
  }
}
