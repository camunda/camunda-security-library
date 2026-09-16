/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class UrlRedactionTest {

  @Test
  void shouldRemoveUserInfo() {
    assertThat(UrlRedaction.redact("https://user:password@idp.example.com/token"))
        .isEqualTo("https://…@idp.example.com/token");
  }

  /** A '@' inside the credentials must not end the user-info early and leak the rest. */
  @Test
  void shouldRemoveUserInfoContainingAnAtSign() {
    assertThat(UrlRedaction.redact("https://user@corp:p@ss@idp.example.com/token"))
        .isEqualTo("https://…@idp.example.com/token");
  }

  /**
   * A scheme-relative authority is still an authority. Such a value reaches these messages — an
   * {@code issuer-uri} of this shape is rejected for not being absolute, and the rejection quotes
   * it — so missing it would leak the credential the helper exists to hide.
   */
  @Test
  void shouldRemoveUserInfoFromASchemeRelativeAuthority() {
    assertThat(UrlRedaction.redact("//user:password@idp.example.com/realm"))
        .isEqualTo("//…@idp.example.com/realm");
  }

  /** A single leading slash is a path, not an authority. */
  @Test
  void shouldLeaveARootRelativePathAlone() {
    assertThat(UrlRedaction.redact("/goodbye")).isEqualTo("/goodbye");
  }

  /** A '@' in the path belongs to the path, not to an authority that has already ended. */
  @Test
  void shouldKeepAnAtSignInThePath() {
    assertThat(UrlRedaction.redact("https://idp.example.com/users/me@example.com"))
        .isEqualTo("https://idp.example.com/users/me@example.com");
  }

  @Test
  void shouldRemoveTheQueryString() {
    assertThat(UrlRedaction.redact("https://idp.example.com/logout?id_token_hint=secret"))
        .isEqualTo("https://idp.example.com/logout…");
  }

  /**
   * The '#' stays so a message rejecting a value for carrying a fragment can still point at it; the
   * contents go, because OAuth returns tokens in fragments and nothing stops one reaching
   * configuration.
   */
  @Test
  void shouldKeepTheFragmentMarkerButNotItsContents() {
    assertThat(UrlRedaction.redact("https://idp.example.com/cb#access_token=secret"))
        .isEqualTo("https://idp.example.com/cb#…");
  }

  @Test
  void shouldRedactBothTheQueryAndTheFragmentContents() {
    assertThat(UrlRedaction.redact("https://idp.example.com/cb?token=secret#access_token=secret"))
        .isEqualTo("https://idp.example.com/cb…#…");
  }

  @Test
  void shouldLeaveABareFragmentMarkerAlone() {
    assertThat(UrlRedaction.redact("https://idp.example.com/cb#"))
        .isEqualTo("https://idp.example.com/cb#");
  }

  /**
   * A rejected value is exactly what these messages quote, and CR/LF is one of the reasons a value
   * gets rejected. Passed through unescaped it would forge a line in the log the message lands in.
   */
  @Test
  void shouldEscapeControlCharacters() {
    assertThat(UrlRedaction.redact("https://idp.example.com/cb\r\nINFO forged"))
        .isEqualTo("https://idp.example.com/cb\\u000d\\u000aINFO forged");
  }

  /** Values reach this helper unexpanded and sometimes unparseable; none of that may throw. */
  @ValueSource(
      strings = {
        "{baseUrl}/post-logout",
        "{baseScheme}://{baseHost}/logged-out",
        "/goodbye",
        "goodbye",
        "https://",
        "{baseUrl}{tenantId",
        ""
      })
  @ParameterizedTest
  void shouldLeaveAValueWithNothingToStripUnchanged(final String url) {
    assertThat(UrlRedaction.redact(url)).isEqualTo(url);
  }

  @Test
  void shouldTolerateNull() {
    assertThat(UrlRedaction.redact(null)).isNull();
  }
}
