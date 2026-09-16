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
   * The fragment survives a redacted query. Messages that reject a value for carrying a fragment
   * have to show it, or the operator cannot see what to remove.
   */
  @Test
  void shouldKeepTheFragmentWhileRemovingTheQuery() {
    assertThat(UrlRedaction.redact("https://idp.example.com/cb?token=secret#section"))
        .isEqualTo("https://idp.example.com/cb…#section");
  }

  @Test
  void shouldKeepAFragmentWithNoQueryPresent() {
    assertThat(UrlRedaction.redact("https://idp.example.com/cb#section"))
        .isEqualTo("https://idp.example.com/cb#section");
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
