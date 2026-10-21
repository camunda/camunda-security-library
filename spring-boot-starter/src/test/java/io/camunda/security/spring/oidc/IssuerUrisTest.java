/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class IssuerUrisTest {

  @Test
  void shouldFindAnIssuerInItsOtherTrailingSlashForm() {
    final var byIssuer = Map.of("https://login.microsoftonline.com/tenant/v2.0/", "entra");

    assertThat(IssuerUris.lookup(byIssuer, "https://login.microsoftonline.com/tenant/v2.0"))
        .isEqualTo("entra");
    assertThat(IssuerUris.lookup(byIssuer, "https://login.microsoftonline.com/tenant/v2.0/"))
        .isEqualTo("entra");
  }

  /** Two providers whose issuers differ only by the slash each keep their own tokens. */
  @Test
  void shouldPreferTheExactIssuer() {
    final var byIssuer =
        Map.of("https://idp.example.com/", "with-slash", "https://idp.example.com", "without");

    assertThat(IssuerUris.lookup(byIssuer, "https://idp.example.com/")).isEqualTo("with-slash");
    assertThat(IssuerUris.lookup(byIssuer, "https://idp.example.com")).isEqualTo("without");
  }

  @Test
  void shouldFindNothingForAnUnknownOrMissingIssuer() {
    final var byIssuer = Map.of("https://idp.example.com", "idp");

    assertThat(IssuerUris.lookup(byIssuer, "https://other.example.com")).isNull();
    assertThat(IssuerUris.lookup(byIssuer, null)).isNull();
  }

  @Test
  void shouldMatchTheMemberOfASetInEitherForm() {
    final var issuers = Set.of("https://dev-1234.okta.com/");

    assertThat(IssuerUris.match(issuers, "https://dev-1234.okta.com"))
        .isEqualTo("https://dev-1234.okta.com/");
    assertThat(IssuerUris.match(issuers, "https://other.okta.com")).isNull();
    assertThat(IssuerUris.match(issuers, null)).isNull();
  }

  @ParameterizedTest
  @CsvSource({
    "https://login.microsoftonline.com/tenant/v2.0/, https://login.microsoftonline.com/tenant/v2.0",
    "https://login.microsoftonline.com/tenant/v2.0, https://login.microsoftonline.com/tenant/v2.0/",
    "https://dev-1234.okta.com/, https://dev-1234.okta.com",
    "https://tenant.auth0.com, https://tenant.auth0.com/"
  })
  void shouldToggleTheTrailingSlash(final String issuer, final String expected) {
    assertThat(IssuerUris.withToggledTrailingSlash(issuer)).isEqualTo(expected);
  }

  /** Nothing that isn't a plain issuer URL, and never down to a bare scheme. */
  @ParameterizedTest
  @ValueSource(strings = {"https://", "https://idp//", "https://idp/?x=1", "https://idp/#f", "/"})
  void shouldNotToggleAValueThatIsNotAPlainIssuerUrl(final String issuer) {
    assertThat(IssuerUris.withToggledTrailingSlash(issuer)).isNull();
  }
}
