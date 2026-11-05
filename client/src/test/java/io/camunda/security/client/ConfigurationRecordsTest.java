/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ConfigurationRecordsTest {

  private static final URI TOKEN_URI = URI.create("https://idp.example/token");

  private static OidcClientCredentialsConfiguration oidc(
      final URI uri, final String id, final String secret, final Duration connect) {
    return new OidcClientCredentialsConfiguration(uri, id, secret, null, null, null, connect, null);
  }

  @Test
  void oidcDefaultsTimeoutsAndScopes() {
    final var config = oidc(TOKEN_URI, "id", "secret", null);

    assertThat(config.connectTimeout()).isEqualTo(Duration.ofSeconds(10));
    assertThat(config.readTimeout()).isEqualTo(Duration.ofSeconds(10));
    assertThat(config.scopes()).isEmpty();
  }

  @Test
  void oidcCopiesScopes() {
    final var scopes = new java.util.ArrayList<>(List.of("a"));
    final var config =
        new OidcClientCredentialsConfiguration(
            TOKEN_URI, "id", "secret", null, scopes, null, null, null);
    scopes.add("b");

    assertThat(config.scopes()).containsExactly("a");
  }

  @Test
  void oidcRejectsMissingOrRelativeTokenUri() {
    assertThatThrownBy(() -> oidc(null, "id", "secret", null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("tokenUri");
    assertThatThrownBy(() -> oidc(URI.create("/token"), "id", "secret", null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("tokenUri");
  }

  @ParameterizedTest
  @ValueSource(strings = {"urn:x", "file:/x", "https:///x", "ftp://idp.example/token"})
  void oidcRejectsTokenUriThatIsNotHttpWithAHost(final String uri) {
    assertThatThrownBy(() -> oidc(URI.create(uri), "id", "secret", null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("tokenUri");
  }

  @Test
  void oidcAcceptsHttpSchemesIgnoringCase() {
    assertThat(oidc(URI.create("HTTP://idp.example/token"), "id", "secret", null)).isNotNull();
    assertThat(oidc(URI.create("Https://idp.example:8443/token"), "id", "secret", null))
        .isNotNull();
  }

  @Test
  void oidcRejectsBlankClientIdOrSecret() {
    assertThatThrownBy(() -> oidc(TOKEN_URI, " ", "secret", null)).hasMessageContaining("clientId");
    assertThatThrownBy(() -> oidc(TOKEN_URI, "id", null, null))
        .hasMessageContaining("clientSecret");
  }

  @Test
  void oidcRejectsNonPositiveTimeout() {
    assertThatThrownBy(() -> oidc(TOKEN_URI, "id", "secret", Duration.ZERO))
        .hasMessageContaining("connectTimeout");
  }

  @Test
  void oidcRejectsATimeoutThatDoesNotFitIntoMilliseconds() {
    assertThatThrownBy(() -> oidc(TOKEN_URI, "id", "secret", Duration.ofDays(30)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("connectTimeout");
    assertThat(
            oidc(TOKEN_URI, "id", "secret", Duration.ofMillis(Integer.MAX_VALUE)).connectTimeout())
        .isEqualTo(Duration.ofMillis(Integer.MAX_VALUE));
  }

  @Test
  void oidcToStringMasksTheSecret() {
    final var text = oidc(TOKEN_URI, "id", "super-secret", null).toString();

    assertThat(text).doesNotContain("super-secret").contains("clientSecret=***", "clientId=id");
  }

  @Test
  void oidcToStringHidesQueryAndFragmentOfTheTokenUri() {
    final var uri = URI.create("https://idp.example:8443/t%0D%0Aoken?k=qs-secret#frag");

    final var text = oidc(uri, "id", "secret", null).toString();

    assertThat(text)
        .contains("tokenUri=https://idp.example:8443/t%0D%0Aoken,")
        .doesNotContain("qs-secret", "frag");
  }

  @Test
  void oidcRejectsATokenUriWithUserInfoWithoutEchoingIt() {
    final var uri = URI.create("https://idp-user:idp-pass@idp.example/token");

    assertThatThrownBy(() -> oidc(uri, "id", "secret", null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("tokenUri must not contain user-info");
  }

  @Test
  void oidcRejectsNullAndBlankScopes() {
    for (final String scope : java.util.Arrays.asList(null, "", " ")) {
      final var scopes = java.util.Arrays.asList("a", scope);
      assertThatThrownBy(
              () ->
                  new OidcClientCredentialsConfiguration(
                      TOKEN_URI, "id", "secret", null, scopes, null, null, null))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("scopes must not contain blank values");
    }
  }

  @Test
  void basicRejectsAUsernameWithAColon() {
    assertThatThrownBy(() -> new BasicAuthConfiguration("a:b", "pw"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("username must not contain ':'");
  }

  @Test
  void basicValidatesAndMasksThePassword() {
    assertThatThrownBy(() -> new BasicAuthConfiguration("", "pw"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("username");
    assertThatThrownBy(() -> new BasicAuthConfiguration("u", null))
        .isInstanceOf(NullPointerException.class);

    assertThat(new BasicAuthConfiguration("u", "pw-secret").toString())
        .doesNotContain("pw-secret")
        .contains("username=u", "password=***");
  }

  @Test
  void oidcEqualsAndHashCodeFollowAllValues() {
    final var config = oidc(TOKEN_URI, "id", "secret", null);

    assertThat(config)
        .isEqualTo(oidc(TOKEN_URI, "id", "secret", null))
        .hasSameHashCodeAs(oidc(TOKEN_URI, "id", "secret", null))
        .isNotEqualTo(oidc(TOKEN_URI, "other", "secret", null))
        .isNotEqualTo(oidc(TOKEN_URI, "id", "other", null))
        .isNotEqualTo(oidc(TOKEN_URI, "id", "secret", Duration.ofSeconds(5)))
        .isNotEqualTo(oidc(URI.create("https://idp.example/other"), "id", "secret", null))
        .isNotEqualTo(
            new OidcClientCredentialsConfiguration(
                TOKEN_URI, "id", "secret", "aud", List.of("a"), "res", null, null))
        .isNotEqualTo(null)
        .isNotEqualTo("id");
  }

  @Test
  void basicEqualsAndHashCodeFollowAllValues() {
    final var config = new BasicAuthConfiguration("u", "pw");

    assertThat(config)
        .isEqualTo(new BasicAuthConfiguration("u", "pw"))
        .hasSameHashCodeAs(new BasicAuthConfiguration("u", "pw"))
        .isNotEqualTo(new BasicAuthConfiguration("other", "pw"))
        .isNotEqualTo(new BasicAuthConfiguration("u", "other"))
        .isNotEqualTo(null)
        .isNotEqualTo("u");
  }
}
