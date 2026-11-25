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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class OidcClientCredentialsConfigurationTest {

  private static final URI TOKEN_URI = URI.create("https://idp.example/token");
  private static final String TOO_LONG_MESSAGE =
      " must not be longer than " + Integer.MAX_VALUE + " milliseconds";

  private static OidcClientCredentialsConfiguration.Builder builder() {
    return OidcClientCredentialsConfiguration.builder(TOKEN_URI, "id", "secret");
  }

  private static OidcClientCredentialsConfiguration.Builder fullBuilder() {
    return fullBuilder(TOKEN_URI, "id", "secret");
  }

  private static OidcClientCredentialsConfiguration.Builder fullBuilder(
      final URI tokenUri, final String clientId, final String clientSecret) {
    return OidcClientCredentialsConfiguration.builder(tokenUri, clientId, clientSecret)
        .audience("aud")
        .scopes(List.of("a", "b"))
        .resource("res")
        .connectTimeout(Duration.ofSeconds(1))
        .readTimeout(Duration.ofSeconds(2))
        .requestTimeout(Duration.ofSeconds(3));
  }

  @Test
  void defaultsTimeoutsAndScopes() {
    final var config = builder().build();

    assertThat(config.connectTimeout()).isEqualTo(Duration.ofSeconds(10));
    assertThat(config.readTimeout()).isEqualTo(Duration.ofSeconds(10));
    assertThat(config.requestTimeout()).isEqualTo(Duration.ofSeconds(30));
    assertThat(config.scopes()).isEmpty();
    assertThat(config.audience()).isNull();
    assertThat(config.resource()).isNull();
  }

  @Test
  void keepsAllValues() {
    final var config = fullBuilder().build();

    assertThat(config.tokenUri()).isEqualTo(TOKEN_URI);
    assertThat(config.clientId()).isEqualTo("id");
    assertThat(config.clientSecret()).isEqualTo("secret");
    assertThat(config.audience()).isEqualTo("aud");
    assertThat(config.scopes()).containsExactly("a", "b");
    assertThat(config.resource()).isEqualTo("res");
    assertThat(config.connectTimeout()).isEqualTo(Duration.ofSeconds(1));
    assertThat(config.readTimeout()).isEqualTo(Duration.ofSeconds(2));
    assertThat(config.requestTimeout()).isEqualTo(Duration.ofSeconds(3));
  }

  @Test
  void nullOptionalValuesKeepTheDefaults() {
    final var config =
        builder()
            .audience(null)
            .scopes(null)
            .resource(null)
            .connectTimeout(null)
            .readTimeout(null)
            .requestTimeout(null)
            .build();

    assertThat(config).isEqualTo(builder().build());
    assertThat(config.connectTimeout()).isEqualTo(Duration.ofSeconds(10));
    assertThat(config.readTimeout()).isEqualTo(Duration.ofSeconds(10));
    assertThat(config.requestTimeout()).isEqualTo(Duration.ofSeconds(30));
    assertThat(config.scopes()).isEmpty();
  }

  @Test
  void copiesScopes() {
    final var scopes = new ArrayList<>(List.of("a"));
    final var config = builder().scopes(scopes).build();
    scopes.add("b");

    assertThat(config.scopes()).containsExactly("a");
  }

  @Test
  void scopesCannotBeChanged() {
    final var config = builder().scopes(List.of("a")).build();

    assertThatThrownBy(() -> config.scopes().add("x"))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void blankAudienceAndResourceBecomeNull() {
    final var config = builder().audience(" ").resource("").build();

    assertThat(config.audience()).isNull();
    assertThat(config.resource()).isNull();
    assertThat(config.toString()).contains("audience=null", "resource=null");
  }

  @Test
  void rejectsMissingOrRelativeTokenUri() {
    assertThatThrownBy(
            () -> OidcClientCredentialsConfiguration.builder(null, "id", "secret").build())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("tokenUri");
    assertThatThrownBy(
            () ->
                OidcClientCredentialsConfiguration.builder(URI.create("/token"), "id", "secret")
                    .build())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("tokenUri");
  }

  @ParameterizedTest
  @ValueSource(strings = {"urn:x", "file:/x", "ftp://idp.example/token"})
  void rejectsTokenUriThatIsNotHttp(final String uri) {
    assertThatThrownBy(
            () ->
                OidcClientCredentialsConfiguration.builder(URI.create(uri), "id", "secret").build())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("tokenUri must be an absolute http or https URI");
  }

  @Test
  void rejectsTokenUriWithoutAReadableHost() {
    assertThatThrownBy(
            () ->
                OidcClientCredentialsConfiguration.builder(URI.create("https:///x"), "id", "secret")
                    .build())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("tokenUri has no host that java.net.URI can read");
  }

  @Test
  void acceptsHttpSchemesIgnoringCase() {
    assertThat(
            OidcClientCredentialsConfiguration.builder(
                    URI.create("HTTP://localhost/token"), "id", "secret")
                .build())
        .isNotNull();
    assertThat(
            OidcClientCredentialsConfiguration.builder(
                    URI.create("Https://idp.example:8443/token"), "id", "secret")
                .build())
        .isNotNull();
  }

  @Test
  void rejectsHttpForAHostThatIsNotLoopback() {
    assertThatThrownBy(
            () ->
                OidcClientCredentialsConfiguration.builder(
                        URI.create("http://idp.example/token"), "id", "secret")
                    .build())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage(
            "tokenUri must use https. Http is allowed only for localhost, 127.0.0.1 and [::1]");
  }

  @Test
  void rejectsATokenUriWithUserInfoWithoutEchoingIt() {
    final var uri = URI.create("https://idp-user:idp-pass@idp.example/token");

    assertThatThrownBy(
            () -> OidcClientCredentialsConfiguration.builder(uri, "id", "secret").build())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("tokenUri must not contain user-info");
  }

  @Test
  void rejectsBlankClientIdOrSecret() {
    assertThatThrownBy(
            () -> OidcClientCredentialsConfiguration.builder(TOKEN_URI, " ", "secret").build())
        .hasMessageContaining("clientId");
    assertThatThrownBy(
            () -> OidcClientCredentialsConfiguration.builder(TOKEN_URI, "id", null).build())
        .hasMessageContaining("clientSecret");
  }

  static Stream<Arguments> invalidTimeouts() {
    final var tooLong = ConfigurationChecks.MAX_TIMEOUT.plusMillis(1);
    return Stream.of("connectTimeout", "readTimeout", "requestTimeout")
        .flatMap(
            field ->
                Stream.of(
                    Arguments.of(field, Duration.ZERO, field + " must be positive"),
                    Arguments.of(field, tooLong, field + TOO_LONG_MESSAGE)));
  }

  @ParameterizedTest
  @MethodSource("invalidTimeouts")
  void rejectsAnInvalidTimeoutNamingTheField(
      final String field, final Duration value, final String message) {
    final var builder = builder();
    switch (field) {
      case "connectTimeout" -> builder.connectTimeout(value);
      case "readTimeout" -> builder.readTimeout(value);
      default -> builder.requestTimeout(value);
    }

    assertThatThrownBy(builder::build)
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage(message);
  }

  @Test
  void acceptsTheLargestTimeout() {
    final var config = builder().connectTimeout(ConfigurationChecks.MAX_TIMEOUT).build();

    assertThat(config.connectTimeout()).isEqualTo(Duration.ofMillis(Integer.MAX_VALUE));
  }

  @Test
  void rejectsNullAndBlankScopes() {
    for (final String scope : Arrays.asList(null, "", " ")) {
      final var scopes = Arrays.asList("a", scope);
      assertThatThrownBy(() -> builder().scopes(scopes).build())
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("scopes must not contain blank values");
    }
  }

  @Test
  void toStringMasksTheSecret() {
    final var text =
        OidcClientCredentialsConfiguration.builder(TOKEN_URI, "id", "super-secret")
            .build()
            .toString();

    assertThat(text).doesNotContain("super-secret").contains("clientSecret=***", "clientId=id");
  }

  @Test
  void toStringHidesQueryAndFragmentOfTheTokenUri() {
    final var uri = URI.create("https://idp.example:8443/t%0D%0Aoken?k=qs-secret#frag");

    final var text =
        OidcClientCredentialsConfiguration.builder(uri, "id", "secret").build().toString();

    assertThat(text)
        .contains("tokenUri=https://idp.example:8443/t%0D%0Aoken,")
        .doesNotContain("qs-secret", "frag");
  }

  @Test
  void equalsAndHashCodeFollowAllValues() {
    final var config = fullBuilder().build();

    assertThat(config)
        .isEqualTo(fullBuilder().build())
        .hasSameHashCodeAs(fullBuilder().build())
        .isNotEqualTo(fullBuilder(URI.create("https://idp.example/other"), "id", "secret").build())
        .isNotEqualTo(fullBuilder(TOKEN_URI, "other", "secret").build())
        .isNotEqualTo(fullBuilder(TOKEN_URI, "id", "other").build())
        .isNotEqualTo(fullBuilder().audience("other").build())
        .isNotEqualTo(fullBuilder().scopes(List.of("a")).build())
        .isNotEqualTo(fullBuilder().resource("other").build())
        .isNotEqualTo(fullBuilder().connectTimeout(Duration.ofSeconds(9)).build())
        .isNotEqualTo(fullBuilder().readTimeout(Duration.ofSeconds(9)).build())
        .isNotEqualTo(fullBuilder().requestTimeout(Duration.ofSeconds(9)).build())
        .isNotEqualTo(null)
        .isNotEqualTo("id");
  }
}
