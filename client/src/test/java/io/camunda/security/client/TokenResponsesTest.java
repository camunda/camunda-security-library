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
import static org.assertj.core.api.Assertions.catchThrowable;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TokenResponsesTest extends OidcTestSupport {

  @Test
  void sendsReservedParametersAndOptionalOnes() throws IOException {
    authorization(provider("hub-api", List.of("read", "write"), "https://hub"));

    assertThat(endpoint.requestBodies()).hasSize(1);
    assertThat(endpoint.requestBodies().getFirst().split("&"))
        .containsExactlyInAnyOrder(
            "grant_type=client_credentials",
            "client_id=my-client",
            "client_secret=" + SECRET,
            "audience=hub-api",
            "scope=read+write",
            "resource=https%3A%2F%2Fhub");
  }

  @Test
  void omitsOptionalParametersWhenUnset() throws IOException {
    authorization(provider());

    assertThat(endpoint.requestBodies().getFirst())
        .doesNotContain("audience")
        .doesNotContain("scope")
        .doesNotContain("resource");
  }

  @Test
  void unsupportedTokenTypeGetsTheFixedMessage() {
    endpoint.respondWith(
        200,
        "{\"access_token\":\"t\",\"token_type\":\"x\\r\\n\\u0085\\u2028y\",\"expires_in\":60}");

    final Throwable failure = catchThrowable(() -> authorization(provider()));

    // Nimbus rejects the type and quotes it in its message. The fixed message does not.
    assertThat(failure)
        .isInstanceOf(TokenRequestException.class)
        .hasMessageContaining("is not usable: the response cannot be parsed")
        .hasMessageNotContaining("token_type")
        .hasMessageNotContaining("\r")
        .hasMessageNotContaining("\n")
        .hasMessageNotContaining("\u0085");
  }

  @Test
  void overflowingExpiresInReturnsTheTokenWithoutCachingIt() throws IOException {
    endpoint.respondWith(
        200,
        "{\"access_token\":\"abc\",\"token_type\":\"Bearer\",\"expires_in\":"
            + Long.MAX_VALUE
            + "}");
    final var provider = provider();

    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer abc");
    authorization(provider);

    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @Test
  void requestAsksForJsonAndKeepsTheQueryOfTheTokenUri() throws IOException {
    final var config =
        OidcClientCredentialsConfiguration.builder(
                URI.create(endpoint.uri() + "?p=policy"), "my-client", SECRET)
            .build();

    authorization(new OidcClientCredentialsProvider(config, clock));

    assertThat(endpoint.acceptHeaders()).containsExactly("application/json");
    assertThat(endpoint.requestQueries()).containsExactly("p=policy");
  }

  @Test
  void successResponseThatIsNotJsonFails() {
    endpoint.respondWithContentType("text/plain");

    final Throwable failure = catchThrowable(() -> authorization(provider()));

    assertThat(failure)
        .isInstanceOf(TokenRequestException.class)
        .hasMessageContaining("not usable");
    assertNoneOfTheMessagesContains(failure, "token-1");
  }

  @ParameterizedTest
  @ValueSource(strings = {"\"\"", "\"  \"", "null"})
  void blankTokenTypeFails(final String tokenType) {
    endpoint.respondWith(
        200, "{\"access_token\":\"abc\",\"token_type\":" + tokenType + ",\"expires_in\":60}");

    final Throwable failure = catchThrowable(() -> authorization(provider()));

    assertThat(failure)
        .isInstanceOf(TokenRequestException.class)
        .hasMessageContaining("not usable");
    assertNoneOfTheMessagesContains(failure, "abc");
  }

  @Test
  void missingTokenTypeFails() {
    endpoint.respondWith(200, "{\"access_token\":\"abc\",\"expires_in\":60}");

    final Throwable failure = catchThrowable(() -> authorization(provider()));

    assertThat(failure)
        .isInstanceOf(TokenRequestException.class)
        .hasMessageContaining("not usable")
        .hasMessageContaining("the response cannot be parsed")
        .hasNoCause();
    assertNoneOfTheMessagesContains(failure, "abc");
  }

  @Test
  void errorResponseFailsWithoutLeakingTheSecret() {
    endpoint.respondWith(
        401, "{\"error\":\"invalid_client\",\"error_description\":\"bad credentials\"}");
    final var provider = provider();

    assertThatThrownBy(() -> authorization(provider))
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> {
              assertThat(e.getStatus()).isEqualTo(401);
              assertThat(e.getError()).isEqualTo("invalid_client");
              assertThat(e.getErrorDescription()).isEqualTo("bad credentials");
              assertThat(e.getMessage()).contains("my-client").doesNotContain(SECRET);
            });
  }

  @Test
  void nonJsonErrorResponseStillFailsWithStatus() {
    endpoint.respondWith(503, "<html>unavailable</html>");
    final var provider = provider();

    assertThatThrownBy(() -> authorization(provider))
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> {
              assertThat(e.getStatus()).isEqualTo(503);
              assertThat(e.getError()).isNull();
            });
  }

  @Test
  void responseWithoutAccessTokenFails() {
    endpoint.respondWith(200, "{\"token_type\":\"Bearer\",\"expires_in\":60}");

    assertThatThrownBy(() -> authorization(provider()))
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> {
              assertThat(e).hasNoCause();
              assertThat(e.getMessage())
                  .contains("not usable")
                  .contains("the response cannot be parsed");
            });
  }

  @Test
  void invalidJsonResponseFails() {
    endpoint.respondWith(200, "not json");

    assertThatThrownBy(() -> authorization(provider()))
        .isInstanceOf(TokenRequestException.class)
        .hasMessageContaining("is not usable: the response cannot be parsed");
  }

  @Test
  void invalidJsonResponseHasNoCauseAndDoesNotQuoteTheBody() {
    endpoint.respondWith(200, "{\"access_token\":\"leaky-token\" oops");

    final Throwable failure = catchThrowable(() -> authorization(provider()));

    assertThat(failure).isInstanceOf(TokenRequestException.class).hasNoCause();
    assertThat(failure.getMessage()).contains("is not usable: the response cannot be parsed");
    assertNoneOfTheMessagesContains(failure, "leaky-token", "oops");
  }

  @Test
  void errorResponseWithLineBreaksIsSanitized() {
    endpoint.respondWith(
        400,
        "{\"error\":\"bad\\r\\nforged\","
            + "\"error_description\":\"a\\nb\\r\\u2028c\\u0085d\\te\"}");

    assertThatThrownBy(() -> authorization(provider()))
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> {
              // Nimbus drops an error code with illegal characters and strips them from the
              // description, so the provider does not sanitize these fields itself.
              assertThat(e.getError()).isNull();
              assertThat(e.getErrorDescription()).isEqualTo("abcde");
              assertThat(e.getMessage()).doesNotContain("\r", "\n", "\u2028", "\u0085", "\t");
            });
  }

  @ParameterizedTest
  @ValueSource(strings = {"true", "123", "\"  \"", "null", "{}"})
  void accessTokenThatIsNotANonBlankStringFails(final String accessToken) {
    endpoint.respondWith(
        200, "{\"access_token\":" + accessToken + ",\"token_type\":\"Bearer\",\"expires_in\":60}");

    final Throwable failure = catchThrowable(() -> authorization(provider()));

    assertThat(failure)
        .isInstanceOf(TokenRequestException.class)
        .hasMessageContaining("not usable");
    assertNoneOfTheMessagesContains(failure, "123");
  }

  @Test
  void tokenWithoutExpiresInIsNotCached() throws IOException {
    endpoint.respondWith(200, "{\"access_token\":\"abc\",\"token_type\":\"Bearer\"}");
    final var provider = provider();

    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer abc");
    authorization(provider);

    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @Test
  void shortLivedTokenIsRefreshedHalfwayThroughItsLifetime() throws IOException {
    endpoint.respondWith(
        200, "{\"access_token\":\"abc\",\"token_type\":\"Bearer\",\"expires_in\":20}");
    final var provider = provider();
    authorization(provider);

    clock.advance(Duration.ofSeconds(9));
    authorization(provider);
    assertThat(endpoint.requestCount()).isEqualTo(1);

    clock.advance(Duration.ofSeconds(2));
    authorization(provider);
    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @Test
  void expiresInAsNumericStringIsCached() throws IOException {
    endpoint.respondWith(
        200, "{\"access_token\":\"abc\",\"token_type\":\"Bearer\",\"expires_in\":\"3599\"}");
    final var provider = provider();

    authorization(provider);
    authorization(provider);

    assertThat(endpoint.requestCount()).isEqualTo(1);
  }

  @Test
  void zeroExpiresInIsNotCached() throws IOException {
    endpoint.respondWith(
        200, "{\"access_token\":\"abc\",\"token_type\":\"Bearer\",\"expires_in\":0}");
    final var provider = provider();

    authorization(provider);
    authorization(provider);

    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @ParameterizedTest
  @ValueSource(strings = {"\"abc\"", "\" 3599 \"", "-5", "\"\"", "null", "true"})
  void invalidExpiresInFails(final String expiresIn) {
    endpoint.respondWith(
        200,
        "{\"access_token\":\"abc-secret\",\"token_type\":\"Bearer\",\"expires_in\":"
            + expiresIn
            + "}");

    final Throwable failure = catchThrowable(() -> authorization(provider()));

    assertThat(failure)
        .isInstanceOf(TokenRequestException.class)
        .hasMessageContaining("not usable");
    assertNoneOfTheMessagesContains(failure, "abc-secret");
  }

  @ParameterizedTest
  @ValueSource(strings = {"mac", "N_A", "DPoP"})
  void otherTokenTypesFail(final String tokenType) {
    endpoint.respondWith(
        200,
        "{\"access_token\":\"abc-secret\",\"token_type\":\"" + tokenType + "\",\"expires_in\":60}");

    final Throwable failure = catchThrowable(() -> authorization(provider()));

    assertThat(failure)
        .isInstanceOf(TokenRequestException.class)
        .hasMessageContaining("not usable");
    assertNoneOfTheMessagesContains(failure, "abc-secret");
  }
}
