/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * Discovery when the configured {@code issuer-uri} and the issuer in the provider's discovery
 * document differ by a trailing slash. Spring requires the two to be identical, so this used to
 * fail gateway startup and browser login (camunda/camunda#61896).
 */
class ScopedClientRegistrationFactoryIssuerTrailingSlashTest {

  /** {@code %1$s} is the server's base URL; {@code %2$s} is appended to it to form the issuer. */
  private static final String DISCOVERY_TEMPLATE =
      """
      {
        "issuer": "%1$s%2$s",
        "authorization_endpoint": "%1$s/auth",
        "token_endpoint": "%1$s/token",
        "jwks_uri": "%1$s/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
      }
      """;

  private final ScopedClientRegistrationFactory factory = new ScopedClientRegistrationFactory();
  private OidcTestServer server;

  @AfterEach
  void stopServer() {
    if (server != null) {
      server.stop();
    }
  }

  /** Entra ID and Okta: the document has no trailing slash, the configuration does. */
  @Test
  void shouldTakeTheProvidersIssuerWhenTheConfiguredOneHasAnExtraTrailingSlash() throws Exception {
    // given
    server = startDiscoveryWithIssuerSuffix("");
    final var base = server.issuerUri();

    // when
    final var registration = register(base + "/");

    // then - the provider's form, which is what its tokens carry, for discovery and validation
    assertThat(registration.getProviderDetails().getIssuerUri()).isEqualTo(base);
    assertThat(ClientRegistrationMetadata.issuer(registration)).contains(base);
  }

  /** Auth0: the document has a trailing slash, the configuration doesn't. */
  @Test
  void shouldTakeTheProvidersIssuerWhenTheConfiguredOneIsMissingItsTrailingSlash()
      throws Exception {
    // given
    server = startDiscoveryWithIssuerSuffix("/");
    final var base = server.issuerUri();

    // when
    final var registration = register(base);

    // then
    assertThat(registration.getProviderDetails().getIssuerUri()).isEqualTo(base + "/");
    assertThat(ClientRegistrationMetadata.issuer(registration)).contains(base + "/");
  }

  @Test
  void shouldKeepTheConfiguredIssuerWhenItMatchesTheProvidersExactly() throws Exception {
    // given
    server = startDiscoveryWithIssuerSuffix("");

    // when
    final var registration = register(server.issuerUri());

    // then
    assertThat(registration.getProviderDetails().getIssuerUri()).isEqualTo(server.issuerUri());
    assertThat(ClientRegistrationMetadata.issuer(registration)).contains(server.issuerUri());
  }

  /**
   * Only a trailing slash is tolerated; any other difference still fails, with Spring's message.
   */
  @Test
  void shouldStillFailWhenTheIssuersDifferByMoreThanATrailingSlash() throws Exception {
    // given
    server = startDiscoveryWithIssuerSuffix("/realms/other");
    final var base = server.issuerUri();

    // when / then
    assertThatThrownBy(() -> register(base))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("did not match the requested issuer \"" + base + "\"");
  }

  /**
   * The first document declares an unrelated issuer, and a second fetch, for the slash variant,
   * returns a document that declares the variant. The retry must not paper over the first, real
   * mismatch: only a document that declared the slash variant itself justifies retrying.
   */
  @Test
  void shouldNotRetryWhenTheFirstDocumentDeclaredAnUnrelatedIssuer() throws Exception {
    // given - the first request answers ".../other", every later one the slash variant
    final var requests = new AtomicInteger();
    final var http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    final var base = "http://127.0.0.1:" + http.getAddress().getPort();
    http.createContext(
        "/.well-known/openid-configuration",
        exchange -> {
          final var issuer = requests.getAndIncrement() == 0 ? base + "/other" : base + "/";
          final var body =
              DISCOVERY_TEMPLATE
                  .replace("%2$s", "")
                  .formatted(base)
                  .replace("\"issuer\": \"" + base + "\"", "\"issuer\": \"" + issuer + "\"");
          final var bytes = body.getBytes(StandardCharsets.UTF_8);
          exchange.getResponseHeaders().add("Content-Type", "application/json");
          exchange.sendResponseHeaders(200, bytes.length);
          try (var out = exchange.getResponseBody()) {
            out.write(bytes);
          }
        });
    http.start();
    try {
      // when / then - the original mismatch, against the unrelated issuer
      assertThatThrownBy(() -> register(base))
          .isInstanceOf(IllegalStateException.class)
          .hasMessageContaining("The Issuer \"" + base + "/other\"");
    } finally {
      http.stop(0);
    }
  }

  /**
   * Spring's message is the only source of the declared issuer; a change to its form must make the
   * retry fall back to failing, never to accepting.
   */
  @Test
  void shouldReadTheDeclaredIssuerFromSpringsMismatchMessage() {
    assertThat(
            ScopedClientRegistrationFactory.declaredIssuer(
                new IllegalStateException(
                    "The Issuer \"https://idp/v2.0\" provided in the configuration metadata did"
                        + " not match the requested issuer \"https://idp/v2.0/\"")))
        .isEqualTo("https://idp/v2.0");
    assertThat(ScopedClientRegistrationFactory.declaredIssuer(new IllegalStateException("other")))
        .isNull();
    assertThat(ScopedClientRegistrationFactory.declaredIssuer(new IllegalStateException()))
        .isNull();
  }

  private OidcTestServer startDiscoveryWithIssuerSuffix(final String suffix) throws Exception {
    // startDiscovery formats the template with the base URL alone, so fill in the suffix first.
    return OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE.replace("%2$s", suffix));
  }

  private ClientRegistration register(final String issuerUri) {
    final var registrations =
        factory.createFromProviderMap(
            Map.of(
                "idp",
                OidcConfiguration.builder()
                    .clientId("client")
                    .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                    .issuerUri(issuerUri)
                    .build()));
    return registrations.iterator().next();
  }
}
