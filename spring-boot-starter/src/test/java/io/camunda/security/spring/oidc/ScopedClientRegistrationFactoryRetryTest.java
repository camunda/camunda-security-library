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

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;

/**
 * Tests that {@link ScopedClientRegistrationFactory} retries a transient discovery failure instead
 * of letting it abort startup.
 */
class ScopedClientRegistrationFactoryRetryTest {

  private static final String DISCOVERY_TEMPLATE =
      """
      {
        "issuer": "%1$s",
        "authorization_endpoint": "%1$s/auth",
        "token_endpoint": "%1$s/token",
        "jwks_uri": "%1$s/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
      }
      """;

  /**
   * Discovery document naming an issuer other than the server serving it — the shape Entra ID
   * produces when the configured issuer differs from the document's by a trailing slash.
   * Deterministic: no number of retries changes the outcome.
   */
  private static final String DISCOVERY_TEMPLATE_MISMATCHED_ISSUER =
      """
      {
        "issuer": "https://issuer.example.com/not-the-server",
        "authorization_endpoint": "%1$s/auth",
        "token_endpoint": "%1$s/token",
        "jwks_uri": "%1$s/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
      }
      """;

  private ScopedClientRegistrationFactory factory;
  private OidcTestServer oidcServer;

  @BeforeEach
  void setUp() {
    factory = new ScopedClientRegistrationFactory();
  }

  @AfterEach
  void tearDown() {
    if (oidcServer != null) {
      oidcServer.close();
      oidcServer = null;
    }
  }

  @Test
  void shouldRetryATransientDiscoveryFailure() throws Exception {
    // given an IdP that fails its first discovery request and serves normally afterwards
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE);
    oidcServer.failNextDiscoveryRequests(1);
    final var providers = Map.of("idp-1", issuerBased("client-1", oidcServer.issuerUri()));

    // when
    final var registrations = factory.createFromProviderMap(providers);

    // then the registration is built, and the server was asked twice: the failed attempt and the
    // retry that succeeded
    assertThat(registrations).hasSize(1);
    assertThat(oidcServer.discoveryRequestCount()).isEqualTo(2);
  }

  /**
   * An unreachable IdP is the failure the reported outage raised, but reproducing one over a real
   * socket is not portable: a server that announces a body and sends none reads as a truncated
   * response on some platforms and as an empty one on others. The classification is asserted
   * directly instead.
   */
  @Test
  void shouldTreatAnUnreachableIdpAsTransient() {
    // given the shape getBuilder produces for a connect timeout or a refused connection
    final var failure =
        new IllegalArgumentException(
            "Unable to resolve Configuration with the provided Issuer of \"https://idp.example\"",
            new ResourceAccessException("Connect timed out"));

    // when / then
    assertThat(ScopedClientRegistrationFactory.isTransient(failure)).isTrue();
  }

  @Test
  void shouldTreatAServerErrorAsTransient() {
    // given the shape getBuilder produces for a 5xx
    final var failure =
        new IllegalArgumentException(
            "Unable to resolve Configuration with the provided Issuer of \"https://idp.example\"",
            new HttpServerErrorException(HttpStatus.INTERNAL_SERVER_ERROR));

    // when / then
    assertThat(ScopedClientRegistrationFactory.isTransient(failure)).isTrue();
  }

  @Test
  void shouldNotTreatAClientErrorAsTransient() {
    // given a 4xx, which says the address is wrong rather than momentarily unavailable
    final var failure =
        new IllegalArgumentException(
            "Unable to resolve Configuration with the provided Issuer of \"https://idp.example\"",
            new HttpClientErrorException(HttpStatus.NOT_FOUND));

    // when / then
    assertThat(ScopedClientRegistrationFactory.isTransient(failure)).isFalse();
  }

  @Test
  void shouldNotTreatAnIssuerMismatchAsTransient() {
    // given the document naming a different issuer than the one requested
    final var failure =
        new IllegalStateException(
            "The Issuer \"https://idp.example\" provided in the configuration metadata did not"
                + " match the requested issuer \"https://idp.example/\"");

    // when / then
    assertThat(ScopedClientRegistrationFactory.isTransient(failure)).isFalse();
  }

  @Test
  void shouldNotRetryADeterministicFailure() throws Exception {
    // given an IdP whose document names a different issuer than the one asked for
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE_MISMATCHED_ISSUER);
    final var providers = Map.of("idp-1", issuerBased("client-1", oidcServer.issuerUri()));

    // when
    assertThatThrownBy(() -> factory.createFromProviderMap(providers))
        .isInstanceOf(RuntimeException.class);

    // then the retry budget was not spent on it: the answer is settled by the document itself, so
    // trying again would only lengthen a startup path that is already blocking
    assertThat(oidcServer.discoveryRequestCount()).isEqualTo(1);
  }

  @Test
  void shouldStopRetryingWhenTheBudgetIsExhausted() throws Exception {
    // given an IdP that fails the first attempt and its retry
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE);
    oidcServer.failNextDiscoveryRequests(2);
    final var providers = Map.of("idp-1", issuerBased("client-1", oidcServer.issuerUri()));

    // when every attempt fails
    assertThatThrownBy(() -> factory.createFromProviderMap(providers))
        .isInstanceOf(RuntimeException.class);

    // then retrying stopped at the budget instead of continuing to block startup
    assertThat(oidcServer.discoveryRequestCount()).isEqualTo(2);

    // and nothing was cached, so a later build resolves the issuer afresh once the IdP recovers
    assertThat(factory.createFromProviderMap(providers)).hasSize(1);
    assertThat(oidcServer.discoveryRequestCount()).isEqualTo(3);
  }

  /** Creates an {@link OidcConfiguration} that resolves its endpoints through issuer discovery. */
  private static OidcConfiguration issuerBased(final String clientId, final String issuerUri) {
    return OidcConfiguration.builder()
        .clientId(clientId)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .issuerUri(issuerUri)
        .build();
  }
}
