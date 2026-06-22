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
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

/**
 * Unit tests for {@link ScopedOidcIdTokenDecoderFactory}. Proves the scoped id_token decoder
 * verifies signatures against the JWK set discovered from {@code issuer-uri} alone (no explicit
 * {@code jwk-set-uri} on the decoder path), and that — unlike a cluster-keyed {@code Map::get}
 * {@code jwsAlgorithmResolver} — it resolves a non-null algorithm for registrations it has never
 * seen as map keys. Signs real RS256 JWTs against a local JWKS/discovery server.
 */
final class ScopedOidcIdTokenDecoderFactoryTest {

  private OidcTestServer server;

  @AfterEach
  void stopServer() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  void shouldVerifyIdTokenSignatureUsingJwkSetDiscoveredFromIssuerUriOnly() throws Exception {
    // given a scoped provider configured with ONLY issuer-uri (no explicit jwk-set-uri),
    // discovered into a ClientRegistration the same way the scoped webapp chain does
    server = OidcTestServer.startRsa("scoped-key");
    final var oidc =
        OidcConfiguration.builder().clientId("client-a").issuerUri(server.issuerUri()).build();
    final var providerMap = Map.of("tenanta", oidc);
    final var registration = discoverRegistration("tenanta", server.issuerUri());
    assertThat(registration.getProviderDetails().getJwkSetUri())
        .as("discovery from issuer-uri must populate the jwkSetUri")
        .isEqualTo(server.jwksUri());

    final var validatorFactory =
        new TokenValidatorFactory(providerMap, OidcConfiguration.DEFAULT_CLOCK_SKEW, List.of());
    final var factory = new ScopedOidcIdTokenDecoderFactory(providerMap, validatorFactory);

    // when an RS256-signed token is decoded by the scoped factory's decoder
    final var decoder = factory.createDecoder(registration);
    final var token = server.sign(server.issuerUri());
    final var jwt = decoder.decode(token);

    // then signature verification succeeds against the discovered JWK set
    assertThat(jwt.getSubject()).isEqualTo("alice");
    assertThat(jwt.getIssuer().toString()).isEqualTo(server.issuerUri());
  }

  @Test
  void shouldResolveNonNullAlgorithmForRegistrationNotPresentAsMapKey() throws Exception {
    // given a cluster-keyed Map::get resolver (the failure mode) keyed by one registration instance
    server = OidcTestServer.startRsa("scoped-key");
    final var clusterRegistration = discoverRegistration("tenanta", server.issuerUri());
    final var clusterKeyedFactory = new OidcIdTokenDecoderFactory();
    clusterKeyedFactory.setJwsAlgorithmResolver(
        Map.of(
                clusterRegistration,
                (org.springframework.security.oauth2.jose.jws.JwsAlgorithm)
                    SignatureAlgorithm.RS256)
            ::get);

    // and a DISTINCT registration instance for the same issuer (as the scoped chain builds)
    final var scopedRegistration = discoverRegistration("tenanta", server.issuerUri());
    final var token = server.sign(server.issuerUri());

    // when the cluster-keyed resolver is asked about the scoped instance, it resolves null and
    // fails
    // (this reproduces the bug: missing_signature_verifier / JWS Algorithm: 'null')
    assertThatThrownBy(() -> clusterKeyedFactory.createDecoder(scopedRegistration).decode(token))
        .isInstanceOf(OAuth2AuthenticationException.class)
        .hasMessageContaining("missing_signature_verifier");

    // then the scoped factory, keyed by the provider map rather than registration identity,
    // resolves a non-null algorithm and verifies the same token successfully
    final var oidc =
        OidcConfiguration.builder().clientId("client-a").issuerUri(server.issuerUri()).build();
    final var providerMap = Map.of("tenanta", oidc);
    final var validatorFactory =
        new TokenValidatorFactory(providerMap, OidcConfiguration.DEFAULT_CLOCK_SKEW, List.of());
    final var scopedFactory = new ScopedOidcIdTokenDecoderFactory(providerMap, validatorFactory);

    final var jwt = scopedFactory.createDecoder(scopedRegistration).decode(token);
    assertThat(jwt.getSubject()).isEqualTo("alice");
  }

  private static ClientRegistration discoverRegistration(
      final String registrationId, final String issuerUri) {
    return ClientRegistrations.fromIssuerLocation(issuerUri)
        .registrationId(registrationId)
        .clientId("client-a")
        .build();
  }
}
