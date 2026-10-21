/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.config.oidc.OidcUserInfoAugmentationConfiguration;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.spring.converter.OidcTokenAuthenticationConverter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * The claims provider is shared by all scopes and picks a UserInfo endpoint by issuer, while each
 * scope verifies tokens with its own providers. The UserInfo use of a token must follow the
 * provider that verified it, also where the global configuration gives its issuer to another
 * provider.
 */
@ExtendWith(MockitoExtension.class)
class ScopedUserInfoOwnershipTest {

  @Mock private OidcUserInfoFetcher fetcher;
  @Mock private MembershipPort membershipPort;

  private OidcTestServer server;

  @BeforeEach
  void startServer() throws Exception {
    server = OidcTestServer.startRsa("shared-key");
    lenient().when(fetcher.fetch(any(), any())).thenReturn(Map.of("sub", "alice"));
  }

  @AfterEach
  void stopServer() {
    server.stop();
  }

  /**
   * The identity provider declares {@code https://idp}. Global: A at {@code https://idp/} with
   * UserInfo, declared first, and B at {@code https://idp} without. The global claims provider
   * gives both forms to A. A scope holds only B, and B verifies a token of {@code https://idp}: no
   * UserInfo request is made, as B disables UserInfo.
   */
  @Test
  void shouldNotCallTheUserInfoOfAnotherProviderForAScopedToken() throws Exception {
    // given
    final var providerA = server.oidcConfiguration("client-a");
    providerA.setIssuerUri(server.issuerUri() + "/");
    providerA.setUserInfoEnabled(true);
    final var providerB = server.oidcConfiguration("client-b");
    providerB.setUserInfoEnabled(false);
    final var converter = sharedConverter(providerA, providerB);

    final var scope = new AuthenticationConfiguration();
    scope.getProviders().getOidc().put("b", providerB);
    final var scopedDecoder =
        new ScopedJwtDecoderFactory(
                new ScopedClientRegistrationFactory(),
                new OidcAccessTokenDecoderFactory(
                    new JWSKeySelectorFactory(),
                    new TokenValidatorFactory(
                        Map.of("b", providerB), OidcConfiguration.DEFAULT_CLOCK_SKEW, List.of())))
            .buildIssuerAwareDecoder(scope);

    // when
    final var jwt =
        scopedDecoder.decode(server.sign(server.issuerUri(), Map.of("scope", "openid")));
    final var authentication = converter.convert(new JwtAuthenticationToken(jwt));

    // then
    assertThat(authentication.authenticatedUsername()).isEqualTo("alice");
    verifyNoInteractions(fetcher);
  }

  /**
   * The same token from a decoder of the host carries no decision, so the global claims provider
   * decides by issuer, and gives it A's UserInfo, as before.
   */
  @Test
  void shouldKeepTheLookupByIssuerForATokenOfAnotherDecoder() throws Exception {
    // given
    final var providerA = server.oidcConfiguration("client-a");
    providerA.setIssuerUri(server.issuerUri() + "/");
    providerA.setUserInfoEnabled(true);
    final var providerB = server.oidcConfiguration("client-b");
    providerB.setUserInfoEnabled(false);
    final var converter = sharedConverter(providerA, providerB);
    final var token = server.sign(server.issuerUri(), Map.of("scope", "openid"));

    // when
    converter.convert(
        new JwtAuthenticationToken(
            NimbusJwtDecoder.withJwkSetUri(server.jwksUri()).build().decode(token)));

    // then
    verify(fetcher).fetch(any(), any());
  }

  /** The shared converter, with the global claims provider of A and B, A declared first. */
  private OidcTokenAuthenticationConverter sharedConverter(
      final OidcConfiguration providerA, final OidcConfiguration providerB) {
    final Map<String, OidcConfiguration> global = new LinkedHashMap<>();
    global.put("a", providerA);
    global.put("b", providerB);
    final Map<String, ClientRegistration> registrations =
        Map.of(
            "a", registration("a", providerA.getIssuerUri(), server.issuerUri() + "/userinfo"),
            "b", registration("b", providerB.getIssuerUri(), null));
    final var claimsProvider =
        new CachingOidcClaimsProvider(
            fetcher,
            CachingOidcClaimsProvider.userInfoUriByIssuer(
                IssuerRegistrations.ofConfiguration(global, registrations::get), global),
            new OidcUserInfoAugmentationConfiguration(),
            null);
    return new OidcTokenAuthenticationConverter(
        new LazyTokenClaimsConverter("sub", null, false, membershipPort), claimsProvider);
  }

  private ClientRegistration registration(
      final String registrationId, final String issuer, final String userInfoUri) {
    return ClientRegistration.withRegistrationId(registrationId)
        .clientId("client-" + registrationId)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/cb")
        .authorizationUri(server.issuerUri() + "/auth")
        .tokenUri(server.issuerUri() + "/token")
        .jwkSetUri(server.jwksUri())
        .userInfoUri(userInfoUri)
        .issuerUri(issuer)
        .build();
  }
}
