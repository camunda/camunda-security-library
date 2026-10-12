/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.spring.oidc.JWSKeySelectorFactory;
import io.camunda.security.spring.oidc.OidcAccessTokenDecoderFactory;
import io.camunda.security.spring.oidc.OidcTestServer;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import io.camunda.security.spring.oidc.TokenValidatorFactory;
import io.camunda.security.spring.spi.OidcLoginScopePort;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

/**
 * End-to-end regression test for camunda-security-library#720. Two scopes share the registration id
 * {@code oidc} but sit on different IdPs (separate issuer and signing key), and one scope requires
 * an audience the other does not. One converter serves both, as in a host, over a real {@link
 * OidcAccessTokenDecoderFactory} and registrations built by {@link
 * ScopedClientRegistrationFactory}. The outcome must not depend on which scope logs in first.
 */
@ExtendWith(MockitoExtension.class)
final class OidcUserAuthenticationConverterScopedLoginTest {

  private static final String REGISTRATION_ID = "oidc";
  private static final String SCOPE_A = "scope-a";
  private static final String SCOPE_B = "scope-b";

  @Mock private LazyTokenClaimsConverter tokenClaimsConverter;

  private final Map<String, ClientRegistration> registrationByScope = new ConcurrentHashMap<>();
  private final ThreadLocal<String> currentScope = new ThreadLocal<>();
  private final Map<String, String> accessTokens = new ConcurrentHashMap<>();

  private OidcTestServer idpA;
  private OidcTestServer idpB;
  private OidcUserAuthenticationConverter converter;

  @BeforeEach
  void setUp() throws Exception {
    idpA = OidcTestServer.startRsa("key-a");
    idpB = OidcTestServer.startRsa("key-b");
    final var registrationFactory = new ScopedClientRegistrationFactory();
    registrationByScope.put(SCOPE_A, registration(registrationFactory, idpA, null));
    registrationByScope.put(SCOPE_B, registration(registrationFactory, idpB, Set.of("audience-x")));

    final var authorizedClientRepository = mock(OAuth2AuthorizedClientRepository.class);
    when(authorizedClientRepository.loadAuthorizedClient(
            org.mockito.ArgumentMatchers.eq(REGISTRATION_ID),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any()))
        .thenAnswer(
            invocation ->
                new OAuth2AuthorizedClient(
                    registrationByScope.get(currentScope.get()),
                    "alice",
                    new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER,
                        accessTokens.get(currentScope.get()),
                        Instant.now(),
                        Instant.now().plusSeconds(60))));
    // The host's singleton validator factory knows scope A's provider only; the registration of
    // each scope carries its own issuer and audiences.
    final var decoderFactory =
        new OidcAccessTokenDecoderFactory(
            new JWSKeySelectorFactory(),
            new TokenValidatorFactory(
                Map.of(REGISTRATION_ID, idpA.oidcConfiguration("client")),
                OidcConfiguration.DEFAULT_CLOCK_SKEW,
                List.of()));
    converter =
        OidcUserAuthenticationConverter.scoped(
            authorizedClientRepository,
            decoderFactory,
            tokenClaimsConverter,
            mock(HttpServletRequest.class),
            new OidcLoginScopePort() {
              @Override
              public String resolveScope(final HttpServletRequest request) {
                return currentScope.get();
              }

              @Override
              public AdditionalJwkSetUrisByRegistrationId additionalJwkSetUris(final String scope) {
                return AdditionalJwkSetUrisByRegistrationId.empty();
              }

              @Override
              public Map<String, Boolean> preferIdTokenClaims(final String scope) {
                return Map.of();
              }
            });
  }

  @AfterEach
  void tearDown() {
    idpA.stop();
    idpB.stop();
  }

  @ParameterizedTest
  @ValueSource(strings = {"A_FIRST", "B_FIRST"})
  void shouldDecodeEachScopesAccessTokenWithItsOwnIssuerAndKeysRegardlessOfLoginOrder(
      final String order) throws Exception {
    accessTokens.put(
        SCOPE_A, idpA.signWithAudience(idpA.issuerUri(), List.of()) /* no audience required */);
    accessTokens.put(SCOPE_B, idpB.signWithAudience(idpB.issuerUri(), "audience-x"));
    final var scopes =
        "A_FIRST".equals(order) ? List.of(SCOPE_A, SCOPE_B) : List.of(SCOPE_B, SCOPE_A);

    for (final var scope : scopes) {
      final var claims = login(scope);

      assertThat(claims).as("claims of %s", scope).doesNotContainKey("source");
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"A_FIRST", "B_FIRST"})
  void shouldRejectAnAccessTokenWithoutTheAudienceOfItsOwnScopeRegardlessOfLoginOrder(
      final String order) throws Exception {
    accessTokens.put(SCOPE_A, idpA.signWithAudience(idpA.issuerUri(), List.of()));
    // Scope B requires audience-x; this token, signed by B's own IdP, does not carry it.
    accessTokens.put(SCOPE_B, idpB.signWithAudience(idpB.issuerUri(), List.of()));
    final var scopes =
        "A_FIRST".equals(order) ? List.of(SCOPE_A, SCOPE_B) : List.of(SCOPE_B, SCOPE_A);

    for (final var scope : scopes) {
      final var claims = login(scope);

      if (SCOPE_B.equals(scope)) {
        assertThat(claims).containsEntry("source", "id");
      } else {
        assertThat(claims).doesNotContainKey("source");
      }
    }
  }

  private Map<String, Object> login(final String scope) {
    currentScope.set(scope);
    final var now = Instant.now();
    final var idToken =
        new OidcIdToken("id", now, now.plusSeconds(60), Map.of("sub", "alice", "source", "id"));
    final var principal =
        new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_USER")), idToken);
    when(tokenClaimsConverter.convert(anyMap()))
        .thenReturn(CamundaAuthentication.of(b -> b.user("alice")));

    converter.convert(
        new OAuth2AuthenticationToken(principal, principal.getAuthorities(), REGISTRATION_ID));

    @SuppressWarnings("unchecked")
    final ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
    verify(tokenClaimsConverter, org.mockito.Mockito.atLeastOnce()).convert(captor.capture());
    return captor.getValue();
  }

  private static ClientRegistration registration(
      final ScopedClientRegistrationFactory factory,
      final OidcTestServer idp,
      final Set<String> audiences) {
    final var config = idp.oidcConfiguration("client");
    config.setAudiences(audiences);
    return factory.createWithoutLoginRoutes(Map.of(REGISTRATION_ID, config)).getFirst();
  }
}
