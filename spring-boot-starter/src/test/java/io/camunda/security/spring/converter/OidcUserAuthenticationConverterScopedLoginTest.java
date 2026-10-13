/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
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
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
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
 * ScopedClientRegistrationFactory}. The outcome must not depend on which scope logs in first, and
 * the host passes no scope: each login's own registration carries its settings.
 */
@ExtendWith(MockitoExtension.class)
final class OidcUserAuthenticationConverterScopedLoginTest {

  private static final String REGISTRATION_ID = "oidc";
  private static final String SCOPE_A = "scope-a";
  private static final String SCOPE_B = "scope-b";

  @Mock private LazyTokenClaimsConverter tokenClaimsConverter;
  @Mock private OAuth2AuthorizedClientRepository authorizedClientRepository;
  @Mock private HttpServletRequest request;

  private final ScopedClientRegistrationFactory registrationFactory =
      new ScopedClientRegistrationFactory();
  private final Map<String, ClientRegistration> registrationByScope = new HashMap<>();
  private final Map<String, String> accessTokens = new HashMap<>();
  private String currentScope;

  private OidcTestServer idpA;
  private OidcTestServer idpB;
  private OidcUserAuthenticationConverter converter;

  @BeforeEach
  void setUp() throws Exception {
    idpA = OidcTestServer.startRsa("key-a");
    idpB = OidcTestServer.startRsa("key-b");
    registrationByScope.put(SCOPE_A, registration(idpA, null, false));
    registrationByScope.put(SCOPE_B, registration(idpB, Set.of("audience-x"), false));

    when(authorizedClientRepository.loadAuthorizedClient(eq(REGISTRATION_ID), any(), any()))
        .thenAnswer(
            invocation ->
                new OAuth2AuthorizedClient(
                    registrationByScope.get(currentScope),
                    "alice",
                    new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER,
                        accessTokens.get(currentScope),
                        Instant.now(),
                        Instant.now().plusSeconds(60))));
    converter = converter(Map.of());
  }

  @AfterEach
  void tearDown() {
    if (idpA != null) {
      idpA.stop();
    }
    if (idpB != null) {
      idpB.stop();
    }
  }

  static Stream<List<String>> loginOrders() {
    return Stream.of(List.of(SCOPE_A, SCOPE_B), List.of(SCOPE_B, SCOPE_A));
  }

  @ParameterizedTest
  @MethodSource("loginOrders")
  void shouldDecodeEachScopesAccessTokenWithItsOwnIssuerAndKeys(final List<String> order)
      throws Exception {
    // given each token carries a claim that only its own scope's keys can verify
    accessTokens.put(SCOPE_A, idpA.sign(idpA.issuerUri(), Map.of("scope", SCOPE_A)));
    accessTokens.put(
        SCOPE_B, idpB.sign(idpB.issuerUri(), Map.of("scope", SCOPE_B, "aud", "audience-x")));

    for (final var scope : order) {
      // when
      final var claims = login(scope);

      // then
      assertThat(claims).as("claims of %s", scope).containsEntry("scope", scope);
    }
  }

  @ParameterizedTest
  @MethodSource("loginOrders")
  void shouldRejectAnAccessTokenWithoutTheAudienceOfItsOwnScope(final List<String> order)
      throws Exception {
    // given scope B requires audience-x, and its token, signed by B's own IdP, does not carry it
    accessTokens.put(SCOPE_A, idpA.sign(idpA.issuerUri(), Map.of("scope", SCOPE_A)));
    accessTokens.put(SCOPE_B, idpB.sign(idpB.issuerUri(), Map.of("scope", SCOPE_B)));

    for (final var scope : order) {
      // when
      final var claims = login(scope);

      // then
      if (SCOPE_B.equals(scope)) {
        assertThat(claims).containsEntry("source", "id").doesNotContainKey("scope");
      } else {
        assertThat(claims).containsEntry("scope", SCOPE_A);
      }
    }
  }

  @ParameterizedTest
  @MethodSource("loginOrders")
  void shouldApplyPreferIdTokenClaimsOfEachScope(final List<String> order) throws Exception {
    // given only scope A prefers the ID token claims
    registrationByScope.put(SCOPE_A, registration(idpA, null, true));
    accessTokens.put(SCOPE_A, idpA.sign(idpA.issuerUri(), Map.of("scope", SCOPE_A)));
    accessTokens.put(
        SCOPE_B, idpB.sign(idpB.issuerUri(), Map.of("scope", SCOPE_B, "aud", "audience-x")));

    for (final var scope : order) {
      // when
      final var claims = login(scope);

      // then
      if (SCOPE_A.equals(scope)) {
        assertThat(claims).containsEntry("source", "id");
      } else {
        assertThat(claims).containsEntry("scope", SCOPE_B);
      }
    }
  }

  @Test
  void shouldLetAFalseRegistrationEntryWinOverATrueHostLookup() throws Exception {
    // given the host map says prefer for "oidc", but the registration of scope B says no
    converter = converter(Map.of(REGISTRATION_ID, true));
    accessTokens.put(
        SCOPE_B, idpB.sign(idpB.issuerUri(), Map.of("scope", SCOPE_B, "aud", "audience-x")));

    // when
    final var claims = login(SCOPE_B);

    // then
    assertThat(claims).containsEntry("scope", SCOPE_B);
  }

  @Test
  void shouldLetATrueRegistrationEntryWinOverAFalseHostLookup() throws Exception {
    // given the host map says no for "oidc", but the registration of scope A says prefer
    registrationByScope.put(SCOPE_A, registration(idpA, null, true));
    converter = converter(Map.of(REGISTRATION_ID, false));
    accessTokens.put(SCOPE_A, idpA.sign(idpA.issuerUri(), Map.of("scope", SCOPE_A)));

    // when
    final var claims = login(SCOPE_A);

    // then
    assertThat(claims).containsEntry("source", "id");
  }

  private OidcUserAuthenticationConverter converter(
      final Map<String, Boolean> preferByRegistration) {
    // The host's validator factory knows no provider; the registration of each scope carries its
    // own issuer and audiences.
    final var decoderFactory =
        new OidcAccessTokenDecoderFactory(
            new JWSKeySelectorFactory(),
            new TokenValidatorFactory(Map.of(), OidcConfiguration.DEFAULT_CLOCK_SKEW, List.of()));
    return new OidcUserAuthenticationConverter(
        authorizedClientRepository,
        decoderFactory,
        tokenClaimsConverter,
        request,
        AdditionalJwkSetUrisByRegistrationId.empty(),
        preferByRegistration);
  }

  private Map<String, Object> login(final String scope) {
    currentScope = scope;
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
    verify(tokenClaimsConverter, atLeastOnce()).convert(captor.capture());
    return captor.getValue();
  }

  private ClientRegistration registration(
      final OidcTestServer idp, final Set<String> audiences, final boolean preferIdTokenClaims) {
    final var config = idp.oidcConfiguration("client");
    config.setAudiences(audiences);
    config.setPreferIdTokenClaims(preferIdTokenClaims);
    return registrationFactory.createWithoutLoginRoutes(Map.of(REGISTRATION_ID, config)).getFirst();
  }
}
