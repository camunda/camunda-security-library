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
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.spring.oidc.OidcAccessTokenDecoderFactory;
import io.camunda.security.spring.oidc.TokenValidatorFactory;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * Regression test for camunda-security-library#720: one converter serves every scope, and scopes
 * that share a registration id must not share an access-token decoder, additional JWK Set URIs or
 * the {@code prefer-id-token-claims} setting.
 */
@ExtendWith(MockitoExtension.class)
final class OidcUserAuthenticationConverterScopeTest {

  private static final String REGISTRATION_ID = "oidc";

  @Mock private OAuth2AuthorizedClientRepository authorizedClientRepository;
  @Mock private OidcAccessTokenDecoderFactory decoderFactory;
  @Mock private LazyTokenClaimsConverter tokenClaimsConverter;
  @Mock private HttpServletRequest request;
  @Mock private OidcLoginScopeResolver scopeResolver;
  @Mock private JwtDecoder decoderA;
  @Mock private JwtDecoder decoderB;

  private final AtomicReference<String> scope = new AtomicReference<>();
  private ListAppender<ILoggingEvent> logAppender;
  private Logger converterLogger;

  @BeforeEach
  void setUp() {
    converterLogger = (Logger) LoggerFactory.getLogger(OidcUserAuthenticationConverter.class);
    logAppender = new ListAppender<>();
    logAppender.start();
    converterLogger.addAppender(logAppender);
    lenient().when(scopeResolver.resolveScope(request)).thenAnswer(inv -> scope.get());
  }

  @AfterEach
  void tearDown() {
    converterLogger.detachAppender(logAppender);
    logAppender.stop();
  }

  @Test
  void shouldBuildOneDecoderPerScopeWhenScopesShareARegistrationId() {
    final var registration = registration("https://idp/jwks", null);
    scopeUris("a", List.of("jwks-a"));
    scopeUris("b", List.of("jwks-b"));
    when(decoderFactory.createAccessTokenDecoder(any(), eq(List.of("jwks-a"))))
        .thenReturn(decoderA);
    when(decoderFactory.createAccessTokenDecoder(any(), eq(List.of("jwks-b"))))
        .thenReturn(decoderB);
    when(decoderA.decode("token")).thenReturn(jwt());
    when(decoderB.decode("token")).thenReturn(jwt());
    stubClients(registration);
    final var converter = converter();

    scope.set("a");
    converter.convert(login());
    scope.set("b");
    converter.convert(login());
    scope.set("a");
    converter.convert(login());

    verify(decoderFactory, times(1)).createAccessTokenDecoder(any(), eq(List.of("jwks-a")));
    verify(decoderFactory, times(1)).createAccessTokenDecoder(any(), eq(List.of("jwks-b")));
  }

  @Test
  void shouldNotShareDecoderWhenTheFirstScopeHasNoAudienceAndTheSecondRequiresOne() {
    final var looser = registration("https://idp/jwks", Set.of());
    final var stricter = registration("https://idp/jwks", Set.of("x"));
    scopeUris(null, null);
    when(decoderFactory.createAccessTokenDecoder(looser, null)).thenReturn(decoderA);
    when(decoderFactory.createAccessTokenDecoder(stricter, null)).thenReturn(decoderB);
    when(decoderA.decode("token")).thenReturn(jwt());
    when(decoderB.decode("token")).thenThrow(new JwtException("missing audience x"));
    stubClients(looser, stricter);
    final var converter = converter();

    converter.convert(login());
    converter.convert(login());

    verify(decoderA).decode("token");
    verify(decoderB).decode("token");
  }

  @Test
  void shouldNotShareDecoderBetweenRegistrationsWithDifferentJwkSetUris() {
    final var first = registration("https://a/jwks", null);
    final var second = registration("https://b/jwks", null);
    scopeUris(null, null);
    when(decoderFactory.createAccessTokenDecoder(first, null)).thenReturn(decoderA);
    when(decoderFactory.createAccessTokenDecoder(second, null)).thenReturn(decoderB);
    when(decoderA.decode("token")).thenReturn(jwt());
    when(decoderB.decode("token")).thenReturn(jwt());
    stubClients(first, second);
    final var converter = converter();

    converter.convert(login());
    converter.convert(login());

    verify(decoderA).decode("token");
    verify(decoderB).decode("token");
  }

  @Test
  void shouldResolvePreferIdTokenClaimsPerScope() {
    final var registration = registration("https://idp/jwks", null);
    when(scopeResolver.preferIdTokenClaims("a")).thenReturn(Map.of(REGISTRATION_ID, true));
    when(scopeResolver.preferIdTokenClaims("b")).thenReturn(Map.of());
    scopeUris("b", null);
    when(decoderFactory.createAccessTokenDecoder(registration, null)).thenReturn(decoderB);
    when(decoderB.decode("token")).thenReturn(jwt());
    stubClients(registration);
    final var converter = converter();

    scope.set("a");
    converter.convert(login());
    verify(decoderFactory, never()).createAccessTokenDecoder(any(), any());

    scope.set("b");
    converter.convert(login());
    verify(decoderFactory).createAccessTokenDecoder(registration, null);
  }

  @Test
  void shouldNameRegistrationAndScopeInTheFallbackWarnings() {
    final var registration = registration("https://idp/jwks", null);
    scope.set("scope-b");
    scopeUris("scope-b", null);
    when(decoderFactory.createAccessTokenDecoder(registration, null)).thenReturn(decoderA);
    when(decoderA.decode("token")).thenThrow(new JwtException("bad signature"));
    stubClients(registration);

    converter().convert(login());

    final var warnings =
        logAppender.list.stream()
            .filter(event -> event.getLevel() == Level.WARN)
            .map(ILoggingEvent::getFormattedMessage)
            .toList();
    assertThat(warnings)
        .hasSize(2)
        .allSatisfy(message -> assertThat(message).contains("'oidc'").contains("'scope-b'"));
  }

  @Test
  void shouldKeepUnscopedSettingsWhenNoResolverIsGiven() {
    final var registration = registration("https://idp/jwks", null);
    when(decoderFactory.createAccessTokenDecoder(registration, List.of("jwks-x")))
        .thenReturn(decoderA);
    when(decoderA.decode("token")).thenReturn(jwt());
    stubClients(registration);
    final var converter =
        new OidcUserAuthenticationConverter(
            authorizedClientRepository,
            decoderFactory,
            tokenClaimsConverter,
            request,
            new AdditionalJwkSetUrisByRegistrationId(Map.of(REGISTRATION_ID, List.of("jwks-x"))));

    converter.convert(login());

    verify(decoderFactory).createAccessTokenDecoder(registration, List.of("jwks-x"));
  }

  private OidcUserAuthenticationConverter converter() {
    return new OidcUserAuthenticationConverter(
        authorizedClientRepository, decoderFactory, tokenClaimsConverter, request, scopeResolver);
  }

  /** Declares the additional JWK Set URIs the resolver answers for {@code forScope}. */
  private void scopeUris(final String forScope, final List<String> uris) {
    final var lookup =
        uris == null
            ? AdditionalJwkSetUrisByRegistrationId.empty()
            : new AdditionalJwkSetUrisByRegistrationId(Map.of(REGISTRATION_ID, uris));
    when(scopeResolver.additionalJwkSetUris(forScope)).thenReturn(lookup);
  }

  /** Each login finds the next registration; the last one repeats. */
  private void stubClients(final ClientRegistration... registrations) {
    final var next = new AtomicInteger();
    when(authorizedClientRepository.loadAuthorizedClient(
            eq(REGISTRATION_ID), any(OAuth2AuthenticationToken.class), eq(request)))
        .thenAnswer(
            invocation -> {
              final var now = Instant.now();
              final var registration =
                  registrations[Math.min(next.getAndIncrement(), registrations.length - 1)];
              return new OAuth2AuthorizedClient(
                  registration,
                  "alice",
                  new OAuth2AccessToken(
                      OAuth2AccessToken.TokenType.BEARER, "token", now, now.plusSeconds(60)));
            });
    when(tokenClaimsConverter.convert(anyMap()))
        .thenReturn(CamundaAuthentication.of(b -> b.user("alice")));
  }

  private OAuth2AuthenticationToken login() {
    final var now = Instant.now();
    final var idToken =
        new OidcIdToken("id", now, now.plusSeconds(60), Map.of("sub", "alice", "source", "id"));
    final var principal =
        new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_USER")), idToken);
    return new OAuth2AuthenticationToken(principal, principal.getAuthorities(), REGISTRATION_ID);
  }

  private static Jwt jwt() {
    final var now = Instant.now();
    return new Jwt("token", now, now.plusSeconds(60), Map.of("alg", "RS256"), Map.of("sub", "a"));
  }

  private static ClientRegistration registration(
      final String jwkSetUri, final Set<String> audiences) {
    final var builder =
        ClientRegistration.withRegistrationId(REGISTRATION_ID)
            .clientId("client")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationUri("https://idp/auth")
            .tokenUri("https://idp/token")
            .jwkSetUri(jwkSetUri)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}");
    if (audiences != null) {
      builder.providerConfigurationMetadata(
          Map.of(TokenValidatorFactory.AUDIENCES_METADATA_KEY, audiences));
    }
    return builder.build();
  }
}
