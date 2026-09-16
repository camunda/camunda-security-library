/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.camunda.security.api.context.OidcClaimsProvider;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.spring.oidc.OidcTestServer;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

@ExtendWith(MockitoExtension.class)
class OidcTokenAuthenticationConverterTest {

  @Mock private LazyTokenClaimsConverter tokenClaimsConverter;
  @Mock private OidcClaimsProvider claimsProvider;
  @InjectMocks private OidcTokenAuthenticationConverter converter;

  @Test
  void supportsJwtAuthenticationToken() {
    assertThat(converter.supports(mock(JwtAuthenticationToken.class))).isTrue();
  }

  @Test
  void doesNotSupportOAuth2AuthenticationToken() {
    assertThat(converter.supports(mock(OAuth2AuthenticationToken.class))).isFalse();
  }

  @Test
  void passesJwtClaimsThroughProviderToConverter() {
    final var jwt =
        Jwt.withTokenValue("token").header("alg", "RS256").claim("sub", "alice").build();
    final var authentication = new JwtAuthenticationToken(jwt);
    when(claimsProvider.claimsFor(jwt.getClaims(), "token")).thenReturn(jwt.getClaims());
    final var expected = CamundaAuthentication.of(b -> b.user("alice"));
    when(tokenClaimsConverter.convert(jwt.getClaims())).thenReturn(expected);

    assertThat(converter.convert(authentication)).isSameAs(expected);
  }

  @Test
  void usesAugmentedClaimsFromProviderForConversion() {
    final var jwt =
        Jwt.withTokenValue("token").header("alg", "RS256").claim("sub", "alice").build();
    final var authentication = new JwtAuthenticationToken(jwt);
    final Map<String, Object> augmented = Map.of("sub", "alice", "groups", List.of("eng"));
    when(claimsProvider.claimsFor(any(), eq("token"))).thenReturn(augmented);
    final var expected = CamundaAuthentication.of(b -> b.user("alice"));
    when(tokenClaimsConverter.convert(augmented)).thenReturn(expected);

    assertThat(converter.convert(authentication)).isSameAs(expected);
  }

  @Test
  void throwsOAuth2AuthenticationExceptionWhenNeitherClaimPresent() {
    final var jwt = Jwt.withTokenValue("token").header("alg", "RS256").claim("x", "y").build();
    final var authentication = new JwtAuthenticationToken(jwt);
    when(claimsProvider.claimsFor(jwt.getClaims(), "token")).thenReturn(jwt.getClaims());
    when(tokenClaimsConverter.convert(jwt.getClaims()))
        .thenThrow(
            new IllegalArgumentException("Neither username claim nor client-id claim found"));

    assertThatThrownBy(() -> converter.convert(authentication))
        .isInstanceOfSatisfying(
            OAuth2AuthenticationException.class,
            ex ->
                assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN));
  }

  @Test
  void usesPerIssuerConverterWhenIssuerMatches() {
    final var perIssuerConverter = mock(LazyTokenClaimsConverter.class);
    final var jwt =
        Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .claim("iss", "https://entra.example.com")
            .claim("sub", "alice")
            .build();
    final var authentication = new JwtAuthenticationToken(jwt);
    final var issuerAwareConverter =
        new OidcTokenAuthenticationConverter(
            tokenClaimsConverter,
            claimsProvider,
            new TokenClaimsConvertersByIssuer(
                Map.of("https://entra.example.com", perIssuerConverter)));
    when(claimsProvider.claimsFor(jwt.getClaims(), "token")).thenReturn(jwt.getClaims());
    final var expected = CamundaAuthentication.of(b -> b.user("alice"));
    when(perIssuerConverter.convert(jwt.getClaims())).thenReturn(expected);

    assertThat(issuerAwareConverter.convert(authentication)).isSameAs(expected);
    verifyNoInteractions(tokenClaimsConverter);
  }

  @Test
  void fallsBackToDefaultConverterWhenIssuerDoesNotMatchAnyEntry() {
    final var perIssuerConverter = mock(LazyTokenClaimsConverter.class);
    final var jwt =
        Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .claim("iss", "https://auth0.example.com")
            .claim("sub", "alice")
            .build();
    final var authentication = new JwtAuthenticationToken(jwt);
    final var issuerAwareConverter =
        new OidcTokenAuthenticationConverter(
            tokenClaimsConverter,
            claimsProvider,
            new TokenClaimsConvertersByIssuer(
                Map.of("https://entra.example.com", perIssuerConverter)));
    when(claimsProvider.claimsFor(jwt.getClaims(), "token")).thenReturn(jwt.getClaims());
    final var expected = CamundaAuthentication.of(b -> b.user("alice"));
    when(tokenClaimsConverter.convert(jwt.getClaims())).thenReturn(expected);

    assertThat(issuerAwareConverter.convert(authentication)).isSameAs(expected);
    verifyNoInteractions(perIssuerConverter);
  }

  @Test
  void fallsBackToDefaultConverterWhenIssuerClaimIsAbsent() {
    final var perIssuerConverter = mock(LazyTokenClaimsConverter.class);
    final var jwt =
        Jwt.withTokenValue("token").header("alg", "RS256").claim("sub", "alice").build();
    final var authentication = new JwtAuthenticationToken(jwt);
    final var issuerAwareConverter =
        new OidcTokenAuthenticationConverter(
            tokenClaimsConverter,
            claimsProvider,
            new TokenClaimsConvertersByIssuer(
                Map.of("https://entra.example.com", perIssuerConverter)));
    when(claimsProvider.claimsFor(jwt.getClaims(), "token")).thenReturn(jwt.getClaims());
    final var expected = CamundaAuthentication.of(b -> b.user("alice"));
    when(tokenClaimsConverter.convert(jwt.getClaims())).thenReturn(expected);

    assertThat(issuerAwareConverter.convert(authentication)).isSameAs(expected);
    verifyNoInteractions(perIssuerConverter);
  }

  @Test
  void matchesIssuerFromARealDecodedBearerToken() throws Exception {
    // Decodes an actually-signed token through a real NimbusJwtDecoder (the same construction
    // OidcAccessTokenDecoderFactory uses), rather than a hand-built claims map, to prove the
    // decoder-to-converter boundary itself works. This decoder normalizes 'iss' to a String (see
    // MappedJwtClaimSetConverter#convertIssuer) — the java.net.URL case only comes from a
    // host-supplied JwtDecoder with its own claim-set converter, covered separately below.
    try (final var server = OidcTestServer.startRsa("entra-kid")) {
      final var decoder = NimbusJwtDecoder.withJwkSetUri(server.jwksUri()).build();
      final var jwt = decoder.decode(server.sign(server.issuerUri()));
      assertThat(jwt.getClaims().get(JwtClaimNames.ISS)).isInstanceOf(String.class);

      final var perIssuerConverter = mock(LazyTokenClaimsConverter.class);
      final var authentication = new JwtAuthenticationToken(jwt);
      final var issuerAwareConverter =
          new OidcTokenAuthenticationConverter(
              tokenClaimsConverter,
              claimsProvider,
              new TokenClaimsConvertersByIssuer(Map.of(server.issuerUri(), perIssuerConverter)));
      when(claimsProvider.claimsFor(jwt.getClaims(), jwt.getTokenValue()))
          .thenReturn(jwt.getClaims());
      final var expected = CamundaAuthentication.of(b -> b.user("alice"));
      when(perIssuerConverter.convert(jwt.getClaims())).thenReturn(expected);

      assertThat(issuerAwareConverter.convert(authentication)).isSameAs(expected);
      verifyNoInteractions(tokenClaimsConverter);
    }
  }

  @Test
  void matchesIssuerWhenClaimIsStoredAsUrl() throws Exception {
    // A URL-typed 'iss' isn't produced by this library's own bearer-token decoder (see the real
    // decode test above), but a host-supplied JwtDecoder bean could configure its own claim-set
    // converter and store one — and Jwt#getIssuer() always returns URL regardless of the raw
    // claim's stored type. The lookup must tolerate that representation too.
    final var perIssuerConverter = mock(LazyTokenClaimsConverter.class);
    final var jwt =
        Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .claim("iss", URI.create("https://entra.example.com").toURL())
            .claim("sub", "alice")
            .build();
    final var authentication = new JwtAuthenticationToken(jwt);
    final var issuerAwareConverter =
        new OidcTokenAuthenticationConverter(
            tokenClaimsConverter,
            claimsProvider,
            new TokenClaimsConvertersByIssuer(
                Map.of("https://entra.example.com", perIssuerConverter)));
    when(claimsProvider.claimsFor(jwt.getClaims(), "token")).thenReturn(jwt.getClaims());
    final var expected = CamundaAuthentication.of(b -> b.user("alice"));
    when(perIssuerConverter.convert(jwt.getClaims())).thenReturn(expected);

    assertThat(issuerAwareConverter.convert(authentication)).isSameAs(expected);
    verifyNoInteractions(tokenClaimsConverter);
  }

  @Test
  void treatsNullConvertersRecordAsEmpty() {
    final var jwt =
        Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .claim("iss", "https://auth0.example.com")
            .claim("sub", "alice")
            .build();
    final var authentication = new JwtAuthenticationToken(jwt);
    final var issuerAwareConverter =
        new OidcTokenAuthenticationConverter(tokenClaimsConverter, claimsProvider, null);
    when(claimsProvider.claimsFor(jwt.getClaims(), "token")).thenReturn(jwt.getClaims());
    final var expected = CamundaAuthentication.of(b -> b.user("alice"));
    when(tokenClaimsConverter.convert(jwt.getClaims())).thenReturn(expected);

    assertThat(issuerAwareConverter.convert(authentication)).isSameAs(expected);
  }

  @Test
  void logsDebugWithDefaultLabelWhenIssuerHasNoEntry() {
    final var appender = attachAppender();
    try {
      final var jwt =
          Jwt.withTokenValue("token")
              .header("alg", "RS256")
              .claim("iss", "https://auth0.example.com")
              .claim("sub", "alice")
              .build();
      final var authentication = new JwtAuthenticationToken(jwt);
      when(claimsProvider.claimsFor(jwt.getClaims(), "token")).thenReturn(jwt.getClaims());
      when(tokenClaimsConverter.convert(jwt.getClaims()))
          .thenReturn(CamundaAuthentication.of(b -> b.user("alice")));

      converter.convert(authentication);

      assertThat(appender.list)
          .anySatisfy(
              event -> {
                assertThat(event.getLevel()).isEqualTo(Level.DEBUG);
                assertThat(event.getFormattedMessage())
                    .contains("https://auth0.example.com")
                    .contains("default");
              });
    } finally {
      detachAppender(appender);
    }
  }

  @Test
  void logsDebugWithIssuerSpecificLabelWhenIssuerMatches() {
    final var appender = attachAppender();
    try {
      final var perIssuerConverter = mock(LazyTokenClaimsConverter.class);
      final var jwt =
          Jwt.withTokenValue("token")
              .header("alg", "RS256")
              .claim("iss", "https://entra.example.com")
              .claim("sub", "alice")
              .build();
      final var authentication = new JwtAuthenticationToken(jwt);
      final var issuerAwareConverter =
          new OidcTokenAuthenticationConverter(
              tokenClaimsConverter,
              claimsProvider,
              new TokenClaimsConvertersByIssuer(
                  Map.of("https://entra.example.com", perIssuerConverter)));
      when(claimsProvider.claimsFor(jwt.getClaims(), "token")).thenReturn(jwt.getClaims());
      when(perIssuerConverter.convert(jwt.getClaims()))
          .thenReturn(CamundaAuthentication.of(b -> b.user("alice")));

      issuerAwareConverter.convert(authentication);

      assertThat(appender.list)
          .anySatisfy(
              event -> {
                assertThat(event.getLevel()).isEqualTo(Level.DEBUG);
                assertThat(event.getFormattedMessage())
                    .contains("https://entra.example.com")
                    .contains("issuer-specific");
              });
    } finally {
      detachAppender(appender);
    }
  }

  private static ListAppender<ILoggingEvent> attachAppender() {
    final Logger logger = (Logger) LoggerFactory.getLogger(OidcTokenAuthenticationConverter.class);
    logger.setLevel(Level.DEBUG);
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private static void detachAppender(final ListAppender<ILoggingEvent> appender) {
    final Logger logger = (Logger) LoggerFactory.getLogger(OidcTokenAuthenticationConverter.class);
    logger.detachAppender(appender);
    logger.setLevel(null);
  }
}
