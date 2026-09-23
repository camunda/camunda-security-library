/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.KeySourceException;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

@ExtendWith(MockitoExtension.class)
class OidcAccessTokenDecoderFactoryTest {

  @Mock private JWSKeySelectorFactory jwsKeySelectorFactory;
  @Mock private TokenValidatorFactory tokenValidatorFactory;

  @Test
  void wrapMapsBadJwtKeySourceCausedJwtExceptionToBadJwtException() {
    // The delegate behaves like NimbusJwtDecoder when IssuerAwareJWSKeySelector throws
    // BadJwtKeySourceException for a token-level fault (unknown / missing iss): it catches the
    // KeySourceException (a JOSEException) and rewraps it as a generic JwtException — which
    // Spring Security would treat as a 500 service error rather than a 401 invalid_token.
    final var keySourceCause = new BadJwtKeySourceException("Unknown issuer 'https://nope'");
    final JwtDecoder delegate =
        token -> {
          throw new JwtException(
              "An error occurred while attempting to decode the Jwt: "
                  + keySourceCause.getMessage(),
              keySourceCause);
        };

    final var wrapped = OidcAccessTokenDecoderFactory.wrapKeySourceFailuresAsBadJwt(delegate);

    assertThatThrownBy(() -> wrapped.decode("any-token"))
        .isInstanceOf(BadJwtException.class)
        .hasCause(keySourceCause);
  }

  @Test
  void wrapPropagatesGenericKeySourceCausedJwtExceptionUnchanged() {
    // A plain KeySourceException — e.g. from CompositeJWKSource on JWKS fetch failure, or
    // Nimbus's RemoteJWKSet on network/IO errors — represents an infrastructure fault, NOT a
    // bad token. Mapping it to BadJwtException would surface IdP outages as misleading 401s
    // and hide the real problem from operators. Must stay a generic JwtException → 500.
    final var infrastructureCause =
        new KeySourceException("Couldn't retrieve JWK set", new IOException("connect timeout"));
    final var original =
        new JwtException(
            "An error occurred while attempting to decode the Jwt: "
                + infrastructureCause.getMessage(),
            infrastructureCause);
    final JwtDecoder delegate =
        token -> {
          throw original;
        };

    final var wrapped = OidcAccessTokenDecoderFactory.wrapKeySourceFailuresAsBadJwt(delegate);

    assertThatThrownBy(() -> wrapped.decode("any-token")).isSameAs(original);
  }

  @Test
  void wrapPropagatesBadJwtExceptionUnchanged() {
    // A BadJwtException from the delegate must pass through as-is — it's already the right
    // type for Spring Security's invalid_token mapping.
    final var original = new BadJwtException("malformed");
    final JwtDecoder delegate =
        token -> {
          throw original;
        };

    final var wrapped = OidcAccessTokenDecoderFactory.wrapKeySourceFailuresAsBadJwt(delegate);

    assertThatThrownBy(() -> wrapped.decode("any-token")).isSameAs(original);
  }

  @Test
  void wrapPropagatesNonKeySourceJwtExceptionUnchanged() {
    // A JwtException with some other cause is *not* an authentication / bad-token problem and
    // should keep its semantic — e.g. a parser error or any other non-KeySourceException flow.
    final var cause = new RuntimeException("unexpected");
    final var original = new JwtException("Some other failure", cause);
    final JwtDecoder delegate =
        token -> {
          throw original;
        };

    final var wrapped = OidcAccessTokenDecoderFactory.wrapKeySourceFailuresAsBadJwt(delegate);

    assertThatThrownBy(() -> wrapped.decode("any-token")).isSameAs(original);
  }

  @Test
  void wrapPassesThroughSuccessfulDecode() {
    final var expected =
        Jwt.withTokenValue("tok")
            .header("alg", "RS256")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(60))
            .claims(c -> c.put("sub", "alice"))
            .build();
    final JwtDecoder delegate = token -> expected;

    final var wrapped = OidcAccessTokenDecoderFactory.wrapKeySourceFailuresAsBadJwt(delegate);

    assertThat(wrapped.decode("any-token")).isSameAs(expected);
  }

  @Test
  void wrapHandlesIndirectBadJwtKeySourceCauseOnlyAtImmediateLevel() {
    // The NimbusJwtDecoder behaviour we observe in practice always puts the
    // BadJwtKeySourceException as the *immediate* cause of the JwtException. Anything deeper
    // is a different failure shape we don't want to misclassify, so the wrap only inspects
    // ex.getCause().
    final var deepCause = new BadJwtKeySourceException("buried");
    final var middle = new RuntimeException("intermediate", deepCause);
    final var jwtException = new JwtException("decode failed", middle);
    final JwtDecoder delegate =
        token -> {
          throw jwtException;
        };

    final var wrapped = OidcAccessTokenDecoderFactory.wrapKeySourceFailuresAsBadJwt(delegate);

    assertThatThrownBy(() -> wrapped.decode("any-token")).isSameAs(jwtException);
  }

  @Test
  void shouldTakeTheAdditionalJwkSetUrisOfTheFirstRegistrationOfASharedIssuerAndWarn() {
    // given two registrations of one issuer, and additional key sets on each of them
    final var issuer = "https://shared-issuer";
    final var registrations =
        List.of(
            registration("owner", issuer, "https://owner/jwks"),
            registration("loser", issuer, "https://loser/jwks"));
    final var providers =
        Map.of(
            "owner", providerConfiguration(issuer, "https://owner/extra-jwks"),
            "loser", providerConfiguration(issuer, "https://loser/extra-jwks"));
    final var factory =
        new OidcAccessTokenDecoderFactory(jwsKeySelectorFactory, tokenValidatorFactory);
    final var appender = attachAppender();

    try {
      // when
      assertThat(factory.selectAccessTokenDecoder(registrations, providers)).isNotNull();

      // then the operator reads that the key sets of the second registration verify no token of
      // that issuer, which would otherwise let it sign tokens the decoder accepts
      assertThat(appender.list)
          .anySatisfy(
              event -> {
                assertThat(event.getLevel()).isEqualTo(Level.WARN);
                assertThat(event.getFormattedMessage())
                    .contains(issuer)
                    .contains("'owner' wins")
                    .contains("ignore the additional JWK Set URIs of 'loser'");
              });
    } finally {
      detachAppender(appender);
    }
  }

  @Test
  void shouldNotThrowOnANullRegistrationIdAmongMultipleProviders() {
    // given a provider map with a blank/null registrationId — warn-only, not rejected — alongside
    // a valid one, selecting the issuer-aware decoder must not let the null key reach
    // IssuerRegistrations.ofConfiguration's Map.copyOf and abort
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    final var providerA = new OidcConfiguration();
    providerA.setIssuerUri("https://idp-a.example");
    final var providerB = new OidcConfiguration();
    providerB.setIssuerUri("https://idp-b.example");
    providers.put(null, providerA);
    providers.put("b", providerB);
    final var factory =
        new OidcAccessTokenDecoderFactory(jwsKeySelectorFactory, tokenValidatorFactory);

    assertThatCode(() -> factory.selectAccessTokenDecoder(providers, registrationId -> null))
        .doesNotThrowAnyException();
  }

  @Test
  void shouldNotCountABlankRegistrationIdTowardsTheIssuerRequirement() {
    // given one real provider with an issuer-uri and a blank-registrationId leftover with none —
    // the blank entry must not count towards the multi-provider issuer requirement, or a
    // single-provider deployment aborts startup naming no provider at all
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    final var real = new OidcConfiguration();
    real.setIssuerUri("https://idp-a.example");
    providers.put("a", real);
    providers.put(null, new OidcConfiguration());
    final var factory =
        new OidcAccessTokenDecoderFactory(jwsKeySelectorFactory, tokenValidatorFactory);

    assertThatCode(() -> factory.validateProvidersHaveIssuer(providers)).doesNotThrowAnyException();
  }

  @Test
  void shouldUseTheSameFilteredProviderViewForJwkSetUrisAsForIssuerRegistrations() {
    // given a blank-registrationId provider and a valid one sharing an issuer, the blank one
    // first — before this fix, buildAdditionalJwkSetUrisByIssuer read the unfiltered map and could
    // pick the blank provider as issuer owner while IssuerRegistrations picked "b", letting "b"'s
    // tokens be checked against the blank provider's additional JWK Set URIs
    final var issuer = "https://shared.example";
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put(null, providerConfiguration(issuer, "https://blank/extra-jwks"));
    providers.put("b", providerConfiguration(issuer, "https://b/extra-jwks"));
    final var factory =
        new OidcAccessTokenDecoderFactory(jwsKeySelectorFactory, tokenValidatorFactory);
    final var appender = attachAppender();

    try {
      factory.selectAccessTokenDecoder(providers, registrationId -> null);

      // then no duplicate-issuer warning fires for the additional-JWK-set pass — the blank
      // provider never entered ownership resolution to begin with, agreeing with the filtered view
      // IssuerRegistrations uses
      assertThat(appender.list)
          .noneSatisfy(
              event ->
                  assertThat(event.getFormattedMessage())
                      .contains("ignore the additional JWK Set URIs"));
    } finally {
      detachAppender(appender);
    }
  }

  private static ClientRegistration registration(
      final String registrationId, final String issuerUri, final String jwkSetUri) {
    return ClientRegistration.withRegistrationId(registrationId)
        .clientId("client-" + registrationId)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .tokenUri(issuerUri + "/token")
        .jwkSetUri(jwkSetUri)
        .issuerUri(issuerUri)
        .build();
  }

  private static OidcConfiguration providerConfiguration(
      final String issuerUri, final String additionalJwkSetUri) {
    final var configuration = new OidcConfiguration();
    configuration.setIssuerUri(issuerUri);
    configuration.setAdditionalJwkSetUris(List.of(additionalJwkSetUri));
    return configuration;
  }

  private static ListAppender<ILoggingEvent> attachAppender() {
    final var logger = (Logger) LoggerFactory.getLogger(OidcAccessTokenDecoderFactory.class);
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private static void detachAppender(final ListAppender<ILoggingEvent> appender) {
    ((Logger) LoggerFactory.getLogger(OidcAccessTokenDecoderFactory.class))
        .detachAppender(appender);
  }
}
