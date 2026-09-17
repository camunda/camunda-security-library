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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

@ExtendWith(MockitoExtension.class)
class IssuerAwareJWSKeySelectorTest {

  @Mock private JWSKeySelectorFactory jwsKeySelectorFactory;
  @Mock private ClientRegistration clientRegistration;
  @Mock private ProviderDetails providerDetails;
  @Mock private JWSKeySelector<SecurityContext> keySelector;

  @Test
  void shouldThrowBadJwtKeySourceExceptionForUnknownIssuer() {
    when(clientRegistration.getProviderDetails()).thenReturn(providerDetails);
    when(providerDetails.getIssuerUri()).thenReturn("https://known-issuer");

    final var selector =
        new IssuerAwareJWSKeySelector(List.of(clientRegistration), jwsKeySelectorFactory);
    final var claims = new JWTClaimsSet.Builder().issuer("https://other-issuer").build();
    final var header = new JWSHeader(JWSAlgorithm.RS256);

    // The internal lookup throws IllegalArgumentException for unknown issuers; selectKeys must
    // wrap that as the BadJwtKeySourceException marker subtype so
    // OidcAccessTokenDecoderFactory maps it to BadJwtException → 401 invalid_token rather than
    // a generic 500.
    assertThatThrownBy(() -> selector.selectKeys(header, claims, null))
        .isInstanceOf(BadJwtKeySourceException.class)
        .hasMessageContaining("https://other-issuer");
  }

  @Test
  void shouldThrowBadJwtKeySourceExceptionForMissingIssuer() {
    final var selector = new IssuerAwareJWSKeySelector(List.of(), jwsKeySelectorFactory);
    final var claims = new JWTClaimsSet.Builder().build();
    final var header = new JWSHeader(JWSAlgorithm.RS256);

    // Missing 'iss' is a token-level fault — should use the marker subtype, not bare
    // KeySourceException, so the caller surfaces a 401 invalid_token rather than a 500.
    assertThatThrownBy(() -> selector.selectKeys(header, claims, null))
        .isInstanceOf(BadJwtKeySourceException.class)
        .hasMessageContaining("Missing or empty");
  }

  @Test
  void shouldTakeTheKeysOfTheFirstRegistrationOfASharedIssuerAndWarn() throws Exception {
    // given two registrations of one issuer, each with its own key set
    final var issuer = "https://shared-issuer";
    final var owner = registration("owner", issuer, "https://owner/jwks");
    final var loser = registration("loser", issuer, "https://loser/jwks");
    when(jwsKeySelectorFactory.createJWSKeySelector("https://owner/jwks", null))
        .thenReturn(keySelector);
    final var appender = attachAppender();

    try {
      // when a token of that issuer arrives
      final var selector =
          new IssuerAwareJWSKeySelector(List.of(owner, loser), jwsKeySelectorFactory);
      selector.selectKeys(
          new JWSHeader(JWSAlgorithm.RS256),
          new JWTClaimsSet.Builder().issuer(issuer).build(),
          null);

      // then the first registration verifies it, and the operator reads which key set the
      // selector therefore never asks
      verify(jwsKeySelectorFactory).createJWSKeySelector("https://owner/jwks", null);
      assertThat(appender.list)
          .anySatisfy(
              event -> {
                assertThat(event.getLevel()).isEqualTo(Level.WARN);
                assertThat(event.getFormattedMessage())
                    .contains(issuer)
                    .contains("'owner' wins")
                    .contains("ignore the JWK Set URI of 'loser'");
              });
    } finally {
      detachAppender(appender);
    }
  }

  private static ClientRegistration registration(
      final String registrationId, final String issuerUri, final String jwkSetUri) {
    return ClientRegistration.withRegistrationId(registrationId)
        .clientId("client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/cb")
        .authorizationUri(issuerUri + "/auth")
        .tokenUri(issuerUri + "/token")
        .jwkSetUri(jwkSetUri)
        .issuerUri(issuerUri)
        .build();
  }

  private static ListAppender<ILoggingEvent> attachAppender() {
    final var logger = (Logger) LoggerFactory.getLogger(IssuerAwareJWSKeySelector.class);
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private static void detachAppender(final ListAppender<ILoggingEvent> appender) {
    ((Logger) LoggerFactory.getLogger(IssuerAwareJWSKeySelector.class)).detachAppender(appender);
  }
}
