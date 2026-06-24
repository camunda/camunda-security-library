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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.config.oidc.OidcUserInfoAugmentationConfiguration;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.spring.converter.OidcTokenAuthenticationConverter;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Integration test: wires a real {@link CachingOidcClaimsProvider} into the {@link
 * OidcTokenAuthenticationConverter} and verifies the fail-open invariant end-to-end — JWT claims
 * flow through unchanged when the UserInfo fetch fails, and the failure is recorded at ERROR.
 */
@ExtendWith(MockitoExtension.class)
class OidcClaimsAugmentationChainTest {

  private static final String ISSUER = "https://idp.example";
  private static final Map<String, String> URI_BY_ISSUER =
      Map.of(ISSUER, "https://idp.example/userinfo");

  @Mock private OidcUserInfoFetcher fetcher;
  @Mock private LazyTokenClaimsConverter tokenClaimsConverter;

  private OidcTokenAuthenticationConverter converter;
  private ListAppender<ILoggingEvent> logAppender;

  @BeforeEach
  void setUp() {
    final CachingOidcClaimsProvider provider =
        new CachingOidcClaimsProvider(
            fetcher, URI_BY_ISSUER, new OidcUserInfoAugmentationConfiguration(), null);
    converter = new OidcTokenAuthenticationConverter(tokenClaimsConverter, provider);

    final Logger logger = (Logger) LoggerFactory.getLogger(CachingOidcClaimsProvider.class);
    logAppender = new ListAppender<>();
    logAppender.start();
    logger.addAppender(logAppender);
  }

  @AfterEach
  void tearDown() {
    final Logger logger = (Logger) LoggerFactory.getLogger(CachingOidcClaimsProvider.class);
    logger.detachAppender(logAppender);
  }

  @Test
  void failOpenAndLogsErrorWhenUserInfoFetchFails() {
    when(fetcher.fetch(any(), any()))
        .thenThrow(new OidcUserInfoFetchException("503 Service Unavailable"));
    final Jwt jwt =
        Jwt.withTokenValue("bearer-token")
            .header("alg", "RS256")
            .claim("iss", ISSUER)
            .claim("sub", "alice")
            .claim("scope", "openid profile")
            .build();
    final var expected = CamundaAuthentication.of(b -> b.user("alice"));
    when(tokenClaimsConverter.convert(jwt.getClaims())).thenReturn(expected);

    final var result = converter.convert(new JwtAuthenticationToken(jwt));

    // Fail-open: JWT claims flow through unchanged; the authentication succeeds.
    assertThat(result).isSameAs(expected);
    verify(tokenClaimsConverter).convert(jwt.getClaims());

    // Failure is logged at ERROR with the issuer so it is diagnosable in production.
    assertThat(logAppender.list)
        .anySatisfy(
            event -> {
              assertThat(event.getLevel()).isEqualTo(Level.ERROR);
              assertThat(event.getFormattedMessage()).contains(ISSUER);
            });
  }
}
