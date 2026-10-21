/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

@ExtendWith(MockitoExtension.class)
class RegisteredIssuerClaimsConvertersTest {

  private static final String ISSUER = "https://idp.example.com/realm";

  @Mock private LazyTokenClaimsConverter firstConverter;
  @Mock private LazyTokenClaimsConverter secondConverter;

  @Test
  void shouldRouteByTheIssuerTheRegistrationCarries() {
    // given - configured as ISSUER + "/", resolved to ISSUER
    final var converters =
        new RegisteredIssuerClaimsConverters(
            List.of(registration("a", ISSUER)), Map.of("a", firstConverter));

    // when / then
    assertThat(converters.apply(ISSUER)).isSameAs(firstConverter);
    assertThat(converters.apply(ISSUER + "/")).isNull();
  }

  /** The decoder routes a shared issuer to the first registration, so the converters do too. */
  @Test
  void shouldGiveASharedIssuerTheConverterOfTheFirstRegistration() {
    // given
    final var converters =
        new RegisteredIssuerClaimsConverters(
            List.of(registration("first", ISSUER), registration("second", ISSUER)),
            Map.of("first", firstConverter, "second", secondConverter));

    // when / then
    assertThat(converters.apply(ISSUER)).isSameAs(firstConverter);
  }

  /**
   * The first registration of an issuer is not configured: its tokens get no converter, so the
   * default one, and not that of a later registration of the issuer.
   */
  @Test
  void shouldNotGiveTheConverterOfALaterRegistrationToAnUnconfiguredOwner() {
    // given
    final var converters =
        new RegisteredIssuerClaimsConverters(
            List.of(registration("host-only", ISSUER), registration("second", ISSUER)),
            Map.of("second", secondConverter));

    // when / then
    assertThat(converters.apply(ISSUER)).isNull();
  }

  @Test
  void shouldReadTheRegistrationsOnTheFirstLookupOnly() {
    // given
    final var iterations = new AtomicInteger();
    final Iterable<ClientRegistration> registrations =
        () -> {
          iterations.incrementAndGet();
          return List.of(registration("a", ISSUER)).iterator();
        };

    // when
    final var converters =
        new RegisteredIssuerClaimsConverters(registrations, Map.of("a", firstConverter));

    // then
    assertThat(iterations).hasValue(0);
    converters.apply(ISSUER);
    converters.apply("https://other.example.com");
    assertThat(iterations).hasValue(1);
  }

  private static ClientRegistration registration(final String registrationId, final String issuer) {
    return ClientRegistration.withRegistrationId(registrationId)
        .clientId("client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/sso-callback")
        .authorizationUri(issuer + "/auth")
        .tokenUri(issuer + "/token")
        .jwkSetUri(issuer + "/" + registrationId + "/jwks")
        .issuerUri(issuer)
        .build();
  }
}
