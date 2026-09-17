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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Unit tests for {@link IssuerRegistrations}, the source an issuer-aware decoder takes the
 * registration of a token's issuer from.
 */
final class IssuerRegistrationsTest {

  private static final Map<String, OidcConfiguration> TWO_PROVIDERS =
      Map.of(
          "provider-a", provider("https://issuer-a.example"),
          "provider-b", provider("https://issuer-b.example"));

  @Test
  void shouldResolveTheIssuerOfTheTokenOnly() {
    // given two configured providers
    final var resolutions = new ArrayList<String>();
    final var registrations =
        IssuerRegistrations.ofConfiguration(TWO_PROVIDERS, recording(resolutions));

    // when one issuer is looked up
    final var registration = registrations.forIssuer("https://issuer-a.example");

    // then the other provider is not resolved, so it cannot fail the lookup
    assertThat(registration.getRegistrationId()).isEqualTo("provider-a");
    assertThat(resolutions).containsExactly("provider-a");
  }

  @Test
  void shouldKeepARegistrationAfterASuccessfulResolution() {
    final var resolutions = new ArrayList<String>();
    final var registrations =
        IssuerRegistrations.ofConfiguration(TWO_PROVIDERS, recording(resolutions));

    final var first = registrations.forIssuer("https://issuer-a.example");
    final var second = registrations.forIssuer("https://issuer-a.example");

    // the second token of the issuer makes no discovery of its own
    assertThat(second).isSameAs(first);
    assertThat(resolutions).containsExactly("provider-a");
  }

  @Test
  void shouldResolveAgainAfterAFailedResolution() {
    // given a provider that does not answer the first lookup
    final var attempts = new ArrayList<String>();
    final var registrations =
        IssuerRegistrations.ofConfiguration(
            TWO_PROVIDERS,
            registrationId -> {
              attempts.add(registrationId);
              if (attempts.size() == 1) {
                throw new IllegalArgumentException("unreachable");
              }
              return registration(registrationId, "https://issuer-a.example");
            });

    // when the first lookup fails
    assertThatThrownBy(() -> registrations.forIssuer("https://issuer-a.example"))
        .isInstanceOf(IllegalArgumentException.class);

    // then the next lookup makes a new attempt, so the provider needs no restart
    assertThat(registrations.forIssuer("https://issuer-a.example").getRegistrationId())
        .isEqualTo("provider-a");
    assertThat(attempts).hasSize(2);
  }

  @Test
  void shouldGiveNoRegistrationForAnIssuerNoProviderDeclares() {
    final var registrations =
        IssuerRegistrations.ofConfiguration(
            TWO_PROVIDERS, IssuerRegistrationsTest::noResolutionExpected);

    // the caller answers such a token as a refused credential, so the lookup gives no registration
    // instead of a failure
    assertThat(registrations.forIssuer("https://other.example")).isNull();
  }

  @Test
  void shouldFailWhenTheRepositoryGivesNoRegistrationOfADeclaredIssuer() {
    // given a repository that holds no registration under the registrationId of a declared issuer
    final var registrations =
        IssuerRegistrations.ofConfiguration(TWO_PROVIDERS, registrationId -> null);

    // then the token names an accepted issuer, so the repository is the reason, and the lookup must
    // not give the answer of an issuer no provider declares, which reads as a refused credential
    assertThatThrownBy(() -> registrations.forIssuer("https://issuer-a.example"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("provider-a")
        .hasMessageContaining("https://issuer-a.example");
  }

  @Test
  void shouldRouteADuplicatedIssuerToTheFirstProviderOfTheMap() {
    // given two providers of the same issuer, in the order of the configuration
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put("provider-a", provider("https://shared.example"));
    providers.put("provider-b", provider("https://shared.example"));
    final var resolutions = new ArrayList<String>();

    final var registrations =
        IssuerRegistrations.ofConfiguration(providers, recording(resolutions));
    final var registration = registrations.forIssuer("https://shared.example");

    // then the first provider of the configuration verifies the tokens of the issuer, so the keys a
    // token reaches are the keys of the provider that every other stage of the request reads
    assertThat(registration.getRegistrationId()).isEqualTo("provider-a");
    assertThat(resolutions).containsExactly("provider-a");
  }

  @Test
  void shouldAcceptNoIssuerOfAProviderThatDeclaresNone() {
    final var providers =
        Map.of("provider-a", provider("https://issuer-a.example"), "provider-b", provider(null));

    final var registrations =
        IssuerRegistrations.ofConfiguration(
            providers, IssuerRegistrationsTest::noResolutionExpected);

    assertThat(registrations.issuers()).containsExactly("https://issuer-a.example");
  }

  @Test
  void shouldTakeTheIssuersFromResolvedRegistrations() {
    final var registration = registration("provider-a", "https://issuer-a.example");

    final var registrations = IssuerRegistrations.ofResolved(List.of(registration));

    assertThat(registrations.issuers()).containsExactly("https://issuer-a.example");
    assertThat(registrations.forIssuer("https://issuer-a.example")).isSameAs(registration);
    assertThat(registrations.forIssuer("https://issuer-b.example")).isNull();
  }

  private static Function<String, ClientRegistration> recording(final List<String> resolutions) {
    return registrationId -> {
      resolutions.add(registrationId);
      return registration(registrationId, "https://" + registrationId + ".example");
    };
  }

  private static ClientRegistration noResolutionExpected(final String registrationId) {
    throw new AssertionError(
        "resolved '%s', which the lookup must not need".formatted(registrationId));
  }

  private static OidcConfiguration provider(final String issuerUri) {
    return OidcConfiguration.builder()
        .clientId("client")
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .issuerUri(issuerUri)
        .authorizationUri("https://idp.example/auth")
        .tokenUri("https://idp.example/token")
        .jwkSetUri("https://idp.example/jwks")
        .build();
  }

  private static ClientRegistration registration(
      final String registrationId, final String issuerUri) {
    return ClientRegistration.withRegistrationId(registrationId)
        .clientId("client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .authorizationUri("https://idp.example/auth")
        .tokenUri("https://idp.example/token")
        .jwkSetUri("https://idp.example/jwks")
        .issuerUri(issuerUri)
        .build();
  }
}
