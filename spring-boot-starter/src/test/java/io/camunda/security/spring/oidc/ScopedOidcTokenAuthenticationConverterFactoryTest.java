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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.spring.scope.ScopedCamundaAuthenticationToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Verifies that {@link ScopedOidcTokenAuthenticationConverterFactory} resolves a bearer token with
 * the scope's own claim configuration — including the case the global issuer-keyed map cannot
 * handle: two scopes that share one issuer but configure different claims (ADR-0033, fixing
 * camunda/camunda#64685's shared-issuer variant).
 */
@ExtendWith(MockitoExtension.class)
class ScopedOidcTokenAuthenticationConverterFactoryTest {

  private static final String SHARED_ISSUER = "https://login.microsoftonline.com/common/v2.0";

  @Mock private MembershipPort membershipPort;

  private ScopedOidcTokenAuthenticationConverterFactory factory() {
    final var claimsProviderFactory =
        new ScopedOidcClaimsProviderFactory(
            new ScopedClientRegistrationFactory(),
            OidcUserInfoHttpClient.defaultHttpClient(),
            new ObjectMapper(),
            null);
    return new ScopedOidcTokenAuthenticationConverterFactory(
        new ScopedClientRegistrationFactory(),
        claimsProviderFactory,
        membershipPort,
        MembershipResolutionContextPropagator.identity());
  }

  @Test
  void resolvesWithTheScopesOwnUsernameClaim() {
    final var converter =
        factory().buildConverter(scope(SHARED_ISSUER, "upn"), "basePath=/physical-tenants/a");
    final var jwt =
        Jwt.withTokenValue("t")
            .header("alg", "RS256")
            .claim("iss", SHARED_ISSUER)
            .claim("ver", "2.0")
            .claim("upn", "dave")
            .build();

    final var authentication = converter.convert(jwt);

    assertThat(authentication).isInstanceOf(ScopedCamundaAuthenticationToken.class);
    assertThat(((ScopedCamundaAuthenticationToken) authentication).getCamundaAuthentication())
        .satisfies(a -> assertThat(a.authenticatedUsername()).isEqualTo("dave"));
  }

  @Test
  void twoScopesSharingOneIssuerEachResolveWithTheirOwnClaims() {
    // The case the global issuer-keyed map cannot do: one Entra issuer, two app registrations whose
    // username-claims differ. Each scope's converter must read its own claim from the same token.
    final var converterA =
        factory().buildConverter(scope(SHARED_ISSUER, "upn"), "basePath=/physical-tenants/a");
    final var converterB =
        factory()
            .buildConverter(
                scope(SHARED_ISSUER, "preferred_username"), "basePath=/physical-tenants/b");
    final var jwt =
        Jwt.withTokenValue("t")
            .header("alg", "RS256")
            .claim("iss", SHARED_ISSUER)
            .claim("ver", "2.0")
            .claim("upn", "dave")
            .claim("preferred_username", "alice")
            .build();

    assertThat(camundaUsername(converterA.convert(jwt))).isEqualTo("dave");
    assertThat(camundaUsername(converterB.convert(jwt))).isEqualTo("alice");
  }

  @Test
  void resolvesPerProviderWithinOneScopeThatConfiguresMultipleProviders() {
    // A single scope with two providers.oidc.* entries on different issuers, each with its own
    // claim.
    final var okta = providerConfig("https://okta.example.com", "okta_user");
    final var entra = providerConfig("https://entra.example.com", "upn");
    final var authentication = new AuthenticationConfiguration();
    authentication.setMethod(AuthenticationMethod.OIDC);
    authentication.getProviders().getOidc().put("okta", okta);
    authentication.getProviders().getOidc().put("entra", entra);

    final var converter =
        factory().buildConverter(authentication, "basePath=/physical-tenants/multi");

    assertThat(
            camundaUsername(
                converter.convert(
                    Jwt.withTokenValue("t")
                        .header("alg", "RS256")
                        .claim("iss", "https://okta.example.com")
                        .claim("okta_user", "olivia")
                        .build())))
        .isEqualTo("olivia");
    assertThat(
            camundaUsername(
                converter.convert(
                    Jwt.withTokenValue("t")
                        .header("alg", "RS256")
                        .claim("iss", "https://entra.example.com")
                        .claim("upn", "ernie")
                        .build())))
        .isEqualTo("ernie");
  }

  @Test
  void failsWithInvalidTokenWhenTheScopesClaimIsAbsent() {
    final var converter =
        factory().buildConverter(scope(SHARED_ISSUER, "upn"), "basePath=/physical-tenants/a");
    final var jwt =
        Jwt.withTokenValue("t")
            .header("alg", "RS256")
            .claim("iss", SHARED_ISSUER)
            .claim("ver", "2.0")
            .claim("preferred_username", "alice") // not the scope's configured claim
            .build();

    assertThatThrownBy(() -> converter.convert(jwt))
        .isInstanceOfSatisfying(
            OAuth2AuthenticationException.class,
            ex ->
                assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN));
  }

  private static String camundaUsername(final Authentication authentication) {
    return ((ScopedCamundaAuthenticationToken) authentication)
        .getCamundaAuthentication()
        .authenticatedUsername();
  }

  private static AuthenticationConfiguration scope(
      final String issuerUri, final String usernameClaim) {
    final var authentication = new AuthenticationConfiguration();
    authentication.setMethod(AuthenticationMethod.OIDC);
    authentication.setOidc(providerConfig(issuerUri, usernameClaim));
    return authentication;
  }

  private static OidcConfiguration providerConfig(
      final String issuerUri, final String usernameClaim) {
    final var oidc = new OidcConfiguration();
    oidc.setClientId("scope-client");
    oidc.setIssuerUri(issuerUri);
    oidc.setUsernameClaim(usernameClaim);
    oidc.setPreferUsernameClaim(true);
    return oidc;
  }
}
