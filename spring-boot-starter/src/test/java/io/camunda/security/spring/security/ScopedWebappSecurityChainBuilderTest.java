/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.LOGIN_URL;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

class ScopedWebappSecurityChainBuilderTest {

  private static final String PRIMARY_AUTH_BASE_URI = "/oauth2/authorization";

  private static ClientRegistration registration(final String id) {
    return ClientRegistration.withRegistrationId(id)
        .clientId(id + "-client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/sso-callback")
        .authorizationUri("https://idp/authorize")
        .tokenUri("https://idp/token")
        .build();
  }

  // Primary chain (authorizationBaseUri = "/oauth2/authorization")

  @Test
  void singleRegistrationRedirectsStraightToProvider() {
    final ClientRegistrationRepository repo =
        new InMemoryClientRegistrationRepository(registration("oidc"));
    assertThat(
            ScopedWebappSecurityChainBuilder.resolveOauthRedirectTarget(
                repo, LOGIN_URL, PRIMARY_AUTH_BASE_URI))
        .isEqualTo("/oauth2/authorization/oidc");
  }

  @Test
  void multipleRegistrationsRedirectToLoginPicker() {
    final ClientRegistrationRepository repo =
        new InMemoryClientRegistrationRepository(registration("a"), registration("b"));
    // Scoped login URL proves that loginUrl is threaded through rather than using the constant.
    final var scopedLoginUrl = "/physical-tenants/t1/login";
    assertThat(
            ScopedWebappSecurityChainBuilder.resolveOauthRedirectTarget(
                repo, scopedLoginUrl, PRIMARY_AUTH_BASE_URI))
        .isEqualTo(scopedLoginUrl);
  }

  @Test
  void nonIterableRepositoryFallsBackToDefaultRegistrationId() {
    final ClientRegistrationRepository repo = registrationId -> registration(registrationId);
    assertThat(
            ScopedWebappSecurityChainBuilder.resolveOauthRedirectTarget(
                repo, LOGIN_URL, PRIMARY_AUTH_BASE_URI))
        .isEqualTo("/oauth2/authorization/oidc");
  }

  // Scoped chain: single-IdP redirect target must be prefixed with basePath

  /**
   * For a scoped chain with a single IdP, the redirect target must be {@code
   * <basePath>/oauth2/authorization/<id>} — not the unprefixed {@code /oauth2/authorization/<id>}.
   * Without threading {@code authorizationBaseUri}, the 302 would send the browser outside the
   * scope prefix, breaking scoped single-IdP login.
   */
  @Test
  void scopedSingleIdpRedirectTargetIsPrefixedWithBasePath() {
    final var basePath = "/physical-tenants/t1";
    final var authorizationBaseUri = basePath + "/oauth2/authorization";
    final ClientRegistrationRepository repo =
        new InMemoryClientRegistrationRepository(registration("oidc"));
    assertThat(
            ScopedWebappSecurityChainBuilder.resolveOauthRedirectTarget(
                repo, basePath + LOGIN_URL, authorizationBaseUri))
        .isEqualTo(basePath + "/oauth2/authorization/oidc");
  }

  /**
   * For a scoped chain with a non-iterable repository (fallback case), the redirect target must
   * also be prefixed — {@code <basePath>/oauth2/authorization/oidc}.
   */
  @Test
  void scopedNonIterableRepositoryFallsBackToPrefixedDefaultRegistrationId() {
    final var basePath = "/physical-tenants/t1";
    final var authorizationBaseUri = basePath + "/oauth2/authorization";
    final ClientRegistrationRepository repo = registrationId -> registration(registrationId);
    assertThat(
            ScopedWebappSecurityChainBuilder.resolveOauthRedirectTarget(
                repo, basePath + LOGIN_URL, authorizationBaseUri))
        .isEqualTo(basePath + "/oauth2/authorization/oidc");
  }

  /**
   * Confirms that the primary (non-scoped) single-IdP redirect target is unchanged — {@code
   * /oauth2/authorization/<id>} — so the fix is behaviour-neutral for primary chains.
   */
  @Test
  void primaryChainSingleIdpRedirectTargetIsUnchanged() {
    final ClientRegistrationRepository repo =
        new InMemoryClientRegistrationRepository(registration("oidc"));
    assertThat(
            ScopedWebappSecurityChainBuilder.resolveOauthRedirectTarget(
                repo, LOGIN_URL, PRIMARY_AUTH_BASE_URI))
        .isEqualTo("/oauth2/authorization/oidc");
  }
}
