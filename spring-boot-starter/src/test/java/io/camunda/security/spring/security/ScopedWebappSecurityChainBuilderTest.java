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

  private static ClientRegistration registration(final String id) {
    return ClientRegistration.withRegistrationId(id)
        .clientId(id + "-client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/sso-callback")
        .authorizationUri("https://idp/authorize")
        .tokenUri("https://idp/token")
        .build();
  }

  @Test
  void singleRegistrationRedirectsStraightToProvider() {
    final ClientRegistrationRepository repo =
        new InMemoryClientRegistrationRepository(registration("oidc"));
    assertThat(ScopedWebappSecurityChainBuilder.resolveOauthRedirectTarget(repo, LOGIN_URL))
        .isEqualTo("/oauth2/authorization/oidc");
  }

  @Test
  void multipleRegistrationsRedirectToLoginPicker() {
    final ClientRegistrationRepository repo =
        new InMemoryClientRegistrationRepository(registration("a"), registration("b"));
    // Scoped login URL proves that loginUrl is threaded through rather than using the constant.
    final var scopedLoginUrl = "/physical-tenants/t1/login";
    assertThat(ScopedWebappSecurityChainBuilder.resolveOauthRedirectTarget(repo, scopedLoginUrl))
        .isEqualTo(scopedLoginUrl);
  }

  @Test
  void nonIterableRepositoryFallsBackToDefaultRegistrationId() {
    final ClientRegistrationRepository repo = registrationId -> registration(registrationId);
    assertThat(ScopedWebappSecurityChainBuilder.resolveOauthRedirectTarget(repo, LOGIN_URL))
        .isEqualTo("/oauth2/authorization/oidc");
  }
}
