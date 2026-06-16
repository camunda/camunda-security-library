/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

class CamundaOidcAuthorizationRequestResolverPrefixTest {

  private static final String BASE = "/physical-tenants/t1/oauth2/authorization";

  private static ClientRegistration registration() {
    return ClientRegistration.withRegistrationId("oidc")
        .clientId("client")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/physical-tenants/t1/sso-callback")
        .scope("openid")
        .authorizationUri("https://idp/authorize")
        .tokenUri("https://idp/token")
        .clientName("oidc")
        .build();
  }

  @Test
  void resolvesRegistrationFromPrefixedAuthorizationPath() {
    final ClientRegistrationRepository repo =
        new InMemoryClientRegistrationRepository(registration());
    final var resolver = new CamundaOidcAuthorizationRequestResolver(repo, Map.of(), BASE);

    final var request = new MockHttpServletRequest("GET", BASE + "/oidc");
    request.setServletPath(BASE + "/oidc");

    final var result = resolver.resolve(request);

    assertThat(result).as("resolver must match the prefixed authorization path").isNotNull();
    assertThat(result.getClientId()).isEqualTo("client");
  }

  @Test
  void doesNotMatchUnprefixedPathWhenConstructedWithPrefix() {
    final ClientRegistrationRepository repo =
        new InMemoryClientRegistrationRepository(registration());
    final var resolver = new CamundaOidcAuthorizationRequestResolver(repo, Map.of(), BASE);

    final var request = new MockHttpServletRequest("GET", "/oauth2/authorization/oidc");
    request.setServletPath("/oauth2/authorization/oidc");

    assertThat(resolver.resolve(request))
        .as("a prefix-bound resolver must not match the unprefixed path")
        .isNull();
  }
}
