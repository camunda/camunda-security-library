/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

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

  @Test
  void trailingSlashOnBaseUriStillMatchesNormalRequestPath() {
    // given — base URI supplied with a trailing slash
    final String baseWithSlash = BASE + "/";
    final ClientRegistrationRepository repo =
        new InMemoryClientRegistrationRepository(registration());
    final var resolver = new CamundaOidcAuthorizationRequestResolver(repo, Map.of(), baseWithSlash);

    // when — normal (non-double-slash) request path
    final var request = new MockHttpServletRequest("GET", BASE + "/oidc");
    request.setServletPath(BASE + "/oidc");

    // then — trailing slash must have been stripped; the matcher must still fire
    assertThat(resolver.resolve(request))
        .as("resolver constructed with trailing-slash base URI must match normal request path")
        .isNotNull();
  }

  @Test
  void nullSourcesByRegistrationIdThrowsNullPointerException() {
    final ClientRegistrationRepository repo =
        new InMemoryClientRegistrationRepository(registration());
    assertThatNullPointerException()
        .isThrownBy(() -> new CamundaOidcAuthorizationRequestResolver(repo, null, BASE))
        .withMessage("sourcesByRegistrationId must not be null");
  }

  @Test
  void relativeBaseUriThrowsIllegalArgumentException() {
    // given — a relative base URI without a leading '/'
    final ClientRegistrationRepository repo =
        new InMemoryClientRegistrationRepository(registration());
    final String relativeUri = "oauth2/authorization";

    // when / then — constructor must reject it with a clear message
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new CamundaOidcAuthorizationRequestResolver(repo, Map.of(), relativeUri))
        .withMessageContaining("absolute")
        .withMessageContaining("/");
  }

  @Test
  void rootAuthorizationBaseUriThrowsIllegalArgumentException() {
    // given — root path, which BasePaths.normalize maps to an empty string
    final ClientRegistrationRepository repo =
        new InMemoryClientRegistrationRepository(registration());

    // when / then — constructor must reject it; message must mention the root path
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new CamundaOidcAuthorizationRequestResolver(repo, Map.of(), "/"))
        .withMessageContaining("/");
  }
}
