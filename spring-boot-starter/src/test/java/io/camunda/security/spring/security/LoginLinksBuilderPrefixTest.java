/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

class LoginLinksBuilderPrefixTest {

  @Test
  void buildLoginLinksWithPrefixGeneratesPrefixedUrls() {
    final var repo =
        new InMemoryClientRegistrationRepository(registration("oidc"), registration("keycloak"));
    final var links = LoginLinksBuilder.buildLoginLinks(repo, "/physical-tenants/t1");
    assertThat(links)
        .containsKey("/physical-tenants/t1/oauth2/authorization/oidc")
        .containsKey("/physical-tenants/t1/oauth2/authorization/keycloak")
        .doesNotContainKey("/oauth2/authorization/oidc")
        .doesNotContainKey("/oauth2/authorization/keycloak");
  }

  @Test
  void buildLoginLinksWithEmptyPrefixMatchesNonPrefixedBehavior() {
    final var repo = new InMemoryClientRegistrationRepository(registration("oidc"));
    final var links = LoginLinksBuilder.buildLoginLinks(repo, "");
    assertThat(links).containsKey("/oauth2/authorization/oidc");
  }

  @Test
  void defaultOauth2LoginPickerFilterWithBaseUriUsesPrefix() {
    final var repo = new InMemoryClientRegistrationRepository(registration("oidc"));
    final var filter =
        LoginLinksBuilder.defaultOauth2LoginPickerFilter(
            repo, "/physical-tenants/t1/login", "/physical-tenants/t1");
    assertThat(filter.getLoginPageUrl()).isEqualTo("/physical-tenants/t1/login");
    assertThat(filter).isNotNull();
  }

  private static ClientRegistration registration(final String id) {
    return ClientRegistration.withRegistrationId(id)
        .clientId(id + "-client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/sso-callback")
        .authorizationUri("https://idp/authorize")
        .tokenUri("https://idp/token")
        .build();
  }
}
