/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.spring.scope.DefaultOAuth2AuthorizedClientManagerFactory;
import java.net.ServerSocket;
import java.util.LinkedHashMap;
import org.junit.jupiter.api.Test;

class ScopedOidcClientsTest {

  @Test
  void shouldResolveEveryProviderConfiguredWithExplicitEndpoints() {
    // given
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put("app", explicit("app"));
    final var clients =
        ScopedOidcClients.forLogin(
            new ScopedClientRegistrationFactory(),
            providers,
            "/tenants/t1/sso-callback",
            "basePath=/tenants/t1",
            new DefaultOAuth2AuthorizedClientManagerFactory());

    // when
    final var failures = clients.resolveAll();

    // then
    assertThat(failures).isEmpty();
    assertThat(clients.registrations().resolvedRegistrations()).hasSize(1);
  }

  @Test
  void shouldReportAProviderWhoseIssuerCannotBeReached() throws Exception {
    // given
    final int closedPort;
    try (final var socket = new ServerSocket(0)) {
      closedPort = socket.getLocalPort();
    }
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put("reachable", explicit("reachable"));
    providers.put(
        "down",
        OidcConfiguration.builder()
            .issuerUri("http://127.0.0.1:" + closedPort)
            .clientId("down")
            .build());
    final var clients =
        ScopedOidcClients.withoutLoginRoutes(
            new ScopedClientRegistrationFactory(),
            providers,
            "basePath=/tenants/t1",
            new DefaultOAuth2AuthorizedClientManagerFactory());

    // when
    final var failures = clients.resolveAll();

    // then
    assertThat(failures).containsOnlyKeys("down");
  }

  private static OidcConfiguration explicit(final String clientId) {
    return OidcConfiguration.builder()
        .clientId(clientId)
        .clientSecret("secret")
        .authorizationUri("https://idp.example/auth")
        .tokenUri("https://idp.example/token")
        .jwkSetUri("https://idp.example/jwks")
        .build();
  }
}
