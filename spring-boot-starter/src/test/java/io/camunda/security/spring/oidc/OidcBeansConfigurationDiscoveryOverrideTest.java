/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.spring.CamundaSecurityConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

/**
 * Verifies that {@link OidcBeansConfiguration} merges OIDC discovery with explicit endpoint
 * overrides — an explicitly-configured authorization-uri, token-uri, user-info-uri, jwk-set-uri, or
 * end-session-endpoint-uri wins over the value returned by the IdP's discovery document, and a
 * missing discovered endpoint is filled by the explicit value. Mirrors OC's previous {@code
 * ClientRegistrationFactory} behaviour, which deployments depend on when running against IdPs that
 * publish incomplete or wrong discovery metadata. See camunda/camunda-security-library#233.
 */
final class OidcBeansConfigurationDiscoveryOverrideTest {

  private OidcTestServer server;

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withPropertyValues("camunda.security.authentication.method=oidc")
          .withUserConfiguration(StubOidcInfrastructure.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  OidcBeansConfiguration.class,
                  OidcWebappClientBeansConfiguration.class));

  @AfterEach
  void stopServer() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  void explicitAuthorizationUriOverridesDiscoveredValue() throws Exception {
    server =
        OidcTestServer.startDiscovery(
            """
            {
              "issuer": "%s",
              "authorization_endpoint": "https://discovered.example.com/auth",
              "token_endpoint": "https://discovered.example.com/token",
              "jwks_uri": "https://discovered.example.com/jwks",
              "subject_types_supported": ["public"]
            }""");

    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.foo.client-id=foo",
            "camunda.security.authentication.providers.oidc.foo.redirect-uri=https://app/cb",
            "camunda.security.authentication.providers.oidc.foo.issuer-uri=" + server.issuerUri(),
            "camunda.security.authentication.providers.oidc.foo.authorization-uri=https://explicit.example.com/auth")
        .run(
            ctx -> {
              final var registration =
                  ctx.getBean(ClientRegistrationRepository.class).findByRegistrationId("foo");
              assertThat(registration).isNotNull();
              assertThat(registration.getProviderDetails().getAuthorizationUri())
                  .isEqualTo("https://explicit.example.com/auth");
              assertThat(registration.getProviderDetails().getTokenUri())
                  .isEqualTo("https://discovered.example.com/token");
            });
  }

  @Test
  void explicitAuthorizationUriFillsMissingDiscoveredEndpoint() throws Exception {
    // Discovery JSON intentionally omits authorization_endpoint — mirrors IdPs that publish
    // incomplete metadata. Without the explicit override CSL would throw "authorizationUri cannot
    // be empty" at ClientRegistration.Builder.build().
    server =
        OidcTestServer.startDiscovery(
            """
            {
              "issuer": "%s",
              "token_endpoint": "https://discovered.example.com/token",
              "jwks_uri": "https://discovered.example.com/jwks",
              "subject_types_supported": ["public"]
            }""");

    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.foo.client-id=foo",
            "camunda.security.authentication.providers.oidc.foo.redirect-uri=https://app/cb",
            "camunda.security.authentication.providers.oidc.foo.issuer-uri=" + server.issuerUri(),
            "camunda.security.authentication.providers.oidc.foo.authorization-uri=https://explicit.example.com/auth")
        .run(
            ctx -> {
              final var registration =
                  ctx.getBean(ClientRegistrationRepository.class).findByRegistrationId("foo");
              assertThat(registration).isNotNull();
              assertThat(registration.getProviderDetails().getAuthorizationUri())
                  .isEqualTo("https://explicit.example.com/auth");
            });
  }

  @Test
  void explicitJwkSetUriAndUserInfoUriOverrideDiscoveredValues() throws Exception {
    server =
        OidcTestServer.startDiscovery(
            """
            {
              "issuer": "%s",
              "authorization_endpoint": "https://discovered.example.com/auth",
              "token_endpoint": "https://discovered.example.com/token",
              "jwks_uri": "https://discovered.example.com/jwks",
              "userinfo_endpoint": "https://discovered.example.com/userinfo",
              "subject_types_supported": ["public"]
            }""");

    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.foo.client-id=foo",
            "camunda.security.authentication.providers.oidc.foo.redirect-uri=https://app/cb",
            "camunda.security.authentication.providers.oidc.foo.issuer-uri=" + server.issuerUri(),
            "camunda.security.authentication.providers.oidc.foo.jwk-set-uri=https://explicit.example.com/jwks",
            "camunda.security.authentication.providers.oidc.foo.user-info-uri=https://explicit.example.com/userinfo")
        .run(
            ctx -> {
              final var registration =
                  ctx.getBean(ClientRegistrationRepository.class).findByRegistrationId("foo");
              assertThat(registration).isNotNull();
              assertThat(registration.getProviderDetails().getJwkSetUri())
                  .isEqualTo("https://explicit.example.com/jwks");
              assertThat(registration.getProviderDetails().getUserInfoEndpoint().getUri())
                  .isEqualTo("https://explicit.example.com/userinfo");
            });
  }

  @Test
  void explicitEndSessionEndpointSurvivesDiscoveryAndBuild() throws Exception {
    // Spring's ClientRegistration carries end_session_endpoint via providerConfigurationMetadata,
    // not a typed field, so the override path is easy to break silently. This test asserts the
    // explicit URI is present on the built registration's metadata map.
    server =
        OidcTestServer.startDiscovery(
            """
            {
              "issuer": "%s",
              "authorization_endpoint": "https://discovered.example.com/auth",
              "token_endpoint": "https://discovered.example.com/token",
              "jwks_uri": "https://discovered.example.com/jwks",
              "subject_types_supported": ["public"]
            }""");

    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.foo.client-id=foo",
            "camunda.security.authentication.providers.oidc.foo.redirect-uri=https://app/cb",
            "camunda.security.authentication.providers.oidc.foo.issuer-uri=" + server.issuerUri(),
            "camunda.security.authentication.providers.oidc.foo.end-session-endpoint-uri=https://explicit.example.com/logout")
        .run(
            ctx -> {
              final var registration =
                  ctx.getBean(ClientRegistrationRepository.class).findByRegistrationId("foo");
              assertThat(registration).isNotNull();
              assertThat(registration.getProviderDetails().getConfigurationMetadata())
                  .containsEntry("end_session_endpoint", "https://explicit.example.com/logout");
            });
  }

  @Test
  void explicitClientNameIsAppliedWhenSet() throws Exception {
    // OC's previous ClientRegistrationFactory honoured a configured client-name; verify CSL does
    // the same. Spring defaults the client name to the registrationId when unset, so this only
    // matters for adopters who override it for display (e.g., on a login page).
    server =
        OidcTestServer.startDiscovery(
            """
            {
              "issuer": "%s",
              "authorization_endpoint": "https://discovered.example.com/auth",
              "token_endpoint": "https://discovered.example.com/token",
              "jwks_uri": "https://discovered.example.com/jwks",
              "subject_types_supported": ["public"]
            }""");

    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.foo.client-id=foo",
            "camunda.security.authentication.providers.oidc.foo.client-name=Foo Login",
            "camunda.security.authentication.providers.oidc.foo.redirect-uri=https://app/cb",
            "camunda.security.authentication.providers.oidc.foo.issuer-uri=" + server.issuerUri())
        .run(
            ctx -> {
              final var registration =
                  ctx.getBean(ClientRegistrationRepository.class).findByRegistrationId("foo");
              assertThat(registration).isNotNull();
              assertThat(registration.getClientName()).isEqualTo("Foo Login");
            });
  }

  @Test
  void discoveredValuesAreKeptWhenExplicitUrisAreUnset() throws Exception {
    server =
        OidcTestServer.startDiscovery(
            """
            {
              "issuer": "%s",
              "authorization_endpoint": "https://discovered.example.com/auth",
              "token_endpoint": "https://discovered.example.com/token",
              "jwks_uri": "https://discovered.example.com/jwks",
              "subject_types_supported": ["public"]
            }""");

    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.foo.client-id=foo",
            "camunda.security.authentication.providers.oidc.foo.redirect-uri=https://app/cb",
            "camunda.security.authentication.providers.oidc.foo.issuer-uri=" + server.issuerUri())
        .run(
            ctx -> {
              final var registration =
                  ctx.getBean(ClientRegistrationRepository.class).findByRegistrationId("foo");
              assertThat(registration).isNotNull();
              assertThat(registration.getProviderDetails().getAuthorizationUri())
                  .isEqualTo("https://discovered.example.com/auth");
              assertThat(registration.getProviderDetails().getTokenUri())
                  .isEqualTo("https://discovered.example.com/token");
              assertThat(registration.getProviderDetails().getJwkSetUri())
                  .isEqualTo("https://discovered.example.com/jwks");
            });
  }

  @Configuration
  static class StubOidcInfrastructure {

    @Bean
    OAuth2AuthorizedClientRepository authorizedClientRepository() {
      return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager() {
      return request -> null;
    }
  }
}
