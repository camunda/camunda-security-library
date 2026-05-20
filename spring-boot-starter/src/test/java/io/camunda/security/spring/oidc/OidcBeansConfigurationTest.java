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
import io.camunda.security.spring.security.CamundaOidcLogoutSuccessHandler;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

/**
 * Verifies the {@link LogoutSuccessHandler} wiring exposed by {@link OidcBeansConfiguration}: the
 * CSL ships {@link CamundaOidcLogoutSuccessHandler} as the default, and a host-registered {@link
 * LogoutSuccessHandler} bean suppresses it via {@link
 * org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean}. The {@link
 * io.camunda.security.spring.security.OidcWebappSecurityConfiguration} chain picks the resulting
 * bean up via its existing {@code ObjectProvider<LogoutSuccessHandler>} plumbing.
 */
class OidcBeansConfigurationTest {

  // Wrap the configuration under test in AutoConfigurations.of(...) so its
  // @ConditionalOnMissingBean evaluates after user configurations have registered their beans —
  // the same approach WebAppAuthorizationFilterConfigurationTest takes for explicitly-imported
  // configuration classes governed by ADR-0008.
  //
  // OidcBeansConfiguration's other @Bean methods (JwtDecoder, ClientRegistrationRepository,
  // OAuth2AuthorizedClientRepository, OAuth2AuthorizedClientManager) would otherwise need a valid
  // CamundaSecurityLibraryProperties to build from configured issuer/JWK URIs. The stubs below
  // satisfy the @ConditionalOnMissingBean back-off on each, so the slice exercises only the
  // logout-handler bean.
  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withPropertyValues("camunda.security.authentication.method=oidc")
          .withUserConfiguration(StubOidcInfrastructure.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class, OidcBeansConfiguration.class));

  @Test
  void defaultCamundaOidcLogoutSuccessHandlerIsRegisteredWhenNoHostBeanPresent() {
    runner.run(
        ctx -> {
          assertThat(ctx).hasSingleBean(LogoutSuccessHandler.class);
          assertThat(ctx)
              .getBean(LogoutSuccessHandler.class)
              .isInstanceOf(CamundaOidcLogoutSuccessHandler.class);
        });
  }

  @Test
  void hostRegisteredLogoutSuccessHandlerSuppressesTheDefault() {
    runner
        .withUserConfiguration(HostLogoutSuccessHandler.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(LogoutSuccessHandler.class);
              assertThat(ctx)
                  .getBean(LogoutSuccessHandler.class)
                  .isInstanceOf(HostLogoutSuccessHandler.NoOpLogoutSuccessHandler.class);
            });
  }

  @Test
  void defaultCamundaOidcAuthorizationRequestResolverIsRegisteredWhenNoHostBeanPresent() {
    runner.run(
        ctx -> {
          assertThat(ctx).hasSingleBean(OAuth2AuthorizationRequestResolver.class);
          assertThat(ctx)
              .getBean(OAuth2AuthorizationRequestResolver.class)
              .isInstanceOf(CamundaOidcAuthorizationRequestResolver.class);
        });
  }

  @Test
  void hostRegisteredAuthorizationRequestResolverSuppressesTheDefault() {
    runner
        .withUserConfiguration(HostAuthorizationRequestResolver.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(OAuth2AuthorizationRequestResolver.class);
              assertThat(ctx)
                  .getBean(OAuth2AuthorizationRequestResolver.class)
                  .isInstanceOf(HostAuthorizationRequestResolver.NoOpResolver.class);
            });
  }

  @Configuration
  static class StubOidcInfrastructure {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return registrationId -> null;
    }

    @Bean
    JwtDecoder jwtDecoder() {
      return token -> {
        throw new UnsupportedOperationException("stub");
      };
    }

    @Bean
    OAuth2AuthorizedClientRepository authorizedClientRepository() {
      return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager() {
      return request -> null;
    }
  }

  @Configuration
  static class HostLogoutSuccessHandler {

    @Bean
    LogoutSuccessHandler hostLogoutSuccessHandler() {
      return new NoOpLogoutSuccessHandler();
    }

    static final class NoOpLogoutSuccessHandler
        implements org.springframework.security.web.authentication.logout.LogoutSuccessHandler {
      @Override
      public void onLogoutSuccess(
          final jakarta.servlet.http.HttpServletRequest request,
          final jakarta.servlet.http.HttpServletResponse response,
          final org.springframework.security.core.Authentication authentication) {}
    }
  }

  @Configuration
  static class HostAuthorizationRequestResolver {

    @Bean
    OAuth2AuthorizationRequestResolver hostAuthorizationRequestResolver() {
      return new NoOpResolver();
    }

    static final class NoOpResolver implements OAuth2AuthorizationRequestResolver {
      @Override
      public OAuth2AuthorizationRequest resolve(final HttpServletRequest request) {
        return null;
      }

      @Override
      public OAuth2AuthorizationRequest resolve(
          final HttpServletRequest request, final String clientRegistrationId) {
        return null;
      }
    }
  }
}
