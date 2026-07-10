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
import io.camunda.security.core.port.in.OidcProviderConfigurationPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
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
 * Verifies the default OIDC beans exposed by {@link OidcBeansConfiguration} and their {@link
 * org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean} back-off. The OIDC
 * logout success handler is built per chain by {@code ScopedWebappSecurityChainBuilder} rather than
 * exposed as a bean, so no {@link LogoutSuccessHandler} bean is registered here (see {@link
 * #noLogoutSuccessHandlerBeanIsRegistered()}).
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
  void noLogoutSuccessHandlerBeanIsRegistered() {
    runner.run(ctx -> assertThat(ctx).doesNotHaveBean(LogoutSuccessHandler.class));
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

  @Test
  void defaultOidcProviderConfigurationPortIsRegisteredWhenNoHostBeanPresent() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=test-client",
            "camunda.security.authentication.oidc.issuer-uri=https://issuer.example.com")
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(OidcProviderConfigurationPort.class);
              assertThat(ctx)
                  .getBean(OidcProviderConfigurationPort.class)
                  .extracting(p -> p.getOidcAuthenticationConfigurationById("oidc"))
                  .isNotNull();
            });
  }

  @Test
  void hostRegisteredOidcProviderConfigurationPortSuppressesTheDefault() {
    runner
        .withUserConfiguration(HostOidcProviderConfiguration.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(OidcProviderConfigurationPort.class);
              assertThat(ctx)
                  .getBean(OidcProviderConfigurationPort.class)
                  .isInstanceOf(HostOidcProviderConfiguration.NoOpPort.class);
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

  @Configuration
  static class HostOidcProviderConfiguration {

    @Bean
    OidcProviderConfigurationPort hostOidcProviderConfigurationPort() {
      return new NoOpPort();
    }

    static final class NoOpPort implements OidcProviderConfigurationPort {
      @Override
      public OidcConfiguration getOidcAuthenticationConfigurationById(final String registrationId) {
        return null;
      }

      @Override
      public Map<String, OidcConfiguration> getOidcAuthenticationConfigurations() {
        return Map.of();
      }
    }
  }
}
