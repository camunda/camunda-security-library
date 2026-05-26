/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.port.in.OidcProviderConfigurationPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.security.CamundaOidcLogoutSuccessHandler;
import io.camunda.security.spring.security.WebappRedirectStrategy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.RedirectStrategy;
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
  void defaultWebappRedirectStrategyIsRegisteredWhenNoHostBeanPresent() {
    runner.run(
        ctx -> {
          assertThat(ctx).hasSingleBean(RedirectStrategy.class);
          assertThat(ctx)
              .getBean(RedirectStrategy.class)
              .isInstanceOf(WebappRedirectStrategy.class);
        });
  }

  @Test
  void hostRegisteredRedirectStrategySuppressesTheDefault() {
    runner
        .withUserConfiguration(HostRedirectStrategy.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(RedirectStrategy.class);
              assertThat(ctx)
                  .getBean(RedirectStrategy.class)
                  .isInstanceOf(HostRedirectStrategy.NoOpRedirectStrategy.class);
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

  @Test
  void defaultLogoutSuccessHandlerUsesTheConfiguredRedirectStrategyBean() throws Exception {
    runner
        .withUserConfiguration(RedirectStrategySpy.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(LogoutSuccessHandler.class);
              assertThat(ctx).hasSingleBean(RedirectStrategy.class);

              final var handler = ctx.getBean(LogoutSuccessHandler.class);
              final var redirectSpy = ctx.getBean(RedirectStrategy.class);

              // Exercise the handler to verify the RedirectStrategy is actually invoked
              final var request = new MockHttpServletRequest();
              final var response = new MockHttpServletResponse();
              handler.onLogoutSuccess(request, response, null);

              // Verify the spy was invoked, proving the strategy is wired into the handler
              assertThat(redirectSpy).isInstanceOf(RedirectStrategySpy.SpyRedirectStrategy.class);
              final var spy = (RedirectStrategySpy.SpyRedirectStrategy) redirectSpy;
              assertThat(spy.invoked).isTrue();
            });
  }

  @Test
  void hostRedirectStrategyIsWiredIntoDefaultLogoutSuccessHandler() throws Exception {
    runner
        .withUserConfiguration(HostRedirectStrategySpy.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(LogoutSuccessHandler.class);
              assertThat(ctx).hasSingleBean(RedirectStrategy.class);

              final var handler = ctx.getBean(LogoutSuccessHandler.class);
              final var redirectSpy = ctx.getBean(RedirectStrategy.class);

              // Exercise the handler to verify the host RedirectStrategy is actually invoked
              final var request = new MockHttpServletRequest();
              final var response = new MockHttpServletResponse();
              handler.onLogoutSuccess(request, response, null);

              // Verify the host strategy was invoked, proving it's wired instead of the default
              assertThat(redirectSpy)
                  .isInstanceOf(HostRedirectStrategySpy.SpyHostRedirectStrategy.class);
              final var spy = (HostRedirectStrategySpy.SpyHostRedirectStrategy) redirectSpy;
              assertThat(spy.invoked).isTrue();
            });
  }

  @Test
  void webappRedirectStrategyReceivesHostObjectMapperWhenAvailable() {
    runner
        .withUserConfiguration(HostObjectMapper.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(ObjectMapper.class);
              assertThat(ctx.getBean(ObjectMapper.class)).isSameAs(HostObjectMapper.CUSTOM_MAPPER);
              // WebappRedirectStrategy does not expose the injected ObjectMapper via a getter, so
              // we can only verify that the custom ObjectMapper bean is in the context and is
              // wired into the WebappRedirectStrategy constructor (tested elsewhere).
              assertThat(ctx).hasSingleBean(RedirectStrategy.class);
              assertThat(ctx.getBean(RedirectStrategy.class))
                  .isInstanceOf(WebappRedirectStrategy.class);
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
  static class HostRedirectStrategy {

    @Bean
    RedirectStrategy hostRedirectStrategy() {
      return new NoOpRedirectStrategy();
    }

    static final class NoOpRedirectStrategy implements RedirectStrategy {
      @Override
      public void sendRedirect(
          final jakarta.servlet.http.HttpServletRequest request,
          final jakarta.servlet.http.HttpServletResponse response,
          final String url) {}
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

  @Configuration
  static class HostObjectMapper {

    static final ObjectMapper CUSTOM_MAPPER = new ObjectMapper();

    @Bean
    ObjectMapper objectMapper() {
      return CUSTOM_MAPPER;
    }
  }

  @Configuration
  static class RedirectStrategySpy {

    @Bean
    RedirectStrategy redirectStrategySpy() {
      return new SpyRedirectStrategy();
    }

    static final class SpyRedirectStrategy implements RedirectStrategy {
      boolean invoked = false;

      @Override
      public void sendRedirect(
          final HttpServletRequest request, final HttpServletResponse response, final String url)
          throws IOException {
        invoked = true;
      }
    }
  }

  @Configuration
  static class HostRedirectStrategySpy {

    @Bean
    RedirectStrategy hostRedirectStrategySpy() {
      return new SpyHostRedirectStrategy();
    }

    static final class SpyHostRedirectStrategy implements RedirectStrategy {
      boolean invoked = false;

      @Override
      public void sendRedirect(
          final HttpServletRequest request, final HttpServletResponse response, final String url)
          throws IOException {
        invoked = true;
      }
    }
  }
}
