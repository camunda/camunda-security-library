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
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

/**
 * Verifies the {@link LogoutSuccessHandler} wiring exposed by {@link
 * OidcWebappLogoutConfiguration}: the CSL ships {@link CamundaOidcLogoutSuccessHandler} as the
 * default, and a host-registered {@link LogoutSuccessHandler} bean suppresses it via {@link
 * org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean}. The {@link
 * OidcWebappSecurityConfiguration} chain picks the resulting bean up via its existing {@code
 * ObjectProvider<LogoutSuccessHandler>} plumbing.
 */
class OidcWebappLogoutConfigurationTest {

  // Wrap the configuration under test in AutoConfigurations.of(...) so its
  // @ConditionalOnMissingBean evaluates after user configurations have registered their beans —
  // the same approach WebAppAuthorizationFilterConfigurationTest takes for explicitly-imported
  // configuration classes governed by ADR-0008.
  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withPropertyValues("camunda.security.authentication.method=oidc")
          .withUserConfiguration(StubClientRegistrationRepository.class)
          .withConfiguration(AutoConfigurations.of(OidcWebappLogoutConfiguration.class));

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

  @Configuration
  static class StubClientRegistrationRepository {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return registrationId -> null;
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
}
