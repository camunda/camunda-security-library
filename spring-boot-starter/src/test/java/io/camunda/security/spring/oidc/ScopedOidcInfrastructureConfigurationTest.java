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
import io.camunda.security.spring.CamundaSecurityConfiguration;
import java.util.Collections;
import java.util.Iterator;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * Verifies that {@link ScopedOidcInfrastructureConfiguration#scopedOidcClaimsProviderFactory} is
 * registered (and backs off) correctly when the configuration is loaded the way the {@code
 * CamundaSecurityAutoConfiguration} umbrella loads it: {@link OidcClaimsProviderConfiguration}
 * imported BEFORE {@link ScopedOidcInfrastructureConfiguration}, so the {@code
 * oidcUserInfoHttpClient} gate bean is registered before this bean's {@code @ConditionalOnBean} is
 * evaluated.
 */
class ScopedOidcInfrastructureConfigurationTest {

  @Test
  void scopedClaimsProviderFactoryIsRegisteredWhenAugmentationEnabled() {
    new ApplicationContextRunner()
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.oidc.user-info-augmentation.enabled=true")
        .withUserConfiguration(StubClientRegistrationRepository.class)
        .withUserConfiguration(StubObjectMapper.class)
        .withUserConfiguration(UmbrellaOrderedImports.class)
        .withConfiguration(AutoConfigurations.of(CamundaSecurityConfiguration.class))
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx).hasSingleBean(ScopedOidcClaimsProviderFactory.class);
            });
  }

  @Test
  void scopedClaimsProviderFactoryBacksOffWhenAugmentationDisabled() {
    // Augmentation disabled => no oidcUserInfoHttpClient bean => the factory must back off
    // cleanly without failing context startup.
    new ApplicationContextRunner()
        .withPropertyValues("camunda.security.authentication.method=oidc")
        .withUserConfiguration(StubClientRegistrationRepository.class)
        .withUserConfiguration(StubObjectMapper.class)
        .withUserConfiguration(UmbrellaOrderedImports.class)
        .withConfiguration(AutoConfigurations.of(CamundaSecurityConfiguration.class))
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx).doesNotHaveBean(ScopedOidcClaimsProviderFactory.class);
            });
  }

  /**
   * Imports the two configurations in the SAME order as the umbrella {@code
   * CamundaSecurityAutoConfiguration} (claims-provider config first, scoped infrastructure second).
   * This reproduces the production {@code @ConditionalOnBean} evaluation ordering: the named {@code
   * oidcUserInfoHttpClient} bean is registered before the scoped factory's condition is checked.
   */
  @Configuration
  @Import({OidcClaimsProviderConfiguration.class, ScopedOidcInfrastructureConfiguration.class})
  static class UmbrellaOrderedImports {}

  @Configuration
  static class StubObjectMapper {
    @Bean
    ObjectMapper objectMapper() {
      return new ObjectMapper();
    }
  }

  @Configuration
  static class StubClientRegistrationRepository {
    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return new IterableClientRegistrationRepository();
    }
  }

  /** Empty iterable repository: satisfies the cachingOidcClaimsProvider dependency. */
  static final class IterableClientRegistrationRepository
      implements ClientRegistrationRepository, Iterable<ClientRegistration> {
    @Override
    public ClientRegistration findByRegistrationId(final String registrationId) {
      return null;
    }

    @Override
    public Iterator<ClientRegistration> iterator() {
      return Collections.emptyIterator();
    }
  }
}
