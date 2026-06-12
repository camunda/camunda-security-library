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
import io.camunda.security.api.context.OidcClaimsProvider;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import java.net.http.HttpClient;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

class OidcClaimsProviderConfigurationTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withPropertyValues("camunda.security.authentication.method=oidc")
          .withUserConfiguration(StubClientRegistrationRepository.class)
          .withUserConfiguration(StubObjectMapper.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class, OidcClaimsProviderConfiguration.class));

  @Test
  void noopIsRegisteredByDefaultWhenAugmentationIsDisabled() {
    runner.run(
        ctx -> {
          assertThat(ctx).hasSingleBean(OidcClaimsProvider.class);
          assertThat(ctx.getBean(OidcClaimsProvider.class))
              .isInstanceOf(NoopOidcClaimsProvider.class);
        });
  }

  @Test
  void cachingProviderIsRegisteredWhenAugmentationEnabled() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.user-info-augmentation.enabled=true")
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(OidcClaimsProvider.class);
              assertThat(ctx.getBean(OidcClaimsProvider.class))
                  .isInstanceOf(CachingOidcClaimsProvider.class);
            });
  }

  @Test
  void hostBeanBacksOffBothCslProviders() {
    runner
        .withUserConfiguration(HostOidcClaimsProvider.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(OidcClaimsProvider.class);
              assertThat(ctx.getBean(OidcClaimsProvider.class))
                  .isInstanceOf(HostOidcClaimsProvider.CustomProvider.class);
            });
  }

  @Test
  void httpClientBeanNotCreatedWhenAugmentationIsDisabled() {
    // When augmentation is off, the JDK HttpClient (and its connection pool) should not exist.
    runner.run(ctx -> assertThat(ctx).doesNotHaveBean("oidcUserInfoHttpClient"));
  }

  @Test
  void noBeansRegisteredWhenMethodIsNotOidc() {
    new ApplicationContextRunner()
        .withPropertyValues("camunda.security.authentication.method=basic")
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class, OidcClaimsProviderConfiguration.class))
        .run(ctx -> assertThat(ctx).doesNotHaveBean(OidcClaimsProvider.class));
  }

  @Test
  void hostCanOverrideOidcUserInfoHttpClientBean() {
    // Context must start cleanly — if @ConditionalOnMissingBean(name) didn't back off,
    // Spring would throw BeanDefinitionOverrideException on the duplicate name.
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.user-info-augmentation.enabled=true")
        .withUserConfiguration(HostHttpClientConfig.class)
        .run(ctx -> assertThat(ctx).hasNotFailed());
  }

  @Configuration
  static class StubClientRegistrationRepository {
    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return new EmptyIterableClientRegistrationRepository();
    }

    static final class EmptyIterableClientRegistrationRepository
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

  @Configuration
  static class HostOidcClaimsProvider {
    @Bean
    OidcClaimsProvider customProvider() {
      return new CustomProvider();
    }

    static final class CustomProvider implements OidcClaimsProvider {
      @Override
      public Map<String, Object> claimsFor(
          final Map<String, Object> jwtClaims, final String tokenValue) {
        return jwtClaims;
      }
    }
  }

  @Configuration
  static class StubObjectMapper {
    @Bean
    ObjectMapper objectMapper() {
      return new ObjectMapper();
    }
  }

  @Configuration
  static class HostHttpClientConfig {
    @Bean(name = "oidcUserInfoHttpClient")
    HttpClient customHttpClient() {
      return HttpClient.newHttpClient();
    }
  }
}
