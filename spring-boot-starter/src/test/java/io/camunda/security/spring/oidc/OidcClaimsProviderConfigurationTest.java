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
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

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
  void httpClientNotCreatedWhenHostOverridesOidcClaimsProvider() {
    // When the host replaces the entire augmentation stack with their own OidcClaimsProvider bean,
    // the CSL HttpClient (and its connection pool) must not be started unnecessarily.
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.user-info-augmentation.enabled=true")
        .withUserConfiguration(HostOidcClaimsProvider.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(OidcClaimsProvider.class);
              assertThat(ctx).doesNotHaveBean("oidcUserInfoHttpClient");
            });
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

  @Test
  void routingMapIsPopulatedFromClientRegistrationsWithUserInfoUri() {
    // Uses a real InMemoryClientRegistrationRepository (Iterable) with one registration that has
    // userInfoUri and one that does not, to verify buildUserInfoUriByIssuer filters nulls cleanly.
    new ApplicationContextRunner()
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.oidc.user-info-augmentation.enabled=true")
        .withUserConfiguration(PopulatedClientRegistrationRepository.class)
        .withUserConfiguration(StubObjectMapper.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class, OidcClaimsProviderConfiguration.class))
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx).hasSingleBean(OidcClaimsProvider.class);
              assertThat(ctx.getBean(OidcClaimsProvider.class))
                  .isInstanceOf(CachingOidcClaimsProvider.class);
            });
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

  @Configuration
  static class PopulatedClientRegistrationRepository {
    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      final ClientRegistration withUserInfo =
          ClientRegistration.withRegistrationId("idp-a")
              .clientId("client-a")
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
              .authorizationUri("https://idp-a.example/oauth2/authorize")
              .tokenUri("https://idp-a.example/oauth2/token")
              .userInfoUri("https://idp-a.example/userinfo")
              .issuerUri("https://idp-a.example")
              .build();
      // A registration without userInfoUri — the routing map builder should skip it without error.
      final ClientRegistration withoutUserInfo =
          ClientRegistration.withRegistrationId("idp-b")
              .clientId("client-b")
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
              .authorizationUri("https://idp-b.example/oauth2/authorize")
              .tokenUri("https://idp-b.example/oauth2/token")
              .issuerUri("https://idp-b.example")
              .build();
      return new InMemoryClientRegistrationRepository(withUserInfo, withoutUserInfo);
    }
  }
}
