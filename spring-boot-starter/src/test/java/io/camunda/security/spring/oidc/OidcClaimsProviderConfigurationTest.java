/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.context.OidcClaimsProvider;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import java.net.http.HttpClient;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
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

  // Same as runner but with a registration that exposes a userInfoUri, so the caching provider
  // builds without tripping the fail-fast on an empty issuer→userInfoUri map.
  private final ApplicationContextRunner populatedRunner =
      new ApplicationContextRunner()
          .withPropertyValues("camunda.security.authentication.method=oidc")
          .withUserConfiguration(PopulatedClientRegistrationRepository.class)
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
    populatedRunner
        .withPropertyValues(
            "camunda.security.authentication.oidc.user-info-augmentation.enabled=true")
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(OidcClaimsProvider.class);
              assertThat(ctx.getBean(OidcClaimsProvider.class))
                  .isInstanceOf(DeferredOidcClaimsProvider.class);
              assertThat(claimsForUnaugmentedToken(ctx.getBean(OidcClaimsProvider.class)))
                  .containsEntry("iss", "https://idp-a.example");
            });
  }

  @Test
  void cachingProviderFailsOnFirstLookupWhenNoUserInfoUriResolved() {
    // Augmentation enabled but no ClientRegistration exposes a userInfoUri — a config mismatch that
    // must fail loudly so the operator notices, rather than silently running without augmentation.
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.user-info-augmentation.enabled=true")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThatThrownBy(
                      () -> claimsForUnaugmentedToken(ctx.getBean(OidcClaimsProvider.class)))
                  .isInstanceOf(IllegalStateException.class);
            });
  }

  @Test
  void shouldNameTheProviderWhenTheClusterLevelMappingCannotBeBuilt() {
    // given a lazy repository whose only provider exposes no userInfoUri, so the deferred build of
    // the cluster-level mapping fails at the first claims lookup
    final var registrationId = "idp-" + UUID.randomUUID();
    new ApplicationContextRunner()
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.oidc.user-info-augmentation.enabled=true")
        .withBean(
            ClientRegistrationRepository.class,
            () ->
                new LazyClientRegistrationRepository(
                    new ScopedClientRegistrationFactory(),
                    Map.of(registrationId, providerWithExplicitEndpoints())))
        .withUserConfiguration(StubObjectMapper.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class, OidcClaimsProviderConfiguration.class))
        .run(
            ctx -> {
              final var appender = captureResolutionLogs();

              // when
              try {
                assertThatThrownBy(
                        () -> claimsForUnaugmentedToken(ctx.getBean(OidcClaimsProvider.class)))
                    .isInstanceOf(IllegalStateException.class);
              } finally {
                releaseResolutionLogs(appender);
              }

              // then the WARN names the provider, so an operator of a deployment with several
              // identity providers sees which one the failure belongs to
              assertThat(appender.list)
                  .filteredOn(event -> event.getLevel() == Level.WARN)
                  .singleElement()
                  .satisfies(
                      event ->
                          assertThat(event.getFormattedMessage())
                              .contains("'" + registrationId + "'"));
            });
  }

  private static OidcConfiguration providerWithExplicitEndpoints() {
    // Explicit endpoints and no issuer-uri keep the resolution offline: the registration builds
    // without OIDC discovery, and it carries no userInfoUri.
    return OidcConfiguration.builder()
        .clientId("client-id")
        .redirectUri("{baseUrl}/sso-callback")
        .authorizationUri("https://idp-a.example/auth")
        .tokenUri("https://idp-a.example/token")
        .jwkSetUri("https://idp-a.example/jwks")
        .build();
  }

  private static ListAppender<ILoggingEvent> captureResolutionLogs() {
    final var appender = new ListAppender<ILoggingEvent>();
    appender.start();
    ((Logger) LoggerFactory.getLogger(DeferredOidcResolution.class)).addAppender(appender);
    return appender;
  }

  private static void releaseResolutionLogs(final ListAppender<ILoggingEvent> appender) {
    ((Logger) LoggerFactory.getLogger(DeferredOidcResolution.class)).detachAppender(appender);
    appender.stop();
  }

  @Test
  void cachingProviderFailsOnFirstLookupWhenRepositoryNotIterable() {
    // A non-iterable ClientRegistrationRepository cannot yield a per-issuer mapping; with
    // augmentation enabled this must name the non-iterable repository as the cause rather than
    // emit a WARN and then a generic "no mapping" error.
    new ApplicationContextRunner()
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.oidc.user-info-augmentation.enabled=true")
        .withUserConfiguration(NonIterableClientRegistrationRepository.class)
        .withUserConfiguration(StubObjectMapper.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class, OidcClaimsProviderConfiguration.class))
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThatThrownBy(
                      () -> claimsForUnaugmentedToken(ctx.getBean(OidcClaimsProvider.class)))
                  .isInstanceOf(IllegalStateException.class)
                  .hasMessageContaining("not iterable");
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
  void noCachingProviderWhenClientRegistrationRepositoryAbsent() {
    // Simulates method=oidc + webapp-enabled=false + user-info-augmentation.enabled=true with no
    // host-supplied ClientRegistrationRepository: ClientRegistrationRepository is only registered
    // when the webapp chain is enabled (see OidcWebappClientBeansConfiguration), so
    // cachingOidcClaimsProvider must back off rather than fail to start. noopOidcClaimsProvider's
    // condition (enabled=false, matchIfMissing=true) is false here too, so no OidcClaimsProvider
    // bean registers at all — the same silent-absence pattern as the other webapp-enabled=false
    // gates.
    new ApplicationContextRunner()
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.oidc.user-info-augmentation.enabled=true")
        .withUserConfiguration(StubObjectMapper.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class, OidcClaimsProviderConfiguration.class))
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx).doesNotHaveBean(OidcClaimsProvider.class);
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
    // Spring would throw BeanDefinitionOverrideException on the duplicate name. Uses the populated
    // repo so the caching provider builds rather than tripping the no-userInfoUri fail-fast.
    populatedRunner
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
              assertThat(claimsForUnaugmentedToken(ctx.getBean(OidcClaimsProvider.class)))
                  .containsEntry("iss", "https://idp-a.example");
            });
  }

  /**
   * Runs a claims lookup that forces the deferred delegate to be built but performs no UserInfo
   * call: the token carries no {@code openid} scope, so an augmenting provider returns the claims
   * unchanged.
   */
  private static Map<String, Object> claimsForUnaugmentedToken(final OidcClaimsProvider provider) {
    return provider.claimsFor(Map.of("iss", "https://idp-a.example"), "token");
  }

  @Configuration
  static class NonIterableClientRegistrationRepository {
    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      // Functional-interface lambda — does NOT implement Iterable.
      return registrationId -> null;
    }
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
