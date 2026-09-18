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
import static org.assertj.core.api.Assertions.entry;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.context.OidcClaimsProvider;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import java.net.http.HttpClient;
import java.time.Duration;
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
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

class OidcClaimsProviderConfigurationTest {

  // A port nothing listens on, so a discovery request fails without a timeout.
  private static final String UNREACHABLE_ISSUER_URI = "http://127.0.0.1:1/realms/camunda";

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
                      () ->
                          claimsForAugmentedToken(
                              ctx.getBean(OidcClaimsProvider.class), "https://idp-a.example"))
                  .isInstanceOf(AuthenticationServiceException.class)
                  .hasRootCauseInstanceOf(IllegalStateException.class);
            });
  }

  @Test
  void shouldAugmentTheTokenOfTheProviderThatAnswersWhileAnotherProviderDoesNot() throws Exception {
    // given two configured providers, of which one does not answer a discovery request
    final var answering = "idp-" + UUID.randomUUID();
    final var silent = "idp-" + UUID.randomUUID();
    try (final var server = OidcTestServer.startRsa("kid-a")) {
      final var providers =
          Map.of(
              answering,
              OidcConfiguration.builder()
                  .clientId("client-id")
                  .redirectUri("{baseUrl}/sso-callback")
                  .issuerUri(server.issuerUri())
                  // the discovery document of the test server declares no UserInfo endpoint
                  .userInfoUri(server.issuerUri() + "/userinfo")
                  .build(),
              silent,
              OidcConfiguration.builder()
                  .clientId("client-id")
                  .redirectUri("{baseUrl}/sso-callback")
                  .issuerUri(UNREACHABLE_ISSUER_URI)
                  .build());
      new ApplicationContextRunner()
          .withBean(ScopedClientRegistrationFactory.class, ScopedClientRegistrationFactory::new)
          .withPropertyValues(
              "camunda.security.authentication.method=oidc",
              "camunda.security.authentication.oidc.user-info-augmentation.enabled=true",
              "camunda.security.authentication.providers.oidc." + answering + ".client-id=id",
              "camunda.security.authentication.providers.oidc."
                  + answering
                  + ".redirect-uri={baseUrl}/sso-callback",
              "camunda.security.authentication.providers.oidc."
                  + answering
                  + ".issuer-uri="
                  + server.issuerUri(),
              "camunda.security.authentication.providers.oidc."
                  + answering
                  + ".user-info-uri="
                  + server.issuerUri()
                  + "/userinfo",
              "camunda.security.authentication.providers.oidc." + silent + ".client-id=id",
              "camunda.security.authentication.providers.oidc."
                  + silent
                  + ".redirect-uri={baseUrl}/sso-callback",
              "camunda.security.authentication.providers.oidc."
                  + silent
                  + ".issuer-uri="
                  + UNREACHABLE_ISSUER_URI)
          .withBean(
              ClientRegistrationRepository.class,
              () ->
                  new LazyClientRegistrationRepository(
                      new ScopedClientRegistrationFactory(), providers))
          .withUserConfiguration(StubObjectMapper.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class, OidcClaimsProviderConfiguration.class))
          .run(
              ctx -> {
                final var provider = ctx.getBean(OidcClaimsProvider.class);

                // when a token of each issuer asks for augmented claims
                // then the token of the provider that answers keeps its response, and the token of
                // the silent provider fails as a server error
                assertThat(claimsForAugmentedToken(provider, server.issuerUri()))
                    .containsEntry("iss", server.issuerUri());
                assertThatThrownBy(() -> claimsForAugmentedToken(provider, UNREACHABLE_ISSUER_URI))
                    .isInstanceOf(AuthenticationServiceException.class);
              });
    }
  }

  @Test
  void shouldNameTheProviderWhenTheClusterLevelMappingCannotBeBuilt() {
    // given a lazy repository whose only provider does not answer, so the resolution of its
    // UserInfo endpoint fails at the first claims lookup of its issuer
    final var registrationId = "idp-" + UUID.randomUUID();
    new ApplicationContextRunner()
        .withBean(ScopedClientRegistrationFactory.class, ScopedClientRegistrationFactory::new)
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.oidc.user-info-augmentation.enabled=true",
            // the repository below resolves this provider, so the subject of the mapping may name
            // it
            "camunda.security.authentication.providers.oidc." + registrationId + ".client-id=id",
            "camunda.security.authentication.providers.oidc."
                + registrationId
                + ".redirect-uri={baseUrl}/sso-callback",
            "camunda.security.authentication.providers.oidc."
                + registrationId
                + ".issuer-uri="
                + UNREACHABLE_ISSUER_URI)
        .withBean(
            ClientRegistrationRepository.class,
            () ->
                new LazyClientRegistrationRepository(
                    new ScopedClientRegistrationFactory(),
                    Map.of(registrationId, providerWithUnreachableIssuer())))
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
                        () ->
                            claimsForAugmentedToken(
                                ctx.getBean(OidcClaimsProvider.class), UNREACHABLE_ISSUER_URI))
                    .isInstanceOf(AuthenticationServiceException.class);
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

  @Test
  void shouldNameTheHostWhenTheLibraryCannotReadItsRepositoryPerIssuer() {
    // given a host repository that is not of the library's lazy type, holding a registration with
    // no UserInfo endpoint
    final var registrationId = "idp-" + UUID.randomUUID();
    new ApplicationContextRunner()
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.oidc.user-info-augmentation.enabled=true")
        .withBean(
            ClientRegistrationRepository.class,
            () ->
                new InMemoryClientRegistrationRepository(
                    registrationWithoutUserInfo(registrationId)))
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
                        () ->
                            claimsForAugmentedToken(
                                ctx.getBean(OidcClaimsProvider.class), "https://idp-a.example"))
                    .isInstanceOf(AuthenticationServiceException.class);
              } finally {
                releaseResolutionLogs(appender);
              }

              // then the WARN leaves the subject with the host, because such a repository can hold
              // registrations that no configuration of the library describes
              assertThat(appender.list)
                  .filteredOn(event -> event.getLevel() == Level.WARN)
                  .singleElement()
                  .satisfies(
                      event ->
                          assertThat(event.getFormattedMessage())
                              .contains("of the ClientRegistrationRepository of the host")
                              .doesNotContain(registrationId));
            });
  }

  @Test
  void shouldActivateWithoutAClientRegistrationFactoryBean() {
    // given a host that imports this configuration alone, with a repository of its own and no
    // factory bean of the library
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
                    Map.of(registrationId, providerWithUnreachableIssuer())))
        .withUserConfiguration(StubObjectMapper.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class, OidcClaimsProviderConfiguration.class))
        .run(
            ctx -> {
              // then the provider still registers, because the repository it reads carries the
              // providers, and it resolves them itself
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBean(OidcClaimsProvider.class))
                  .isInstanceOf(CachingOidcClaimsProvider.class);
              assertThat(ctx).doesNotHaveBean(ScopedClientRegistrationFactory.class);
            });
  }

  private static OidcConfiguration providerWithUnreachableIssuer() {
    return OidcConfiguration.builder()
        .clientId("client-id")
        .redirectUri("{baseUrl}/sso-callback")
        .issuerUri(UNREACHABLE_ISSUER_URI)
        .build();
  }

  private static ClientRegistration registrationWithoutUserInfo(final String registrationId) {
    // A resolved registration with no userInfoUri, so the mapping of the whole repository stays
    // empty and the first claims lookup fails.
    return ClientRegistration.withRegistrationId(registrationId)
        .clientId("client-id")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/sso-callback")
        .authorizationUri("https://idp-a.example/auth")
        .tokenUri("https://idp-a.example/token")
        .jwkSetUri("https://idp-a.example/jwks")
        .issuerUri("https://idp-a.example")
        .build();
  }

  private static ListAppender<ILoggingEvent> captureResolutionLogs() {
    final var appender = new ListAppender<ILoggingEvent>();
    appender.start();
    ((Logger) LoggerFactory.getLogger(DeferredOidcResolution.class)).addAppender(appender);
    // The rate limit counts per subject, and two tests can fail over the same subject, so a
    // warning of another test would otherwise take the one warning of this interval.
    DeferredOidcResolution.removeIdleSubjects(System.nanoTime() + Duration.ofMinutes(2).toNanos());
    return appender;
  }

  private static void releaseResolutionLogs(final ListAppender<ILoggingEvent> appender) {
    ((Logger) LoggerFactory.getLogger(DeferredOidcResolution.class)).detachAppender(appender);
    appender.stop();
  }

  @Test
  void contextFailsToStartWhenRepositoryNotIterable() {
    // The shape of a repository needs no discovery, so a host that wires a non-iterable repository
    // learns it while the application starts, and not at the first claims lookup.
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
            ctx ->
                assertThat(ctx)
                    .hasFailed()
                    .getFailure()
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("not iterable"));
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

  @Test
  void warnsAndKeepsTheUserInfoEndpointOfTheFirstRegistrationOfASharedIssuer() {
    // given a repository whose two registrations declare the same issuer with their own endpoints
    final var appender = attachAppender();
    try {
      new ApplicationContextRunner()
          .withPropertyValues(
              "camunda.security.authentication.method=oidc",
              "camunda.security.authentication.oidc.user-info-augmentation.enabled=true")
          .withUserConfiguration(SharedIssuerClientRegistrationRepository.class)
          .withUserConfiguration(StubObjectMapper.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class, OidcClaimsProviderConfiguration.class))
          .run(ctx -> assertThat(ctx).hasNotFailed());

      // then augmentation calls the endpoint of the registration the decoder reads, and the
      // operator reads which endpoint it therefore never calls
      assertThat(
              OidcClaimsProviderConfiguration.buildUserInfoUriByIssuer(
                  SharedIssuerClientRegistrationRepository.sharedIssuerRepository()))
          .containsExactly(
              entry("https://shared.example", "https://shared.example/owner/userinfo"));
      assertThat(appender.list)
          .anySatisfy(
              event -> {
                assertThat(event.getLevel()).isEqualTo(Level.WARN);
                assertThat(event.getFormattedMessage())
                    .contains("https://shared.example")
                    .contains("'owner' wins")
                    .contains("ignore the UserInfo endpoint of 'loser'");
              });
    } finally {
      detachAppender(appender);
    }
  }

  private static ListAppender<ILoggingEvent> attachAppender() {
    final var logger = (Logger) LoggerFactory.getLogger(OidcClaimsProviderConfiguration.class);
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private static void detachAppender(final ListAppender<ILoggingEvent> appender) {
    ((Logger) LoggerFactory.getLogger(OidcClaimsProviderConfiguration.class))
        .detachAppender(appender);
  }

  /**
   * Runs a claims lookup that needs no augmentation, because the token carries no {@code openid}
   * scope. Such a lookup builds no deferred delegate.
   */
  private static Map<String, Object> claimsForUnaugmentedToken(final OidcClaimsProvider provider) {
    return provider.claimsFor(Map.of("iss", "https://idp-a.example"), "token");
  }

  /**
   * Runs a claims lookup that needs augmented claims, and therefore the UserInfo endpoint of {@code
   * issuer}.
   */
  private static Map<String, Object> claimsForAugmentedToken(
      final OidcClaimsProvider provider, final String issuer) {
    return provider.claimsFor(Map.of("iss", issuer, "scope", "openid", "sub", "user"), "token");
  }

  @Configuration
  static class SharedIssuerClientRegistrationRepository {
    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return sharedIssuerRepository();
    }

    static ClientRegistrationRepository sharedIssuerRepository() {
      return new InMemoryClientRegistrationRepository(
          sharedIssuerRegistration("owner", "https://shared.example/owner/userinfo"),
          sharedIssuerRegistration("loser", "https://shared.example/loser/userinfo"));
    }

    private static ClientRegistration sharedIssuerRegistration(
        final String registrationId, final String userInfoUri) {
      return ClientRegistration.withRegistrationId(registrationId)
          .clientId("client-" + registrationId)
          .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
          .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
          .authorizationUri("https://shared.example/oauth2/authorize")
          .tokenUri("https://shared.example/oauth2/token")
          .userInfoUri(userInfoUri)
          .issuerUri("https://shared.example")
          .build();
    }
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
