/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

import io.camunda.security.api.model.config.SessionConfiguration;
import io.camunda.security.api.model.session.PersistentSession;
import io.camunda.security.core.port.out.ScopedSessionStorePortProvider;
import io.camunda.security.core.port.out.SessionStorePort;
import io.camunda.security.spring.security.ExpiredSessionRefreshTokenRevocation;
import io.camunda.security.spring.security.RefreshTokenRevoker;
import io.camunda.security.spring.session.WebSessionMapper.SpringBasedWebSessionAttributeConverter;
import io.camunda.security.spring.session.WebSessionRepository.ExpiryCheck;
import java.lang.Thread.UncaughtExceptionHandler;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.session.MapSession;
import org.springframework.session.Session;

/**
 * The runner imports only {@link WebSessionConfiguration} — deliberately not {@code
 * CamundaSecurityConfiguration} — matching how a host activates it standalone via
 * {@code @ImportAutoConfiguration} (see {@code docs/adopters/persistent-web-sessions.md}). This
 * exercises {@code @EnableConfigurationProperties} on the class itself rather than routing around
 * that requirement via a broader import.
 */
class WebSessionConfigurationTest {

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(WebSessionConfiguration.class))
          .withBean(SessionStorePort.class, NoopSessionStore::new);

  @Test
  void beansAreRegisteredWhenEnabled() {
    runner
        .withPropertyValues("camunda.security.session.persistent.enabled=true")
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(WebSessionRepository.class)
                    .hasSingleBean(WebSessionMapper.class)
                    .hasSingleBean(WebSessionAttributeConverter.class)
                    .hasBean("persistentWebSessionDeletionTaskExecutor")
                    .hasBean("webSessionDeletionUncaughtExceptionHandler"));
  }

  @Test
  void webSessionRepositoryAppliesConfiguredMaxInactiveInterval() {
    runner
        .withPropertyValues(
            "camunda.security.session.persistent.enabled=true",
            "camunda.security.session.max-inactive-interval=45m")
        .run(
            ctx -> {
              final var repository = ctx.getBean(WebSessionRepository.class);
              assertThat(repository.createSession().getMaxInactiveInterval())
                  .isEqualTo(java.time.Duration.ofMinutes(45));
            });
  }

  @Test
  void scopedWebSessionRepositoryFactoryReportsUnavailableWithoutProvider() {
    runner
        .withPropertyValues("camunda.security.session.persistent.enabled=true")
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(ScopedWebSessionRepositoryFactory.class);
              assertThat(ctx.getBean(ScopedWebSessionRepositoryFactory.class).isAvailable())
                  .as("no ScopedSessionStorePortProvider contributed → factory unavailable")
                  .isFalse();
            });
  }

  @Test
  void scopedWebSessionRepositoryFactoryBuildsFromProviderWhenPresent() {
    final SessionStorePort scopedPort = new NoopSessionStore();
    runner
        .withPropertyValues("camunda.security.session.persistent.enabled=true")
        .withBean(
            ScopedSessionStorePortProvider.class,
            () -> (ScopedSessionStorePortProvider) basePath -> scopedPort)
        .run(
            ctx -> {
              final var factory = ctx.getBean(ScopedWebSessionRepositoryFactory.class);
              assertThat(factory.isAvailable())
                  .as("a ScopedSessionStorePortProvider is present → factory available")
                  .isTrue();
              assertThat(factory.forBasePath("/physical-tenants/a"))
                  .as("factory builds a per-scope WebSessionRepository via the provider")
                  .isInstanceOf(WebSessionRepository.class);
            });
  }

  @Test
  void distinctByStoreSweepsEachStoreOnceKeepingTheDefault() {
    final SessionStorePort sharedStore = new NoopSessionStore();
    final SessionStorePort distinctStore = new NoopSessionStore();
    final var defaultRepository = repositoryBackedBy(sharedStore);
    final var scopeRepositorySharingStore = repositoryBackedBy(sharedStore);
    final var scopeRepositoryDistinctStore = repositoryBackedBy(distinctStore);

    final var swept =
        WebSessionConfiguration.distinctByStore(
            defaultRepository, List.of(scopeRepositorySharingStore, scopeRepositoryDistinctStore));

    // one repository per distinct store; the default-surface repository is kept on overlap
    assertThat(swept).containsExactlyInAnyOrder(defaultRepository, scopeRepositoryDistinctStore);
    assertThat(swept).doesNotContain(scopeRepositorySharingStore);
  }

  private static WebSessionRepository repositoryBackedBy(final SessionStorePort store) {
    return new WebSessionRepository(
        store,
        new WebSessionMapper(
            new SpringBasedWebSessionAttributeConverter(new GenericConversionService())),
        new MockHttpServletRequest(),
        new SessionConfiguration());
  }

  @Test
  void beansBackOffWhenPropertyAbsent() {
    runner.run(ctx -> assertThat(ctx).doesNotHaveBean(WebSessionRepository.class));
  }

  @Test
  void beansBackOffWhenDisabled() {
    runner
        .withPropertyValues("camunda.security.session.persistent.enabled=false")
        .run(ctx -> assertThat(ctx).doesNotHaveBean(WebSessionRepository.class));
  }

  @Test
  void hostCanOverrideAttributeConverter() {
    runner
        .withPropertyValues("camunda.security.session.persistent.enabled=true")
        .withUserConfiguration(HostConverterConfiguration.class)
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(WebSessionAttributeConverter.class)
                    .getBean(WebSessionAttributeConverter.class)
                    .isInstanceOf(HostConverterConfiguration.HostConverter.class));
  }

  @Test
  void expiredSessionHandlerHandsTheSessionToTheRevocationBean() throws Exception {
    // given - a chain whose registration lookup shows that the revocation saw the session
    final var lookedUp = new CountDownLatch(1);
    try (var revocation = new ExpiredSessionRefreshTokenRevocation()) {
      revocation.register(
          registrationId -> {
            lookedUp.countDown();
            return null;
          },
          new HttpSessionOAuth2AuthorizedClientRepository(),
          new RefreshTokenRevoker(null));
      final var beanFactory = new StaticListableBeanFactory(Map.of("revocation", revocation));

      // when
      WebSessionConfiguration.expiredSessionHandler(
              beanFactory.getBeanProvider(ExpiredSessionRefreshTokenRevocation.class))
          .accept(sessionWithRefreshToken(), ExpiryCheck.REQUEST);

      // then
      assertThat(lookedUp.await(5, TimeUnit.SECONDS)).isTrue();
    }
  }

  @Test
  void expiredSessionHandlerDoesNothingWithoutTheRevocationBean() {
    // given - a host that imports this configuration without the chain builder's
    final var beanFactory = new StaticListableBeanFactory();

    // then
    assertThatCode(
            () ->
                WebSessionConfiguration.expiredSessionHandler(
                        beanFactory.getBeanProvider(ExpiredSessionRefreshTokenRevocation.class))
                    .accept(sessionWithRefreshToken(), ExpiryCheck.REQUEST))
        .doesNotThrowAnyException();
  }

  @Test
  void expiredSessionHandlerLetsOnlyTheSweepWait() {
    // given
    final var revocation = mock(ExpiredSessionRefreshTokenRevocation.class);
    final var handler =
        WebSessionConfiguration.expiredSessionHandler(
            new StaticListableBeanFactory(Map.of("revocation", revocation))
                .getBeanProvider(ExpiredSessionRefreshTokenRevocation.class));
    final var fromSweep = new MapSession();
    final var fromRequest = new MapSession();

    // when
    handler.accept(fromSweep, ExpiryCheck.SWEEP);
    handler.accept(fromRequest, ExpiryCheck.REQUEST);

    // then
    verify(revocation).revokeFromSweep(fromSweep);
    verify(revocation).revoke(fromRequest);
    verifyNoMoreInteractions(revocation);
  }

  private static Session sessionWithRefreshToken() {
    final var idToken =
        new OidcIdToken(
            "id-token", Instant.now(), Instant.now().plusSeconds(60), Map.of("sub", "user"));
    final var authentication =
        new OAuth2AuthenticationToken(new DefaultOidcUser(List.of(), idToken), List.of(), "oidc");
    final var registration =
        ClientRegistration.withRegistrationId("oidc")
            .clientId("client-id")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("https://app.example.com/sso-callback")
            .authorizationUri("https://idp.example.com/oauth2/authorize")
            .tokenUri("https://idp.example.com/oauth2/token")
            .build();
    final var client =
        new OAuth2AuthorizedClient(
            registration,
            "user",
            new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access-token",
                Instant.now(),
                Instant.now().plusSeconds(60)),
            new OAuth2RefreshToken("refresh-token", Instant.now()));
    final var session = new MapSession();
    session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, new SecurityContextImpl(authentication));
    session.setAttribute(
        HttpSessionOAuth2AuthorizedClientRepository.class.getName() + ".AUTHORIZED_CLIENTS",
        Map.of("oidc", client));
    return session;
  }

  @Test
  void hostCanOverrideUncaughtExceptionHandler() {
    final UncaughtExceptionHandler hostHandler = (t, e) -> {};
    runner
        .withPropertyValues("camunda.security.session.persistent.enabled=true")
        .withBean(
            "webSessionDeletionUncaughtExceptionHandler",
            UncaughtExceptionHandler.class,
            () -> hostHandler)
        .run(
            ctx ->
                assertThat(ctx)
                    .getBean(
                        "webSessionDeletionUncaughtExceptionHandler",
                        UncaughtExceptionHandler.class)
                    .isSameAs(hostHandler));
  }

  @Configuration
  static class HostConverterConfiguration {

    @Bean
    WebSessionAttributeConverter webSessionAttributeConverter() {
      return new HostConverter();
    }

    static final class HostConverter implements WebSessionAttributeConverter {
      @Override
      public Object deserialize(final byte[] value) {
        return null;
      }

      @Override
      public byte[] serialize(final Object value) {
        return new byte[0];
      }
    }
  }

  static final class NoopSessionStore implements SessionStorePort {
    @Override
    public PersistentSession get(final String sessionId) {
      return null;
    }

    @Override
    public void upsert(final PersistentSession session) {}

    @Override
    public void delete(final String sessionId) {}

    @Override
    public List<PersistentSession> getAll() {
      return List.of();
    }
  }
}
