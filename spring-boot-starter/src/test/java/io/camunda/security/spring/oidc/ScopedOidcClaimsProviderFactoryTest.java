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
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.context.OidcClaimsProvider;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.config.oidc.OidcUserInfoAugmentationConfiguration;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Unit tests for {@link ScopedOidcClaimsProviderFactory}. Verifies that the factory builds the
 * correct {@link OidcClaimsProvider} type for augmentation-enabled, augmentation-disabled, and
 * no-OIDC-provider configurations, mirroring the structure of {@link ScopedJwtDecoderFactoryTest}.
 *
 * <p>No Spring context is loaded; collaborators are injected via Mockito.
 */
@ExtendWith(MockitoExtension.class)
final class ScopedOidcClaimsProviderFactoryTest {

  @Mock private ScopedClientRegistrationFactory clientRegistrationFactory;
  @Mock private HttpClient httpClient;
  @Mock private ObjectMapper objectMapper;

  @InjectMocks private ScopedOidcClaimsProviderFactory factory;

  // Augmentation enabled → augmenting provider that resolves nothing while the chain is built
  @Test
  void shouldBuildAnAugmentingProviderThatResolvesNoProvider() {
    final var authentication =
        authEnabled("https://idp.example.com", "https://idp.example.com/userinfo");
    final var providers = Map.of("oidc", authentication.getOidc());

    when(clientRegistrationFactory.flatten(authentication)).thenReturn(providers);

    final OidcClaimsProvider provider = factory.buildClaimsProvider(authentication);

    assertThat(provider).isInstanceOf(CachingOidcClaimsProvider.class);
    verifyNoInteractions(httpClient);
    verify(clientRegistrationFactory, never())
        .buildAll(anyMap(), isNull(), eq(ScopedClientRegistrationFactory.LoginRouteChecks.SKIPPED));
    // A token that needs no augmented claims resolves no provider either.
    assertThat(claimsForUnaugmentedToken(provider)).containsEntry("iss", "https://idp.example.com");
    verify(clientRegistrationFactory, never())
        .buildAll(anyMap(), isNull(), eq(ScopedClientRegistrationFactory.LoginRouteChecks.SKIPPED));
  }

  @Test
  void shouldResolveTheProviderOfTheIssuerOfTheTokenOnly() {
    // given a scope of two providers, of which the second one does not answer
    final var authentication =
        authEnabled("https://idp-a.example", "https://idp-a.example/userinfo");
    final var second =
        authEnabled("https://idp-b.example", "https://idp-b.example/userinfo").getOidc();
    final var providers = Map.of("a", authentication.getOidc(), "b", second);
    when(clientRegistrationFactory.flatten(authentication)).thenReturn(providers);
    when(clientRegistrationFactory.buildAll(
            Map.of("a", authentication.getOidc()),
            null,
            ScopedClientRegistrationFactory.LoginRouteChecks.SKIPPED))
        .thenReturn(
            List.of(
                registrationWithUserInfo(
                    "a", "https://idp-a.example", "https://idp-a.example/userinfo")));
    final var provider = factory.buildClaimsProvider(authentication);

    // when a token of the first provider is augmented
    claimsForAugmentedToken(provider, "https://idp-a.example");

    // then the provider that issued no token keeps its registration unresolved, so a provider that
    // does not answer costs the tokens of its own issuer only
    verify(clientRegistrationFactory)
        .buildAll(
            Map.of("a", authentication.getOidc()),
            null,
            ScopedClientRegistrationFactory.LoginRouteChecks.SKIPPED);
    verify(clientRegistrationFactory, never())
        .buildAll(
            Map.of("b", second), null, ScopedClientRegistrationFactory.LoginRouteChecks.SKIPPED);
  }

  @Test
  void shouldFailTheTokenOfAProviderThatDoesNotAnswerAsAServerError() {
    final var authentication =
        authEnabled("https://idp.example.com", "https://idp.example.com/userinfo");
    final var providers = Map.of("oidc", authentication.getOidc());
    when(clientRegistrationFactory.flatten(authentication)).thenReturn(providers);
    when(clientRegistrationFactory.buildAll(
            providers, null, ScopedClientRegistrationFactory.LoginRouteChecks.SKIPPED))
        .thenThrow(new IllegalArgumentException("Unable to resolve the Configuration"));
    final var provider = factory.buildClaimsProvider(authentication);

    // The provider is unreachable, and not the token, so the request must not read as a refused
    // credential.
    assertThatThrownBy(() -> claimsForAugmentedToken(provider, "https://idp.example.com"))
        .isInstanceOf(AuthenticationServiceException.class);
  }

  @Test
  void shouldPassTheTokenOfAnIssuerNoProviderDeclaresUnaugmented() {
    final var authentication =
        authEnabled("https://idp.example.com", "https://idp.example.com/userinfo");
    when(clientRegistrationFactory.flatten(authentication))
        .thenReturn(Map.of("oidc", authentication.getOidc()));
    final var provider = factory.buildClaimsProvider(authentication);

    // Another chain verifies the token, so an unknown issuer is no reason to reject the request
    // here, and it is no reason to resolve a provider either.
    assertThat(claimsForAugmentedToken(provider, "https://other.example"))
        .containsEntry("iss", "https://other.example");
    verify(clientRegistrationFactory, never())
        .buildAll(anyMap(), isNull(), eq(ScopedClientRegistrationFactory.LoginRouteChecks.SKIPPED));
  }

  @Test
  void shouldThrowWhenNoProviderCanEverExposeAUserInfoEndpoint() {
    // given a scope whose only provider turns UserInfo off, while augmentation is enabled
    final var authentication =
        authEnabled("https://idp.example.com", "https://idp.example.com/userinfo");
    authentication.getOidc().setUserInfoEnabled(false);
    when(clientRegistrationFactory.flatten(authentication))
        .thenReturn(Map.of("oidc", authentication.getOidc()));

    // then the contradiction needs no network access to see, so it stops the chain
    assertThatThrownBy(() -> factory.buildClaimsProvider(authentication))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("no OIDC provider can yield");
  }

  // Augmentation disabled → NoopOidcClaimsProvider (no network calls made)
  @Test
  void shouldBuildNoopProviderWhenAugmentationDisabled() {
    final var authentication =
        authDisabled("https://idp.example.com", "https://idp.example.com/userinfo");

    final OidcClaimsProvider provider = factory.buildClaimsProvider(authentication);

    assertThat(provider).isInstanceOf(NoopOidcClaimsProvider.class);
    // Disabled augmentation must short-circuit without consulting any collaborator.
    verifyNoInteractions(clientRegistrationFactory, httpClient);
  }

  // Null augmentation config → NoopOidcClaimsProvider (no network calls made)
  @Test
  void shouldBuildNoopProviderWhenAugmentationConfigIsNull() {
    // given
    final var oidc =
        OidcConfiguration.builder()
            .clientId("client-id")
            .redirectUri("{baseUrl}/login/oauth2/code/oidc")
            .issuerUri("https://idp.example.com")
            .authorizationUri("https://idp.example.com/auth")
            .tokenUri("https://idp.example.com/token")
            .jwkSetUri("https://idp.example.com/jwks")
            .build();
    oidc.setUserInfoAugmentation(null);
    final var authentication = new AuthenticationConfiguration();
    authentication.setOidc(oidc);

    // when
    final OidcClaimsProvider provider = factory.buildClaimsProvider(authentication);

    // then
    assertThat(provider).isInstanceOf(NoopOidcClaimsProvider.class);
    verifyNoInteractions(clientRegistrationFactory, httpClient);
  }

  // Augmentation enabled and the provider exposes no userInfoUri → fails the tokens of its issuer
  @Test
  void shouldThrowWhenTheProviderOfTheIssuerExposesNoUserInfoEndpoint() {
    final var authentication = authEnabled("https://idp.example.com", null);
    final var providers = Map.of("oidc", authentication.getOidc());

    // The provider resolves, but its discovery document names no UserInfo endpoint, so the claims
    // of its tokens would silently lose the attributes the authorization needs.
    when(clientRegistrationFactory.flatten(authentication)).thenReturn(providers);
    when(clientRegistrationFactory.buildAll(
            providers, null, ScopedClientRegistrationFactory.LoginRouteChecks.SKIPPED))
        .thenReturn(List.of(registrationWithoutUserInfo("oidc", "https://idp.example.com")));

    final OidcClaimsProvider provider = factory.buildClaimsProvider(authentication);

    assertThatThrownBy(() -> claimsForAugmentedToken(provider, "https://idp.example.com"))
        .isInstanceOf(AuthenticationServiceException.class)
        .hasMessageContaining("userInfoUri");
  }

  @Test
  void shouldNameTheScopeAndTheProviderWhenTheClaimsMappingCannotBeBuilt() {
    // given a scoped provider that does not answer, so the resolution of its registration fails at
    // the first claims lookup of its issuer
    final var basePath = "/physical-tenants/" + UUID.randomUUID();
    final var authentication =
        authEnabled("https://idp.example.com", "https://idp.example.com/userinfo");
    final var providers = Map.of("oidc", authentication.getOidc());
    when(clientRegistrationFactory.flatten(authentication)).thenReturn(providers);
    when(clientRegistrationFactory.buildAll(
            providers, null, ScopedClientRegistrationFactory.LoginRouteChecks.SKIPPED))
        .thenThrow(new IllegalArgumentException("Unable to resolve the Configuration"));
    final var provider = factory.buildClaimsProvider(authentication, "basePath=" + basePath);
    final var appender = captureResolutionLogs();

    // when
    try {
      assertThatThrownBy(() -> claimsForAugmentedToken(provider, "https://idp.example.com"))
          .isInstanceOf(AuthenticationServiceException.class);
    } finally {
      releaseResolutionLogs(appender);
    }

    // then the WARN tells the operator which provider and which scope the failure belongs to, so
    // two scopes that configure the same provider stay distinguishable
    assertThat(appender.list)
        .filteredOn(event -> event.getLevel() == Level.WARN)
        .singleElement()
        .satisfies(
            event ->
                assertThat(event.getFormattedMessage())
                    .contains("'oidc'")
                    .contains("https://idp.example.com")
                    .contains("basePath=" + basePath));
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

  // Augmentation enabled but no OIDC provider resolves → fail fast (broken config)
  @Test
  void shouldThrowWhenAugmentationEnabledButNoOidcProvider() {
    final var authentication =
        authEnabled("https://idp.example.com", "https://idp.example.com/userinfo");

    // No OIDC provider is configured for this scope — a broken config, mirroring
    // ScopedJwtDecoderFactory. A config error needs no network access, so it still fails where the
    // chain is built rather than on the first request.
    when(clientRegistrationFactory.flatten(authentication)).thenReturn(Map.of());

    assertThatThrownBy(() -> factory.buildClaimsProvider(authentication))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("declares no OIDC provider");
  }

  /**
   * Runs a claims lookup that needs no augmentation, because the token carries no {@code openid}
   * scope.
   */
  private static Map<String, Object> claimsForUnaugmentedToken(final OidcClaimsProvider provider) {
    return provider.claimsFor(Map.of("iss", "https://idp.example.com"), "token");
  }

  /**
   * Runs a claims lookup that needs augmented claims, and therefore the UserInfo endpoint of {@code
   * issuer}. A mocked HTTP client answers the fetch, so the test observes the resolution alone.
   */
  private static Map<String, Object> claimsForAugmentedToken(
      final OidcClaimsProvider provider, final String issuer) {
    return provider.claimsFor(Map.of("iss", issuer, "scope", "openid", "sub", "user"), "token");
  }

  private static AuthenticationConfiguration authEnabled(
      final String issuerUri, final String userInfoUri) {
    return buildAuth(issuerUri, userInfoUri, true);
  }

  private static AuthenticationConfiguration authDisabled(
      final String issuerUri, final String userInfoUri) {
    return buildAuth(issuerUri, userInfoUri, false);
  }

  private static AuthenticationConfiguration buildAuth(
      final String issuerUri, final String userInfoUri, final boolean augmentationEnabled) {
    final var oidcBuilder =
        OidcConfiguration.builder()
            .clientId("client-id")
            .redirectUri("{baseUrl}/login/oauth2/code/oidc")
            .issuerUri(issuerUri)
            .authorizationUri(issuerUri + "/auth")
            .tokenUri(issuerUri + "/token")
            .jwkSetUri(issuerUri + "/jwks");
    if (userInfoUri != null) {
      oidcBuilder.userInfoUri(userInfoUri);
    }
    final var oidc = oidcBuilder.build();
    final var augmentation = new OidcUserInfoAugmentationConfiguration();
    augmentation.setEnabled(augmentationEnabled);
    oidc.setUserInfoAugmentation(augmentation);

    final var authentication = new AuthenticationConfiguration();
    authentication.setOidc(oidc);
    return authentication;
  }

  @Test
  void shouldAugmentASharedIssuerWithTheEndpointOfItsFirstProviderAndWarn() {
    // given two providers of one issuer, each with its own UserInfo endpoint
    final var issuer = "https://shared.example.com";
    final var authentication = authEnabled(issuer, issuer + "/owner/userinfo");
    final var owner = authentication.getOidc();
    final var loser = authEnabled(issuer, issuer + "/loser/userinfo").getOidc();
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put("owner", owner);
    providers.put("loser", loser);
    when(clientRegistrationFactory.flatten(authentication)).thenReturn(providers);
    when(clientRegistrationFactory.buildAll(
            Map.of("owner", owner), null, ScopedClientRegistrationFactory.LoginRouteChecks.SKIPPED))
        .thenReturn(List.of(registrationWithUserInfo("owner", issuer, issuer + "/owner/userinfo")));
    final var appender = attachAppender();

    try {
      // when a token of that issuer is augmented
      claimsForAugmentedToken(factory.buildClaimsProvider(authentication), issuer);

      // then the first provider of the configuration answers for the issuer, and the operator reads
      // whose endpoint the augmentation therefore never calls
      verify(clientRegistrationFactory)
          .buildAll(
              Map.of("owner", owner),
              null,
              ScopedClientRegistrationFactory.LoginRouteChecks.SKIPPED);
      verify(clientRegistrationFactory, never())
          .buildAll(
              Map.of("loser", loser),
              null,
              ScopedClientRegistrationFactory.LoginRouteChecks.SKIPPED);
      assertThat(appender.list)
          .anySatisfy(
              event -> {
                assertThat(event.getLevel()).isEqualTo(Level.WARN);
                assertThat(event.getFormattedMessage())
                    .contains(issuer)
                    .contains("'owner' wins")
                    .contains("ignore the UserInfo endpoint of 'loser'");
              });
    } finally {
      detachAppender(appender);
    }
  }

  @Test
  void shouldPassASharedIssuerUnaugmentedWhenItsOwningProviderTurnsUserInfoOff() {
    // given two providers of one issuer, of which only the ignored second one enables UserInfo
    final var shared = "https://shared.example.com";
    final var authentication = authEnabled(shared, null);
    final var owner = authentication.getOidc();
    owner.setUserInfoEnabled(false);
    final var loser = authEnabled(shared, shared + "/loser/userinfo").getOidc();
    // a second issuer keeps augmentation meaningful for the scope
    final var other =
        authEnabled("https://other.example", "https://other.example/userinfo").getOidc();
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put("owner", owner);
    providers.put("loser", loser);
    providers.put("other", other);
    when(clientRegistrationFactory.flatten(authentication)).thenReturn(providers);
    final var provider = factory.buildClaimsProvider(authentication);

    // when a token of the shared issuer is augmented
    // then the flag of the owning provider answers for the issuer, so the token passes unaugmented
    // instead of failing over an endpoint the augmentation never asked for
    assertThat(claimsForAugmentedToken(provider, shared)).containsEntry("iss", shared);
    // and the configuration answers alone, so such a token also survives an outage of that provider
    verify(clientRegistrationFactory, never())
        .buildAll(anyMap(), isNull(), eq(ScopedClientRegistrationFactory.LoginRouteChecks.SKIPPED));
  }

  @Test
  void shouldThrowWhenOnlyAnIgnoredDuplicateEnablesUserInfo() {
    // given one issuer whose owning provider turns UserInfo off, and an ignored duplicate that
    // enables it
    final var shared = "https://shared.example.com";
    final var authentication = authEnabled(shared, null);
    final var owner = authentication.getOidc();
    owner.setUserInfoEnabled(false);
    final var loser = authEnabled(shared, shared + "/loser/userinfo").getOidc();
    final var providers = new LinkedHashMap<String, OidcConfiguration>();
    providers.put("owner", owner);
    providers.put("loser", loser);
    when(clientRegistrationFactory.flatten(authentication)).thenReturn(providers);

    // then the duplicate rescues nothing, because its registration reaches no request, so the
    // contradiction stops the chain as a single disabled provider does
    assertThatThrownBy(() -> factory.buildClaimsProvider(authentication))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("no OIDC provider can yield");
  }

  private static ListAppender<ILoggingEvent> attachAppender() {
    final var logger = (Logger) LoggerFactory.getLogger(IssuerRegistrations.class);
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private static void detachAppender(final ListAppender<ILoggingEvent> appender) {
    ((Logger) LoggerFactory.getLogger(IssuerRegistrations.class)).detachAppender(appender);
  }

  /** Builds a {@link ClientRegistration} with both issuerUri and userInfoUri set. */
  private static ClientRegistration registrationWithUserInfo(
      final String registrationId, final String issuerUri, final String userInfoUri) {
    return ClientRegistration.withRegistrationId(registrationId)
        .clientId("client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/cb")
        .authorizationUri(issuerUri + "/auth")
        .tokenUri(issuerUri + "/token")
        .userInfoUri(userInfoUri)
        .issuerUri(issuerUri)
        .build();
  }

  /** Builds a {@link ClientRegistration} without a userInfoUri. */
  private static ClientRegistration registrationWithoutUserInfo(
      final String registrationId, final String issuerUri) {
    return ClientRegistration.withRegistrationId(registrationId)
        .clientId("client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/cb")
        .authorizationUri(issuerUri + "/auth")
        .tokenUri(issuerUri + "/token")
        .issuerUri(issuerUri)
        .build();
  }
}
