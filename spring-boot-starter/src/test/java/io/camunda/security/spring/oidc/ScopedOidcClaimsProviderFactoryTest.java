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
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
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

  // Augmentation enabled → augmenting provider, built on first claims lookup
  @Test
  void shouldBuildDeferredCachingProviderWhenAugmentationEnabled() {
    final var authentication =
        authEnabled("https://idp.example.com", "https://idp.example.com/userinfo");
    final var providers = Map.of("oidc", authentication.getOidc());

    when(clientRegistrationFactory.flatten(authentication)).thenReturn(providers);
    when(clientRegistrationFactory.createWithoutLoginRoutes(providers))
        .thenReturn(
            List.of(
                registrationWithUserInfo(
                    "oidc", "https://idp.example.com", "https://idp.example.com/userinfo")));

    final OidcClaimsProvider provider = factory.buildClaimsProvider(authentication);

    assertThat(provider).isInstanceOf(DeferredOidcClaimsProvider.class);
    verifyNoInteractions(httpClient);
    assertThat(claimsForUnaugmentedToken(provider)).containsEntry("iss", "https://idp.example.com");
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

  // Augmentation enabled but no provider exposes a userInfoUri → fails on first claims lookup
  @Test
  void shouldThrowOnFirstLookupWhenAugmentationEnabledButNoUserInfoEndpoint() {
    final var authentication = authEnabled("https://idp.example.com", null);
    final var providers = Map.of("oidc", authentication.getOidc());

    // Provider resolves but has no userInfoUri — augmentation could never run.
    when(clientRegistrationFactory.flatten(authentication)).thenReturn(providers);
    when(clientRegistrationFactory.createWithoutLoginRoutes(providers))
        .thenReturn(List.of(registrationWithoutUserInfo("oidc", "https://idp.example.com")));

    final OidcClaimsProvider provider = factory.buildClaimsProvider(authentication);

    assertThatThrownBy(() -> claimsForUnaugmentedToken(provider))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("userInfoUri");
  }

  @Test
  void shouldNameTheScopeAndTheProviderWhenTheClaimsMappingCannotBeBuilt() {
    // given a scoped provider whose registration exposes no userInfoUri, so the deferred build of
    // the mapping fails at the first claims lookup
    final var basePath = "/physical-tenants/" + UUID.randomUUID();
    final var authentication = authEnabled("https://idp.example.com", null);
    final var providers = Map.of("oidc", authentication.getOidc());
    when(clientRegistrationFactory.flatten(authentication)).thenReturn(providers);
    when(clientRegistrationFactory.createWithoutLoginRoutes(providers))
        .thenReturn(List.of(registrationWithoutUserInfo("oidc", "https://idp.example.com")));
    final var provider = factory.buildClaimsProvider(authentication, "basePath=" + basePath);
    final var appender = captureResolutionLogs();

    // when
    try {
      assertThatThrownBy(() -> claimsForUnaugmentedToken(provider))
          .isInstanceOf(IllegalStateException.class);
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
   * Runs a claims lookup that forces the deferred delegate to be built but performs no UserInfo
   * call: the token carries no {@code openid} scope, so an augmenting provider returns the claims
   * unchanged.
   */
  private static Map<String, Object> claimsForUnaugmentedToken(final OidcClaimsProvider provider) {
    return provider.claimsFor(Map.of("iss", "https://idp.example.com"), "token");
  }

  // buildUserInfoUriByIssuer helper
  @Test
  void shouldExtractIssuerToUserInfoUriFromRegistrations() {
    final ClientRegistration regWithBoth =
        registrationWithUserInfo(
            "idp-a", "https://idp-a.example", "https://idp-a.example/userinfo");
    final ClientRegistration regWithoutUserInfo =
        registrationWithoutUserInfo("idp-b", "https://idp-b.example");

    final Map<String, String> map =
        ScopedOidcClaimsProviderFactory.buildUserInfoUriByIssuer(
            List.of(regWithBoth, regWithoutUserInfo));

    assertThat(map)
        .containsEntry("https://idp-a.example", "https://idp-a.example/userinfo")
        .doesNotContainKey("https://idp-b.example");
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
