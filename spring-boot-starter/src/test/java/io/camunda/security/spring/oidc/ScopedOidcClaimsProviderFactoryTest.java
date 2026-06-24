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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.context.OidcClaimsProvider;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.config.oidc.OidcUserInfoAugmentationConfiguration;
import java.net.http.HttpClient;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
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

  // Augmentation enabled → CachingOidcClaimsProvider
  @Test
  void shouldBuildCachingProviderWhenAugmentationEnabled() {
    final var authentication =
        authEnabled("https://idp.example.com", "https://idp.example.com/userinfo");

    when(clientRegistrationFactory.create(authentication))
        .thenReturn(
            List.of(
                registrationWithUserInfo(
                    "oidc", "https://idp.example.com", "https://idp.example.com/userinfo")));

    final OidcClaimsProvider provider = factory.buildClaimsProvider(authentication);

    assertThat(provider).isInstanceOf(CachingOidcClaimsProvider.class);
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

  // Augmentation enabled, no userInfoUri → CachingOidcClaimsProvider (empty map)
  @Test
  void shouldBuildCachingProviderWithEmptyMapWhenNoUserInfoUriConfigured() {
    final var authentication = authEnabled("https://idp.example.com", null);

    // Registration has no userInfoUri
    when(clientRegistrationFactory.create(authentication))
        .thenReturn(List.of(registrationWithoutUserInfo("oidc", "https://idp.example.com")));

    final OidcClaimsProvider provider = factory.buildClaimsProvider(authentication);

    // Provider is still built — it just won't augment any token (empty issuer→uri map)
    assertThat(provider).isInstanceOf(CachingOidcClaimsProvider.class);
  }

  // Augmentation enabled but no OIDC provider resolves → fail fast (broken config)
  @Test
  void shouldThrowWhenAugmentationEnabledButNoOidcProvider() {
    final var authentication =
        authEnabled("https://idp.example.com", "https://idp.example.com/userinfo");

    // No OIDC provider resolves for this scope — a broken config, mirroring
    // ScopedJwtDecoderFactory.
    when(clientRegistrationFactory.create(authentication)).thenReturn(List.of());

    assertThatThrownBy(() -> factory.buildClaimsProvider(authentication))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("declares no OIDC provider");
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
