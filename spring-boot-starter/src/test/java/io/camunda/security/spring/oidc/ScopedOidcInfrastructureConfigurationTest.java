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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.BadJwtException;

/**
 * Verifies that {@link ScopedOidcInfrastructureConfiguration#scopedOidcClaimsProviderFactory} is
 * always registered — independently of whether the cluster default has UserInfo augmentation
 * enabled — and backs off when a host supplies its own factory. The per-scope {@link
 * io.camunda.security.api.model.config.AuthenticationConfiguration} decides whether augmentation
 * runs; the global {@code oidcUserInfoHttpClient} bean is used when present and a default client is
 * built otherwise, so a scope can enable augmentation independently of the cluster default.
 *
 * <p>The {@link UmbrellaOrderedImports} helper reproduces the production import ordering ({@link
 * OidcClaimsProviderConfiguration} before {@link ScopedOidcInfrastructureConfiguration}), which is
 * still exercised to ensure the two configurations compose without conflicts.
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
  void scopedClaimsProviderFactoryIsRegisteredWhenAugmentationDisabled() {
    // Augmentation disabled => no global oidcUserInfoHttpClient bean => factory still registers
    // using its built-in default client, so a scope can enable augmentation independently.
    new ApplicationContextRunner()
        .withPropertyValues("camunda.security.authentication.method=oidc")
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
  void scopedClaimsProviderFactoryBacksOffWhenHostProvidesOwn() {
    new ApplicationContextRunner()
        .withPropertyValues("camunda.security.authentication.method=oidc")
        .withUserConfiguration(StubClientRegistrationRepository.class)
        .withUserConfiguration(StubObjectMapper.class)
        .withUserConfiguration(CustomScopedFactory.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class, ScopedOidcInfrastructureConfiguration.class))
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx).hasSingleBean(ScopedOidcClaimsProviderFactory.class);
              assertThat(ctx.getBean(ScopedOidcClaimsProviderFactory.class))
                  .isSameAs(ctx.getBean(CustomScopedFactory.class).customFactory);
            });
  }

  @Test
  void shouldApplyTheGlobalValidatorsToScopedDecoders() throws Exception {
    try (final var server = OidcTestServer.startRsa("key")) {
      new ApplicationContextRunner()
          .withUserConfiguration(StubObjectMapper.class, RejectingGlobalValidatorFactory.class)
          .withUserConfiguration(UmbrellaOrderedImports.class)
          .run(
              ctx -> {
                // given
                assertThat(ctx).hasNotFailed();
                final var decoder =
                    ctx.getBean(ScopedJwtDecoderFactory.class)
                        .buildIssuerAwareDecoder(scopeOf(server));

                // when / then
                assertThatThrownBy(() -> decoder.decode(server.sign(server.issuerUri())))
                    .isInstanceOf(BadJwtException.class)
                    .hasMessageContaining("rejected by the host");
              });
    }
  }

  @Test
  void shouldBuildScopedDecodersWithoutGlobalValidatorFactory() throws Exception {
    try (final var server = OidcTestServer.startRsa("key")) {
      new ApplicationContextRunner()
          .withUserConfiguration(StubObjectMapper.class)
          .withUserConfiguration(UmbrellaOrderedImports.class)
          .run(
              ctx -> {
                // given
                assertThat(ctx).hasNotFailed();
                assertThat(ctx).doesNotHaveBean(TokenValidatorFactory.class);
                final var decoder =
                    ctx.getBean(ScopedJwtDecoderFactory.class)
                        .buildIssuerAwareDecoder(scopeOf(server));

                // when / then
                assertThat(decoder.decode(server.sign(server.issuerUri())).getSubject())
                    .isEqualTo("alice");
              });
    }
  }

  private static AuthenticationConfiguration scopeOf(final OidcTestServer server) {
    final var authentication = new AuthenticationConfiguration();
    authentication.setOidc(server.oidcConfiguration("client"));
    return authentication;
  }

  @Configuration
  static class RejectingGlobalValidatorFactory {
    @Bean
    TokenValidatorFactory tokenValidatorFactory() {
      return new TokenValidatorFactory(
          Map.of(),
          OidcConfiguration.DEFAULT_CLOCK_SKEW,
          List.of(
              token ->
                  OAuth2TokenValidatorResult.failure(
                      new OAuth2Error(
                          OAuth2ErrorCodes.INVALID_TOKEN, "rejected by the host", null))));
    }
  }

  /**
   * Imports the two configurations in the SAME order as the umbrella {@code
   * CamundaSecurityAutoConfiguration} (claims-provider config first, scoped infrastructure second),
   * so the tests run against the real production composition. The scoped factory is registered
   * unconditionally, so it must compose cleanly whether or not the claims-provider config
   * contributes the named {@code oidcUserInfoHttpClient} bean (present only when augmentation is
   * enabled); these tests assert it registers in both cases without context failure.
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

  @Configuration
  static class CustomScopedFactory {
    final ScopedOidcClaimsProviderFactory customFactory =
        new ScopedOidcClaimsProviderFactory(
            new ScopedClientRegistrationFactory(),
            OidcUserInfoHttpClient.defaultHttpClient(),
            new ObjectMapper(),
            null);

    @Bean
    ScopedOidcClaimsProviderFactory scopedOidcClaimsProviderFactory() {
      return customFactory;
    }
  }

  /**
   * Iterable repository with one registration that exposes a userInfoUri, so the cluster
   * cachingOidcClaimsProvider builds rather than tripping the no-userInfoUri fail-fast when
   * augmentation is enabled.
   */
  static final class IterableClientRegistrationRepository
      implements ClientRegistrationRepository, Iterable<ClientRegistration> {
    private static final ClientRegistration REGISTRATION =
        ClientRegistration.withRegistrationId("oidc")
            .clientId("client")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/cb")
            .authorizationUri("https://idp.example/auth")
            .tokenUri("https://idp.example/token")
            .userInfoUri("https://idp.example/userinfo")
            .issuerUri("https://idp.example")
            .build();

    @Override
    public ClientRegistration findByRegistrationId(final String registrationId) {
      return "oidc".equals(registrationId) ? REGISTRATION : null;
    }

    @Override
    public Iterator<ClientRegistration> iterator() {
      return List.of(REGISTRATION).iterator();
    }
  }
}
