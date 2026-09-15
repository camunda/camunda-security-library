/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.converter.TokenClaimsConvertersByIssuer;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * Verifies the {@code tokenClaimsConvertersByIssuer} bean that resolves per-provider claim
 * converters by issuer for {@code OidcTokenAuthenticationConverter}. The default {@link
 * LazyTokenClaimsConverter} bean lives in {@code CamundaAuthenticationBeansConfiguration} instead —
 * it isn't OIDC-only, since {@code AuthorizationConfiguration} needs it regardless of
 * authentication method — so it's stubbed directly here rather than pulling in that whole
 * configuration class and its unrelated {@code HttpServletRequest}-dependent beans.
 */
@ExtendWith(MockitoExtension.class)
class OidcBeansConfigurationTokenClaimsConverterTest {

  private static final String DEFAULT_ISSUER = "https://auth0.example.com";
  private static final String ENTRA_ISSUER = "https://entra.example.com";

  @Mock MembershipPort mockMembershipPort;
  @Mock LazyTokenClaimsConverter mockDefaultConverter;

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withPropertyValues("camunda.security.authentication.method=oidc")
          .withUserConfiguration(StubOidcInfrastructure.class)
          .withBean(MembershipPort.class, () -> mockMembershipPort)
          .withBean(LazyTokenClaimsConverter.class, () -> mockDefaultConverter)
          .withBean(
              MembershipResolutionContextPropagator.class,
              MembershipResolutionContextPropagator::identity)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  OidcBeansConfiguration.class,
                  OidcWebappClientBeansConfiguration.class));

  @Test
  void reusesDefaultBeanInstanceForDefaultRegistrationEntry() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER)
        .run(
            ctx -> {
              final var defaultConverter = ctx.getBean(LazyTokenClaimsConverter.class);
              assertThat(byIssuer(ctx)).containsEntry(DEFAULT_ISSUER, defaultConverter);
            });
  }

  @Test
  void buildsDedicatedConverterForAdditionalProviderKeyedByIssuer() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER,
            "camunda.security.authentication.providers.oidc.entra.client-id=entra-client",
            "camunda.security.authentication.providers.oidc.entra.issuer-uri=" + ENTRA_ISSUER,
            "camunda.security.authentication.providers.oidc.entra.username-claim=upn",
            "camunda.security.authentication.providers.oidc.entra.prefer-username-claim=true")
        .run(
            ctx -> {
              final var defaultConverter = ctx.getBean(LazyTokenClaimsConverter.class);
              assertThat(byIssuer(ctx))
                  .hasSize(2)
                  .containsKey(ENTRA_ISSUER)
                  .extractingByKey(ENTRA_ISSUER)
                  .isNotSameAs(defaultConverter);
            });
  }

  @Test
  void skipsProviderConfiguredWithoutIssuerUri() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER,
            "camunda.security.authentication.providers.oidc.legacy.client-id=legacy-client",
            "camunda.security.authentication.providers.oidc.legacy.authorization-uri=https://legacy.example.com/auth",
            "camunda.security.authentication.providers.oidc.legacy.token-uri=https://legacy.example.com/token",
            "camunda.security.authentication.providers.oidc.legacy.jwk-set-uri=https://legacy.example.com/jwks")
        .run(ctx -> assertThat(byIssuer(ctx)).containsOnlyKeys(DEFAULT_ISSUER));
  }

  @Test
  void warnsAndKeepsFirstConverterWhenTwoRegistrationsShareAnIssuer() {
    final ListAppender<ILoggingEvent> appender = attachAppender();
    try {
      runner
          .withPropertyValues(
              "camunda.security.authentication.oidc.client-id=default-client",
              "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER,
              "camunda.security.authentication.providers.oidc.web.client-id=web-client",
              "camunda.security.authentication.providers.oidc.web.issuer-uri=https://shared.example.com",
              "camunda.security.authentication.providers.oidc.backend.client-id=backend-client",
              "camunda.security.authentication.providers.oidc.backend.issuer-uri=https://shared.example.com")
          .run(ctx -> assertThat(byIssuer(ctx)).containsKey("https://shared.example.com"));
      assertThat(appender.list)
          .anySatisfy(
              event -> {
                assertThat(event.getLevel()).isEqualTo(Level.WARN);
                assertThat(event.getFormattedMessage()).contains("https://shared.example.com");
              });
    } finally {
      detachAppender(appender);
    }
  }

  @Test
  void backsOffWhenHostProvidesOwnBean() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER)
        .withUserConfiguration(HostTokenClaimsConvertersByIssuer.class)
        .run(ctx -> assertThat(byIssuer(ctx)).containsOnlyKeys("host-marker"));
  }

  /**
   * Regression test for the Spring {@code Map}-injection interception described on {@link
   * TokenClaimsConvertersByIssuer}: proves a host consuming this bean via a {@code @Bean} method
   * parameter receives the issuer-keyed content, not a bean-name-keyed artifact.
   */
  @Test
  void isConsumableByAHostBeanMethodParameterWithTheCorrectIssuerKeyedContent() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER)
        .withUserConfiguration(HostConsumerOfIssuerConverters.class)
        .run(
            ctx ->
                assertThat(ctx.getBean(HostConsumerOfIssuerConverters.class).received.byIssuer())
                    .containsKey(DEFAULT_ISSUER));
  }

  private static Map<String, LazyTokenClaimsConverter> byIssuer(final ApplicationContext ctx) {
    return ctx.getBean(TokenClaimsConvertersByIssuer.class).byIssuer();
  }

  private static ListAppender<ILoggingEvent> attachAppender() {
    final Logger logger = (Logger) LoggerFactory.getLogger(OidcBeansConfiguration.class);
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private static void detachAppender(final ListAppender<ILoggingEvent> appender) {
    final Logger logger = (Logger) LoggerFactory.getLogger(OidcBeansConfiguration.class);
    logger.detachAppender(appender);
  }

  /**
   * Stubs the OIDC infrastructure beans not under test (mirrors {@link OidcBeansConfigurationTest}
   * so importing {@link OidcWebappClientBeansConfiguration} doesn't require real network
   * discovery).
   */
  @Configuration
  static class StubOidcInfrastructure {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return registrationId -> null;
    }

    @Bean
    JwtDecoder jwtDecoder() {
      return token -> {
        throw new UnsupportedOperationException("stub");
      };
    }

    @Bean
    OAuth2AuthorizedClientRepository authorizedClientRepository() {
      return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager() {
      return request -> null;
    }
  }

  @Configuration
  static class HostTokenClaimsConvertersByIssuer {

    @Bean
    TokenClaimsConvertersByIssuer hostIssuerConverters() {
      return new TokenClaimsConvertersByIssuer(
          Map.of("host-marker", mock(LazyTokenClaimsConverter.class)));
    }
  }

  @Configuration
  static class HostConsumerOfIssuerConverters {

    private TokenClaimsConvertersByIssuer received;

    @Bean
    String hostConsumerMarkerBean(
        final TokenClaimsConvertersByIssuer tokenClaimsConvertersByIssuer) {
      received = tokenClaimsConvertersByIssuer;
      return "marker";
    }
  }
}
