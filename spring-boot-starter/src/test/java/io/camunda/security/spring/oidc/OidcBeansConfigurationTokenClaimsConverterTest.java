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
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

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
  void additionalProviderConverterAppliesItsOwnClaimsToARealDecodedToken() throws Exception {
    // Proves the entra converter is built with its *own* username-claim/client-id-claim/
    // prefer-username-claim by running an actually-signed, actually-decoded token through it —
    // not a hand-built claims map — and that it's not just a distinct instance.
    try (final var server = OidcTestServer.startRsa("entra-kid")) {
      final var decoder = NimbusJwtDecoder.withJwkSetUri(server.jwksUri()).build();
      final var jwt =
          decoder.decode(
              server.sign(server.issuerUri(), Map.of("upn", "carol", "azp", "entra-client-id")));

      runner
          .withPropertyValues(
              "camunda.security.authentication.oidc.client-id=default-client",
              "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER,
              "camunda.security.authentication.providers.oidc.entra.client-id=entra-client",
              "camunda.security.authentication.providers.oidc.entra.issuer-uri="
                  + server.issuerUri(),
              "camunda.security.authentication.providers.oidc.entra.username-claim=upn",
              "camunda.security.authentication.providers.oidc.entra.client-id-claim=azp",
              "camunda.security.authentication.providers.oidc.entra.prefer-username-claim=true")
          .run(
              ctx -> {
                final var entraConverter = byIssuer(ctx).get(server.issuerUri());
                final var authentication = entraConverter.convert(jwt.getClaims());
                assertThat(authentication.authenticatedUsername()).isEqualTo("carol");
                assertThat(authentication.authenticatedClientId()).isNull();
              });
    }
  }

  @Test
  void reusesDefaultBeanInstanceWhenFlatBlockUsesACustomRegistrationId() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER,
            "camunda.security.authentication.oidc.registration-id=primary")
        .run(
            ctx -> {
              final var defaultConverter = ctx.getBean(LazyTokenClaimsConverter.class);
              assertThat(byIssuer(ctx)).containsEntry(DEFAULT_ISSUER, defaultConverter);
            });
  }

  @Test
  void buildsDedicatedConverterWhenANamedProviderOverwritesTheDefaultRegistrationId() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER,
            "camunda.security.authentication.providers.oidc.oidc.client-id=entra-client",
            "camunda.security.authentication.providers.oidc.oidc.issuer-uri=" + ENTRA_ISSUER,
            "camunda.security.authentication.providers.oidc.oidc.username-claim=upn",
            "camunda.security.authentication.providers.oidc.oidc.prefer-username-claim=true")
        .run(
            ctx -> {
              final var defaultConverter = ctx.getBean(LazyTokenClaimsConverter.class);
              assertThat(byIssuer(ctx))
                  .hasSize(1)
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
  void warnsAndKeepsAlphabeticallyFirstConverterWhenTwoRegistrationsShareAnIssuer() {
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
      // "backend" sorts before "web"; neither is the flat entry, so alphabetical order decides.
      assertThat(appender.list)
          .anySatisfy(
              event -> {
                assertThat(event.getLevel()).isEqualTo(Level.WARN);
                assertThat(event.getFormattedMessage())
                    .contains("https://shared.example.com")
                    .contains("'backend'")
                    .contains("'web'");
              });
    } finally {
      detachAppender(appender);
    }
  }

  @Test
  void keepsFlatEntryConverterWhenItSharesAnIssuerWithAnAlphabeticallyEarlierProvider() {
    // "aaa-provider" sorts before the flat entry's registration id ("oidc"), but the flat entry
    // must still win the dedup: it's identified by reference, not by sort order.
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER,
            "camunda.security.authentication.providers.oidc.aaa-provider.client-id=aaa-client",
            "camunda.security.authentication.providers.oidc.aaa-provider.issuer-uri="
                + DEFAULT_ISSUER)
        .run(
            ctx -> {
              final var defaultConverter = ctx.getBean(LazyTokenClaimsConverter.class);
              assertThat(byIssuer(ctx)).containsEntry(DEFAULT_ISSUER, defaultConverter);
            });
  }

  @Test
  void backsOffCleanlyWhenLazyTokenClaimsConverterBeanIsAbsent() {
    // Mirrors the documented @Import(OidcBeansConfiguration.class) quickstart via a REAL host
    // @Configuration + @Import, not AutoConfigurations.of(...): auto-configuration processing
    // registers every class before evaluating any @ConditionalOnBean, so it always sees the full
    // bean set regardless of declaration order — a real @Import host does not get that (ADR-0003),
    // so only this path actually exercises the wiring-failure guard this bean exists for.
    new ApplicationContextRunner()
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER)
        .withUserConfiguration(StubOidcInfrastructure.class, RealImportHostConfiguration.class)
        .withBean(MembershipPort.class, () -> mockMembershipPort)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBeanNamesForType(TokenClaimsConvertersByIssuer.class)).isEmpty();
            });
  }

  @Test
  void fallsBackToIdentityContextPropagatorWhenNoneIsRegistered() {
    // No MembershipResolutionContextPropagator bean at all — building the "entra" provider's
    // dedicated LazyTokenClaimsConverter must not fail wiring on that missing collaborator.
    new ApplicationContextRunner()
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER,
            "camunda.security.authentication.providers.oidc.entra.client-id=entra-client",
            "camunda.security.authentication.providers.oidc.entra.issuer-uri=" + ENTRA_ISSUER)
        .withUserConfiguration(StubOidcInfrastructure.class)
        .withBean(MembershipPort.class, () -> mockMembershipPort)
        .withBean(LazyTokenClaimsConverter.class, () -> mockDefaultConverter)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                OidcBeansConfiguration.class,
                OidcWebappClientBeansConfiguration.class))
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(byIssuer(ctx)).containsKey(ENTRA_ISSUER);
            });
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

  /**
   * A real host {@code @Configuration} + {@code @Import}, as opposed to {@code
   * AutoConfigurations.of(...)}: reproduces the parse-order-sensitive condition evaluation a real
   * host actually gets (ADR-0003), for the one test that needs to prove backoff under that path.
   */
  @Configuration
  @Import({
    CamundaSecurityConfiguration.class,
    OidcBeansConfiguration.class,
    OidcWebappClientBeansConfiguration.class
  })
  static class RealImportHostConfiguration {}

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
