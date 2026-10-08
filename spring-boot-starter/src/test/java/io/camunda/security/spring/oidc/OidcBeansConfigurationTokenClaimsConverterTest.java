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
import static org.mockito.Mockito.mock;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.converter.TokenClaimsConvertersByIssuer;
import java.util.ArrayList;
import java.util.List;
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
  private static final String SCOPE_ISSUER = "https://tenanta.example.com";

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
  void warnsAndKeepsTheFirstConfiguredConverterWhenTwoRegistrationsShareAnIssuer() {
    final ListAppender<ILoggingEvent> appender = attachAppender();
    try {
      runner
          .withPropertyValues(
              "camunda.security.authentication.oidc.client-id=default-client",
              "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER,
              "camunda.security.authentication.providers.oidc.web.client-id=web-client",
              "camunda.security.authentication.providers.oidc.web.issuer-uri=https://shared.example.com",
              "camunda.security.authentication.providers.oidc.web.username-claim=web_user",
              "camunda.security.authentication.providers.oidc.web.prefer-username-claim=true",
              "camunda.security.authentication.providers.oidc.backend.client-id=backend-client",
              "camunda.security.authentication.providers.oidc.backend.issuer-uri=https://shared.example.com",
              "camunda.security.authentication.providers.oidc.backend.username-claim=backend_user",
              "camunda.security.authentication.providers.oidc.backend.prefer-username-claim=true")
          .run(
              ctx -> {
                // A token of the shared issuer carries both usernames, so the claim the converter
                // reads names the registration it was built from.
                final var converter = byIssuer(ctx).get("https://shared.example.com");
                assertThat(converter).isNotNull();
                final var authentication =
                    converter.convert(
                        Map.of(
                            "iss", "https://shared.example.com",
                            "web_user", "web-alice",
                            "backend_user", "backend-bob"));
                assertThat(authentication.authenticatedUsername()).isEqualTo("web-alice");
              });
      // "web" is configured before "backend", and the decoder of the same deployment reads that
      // order too, so the converter of a token comes from the provider that verified it.
      assertThat(appender.list)
          .anySatisfy(
              event -> {
                assertThat(event.getLevel()).isEqualTo(Level.WARN);
                assertThat(event.getFormattedMessage())
                    .contains("https://shared.example.com")
                    .contains("'web' wins")
                    .contains("ignore the claim configuration of 'backend'");
              });
    } finally {
      detachAppender(appender);
    }
  }

  @Test
  void redactsCredentialsFromTheSharedIssuerWarning() {
    // given two providers sharing a credential-bearing issuer — an issuer-uri check elsewhere is
    // warn-only, not rejected, so such a value can survive to this pre-existing duplicate-issuer
    // diagnostic, and it must be redacted here too, or the credential leaks into the log
    final ListAppender<ILoggingEvent> appender = attachAppender();
    try {
      runner
          .withPropertyValues(
              "camunda.security.authentication.oidc.client-id=default-client",
              "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER,
              "camunda.security.authentication.providers.oidc.web.client-id=web-client",
              "camunda.security.authentication.providers.oidc.web.issuer-uri=https://user:s3cret@shared.example.com",
              "camunda.security.authentication.providers.oidc.backend.client-id=backend-client",
              "camunda.security.authentication.providers.oidc.backend.issuer-uri=https://user:s3cret@shared.example.com")
          .run(ctx -> {});

      assertThat(appender.list)
          .anySatisfy(
              event -> {
                assertThat(event.getLevel()).isEqualTo(Level.WARN);
                assertThat(event.getFormattedMessage())
                    .doesNotContain("s3cret")
                    .contains("'web' wins")
                    .contains("ignore the claim configuration of 'backend'");
              });
    } finally {
      detachAppender(appender);
    }
  }

  @Test
  void keepsFlatEntryConverterWhenAProviderSharesItsIssuer() {
    // The merge places the flat block before the provider blocks, so the flat entry owns the
    // issuer it shares with a provider.
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
  void shouldNotLetABlankRegistrationIdWinIssuerOwnershipOverAValidProvider() {
    // given a flat block with a blank registration-id sharing an issuer with a real provider —
    // the flat entry is inserted first by flatten(), so without filtering it would win ownership
    // and the claims converter would be built from the wrong (blank-id) configuration while the
    // decoder verifies the token with the valid "entra" provider
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.registration-id=",
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + ENTRA_ISSUER,
            "camunda.security.authentication.providers.oidc.entra.client-id=entra-client",
            "camunda.security.authentication.providers.oidc.entra.issuer-uri=" + ENTRA_ISSUER,
            "camunda.security.authentication.providers.oidc.entra.username-claim=entra_user")
        .run(
            ctx -> {
              final var converter = byIssuer(ctx).get(ENTRA_ISSUER);
              assertThat(converter).isNotNull().isNotSameAs(mockDefaultConverter);
              final var authentication =
                  converter.convert(Map.of("iss", ENTRA_ISSUER, "entra_user", "alice"));
              assertThat(authentication.authenticatedUsername()).isEqualTo("alice");
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

  @Test
  void includesProviderDeclaredOnlyViaScopeDescriptorKeyedByItsIssuer() {
    // Reproduces camunda/camunda#64685: a physical tenant's own IdP is declared only through a
    // CamundaSecurityScopeProvider descriptor (ADR-0013), not at root. Its issuer must resolve to
    // its own claim converter so the REST bearer path accepts the same tokens gRPC accepts, instead
    // of falling back to the cluster-default converter and rejecting them with 401.
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER)
        .withBean(
            CamundaSecurityScopeProvider.class,
            () -> scopeProvider("/physical-tenants/tenanta", SCOPE_ISSUER, "tenant_user"))
        .run(
            ctx -> {
              final var defaultConverter = ctx.getBean(LazyTokenClaimsConverter.class);
              assertThat(byIssuer(ctx))
                  .containsKey(SCOPE_ISSUER)
                  .extractingByKey(SCOPE_ISSUER)
                  .isNotSameAs(defaultConverter);
              // The token carries only the scope's own claim. The scope converter resolves it...
              final var scopeOnlyClaims =
                  Map.<String, Object>of("iss", SCOPE_ISSUER, "tenant_user", "dave");
              final var authentication = byIssuer(ctx).get(SCOPE_ISSUER).convert(scopeOnlyClaims);
              assertThat(authentication.authenticatedUsername()).isEqualTo("dave");
              // ...while a converter configured with the cluster default's claims — what the bearer
              // path used before this fix — finds neither claim and throws the
              // IllegalArgumentException
              // that surfaces as the reported 401.
              final var rootStyleConverter =
                  new LazyTokenClaimsConverter(
                      "preferred_username", "client_id", false, mockMembershipPort);
              assertThatThrownBy(() -> rootStyleConverter.convert(scopeOnlyClaims))
                  .isInstanceOf(IllegalArgumentException.class);
            });
  }

  @Test
  void twoScopesWithDistinctIssuersEachResolveWithTheirOwnClaims() {
    // The realistic multi-tenant shape: two physical tenants, each with its own IdP (distinct
    // issuer) and its own username-claim. Each issuer resolves with its own scope's configuration.
    final var otherIssuer = "https://tenantb.example.com";
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER)
        .withBean(
            "scopeA",
            CamundaSecurityScopeProvider.class,
            () -> scopeProvider("/physical-tenants/a", SCOPE_ISSUER, "a_user"))
        .withBean(
            "scopeB",
            CamundaSecurityScopeProvider.class,
            () -> scopeProvider("/physical-tenants/b", otherIssuer, "b_user"))
        .run(
            ctx -> {
              assertThat(
                      byIssuer(ctx)
                          .get(SCOPE_ISSUER)
                          .convert(Map.of("iss", SCOPE_ISSUER, "a_user", "alice"))
                          .authenticatedUsername())
                  .isEqualTo("alice");
              assertThat(
                      byIssuer(ctx)
                          .get(otherIssuer)
                          .convert(Map.of("iss", otherIssuer, "b_user", "bob"))
                          .authenticatedUsername())
                  .isEqualTo("bob");
            });
  }

  @Test
  void resolvesAScopeProviderDeclaredOnlyViaItsProvidersBlock() {
    // A scope whose OIDC provider is declared under providers.oidc.<id> (no flat oidc.* client) is
    // flattened the same way the root config is, so its issuer is keyed too.
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER)
        .withBean(
            CamundaSecurityScopeProvider.class,
            () ->
                scopeProviderWithProvidersBlock(
                    "/physical-tenants/tenanta",
                    Map.of("okta", providerConfig(SCOPE_ISSUER, "tenant_user"))))
        .run(
            ctx ->
                assertThat(
                        byIssuer(ctx)
                            .get(SCOPE_ISSUER)
                            .convert(Map.of("iss", SCOPE_ISSUER, "tenant_user", "dave"))
                            .authenticatedUsername())
                    .isEqualTo("dave"));
  }

  @Test
  void ignoresABasicScopeEvenWhenItCarriesAnOidcBlockAndDoesNotShadowAnOidcScope() {
    // A BASIC scope's OIDC block is inactive (AuthenticationConfiguration), and the scoped chains
    // ignore it. It must not claim an issuer; if it did, it would shadow a later OIDC scope that
    // shares the issuer, converting that scope's tokens with the wrong (BASIC-block) claims.
    final var basicScope = new OidcConfiguration();
    basicScope.setClientId("basic-client");
    basicScope.setIssuerUri(SCOPE_ISSUER);
    basicScope.setUsernameClaim("basic_user");
    final var basicAuth = new AuthenticationConfiguration();
    basicAuth.setMethod(AuthenticationMethod.BASIC);
    basicAuth.setOidc(basicScope);
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER)
        .withBean(
            "basicScope",
            CamundaSecurityScopeProvider.class,
            () ->
                (CamundaSecurityScopeProvider)
                    () ->
                        List.of(new ScopedSecurityDescriptor("/physical-tenants/basic", basicAuth)))
        .withBean(
            "oidcScope",
            CamundaSecurityScopeProvider.class,
            () -> scopeProvider("/physical-tenants/oidc", SCOPE_ISSUER, "oidc_user"))
        .run(
            ctx ->
                // The OIDC scope owns the issuer and resolves its own claim; the BASIC block is
                // gone.
                assertThat(
                        byIssuer(ctx)
                            .get(SCOPE_ISSUER)
                            .convert(
                                Map.of(
                                    "iss", SCOPE_ISSUER,
                                    "basic_user", "mallory",
                                    "oidc_user", "dave"))
                            .authenticatedUsername())
                    .isEqualTo("dave"));
  }

  @Test
  void skipsAScopeProviderConfiguredWithoutIssuerUri() {
    // A scope provider with no issuer-uri contributes no entry, exactly as a root provider without
    // one does; only the root issuer remains.
    final var noIssuer = new OidcConfiguration();
    noIssuer.setClientId("scope-client");
    noIssuer.setAuthorizationUri("https://legacy.example.com/auth");
    noIssuer.setTokenUri("https://legacy.example.com/token");
    noIssuer.setJwkSetUri("https://legacy.example.com/jwks");
    final var authentication = new AuthenticationConfiguration();
    authentication.setMethod(AuthenticationMethod.OIDC);
    authentication.setOidc(noIssuer);
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER)
        .withBean(
            CamundaSecurityScopeProvider.class,
            () ->
                () ->
                    List.of(
                        new ScopedSecurityDescriptor("/physical-tenants/legacy", authentication)))
        .run(ctx -> assertThat(byIssuer(ctx)).containsOnlyKeys(DEFAULT_ISSUER));
  }

  @Test
  void rootLevelProviderOwnsIssuerSharedWithAScopeProvider() {
    // Acceptance: root-level providers are processed first, so a deployment behaves as before for
    // an
    // issuer a scope happens to share with root. The root/default converter stays and the scope's
    // converter is not built — the map still holds exactly the one root entry.
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER)
        .withBean(
            CamundaSecurityScopeProvider.class,
            () -> scopeProvider("/physical-tenants/default", DEFAULT_ISSUER, "tenant_user"))
        .run(
            ctx -> {
              final var defaultConverter = ctx.getBean(LazyTokenClaimsConverter.class);
              assertThat(byIssuer(ctx)).hasSize(1).containsEntry(DEFAULT_ISSUER, defaultConverter);
              // The scope's tenant_user claim is not applied: the owning converter is the root
              // default (a mock), so a token carrying only tenant_user does not resolve through it.
              assertThat(byIssuer(ctx).get(DEFAULT_ISSUER)).isSameAs(mockDefaultConverter);
            });
  }

  @Test
  void firstScopeOwnsAnIssuerSharedByTwoScopeProviders() {
    // Two scope providers declare the same issuer; the first contributed descriptor wins, matching
    // the "first provider owns the issuer" rule the root path already uses.
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER)
        .withBean(
            "firstScope",
            CamundaSecurityScopeProvider.class,
            () -> scopeProvider("/physical-tenants/first", SCOPE_ISSUER, "first_user"))
        .withBean(
            "secondScope",
            CamundaSecurityScopeProvider.class,
            () -> scopeProvider("/physical-tenants/second", SCOPE_ISSUER, "second_user"))
        .run(
            ctx -> {
              final var authentication =
                  byIssuer(ctx)
                      .get(SCOPE_ISSUER)
                      .convert(
                          Map.of(
                              "iss", SCOPE_ISSUER,
                              "first_user", "alice",
                              "second_user", "bob"));
              assertThat(authentication.authenticatedUsername()).isEqualTo("alice");
            });
  }

  @Test
  void warnsWhenAScopeSharesTheRootIssuerWithDifferentClaims() {
    // #714: issuer-only keying drops the scope's differing claim config. The WARN must name both
    // sources and link the follow-up, so an operator understands which claims win and why.
    final ListAppender<ILoggingEvent> appender = attachAppender();
    try {
      runner
          .withPropertyValues(
              "camunda.security.authentication.oidc.client-id=default-client",
              "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER,
              "camunda.security.authentication.oidc.username-claim=preferred_username")
          .withBean(
              CamundaSecurityScopeProvider.class,
              () -> scopeProvider("/physical-tenants/tenanta", DEFAULT_ISSUER, "upn"))
          .run(
              ctx ->
                  assertThat(appender.list)
                      .anySatisfy(
                          event -> {
                            assertThat(event.getLevel()).isEqualTo(Level.WARN);
                            assertThat(event.getFormattedMessage())
                                .contains(DEFAULT_ISSUER)
                                .contains("the root providers")
                                .contains("scope '/physical-tenants/tenanta'")
                                .contains("different claim settings")
                                .contains("issues/714");
                          }));
    } finally {
      detachAppender(appender);
    }
  }

  @Test
  void logsAtDebugAndDoesNotWarnWhenAScopeRepeatsTheRootIssuerWithIdenticalClaims() {
    // The benign default-tenant-at-root-and-as-scope overlap: identical claim settings must stay
    // quiet (DEBUG), not warn, so the common physical-tenant layout doesn't spam startup logs.
    final var logger = (Logger) LoggerFactory.getLogger(OidcBeansConfiguration.class);
    final var previousLevel = logger.getLevel();
    logger.setLevel(Level.DEBUG);
    final ListAppender<ILoggingEvent> appender = attachAppender();
    try {
      runner
          .withPropertyValues(
              "camunda.security.authentication.oidc.client-id=default-client",
              "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER,
              "camunda.security.authentication.oidc.username-claim=tenant_user",
              "camunda.security.authentication.oidc.prefer-username-claim=true")
          .withBean(
              CamundaSecurityScopeProvider.class,
              () -> scopeProvider("/physical-tenants/default", DEFAULT_ISSUER, "tenant_user"))
          .run(
              ctx -> {
                assertThat(appender.list).noneMatch(event -> event.getLevel() == Level.WARN);
                assertThat(appender.list)
                    .anySatisfy(
                        event -> {
                          assertThat(event.getLevel()).isEqualTo(Level.DEBUG);
                          assertThat(event.getFormattedMessage())
                              .contains(DEFAULT_ISSUER)
                              .contains("identical claim settings");
                        });
              });
    } finally {
      detachAppender(appender);
      logger.setLevel(previousLevel);
    }
  }

  @Test
  void warnsWithTheScopeLabelOnADuplicateIssuerWithinOneScope() {
    // Two providers inside a single scope share an issuer. IssuerOwnership's within-source WARN
    // must
    // carry the scope's basePath so an operator can locate the offending descriptor.
    final ListAppender<ILoggingEvent> appender = attachAppender();
    try {
      runner
          .withPropertyValues(
              "camunda.security.authentication.oidc.client-id=default-client",
              "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER)
          .withBean(
              CamundaSecurityScopeProvider.class,
              () ->
                  scopeProviderWithProvidersBlock(
                      "/physical-tenants/multi",
                      Map.of(
                          "primary", providerConfig(SCOPE_ISSUER, "primary_user"),
                          "secondary", providerConfig(SCOPE_ISSUER, "secondary_user"))))
          .run(
              ctx ->
                  assertThat(appender.list)
                      .anySatisfy(
                          event -> {
                            assertThat(event.getLevel()).isEqualTo(Level.WARN);
                            assertThat(event.getFormattedMessage())
                                .contains(SCOPE_ISSUER)
                                .contains("scope '/physical-tenants/multi'");
                          }));
    } finally {
      detachAppender(appender);
    }
  }

  @Test
  void redactsCredentialsFromTheSharedIssuerDiagnostic() {
    // A scope provider shares a credential-bearing issuer with the root provider. The issuer-uri
    // check is warn-only, so such a value reaches the cross-source diagnostic — which must redact
    // it
    // just like the IssuerOwnership warning does.
    final var credentialIssuer = "https://user:s3cret@shared.example.com";
    final ListAppender<ILoggingEvent> appender = attachAppender();
    try {
      runner
          .withPropertyValues(
              "camunda.security.authentication.oidc.client-id=default-client",
              "camunda.security.authentication.oidc.issuer-uri=" + credentialIssuer,
              "camunda.security.authentication.oidc.username-claim=preferred_username")
          .withBean(
              CamundaSecurityScopeProvider.class,
              () -> scopeProvider("/physical-tenants/tenanta", credentialIssuer, "upn"))
          .run(
              ctx -> {
                assertThat(appender.list)
                    .noneSatisfy(
                        event -> assertThat(event.getFormattedMessage()).contains("s3cret"));
                assertThat(appender.list)
                    .anySatisfy(
                        event -> {
                          assertThat(event.getLevel()).isEqualTo(Level.WARN);
                          assertThat(event.getFormattedMessage())
                              .contains("different claim settings")
                              .contains("issues/714");
                        });
              });
    } finally {
      detachAppender(appender);
    }
  }

  @Test
  void failsClearlyWhenAScopeProviderReturnsNull() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER)
        .withBean(
            CamundaSecurityScopeProvider.class, () -> (CamundaSecurityScopeProvider) () -> null)
        .run(
            ctx ->
                assertThat(ctx)
                    .hasFailed()
                    .getFailure()
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("returned null"));
  }

  @Test
  void failsClearlyWhenAScopeProviderReturnsAListWithANullElement() {
    final List<ScopedSecurityDescriptor> withNull = new ArrayList<>();
    withNull.add(null);
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER)
        .withBean(
            CamundaSecurityScopeProvider.class, () -> (CamundaSecurityScopeProvider) () -> withNull)
        .run(
            ctx ->
                assertThat(ctx)
                    .hasFailed()
                    .getFailure()
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("null element"));
  }

  private static CamundaSecurityScopeProvider scopeProvider(
      final String basePath, final String issuerUri, final String usernameClaim) {
    final var authentication = new AuthenticationConfiguration();
    authentication.setMethod(AuthenticationMethod.OIDC);
    authentication.setOidc(providerConfig(issuerUri, usernameClaim));
    return () -> List.of(new ScopedSecurityDescriptor(basePath, authentication));
  }

  private static CamundaSecurityScopeProvider scopeProviderWithProvidersBlock(
      final String basePath, final Map<String, OidcConfiguration> providers) {
    final var authentication = new AuthenticationConfiguration();
    authentication.setMethod(AuthenticationMethod.OIDC);
    authentication.getProviders().getOidc().putAll(providers);
    return () -> List.of(new ScopedSecurityDescriptor(basePath, authentication));
  }

  private static OidcConfiguration providerConfig(
      final String issuerUri, final String usernameClaim) {
    final var oidc = new OidcConfiguration();
    oidc.setClientId("scope-client");
    oidc.setIssuerUri(issuerUri);
    oidc.setUsernameClaim(usernameClaim);
    oidc.setPreferUsernameClaim(true);
    return oidc;
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
