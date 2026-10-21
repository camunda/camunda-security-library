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
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
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
      baseRunner().withUserConfiguration(StubOidcInfrastructure.class);

  /**
   * camunda/camunda#61896, with a host repository: provider {@code a} is configured with a trailing
   * slash, and its registration resolved to the issuer the provider declares. Its tokens keep the
   * claim settings of {@code a}, rather than the default ones.
   */
  @Test
  void appliesTheProviderClaimsToAHostRegistrationResolvedToAnotherIssuer() {
    hostRunner(registration("a", "https://idp.example.com/realm"))
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.a.client-id=a-client",
            "camunda.security.authentication.providers.oidc.a.issuer-uri=https://idp.example.com/realm/",
            "camunda.security.authentication.providers.oidc.a.username-claim=upn")
        .run(
            ctx -> {
              final var converter =
                  ctx.getBean(TokenClaimsConvertersByIssuer.class)
                      .getOrDefault("https://idp.example.com/realm", mockDefaultConverter);
              assertThat(converter).isNotSameAs(mockDefaultConverter);
              assertThat(
                      converter
                          .convert(Map.of("sub", "bob", "upn", "alice"))
                          .authenticatedUsername())
                  .isEqualTo("alice");
            });
  }

  /**
   * A host registration that no provider configures gets the default converter, also where its
   * issuer is the slash twin of a configured one.
   */
  @Test
  void usesTheDefaultConverterForAnUnconfiguredRegistrationOfAHostRepository() {
    hostRunner(
            registration("a", "https://idp.example.com/realm"),
            registration("host-only", "https://idp.example.com/realm/"))
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.a.client-id=a-client",
            "camunda.security.authentication.providers.oidc.a.issuer-uri=https://idp.example.com/realm/",
            "camunda.security.authentication.providers.oidc.a.username-claim=upn")
        .run(
            ctx ->
                assertThat(
                        ctx.getBean(TokenClaimsConvertersByIssuer.class)
                            .getOrDefault("https://idp.example.com/realm/", mockDefaultConverter))
                    .isSameAs(mockDefaultConverter));
  }

  /**
   * Providers whose issuer-uris differ only by a trailing slash, behind the default decoder over a
   * host repository: each token keeps the claim settings of the registration that carries its
   * issuer, as the decoder routes it.
   */
  @Test
  void keepsTwinIssuersApartForAHostRepository() {
    hostRunner(
            registration("a", "https://idp.example.com/realm"),
            registration("b", "https://idp.example.com/realm/"))
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.a.client-id=a-client",
            "camunda.security.authentication.providers.oidc.a.issuer-uri=https://idp.example.com/realm",
            "camunda.security.authentication.providers.oidc.a.username-claim=a_user",
            "camunda.security.authentication.providers.oidc.b.client-id=b-client",
            "camunda.security.authentication.providers.oidc.b.issuer-uri=https://idp.example.com/realm/",
            "camunda.security.authentication.providers.oidc.b.username-claim=b_user")
        .run(
            ctx -> {
              assertThat(usernameOf(ctx, "https://idp.example.com/realm")).isEqualTo("alice");
              assertThat(usernameOf(ctx, "https://idp.example.com/realm/")).isEqualTo("bob");
            });
  }

  /**
   * The default decoder over a lazy repository of the host routes by that repository's providers,
   * which can differ from the configuration: here it holds only B. A token of B's slash form gets
   * B's claim settings, and not those of A, which the configuration declares at the twin issuer.
   */
  @Test
  void routesByTheProvidersOfALazyRepositoryOfTheHost() {
    final var onlyB =
        new LazyClientRegistrationRepository(
            new ScopedClientRegistrationFactory(),
            Map.of("b", provider("https://idp.example.com/realm/")));
    runnerWithDecoderRouting(onlyB)
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.a.client-id=a-client",
            "camunda.security.authentication.providers.oidc.a.issuer-uri=https://idp.example.com/realm",
            "camunda.security.authentication.providers.oidc.a.username-claim=a_user",
            "camunda.security.authentication.providers.oidc.b.client-id=b-client",
            "camunda.security.authentication.providers.oidc.b.issuer-uri=https://idp.example.com/realm/",
            "camunda.security.authentication.providers.oidc.b.username-claim=b_user")
        .run(
            ctx -> {
              assertThat(usernameOf(ctx, "https://idp.example.com/realm/")).isEqualTo("bob");
              assertThat(usernameOf(ctx, "https://idp.example.com/realm")).isEqualTo("bob");
            });
  }

  /**
   * Bearer-only, with a decoder of the host and no login repository: the decoder's routing is
   * unknown, so providers whose issuer-uris differ only by a trailing slash keep their own claim
   * settings, and B's token is not mapped with the settings of A, declared first.
   */
  @Test
  void keepsTwinIssuersApartForADecoderOfTheHostWithoutARepository() {
    baseRunner()
        .withBean(
            JwtDecoder.class,
            () ->
                token -> {
                  throw new UnsupportedOperationException("host decoder");
                })
        .withPropertyValues(
            "camunda.security.authentication.webapp-enabled=false",
            "camunda.security.authentication.providers.oidc.a.client-id=a-client",
            "camunda.security.authentication.providers.oidc.a.issuer-uri=https://idp.example.com/realm",
            "camunda.security.authentication.providers.oidc.a.username-claim=a_user",
            "camunda.security.authentication.providers.oidc.b.client-id=b-client",
            "camunda.security.authentication.providers.oidc.b.issuer-uri=https://idp.example.com/realm/",
            "camunda.security.authentication.providers.oidc.b.username-claim=b_user")
        .run(
            ctx -> {
              assertThat(ctx).doesNotHaveBean(ClientRegistrationRepository.class);
              assertThat(usernameOf(ctx, "https://idp.example.com/realm")).isEqualTo("alice");
              assertThat(usernameOf(ctx, "https://idp.example.com/realm/")).isEqualTo("bob");
            });
  }

  /**
   * Neither a repository nor a decoder bean: the scoped decoders route by the configuration, where
   * twin issuers are one issuer, owned by the provider declared first.
   */
  @Test
  void mergesTwinIssuersWithoutARepositoryOrADecoder() {
    baseRunner()
        .withPropertyValues(
            "camunda.security.authentication.webapp-enabled=false",
            "camunda.security.authentication.providers.oidc.a.client-id=a-client",
            "camunda.security.authentication.providers.oidc.a.issuer-uri=https://idp.example.com/realm",
            "camunda.security.authentication.providers.oidc.a.username-claim=a_user",
            "camunda.security.authentication.providers.oidc.b.client-id=b-client",
            "camunda.security.authentication.providers.oidc.b.issuer-uri=https://idp.example.com/realm/",
            "camunda.security.authentication.providers.oidc.b.username-claim=b_user")
        .run(
            ctx -> {
              assertThat(ctx).doesNotHaveBean(ClientRegistrationRepository.class);
              assertThat(ctx).doesNotHaveBean(JwtDecoder.class);
              assertThat(usernameOf(ctx, "https://idp.example.com/realm")).isEqualTo("alice");
              assertThat(usernameOf(ctx, "https://idp.example.com/realm/")).isEqualTo("alice");
            });
  }

  /**
   * Two registrations share an issuer, and the host repository reorders between the decoder's first
   * read and the first claims lookup. The converters read the decoder's snapshot, so the token
   * keeps the claim settings of the registration the decoder routed it to.
   */
  @Test
  void usesTheRegistrationsTheDecoderReadForADynamicHostRepository() {
    final var repository =
        new ReorderableRegistrationRepository(
            registration("a", "https://idp.example.com"),
            registration("b", "https://idp.example.com"));
    runnerWithDecoderRouting(repository)
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.a.client-id=a-client",
            "camunda.security.authentication.providers.oidc.a.issuer-uri=https://idp.example.com",
            "camunda.security.authentication.providers.oidc.a.username-claim=a_user",
            "camunda.security.authentication.providers.oidc.b.client-id=b-client",
            "camunda.security.authentication.providers.oidc.b.issuer-uri=https://idp.example.com/",
            "camunda.security.authentication.providers.oidc.b.username-claim=b_user")
        .run(
            ctx -> {
              // the decoder initializes first and routes the issuer to "a"
              ((DeferredJwtDecoder) ctx.getBean(JwtDecoder.class)).routing().registrations().get();
              repository.reverse();

              assertThat(usernameOf(ctx, "https://idp.example.com")).isEqualTo("alice");
            });
  }

  /**
   * Bearer-only with a decoder of the host and several repository beans, none of them primary: the
   * converters only ask whether a repository exists, so the context starts, with the exact lookup.
   */
  @Test
  void startsWithSeveralRepositoriesAndADecoderOfTheHost() {
    baseRunner()
        .withBean("first", ClientRegistrationRepository.class, () -> registrationId -> null)
        .withBean("second", ClientRegistrationRepository.class, () -> registrationId -> null)
        .withBean(
            JwtDecoder.class,
            () ->
                token -> {
                  throw new UnsupportedOperationException("host decoder");
                })
        .withPropertyValues(
            "camunda.security.authentication.webapp-enabled=false",
            "camunda.security.authentication.providers.oidc.a.client-id=a-client",
            "camunda.security.authentication.providers.oidc.a.issuer-uri=https://idp.example.com/realm",
            "camunda.security.authentication.providers.oidc.a.username-claim=a_user",
            "camunda.security.authentication.providers.oidc.b.client-id=b-client",
            "camunda.security.authentication.providers.oidc.b.issuer-uri=https://idp.example.com/realm/",
            "camunda.security.authentication.providers.oidc.b.username-claim=b_user")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(usernameOf(ctx, "https://idp.example.com/realm/")).isEqualTo("bob");
            });
  }

  /**
   * A host's own decoder need not use the login registrations, so the converters keep the lookup by
   * configured issuer-uri: provider X keeps its claim settings although the enumerable login
   * repository holds only Y.
   */
  @Test
  void keepsTheConfiguredLookupForADecoderOfTheHost() {
    baseRunner()
        .withUserConfiguration(StubOidcClients.class)
        .withBean(
            ClientRegistrationRepository.class,
            () -> new InMemoryClientRegistrationRepository(registration("y", "https://y")))
        .withBean(
            JwtDecoder.class,
            () ->
                token -> {
                  throw new UnsupportedOperationException("host decoder");
                })
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.x.client-id=x-client",
            "camunda.security.authentication.providers.oidc.x.issuer-uri=https://x",
            "camunda.security.authentication.providers.oidc.x.username-claim=a_user")
        .run(ctx -> assertThat(usernameOf(ctx, "https://x")).isEqualTo("alice"));
  }

  /**
   * A single host registration without issuer metadata gets a decoder of its own, which validates
   * the issuer from the provider configuration. Its tokens keep the claim settings of its provider.
   */
  @Test
  void appliesTheProviderClaimsToASingleHostRegistrationWithoutAnIssuer() {
    hostRunner(registration("a", null))
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.a.client-id=a-client",
            "camunda.security.authentication.providers.oidc.a.issuer-uri=https://idp.example.com",
            "camunda.security.authentication.providers.oidc.a.username-claim=a_user")
        .run(ctx -> assertThat(usernameOf(ctx, "https://idp.example.com")).isEqualTo("alice"));
  }

  /**
   * For a host repository the lookup is exact. A token of a host registration that has no entry
   * here, at the slash twin of a configured issuer, gets the default converter, not the twin's.
   */
  @Test
  void usesTheDefaultConverterForAHostRegistrationWithoutAnEntry() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=default-client",
            "camunda.security.authentication.oidc.issuer-uri=" + DEFAULT_ISSUER,
            "camunda.security.authentication.providers.oidc.a.client-id=a-client",
            "camunda.security.authentication.providers.oidc.a.issuer-uri=https://idp.example.com/realm",
            "camunda.security.authentication.providers.oidc.a.username-claim=a_user")
        .run(
            ctx -> {
              final var defaultConverter = ctx.getBean(LazyTokenClaimsConverter.class);
              assertThat(
                      ctx.getBean(TokenClaimsConvertersByIssuer.class)
                          .getOrDefault("https://idp.example.com/realm/", defaultConverter))
                  .isSameAs(defaultConverter);
            });
  }

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
  void additionalProviderWithoutOwnClaimsUsesTheGlobalClaims() throws Exception {
    // the multi-IdP setup: the claims are set only globally, the named provider sets none
    try (final var server = OidcTestServer.startRsa("entra-kid")) {
      final var decoder = NimbusJwtDecoder.withJwkSetUri(server.jwksUri()).build();
      final var userToken =
          decoder.decode(
              server.sign(
                  server.issuerUri(),
                  Map.of("sub", "4f2a", "preferred_username", "alice", "azp", "camunda-web")));
      final var clientToken =
          decoder.decode(server.sign(server.issuerUri(), Map.of("sub", "9c1b", "azp", "my-app")));

      runner
          .withPropertyValues(
              "camunda.security.authentication.oidc.username-claim=preferred_username",
              "camunda.security.authentication.oidc.client-id-claim=azp",
              "camunda.security.authentication.oidc.prefer-username-claim=true",
              "camunda.security.authentication.providers.oidc.entra.client-id=entra-client",
              "camunda.security.authentication.providers.oidc.entra.issuer-uri="
                  + server.issuerUri())
          .run(
              ctx -> {
                final var entraConverter = byIssuer(ctx).get(server.issuerUri());
                assertThat(entraConverter.convert(userToken.getClaims()).authenticatedUsername())
                    .isEqualTo("alice");
                assertThat(entraConverter.convert(clientToken.getClaims()).authenticatedClientId())
                    .isEqualTo("my-app");
              });
    }
  }

  @Test
  void additionalProviderClaimWinsAlsoWhenItIsTheDefaultValue() throws Exception {
    // the provider sets username-claim to sub on purpose, while the global value differs
    try (final var server = OidcTestServer.startRsa("entra-kid")) {
      final var decoder = NimbusJwtDecoder.withJwkSetUri(server.jwksUri()).build();
      final var jwt =
          decoder.decode(
              server.sign(server.issuerUri(), Map.of("sub", "7d3e", "preferred_username", "bob")));

      runner
          .withPropertyValues(
              "camunda.security.authentication.oidc.username-claim=preferred_username",
              "camunda.security.authentication.providers.oidc.entra.client-id=entra-client",
              "camunda.security.authentication.providers.oidc.entra.issuer-uri="
                  + server.issuerUri(),
              "camunda.security.authentication.providers.oidc.entra.username-claim=sub")
          .run(
              ctx ->
                  assertThat(
                          byIssuer(ctx)
                              .get(server.issuerUri())
                              .convert(jwt.getClaims())
                              .authenticatedUsername())
                      .isEqualTo("7d3e"));
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

  private ApplicationContextRunner baseRunner() {
    return new ApplicationContextRunner()
        .withPropertyValues("camunda.security.authentication.method=oidc")
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
  }

  /**
   * With an enumerable host repository holding {@code registrations}, behind the library's default
   * decoder.
   */
  private ApplicationContextRunner hostRunner(final ClientRegistration... registrations) {
    return runnerWithDecoderRouting(new InMemoryClientRegistrationRepository(registrations));
  }

  /** With {@code repository}, and a decoder routed by it as the library's default decoder is. */
  private ApplicationContextRunner runnerWithDecoderRouting(
      final ClientRegistrationRepository repository) {
    return baseRunner()
        .withUserConfiguration(StubOidcClients.class)
        .withBean(ClientRegistrationRepository.class, () -> repository)
        .withBean(
            JwtDecoder.class,
            () ->
                new DeferredJwtDecoder(
                    () -> {
                      throw new UnsupportedOperationException("stub");
                    },
                    routingOf(repository)));
  }

  /** The routing the library's default decoder gives {@code repository}. */
  @SuppressWarnings("unchecked")
  private static DecoderRouting routingOf(final ClientRegistrationRepository repository) {
    if (repository instanceof final LazyClientRegistrationRepository lazy) {
      return DecoderRouting.byProviders(lazy);
    }
    final var iterable = (Iterable<ClientRegistration>) repository;
    return DecoderRouting.byRegistrations(
        DeferredOidcResolution.memoizeOnSuccess(
            () -> {
              final List<ClientRegistration> registrations = new ArrayList<>();
              iterable.forEach(registrations::add);
              return List.copyOf(registrations);
            }));
  }

  /** The username that the converter of {@code issuer} reads from a token of alice and bob. */
  private String usernameOf(final ApplicationContext ctx, final String issuer) {
    return ctx.getBean(TokenClaimsConvertersByIssuer.class)
        .getOrDefault(issuer, mockDefaultConverter)
        .convert(Map.of("sub", "carol", "a_user", "alice", "b_user", "bob"))
        .authenticatedUsername();
  }

  private static OidcConfiguration provider(final String issuerUri) {
    final var provider = new OidcConfiguration();
    provider.setClientId("host-client");
    provider.setIssuerUri(issuerUri);
    provider.setRedirectUri("{baseUrl}/login/oauth2/code/{registrationId}");
    return provider;
  }

  private static ClientRegistration registration(final String registrationId, final String issuer) {
    return ClientRegistration.withRegistrationId(registrationId)
        .clientId(registrationId + "-client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/sso-callback")
        .authorizationUri("https://idp.example.com/" + registrationId + "/auth")
        .tokenUri("https://idp.example.com/" + registrationId + "/token")
        .jwkSetUri("https://idp.example.com/" + registrationId + "/jwks")
        .issuerUri(issuer)
        .build();
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
  @Import(StubOidcClients.class)
  static class StubOidcInfrastructure {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return registrationId -> null;
    }

    /** A decoder of the host, so the claim converters are looked up by configured issuer-uri. */
    @Bean
    JwtDecoder jwtDecoder() {
      return token -> {
        throw new UnsupportedOperationException("stub");
      };
    }
  }

  /** The stubs besides the repository and the decoder, for a test that supplies its own. */
  @Configuration
  static class StubOidcClients {

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
