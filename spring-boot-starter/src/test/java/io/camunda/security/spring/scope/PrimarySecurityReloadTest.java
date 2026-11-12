/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static io.camunda.security.spring.scope.OidcScopeRuntimeTest.logIn;
import static io.camunda.security.spring.scope.ScopeRuntimeTestSupport.proxy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.scope.ScopeReloadOutcome;
import io.camunda.security.api.model.scope.UnreachableIdentityProviderPolicy;
import io.camunda.security.core.port.in.PrimarySecurityReloadPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcBeansConfiguration;
import io.camunda.security.spring.oidc.OidcWebappClientBeansConfiguration;
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
import io.camunda.security.spring.scope.MockIdentityProvider.TokenRequest;
import io.camunda.security.spring.scope.ScopedSecurityChainConfigurationTest.ObjectMapperConfig;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.OidcApiSecurityConfiguration;
import io.camunda.security.spring.security.OidcWebappSecurityConfiguration;
import io.camunda.security.spring.security.ScopedWebappSecurityChainBuilderConfiguration;
import java.lang.ref.WeakReference;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * The primary (unscoped) chains changed at runtime as a scope is changed, against real (loopback)
 * OpenID providers.
 */
class PrimarySecurityReloadTest {

  private static final Logger LOG = LoggerFactory.getLogger(PrimarySecurityReloadTest.class);
  private static final String SCOPE = "/tenants/t1";

  private final List<MockIdentityProvider> idps = new ArrayList<>();
  private MockIdentityProvider idpA;
  private MockIdentityProvider idpB;

  @BeforeEach
  void startIdps() throws Exception {
    idpA = idp();
    idpB = idp();
    idpA.acceptSecrets("app", "s1");
    idpB.acceptSecrets("app", "s1");
  }

  @AfterEach
  void stopIdps() {
    idps.forEach(MockIdentityProvider::close);
  }

  @Test
  void shouldServeAnotherIssuerOnTheApiAndWebappChains() throws Exception {
    runner()
        .run(
            ctx -> {
              // given
              final var tokenA = idpA.accessToken("svc", "api");
              final var tokenB = idpB.accessToken("svc", "api");
              assertThat(bearer(ctx, tokenA)).isEqualTo(200);
              assertThat(bearer(ctx, tokenB)).isEqualTo(401);

              // when
              final var result = port(ctx).apply(primary(idpB, "app", "s1"));

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.REPLACED);
              assertThat(result.generation()).isEqualTo(2);
              assertThat(bearer(ctx, tokenA)).isEqualTo(401);
              assertThat(bearer(ctx, tokenB)).isEqualTo(200);
              final var browser = new TestBrowser(proxy(ctx));
              logIn(browser, idpB, "", "oidc", "app");
              assertThat(browser.get("/app/home").status()).isEqualTo(200);
              assertThat(idpB.tokenRequests())
                  .contains(new TokenRequest("authorization_code", "app", "secret:s1", true));
            });
  }

  @Test
  void shouldValidateBearerTokensAgainstTheNewAudiences() throws Exception {
    runner()
        .run(
            ctx -> {
              // given
              port(ctx).apply(withAudience(primary(idpA, "app", "s1"), "api-a")).orThrow();
              final var tokenA = idpA.accessToken("svc", "api-a");
              assertThat(bearer(ctx, tokenA)).isEqualTo(200);

              // when
              final var result = port(ctx).apply(withAudience(primary(idpA, "app", "s1"), "api-b"));

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.REPLACED);
              assertThat(bearer(ctx, tokenA)).isEqualTo(401);
              assertThat(bearer(ctx, idpA.accessToken("svc", "api-b"))).isEqualTo(200);
            });
  }

  @Test
  void shouldServeAChangedClientId() throws Exception {
    idpA.acceptSecrets("app2", "s9");
    runner()
        .run(
            ctx -> {
              // when
              final var result = port(ctx).apply(primary(idpA, "app2", "s9"));

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.REPLACED);
              logIn(new TestBrowser(proxy(ctx)), idpA, "", "oidc", "app2");
              assertThat(idpA.tokenRequests())
                  .contains(new TokenRequest("authorization_code", "app2", "secret:s9", true));
            });
  }

  @Test
  void shouldServeNamedProvidersAddedAtRuntime() throws Exception {
    runner()
        .run(
            ctx -> {
              // given
              final var authentication = primary(idpA, "app", "s1");
              authentication
                  .getProviders()
                  .getOidc()
                  .put(
                      "second",
                      OidcConfiguration.builder()
                          .issuerUri(idpB.issuer())
                          .clientId("app")
                          .clientSecret("s1")
                          .redirectUri("http://localhost/sso-callback")
                          .build());

              // when
              final var result = port(ctx).apply(authentication);

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.REPLACED);
              assertThat(bearer(ctx, idpA.accessToken("svc", "api"))).isEqualTo(200);
              assertThat(bearer(ctx, idpB.accessToken("svc", "api"))).isEqualTo(200);
              logIn(new TestBrowser(proxy(ctx)), idpB, "", "second", "app");
            });
  }

  @Test
  void shouldEndTheSessionsOfThePrimaryChainsWhenTheirAuthenticationChanges() throws Exception {
    runner()
        .run(
            ctx -> {
              // given
              final var startupSession = new TestBrowser(proxy(ctx));
              logIn(startupSession, idpA, "", "oidc", "app");
              assertThat(startupSession.get("/app/home").status()).isEqualTo(200);
              port(ctx).apply(withAudience(primary(idpA, "app", "s1"), "api")).orThrow();
              final var secondGenerationSession = new TestBrowser(proxy(ctx));
              logIn(secondGenerationSession, idpA, "", "oidc", "app");

              // when
              port(ctx).apply(primary(idpB, "app", "s1")).orThrow();

              // then
              assertThat(startupSession.get("/app/home").status()).isNotEqualTo(200);
              assertThat(secondGenerationSession.get("/app/home").status()).isNotEqualTo(200);
              assertThat(secondGenerationSession.get("/v2/resource").status()).isNotEqualTo(200);
            });
  }

  @Test
  void shouldKeepTheSessionAndRefreshItsTokenWithTheRotatedSecret() throws Exception {
    // given
    idpA.setAccessTokenLifetimeSeconds(1);
    runner()
        .run(
            ctx -> {
              final var browser = new TestBrowser(proxy(ctx));
              logIn(browser, idpA, "", "oidc", "app");
              idpA.acceptSecrets("app", "s1", "s2");

              // when
              final var result = port(ctx).apply(primary(idpA, "app", "s2"));
              idpA.acceptSecrets("app", "s2");

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.CREDENTIALS_ROTATED);
              assertThat(result.sessionsInvalidated()).isFalse();
              await()
                  .atMost(Duration.ofSeconds(10))
                  .pollInterval(Duration.ofMillis(250))
                  .untilAsserted(
                      () -> {
                        assertThat(browser.get("/app/home").status()).isEqualTo(200);
                        assertThat(idpA.tokenRequests())
                            .contains(new TokenRequest("refresh_token", "app", "secret:s2", true));
                      });
              logIn(new TestBrowser(proxy(ctx)), idpA, "", "oidc", "app");
              assertThat(idpA.tokenRequests())
                  .contains(new TokenRequest("authorization_code", "app", "secret:s2", true));
            });
  }

  @Test
  void shouldKeepThePreviousSecretWhenTheIdentityProviderRejectsTheNewOne() throws Exception {
    runner()
        .run(
            ctx -> {
              // when
              final var applied = port(ctx).apply(primary(idpA, "app", "wrong"));
              final var rotated = port(ctx).rotateCredentials(primary(idpA, "app", "wrong"));

              // then
              assertThat(applied.outcome()).isEqualTo(ScopeReloadOutcome.KEPT_PREVIOUS);
              assertThat(rotated.outcome()).isEqualTo(ScopeReloadOutcome.KEPT_PREVIOUS);
              assertThat(rotated.failureCause())
                  .hasValueSatisfying(
                      failure ->
                          assertThat(failure.getMessage())
                              .contains("rejects", "HTTP 401")
                              .doesNotContain("wrong"));
              logIn(new TestBrowser(proxy(ctx)), idpA, "", "oidc", "app");
              assertThat(idpA.tokenRequests())
                  .contains(new TokenRequest("authorization_code", "app", "secret:s1", true));
            });
  }

  @Test
  void shouldKeepThePreviousGenerationWhileTheNewProviderCannotBeReached() throws Exception {
    runner()
        .run(
            ctx -> {
              // given
              final var tokenA = idpA.accessToken("svc", "api");
              final var tokenB = idpB.accessToken("svc", "api");
              idpB.setAvailable(false);

              // when
              final var kept = port(ctx).apply(primary(idpB, "app", "s1"));

              // then
              assertThat(kept.outcome()).isEqualTo(ScopeReloadOutcome.KEPT_PREVIOUS);
              assertThat(kept.generation()).isEqualTo(1);
              assertThat(kept.failureCause()).isPresent();
              assertThat(bearer(ctx, tokenA)).isEqualTo(200);

              // when
              idpB.setAvailable(true);
              final var applied = port(ctx).apply(primary(idpB, "app", "s1"));

              // then
              assertThat(applied.outcome()).isEqualTo(ScopeReloadOutcome.REPLACED);
              assertThat(bearer(ctx, tokenA)).isEqualTo(401);
              assertThat(bearer(ctx, tokenB)).isEqualTo(200);
            });
  }

  @Test
  void shouldApplyAnUnreachableProviderWhenAskedTo() throws Exception {
    runner()
        .run(
            ctx -> {
              // given
              final var tokenA = idpA.accessToken("svc", "api");
              idpB.setAvailable(false);

              // when
              final var result =
                  port(ctx)
                      .apply(primary(idpB, "app", "s1"), UnreachableIdentityProviderPolicy.APPLY);

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.REPLACED);
              assertThat(bearer(ctx, tokenA)).isNotEqualTo(200);
            });
  }

  @Test
  void shouldRejectAChangeOfTheAuthenticationMethod() throws Exception {
    runner()
        .run(
            ctx -> {
              // given
              final var basic = new AuthenticationConfiguration();
              basic.setMethod(AuthenticationMethod.BASIC);

              // when / then
              assertThatThrownBy(() -> port(ctx).apply(basic))
                  .isInstanceOf(IllegalArgumentException.class)
                  .hasMessageContaining("authentication method");
              assertThat(port(ctx).apply(primary(idpA, "app", "s1")).outcome())
                  .isEqualTo(ScopeReloadOutcome.UNCHANGED);
            });
  }

  @Test
  void shouldRejectARotationThatChangesMoreThanTheCredentials() throws Exception {
    runner()
        .run(
            ctx ->
                assertThatThrownBy(() -> port(ctx).rotateCredentials(primary(idpB, "app", "s1")))
                    .isInstanceOf(IllegalArgumentException.class));
  }

  @Test
  void shouldLeaveTheScopesUntouched() throws Exception {
    runner()
        .run(
            ctx -> {
              // given
              ScopeRuntimeTestSupport.reloadPort(ctx)
                  .apply(OidcScopeRuntimeTest.oidc(SCOPE, idpA, "app", "s1"))
                  .orThrow();
              final var scopeGeneration = ScopeRuntimeTestSupport.generation(ctx, SCOPE);
              final var tokenA = idpA.accessToken("svc", "api");
              final var scopeSession = new TestBrowser(proxy(ctx));
              logIn(scopeSession, idpA, SCOPE, "app");

              // when
              port(ctx).apply(primary(idpB, "app", "s1")).orThrow();

              // then
              assertThat(ScopeRuntimeTestSupport.generation(ctx, SCOPE)).isSameAs(scopeGeneration);
              assertThat(OidcScopeRuntimeTest.bearer(ctx, SCOPE, tokenA)).isEqualTo(200);
              assertThat(scopeSession.get(SCOPE + "/app/home").status()).isEqualTo(200);
              assertThat(bearer(ctx, tokenA)).isEqualTo(401);
            });
  }

  @Test
  void shouldReleaseEveryRetiredPrimaryGeneration() throws Exception {
    runner()
        .run(
            ctx -> {
              // given
              final var browser = new TestBrowser(proxy(ctx));
              final List<WeakReference<Object>> retired = new ArrayList<>();
              List<WeakReference<Object>> serving = List.of();
              final List<Long> millis = new ArrayList<>();
              final var changes = 20;

              // when
              for (int i = 0; i < changes; i++) {
                final var idp = i % 2 == 0 ? idpB : idpA;
                final var result =
                    port(ctx).apply(withAudience(primary(idp, "app", "s1"), "a" + i));
                assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.REPLACED);
                millis.add(result.duration().toMillis());
                logIn(browser, idp, "", "oidc", "app");
                assertThat(bearer(ctx, idp.accessToken("svc", "a" + i))).isEqualTo(200);
                retired.addAll(serving);
                serving = oidcReferences(ctx.getBean(PrimaryChains.class).current());
              }

              // then
              millis.sort(Long::compare);
              LOG.info(
                  "Primary chain change over {} changes: p50 {} ms, max {} ms",
                  changes,
                  millis.get(millis.size() / 2),
                  millis.getLast());
              ScopeRuntimeTestSupport.assertCollected(retired);
            });
  }

  private MockIdentityProvider idp() throws Exception {
    final var idp = MockIdentityProvider.start();
    idps.add(idp);
    return idp;
  }

  private static List<WeakReference<Object>> oidcReferences(final ScopeGeneration generation) {
    final List<Object> objects = new ArrayList<>();
    objects.add(generation);
    objects.add(generation.api());
    objects.add(generation.webapp());
    for (final var clients : generation.oidcClients()) {
      objects.add(clients);
      objects.add(clients.registrations());
      objects.add(clients.authorizedClientManager());
      objects.add(clients.assertionJwks());
      objects.addAll(clients.registrations().resolvedRegistrations());
    }
    return ScopeRuntimeTestSupport.weakly(objects);
  }

  private static int bearer(final ApplicationContext ctx, final String token) throws Exception {
    final var request = new MockHttpServletRequest("GET", "/v2/resource");
    request.addHeader("Authorization", "Bearer " + token);
    return ScopeRuntimeTestSupport.send(proxy(ctx), request).status();
  }

  private static AuthenticationConfiguration primary(
      final MockIdentityProvider idp, final String clientId, final String secret) {
    final var authentication = new AuthenticationConfiguration();
    authentication.setMethod(AuthenticationMethod.OIDC);
    authentication.setOidc(
        OidcConfiguration.builder()
            .issuerUri(idp.issuer())
            .clientId(clientId)
            .clientSecret(secret)
            .redirectUri("http://localhost/sso-callback")
            .build());
    return authentication;
  }

  private static AuthenticationConfiguration withAudience(
      final AuthenticationConfiguration authentication, final String audience) {
    authentication.getOidc().setAudiences(Set.of(audience));
    return authentication;
  }

  private static PrimarySecurityReloadPort port(final ApplicationContext ctx) {
    return ctx.getBean(PrimarySecurityReloadPort.class);
  }

  private WebApplicationContextRunner runner() {
    return new WebApplicationContextRunner()
        .withUserConfiguration(
            ObjectMapperConfig.class, OidcScopeRuntimeTest.Paths.class, Scopes.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                OidcApiSecurityConfiguration.class,
                OidcWebappSecurityConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                OidcBeansConfiguration.class,
                OidcWebappClientBeansConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class,
                ScopedSecurityChainConfiguration.class,
                PrimarySecurityReloadConfiguration.class))
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.oidc.client-id=app",
            "camunda.security.authentication.oidc.client-secret=s1",
            "camunda.security.authentication.oidc.redirect-uri=http://localhost/sso-callback",
            "camunda.security.authentication.oidc.issuer-uri=" + idpA.issuer());
  }

  @Configuration
  static class Scopes {

    @Bean
    static CamundaSecurityScopeProvider runtimeScopes() {
      return List::of;
    }
  }
}
