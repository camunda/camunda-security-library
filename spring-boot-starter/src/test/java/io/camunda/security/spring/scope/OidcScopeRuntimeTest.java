/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static io.camunda.security.spring.scope.ScopeRuntimeTestSupport.assertCollected;
import static io.camunda.security.spring.scope.ScopeRuntimeTestSupport.generation;
import static io.camunda.security.spring.scope.ScopeRuntimeTestSupport.proxy;
import static io.camunda.security.spring.scope.ScopeRuntimeTestSupport.reloadPort;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.scope.ScopeReloadOutcome;
import io.camunda.security.api.model.scope.UnreachableIdentityProviderPolicy;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import io.camunda.security.spring.scope.MockIdentityProvider.TokenRequest;
import io.camunda.security.spring.scope.ScopedSecurityChainConfigurationTest.ObjectMapperConfig;
import io.camunda.security.spring.scope.ScopedSecurityChainConfigurationTest.StubUserDetailsPort;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.BasicAuthApiSecurityConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import io.camunda.security.spring.user.UserConfiguration;
import java.lang.ref.WeakReference;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * OIDC scopes changed at runtime against a real (loopback) OpenID provider: logins, bearer tokens,
 * credential rotation, the session policy and an unreachable provider.
 */
class OidcScopeRuntimeTest {

  private static final String S1 = "/tenants/t1";
  private static final String S2 = "/tenants/t2";
  private static final AtomicReference<List<ScopedSecurityDescriptor>> CONTRIBUTED =
      new AtomicReference<>(List.of());

  private final List<MockIdentityProvider> idps = new ArrayList<>();

  @BeforeEach
  void noScopesAtStartup() {
    CONTRIBUTED.set(List.of());
  }

  @AfterEach
  void stopIdps() {
    idps.forEach(MockIdentityProvider::close);
    CONTRIBUTED.set(List.of());
  }

  static WebApplicationContextRunner runner() {
    return new WebApplicationContextRunner()
        .withUserConfiguration(
            ObjectMapperConfig.class, Paths.class, StubUserDetailsPort.class, Scopes.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                BasicAuthApiSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                UserConfiguration.class,
                ScopedSecurityChainConfiguration.class))
        .withPropertyValues("camunda.security.authentication.method=basic");
  }

  @Test
  void shouldLogInThroughAScopeAddedAtRuntime() throws Exception {
    final var idp = idp();
    idp.acceptSecrets("app", "s1");
    runner()
        .run(
            ctx -> {
              // given
              final var browser = new TestBrowser(proxy(ctx));

              // when
              final var result = reloadPort(ctx).apply(oidc(S1, idp, "app", "s1"));
              logIn(browser, idp, S1, "app");

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.ADDED);
              assertThat(browser.get(S1 + "/app/home").status()).isEqualTo(200);
              assertThat(idp.tokenRequests())
                  .containsExactly(
                      new TokenRequest("authorization_code", "app", "secret:s1", true));
            });
  }

  @Test
  void shouldServeAStartupScopeAndChangeItAtRuntime() throws Exception {
    final var idpA = idp();
    final var idpB = idp();
    idpA.acceptSecrets("app", "s1");
    idpB.acceptSecrets("app", "s1");
    CONTRIBUTED.set(List.of(oidc(S1, idpA, "app", "s1")));
    runner()
        .run(
            ctx -> {
              // given
              final var tokenA = idpA.accessToken("svc", "api");
              final var tokenB = idpB.accessToken("svc", "api");
              assertThat(bearer(ctx, S1, tokenA)).isEqualTo(200);

              // when
              reloadPort(ctx).apply(oidc(S1, idpB, "app", "s1")).orThrow();

              // then
              assertThat(bearer(ctx, S1, tokenA)).isEqualTo(401);
              assertThat(bearer(ctx, S1, tokenB)).isEqualTo(200);
            });
  }

  @Test
  void shouldValidateBearerTokensAgainstTheCurrentAudiences() throws Exception {
    final var idp = idp();
    runner()
        .run(
            ctx -> {
              // given
              final var token = idp.accessToken("svc", "api-a");
              reloadPort(ctx).apply(withAudience(oidc(S1, idp, "app", "s1"), "api-a"));
              assertThat(bearer(ctx, S1, token)).isEqualTo(200);

              // when
              final var result =
                  reloadPort(ctx).apply(withAudience(oidc(S1, idp, "app", "s1"), "api-b"));

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.REPLACED);
              assertThat(bearer(ctx, S1, token)).isEqualTo(401);
              assertThat(bearer(ctx, S1, idp.accessToken("svc", "api-b"))).isEqualTo(200);
            });
  }

  @Test
  void shouldFinishALoginStartedBeforeTheSecretWasRotated() throws Exception {
    final var idp = idp();
    idp.acceptSecrets("app", "s1");
    runner()
        .run(
            ctx -> {
              // given
              reloadPort(ctx).apply(oidc(S1, idp, "app", "s1"));
              final var browser = new TestBrowser(proxy(ctx));
              final var authorization = startLogIn(browser, idp, S1, "oidc");
              idp.acceptSecrets("app", "s2");

              // when
              final var result = reloadPort(ctx).rotateCredentials(oidc(S1, idp, "app", "s2"));
              finishLogIn(browser, idp, S1, "app", authorization);

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.CREDENTIALS_ROTATED);
              assertThat(result.sessionsInvalidated()).isFalse();
              assertThat(browser.get(S1 + "/app/home").status()).isEqualTo(200);
              assertThat(idp.tokenRequests())
                  .containsExactly(
                      new TokenRequest("authorization_code", "app", "secret:s2", true));
            });
  }

  @Test
  void shouldKeepTheSessionAndRefreshItsTokenWithTheRotatedSecret() throws Exception {
    final var idp = idp();
    idp.acceptSecrets("app", "s1");
    idp.setAccessTokenLifetimeSeconds(1);
    runner()
        .run(
            ctx -> {
              // given
              reloadPort(ctx).apply(oidc(S1, idp, "app", "s1"));
              final var browser = new TestBrowser(proxy(ctx));
              logIn(browser, idp, S1, "app");
              final var session = browser.cookie(sessionCookie(S1));
              idp.acceptSecrets("app", "s2");

              // when
              reloadPort(ctx).rotateCredentials(oidc(S1, idp, "app", "s2")).orThrow();

              // then
              await()
                  .atMost(Duration.ofSeconds(10))
                  .pollInterval(Duration.ofMillis(250))
                  .untilAsserted(
                      () -> {
                        assertThat(browser.get(S1 + "/app/home").status()).isEqualTo(200);
                        assertThat(idp.tokenRequests())
                            .contains(new TokenRequest("refresh_token", "app", "secret:s2", true));
                      });
              assertThat(browser.cookie(sessionCookie(S1))).isEqualTo(session);
              assertThat(idp.tokenRequests()).noneMatch(request -> !request.granted());
            });
  }

  @Test
  void shouldEndTheSessionsOfAScopeWhoseIssuerChanged() throws Exception {
    final var idpA = idp();
    final var idpB = idp();
    idpA.acceptSecrets("app", "s1");
    idpA.setAccessTokenLifetimeSeconds(1);
    runner()
        .run(
            ctx -> {
              // given
              reloadPort(ctx).apply(oidc(S1, idpA, "app", "s1"));
              final var browser = new TestBrowser(proxy(ctx));
              logIn(browser, idpA, S1, "app");
              final var requestsBefore = idpA.tokenRequests().size();

              // when
              final var result = reloadPort(ctx).apply(oidc(S1, idpB, "app", "s1"));
              final var afterChange = browser.get(S1 + "/app/home");

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.REPLACED);
              assertThat(result.sessionsInvalidated()).isTrue();
              assertThat(afterChange.served()).isFalse();
              assertThat(afterChange.response().getRedirectedUrl())
                  .endsWith(S1 + "/oauth2/authorization/oidc");
              assertThat(idpA.tokenRequests()).hasSize(requestsBefore);
            });
  }

  @Test
  void shouldEndTheSessionsOfAScopeWhoseClientChanged() throws Exception {
    final var idp = idp();
    idp.acceptSecrets("app", "s1");
    idp.acceptSecrets("other-app", "s1");
    runner()
        .run(
            ctx -> {
              // given
              reloadPort(ctx).apply(oidc(S1, idp, "app", "s1"));
              final var browser = new TestBrowser(proxy(ctx));
              logIn(browser, idp, S1, "app");

              // when
              reloadPort(ctx).apply(oidc(S1, idp, "other-app", "s1")).orThrow();

              // then
              assertThat(browser.get(S1 + "/app/home").served()).isFalse();
            });
  }

  @Test
  void shouldKeepTheSessionsOfOtherScopes() throws Exception {
    final var idp = idp();
    idp.acceptSecrets("app-1", "s1");
    idp.acceptSecrets("app-2", "s1");
    runner()
        .run(
            ctx -> {
              // given
              reloadPort(ctx).apply(oidc(S1, idp, "app-1", "s1"));
              reloadPort(ctx).apply(oidc(S2, idp, "app-2", "s1"));
              final var browser = new TestBrowser(proxy(ctx));
              logIn(browser, idp, S1, "app-1");
              logIn(browser, idp, S2, "app-2");

              // when
              reloadPort(ctx).apply(withAudience(oidc(S1, idp, "app-1", "s1"), "x")).orThrow();
              reloadPort(ctx).remove(S1).orThrow();

              // then
              assertThat(browser.get(S2 + "/app/home").status()).isEqualTo(200);
              assertThat(browser.get(S1 + "/app/home").status()).isEqualTo(404);
            });
  }

  @Test
  void shouldAddChangeAndRemoveNamedProvidersOfAScope() throws Exception {
    final var idpA = idp();
    final var idpB = idp();
    final var idpC = idp();
    idpA.acceptSecrets("a", "s");
    idpB.acceptSecrets("b", "s");
    idpC.acceptSecrets("c", "s");
    runner()
        .run(
            ctx -> {
              // given
              reloadPort(ctx).apply(providers(S1, Map.of("a", idpA, "b", idpB))).orThrow();
              final var browser = new TestBrowser(proxy(ctx));
              logIn(browser, idpB, S1, "b", "b");
              assertThat(browser.get(S1 + "/app/home").status()).isEqualTo(200);

              // when
              reloadPort(ctx).apply(providers(S1, Map.of("a", idpA, "c", idpC))).orThrow();

              // then
              assertThat(browser.get(S1 + "/app/home").served()).isFalse();
              final var removedProvider = browser.get(S1 + "/oauth2/authorization/b");
              assertThat(String.valueOf(removedProvider.response().getRedirectedUrl()))
                  .doesNotStartWith(idpB.issuer());
              logIn(browser, idpC, S1, "c", "c");
              assertThat(browser.get(S1 + "/app/home").status()).isEqualTo(200);
              assertThat(bearer(ctx, S1, idpC.accessToken("svc", "api"))).isEqualTo(200);
              assertThat(bearer(ctx, S1, idpB.accessToken("svc", "api"))).isEqualTo(401);
            });
  }

  @Test
  void shouldKeepTheLiveGenerationWhenTheNewIdentityProviderCannotBeReached() throws Exception {
    final var idpA = idp();
    final var idpDown = idp();
    idpDown.setAvailable(false);
    runner()
        .run(
            ctx -> {
              // given
              reloadPort(ctx).apply(oidc(S1, idpA, "app", "s1")).orThrow();
              reloadPort(ctx).apply(oidc(S2, idpA, "app", "s1")).orThrow();
              final var before = generation(ctx, S1);
              final var tokenA = idpA.accessToken("svc", "api");

              // when
              final var result = reloadPort(ctx).apply(oidc(S1, idpDown, "app", "s1"));

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.KEPT_PREVIOUS);
              assertThat(result.failure()).isNotNull();
              assertThat(generation(ctx, S1)).isSameAs(before);
              assertThat(bearer(ctx, S1, tokenA)).isEqualTo(200);
              assertThat(bearer(ctx, S2, tokenA)).isEqualTo(200);
            });
  }

  @Test
  void shouldApplyAnUnreachableIdentityProviderOnRequestAndRecoverWhenItAnswers() throws Exception {
    final var idpA = idp();
    final var idpLater = idp();
    idpLater.setAvailable(false);
    runner()
        .run(
            ctx -> {
              // given
              reloadPort(ctx).apply(oidc(S1, idpA, "app", "s1")).orThrow();
              final var token = idpLater.accessToken("svc", "api");

              // when
              final var replaced =
                  reloadPort(ctx)
                      .apply(
                          oidc(S1, idpLater, "app", "s1"), UnreachableIdentityProviderPolicy.APPLY);
              final var added = reloadPort(ctx).apply(oidc(S2, idpLater, "app", "s1"));

              // then
              assertThat(replaced.outcome()).isEqualTo(ScopeReloadOutcome.REPLACED);
              assertThat(added.outcome()).isEqualTo(ScopeReloadOutcome.ADDED);
              final var withdrawn = idpA.accessToken("svc", "api");
              assertThat(bearer(ctx, S1, withdrawn)).isEqualTo(500);
              assertThat(bearer(ctx, S1, token)).isEqualTo(500);
              idpLater.setAvailable(true);
              assertThat(bearer(ctx, S1, token)).isEqualTo(200);
              assertThat(bearer(ctx, S2, token)).isEqualTo(200);
              assertThat(bearer(ctx, S1, withdrawn)).isEqualTo(401);
            });
  }

  @Test
  void shouldReleaseTheOidcStateOfRetiredGenerations() throws Exception {
    final var idpA = idp();
    final var idpB = idp();
    idpA.acceptSecrets("app", "s1");
    runner()
        .run(
            ctx -> {
              // given
              final var factory = ctx.getBean(ScopedClientRegistrationFactory.class);
              final List<WeakReference<Object>> retired = new ArrayList<>();
              final var browser = new TestBrowser(proxy(ctx));

              // when
              for (int i = 0; i < 8; i++) {
                reloadPort(ctx).apply(withAudience(oidc(S1, idpA, "app", "s1"), "a" + i));
                logIn(browser, idpA, S1, "app");
                bearer(ctx, S1, idpA.accessToken("svc", "a" + i));
                retired.addAll(oidcReferences(generation(ctx, S1)));
                reloadPort(ctx).apply(oidc(S2, idpB, "app", "s1")).orThrow();
                retired.addAll(oidcReferences(generation(ctx, S2)));
                reloadPort(ctx).remove(S2).orThrow();
              }
              reloadPort(ctx).remove(S1).orThrow();

              // then
              assertCollected(retired);
              assertThat(factory.cachedDiscoveryIssuers()).isEmpty();
            });
  }

  private MockIdentityProvider idp() throws Exception {
    final var idp = MockIdentityProvider.start();
    idps.add(idp);
    return idp;
  }

  /** The generation and the OIDC state it built and resolved. */
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

  /** Status of a bearer-token request to the scope's API. */
  static int bearer(final ApplicationContext ctx, final String basePath, final String token)
      throws Exception {
    final var request = new MockHttpServletRequest("GET", basePath + "/v2/resource");
    request.addHeader("Authorization", "Bearer " + token);
    return ScopeRuntimeTestSupport.send(proxy(ctx), request).status();
  }

  static void logIn(
      final TestBrowser browser,
      final MockIdentityProvider idp,
      final String basePath,
      final String clientId)
      throws Exception {
    logIn(browser, idp, basePath, "oidc", clientId);
  }

  static void logIn(
      final TestBrowser browser,
      final MockIdentityProvider idp,
      final String basePath,
      final String registrationId,
      final String clientId)
      throws Exception {
    finishLogIn(
        browser, idp, basePath, clientId, startLogIn(browser, idp, basePath, registrationId));
  }

  /** Follows the scope's login redirect to the provider and returns the authorization request. */
  static Map<String, String> startLogIn(
      final TestBrowser browser,
      final MockIdentityProvider idp,
      final String basePath,
      final String registrationId)
      throws Exception {
    final var start = browser.get(basePath + "/oauth2/authorization/" + registrationId);
    final var location = start.response().getRedirectedUrl();
    assertThat(location).as("redirect to the provider").startsWith(idp.issuer() + "/auth");
    return query(location);
  }

  /** Answers the authorization request with a code and delivers it to the scope's callback. */
  static void finishLogIn(
      final TestBrowser browser,
      final MockIdentityProvider idp,
      final String basePath,
      final String clientId,
      final Map<String, String> authorization)
      throws Exception {
    final var callback = deliverCode(browser, idp, basePath, clientId, authorization);
    assertThat(callback.response().getRedirectedUrl())
        .as("login succeeded")
        .isNotNull()
        .doesNotContain("error");
  }

  /** Delivers a code for the authorization request to the scope's callback, whatever happens. */
  static ScopeRuntimeTestSupport.Sent deliverCode(
      final TestBrowser browser,
      final MockIdentityProvider idp,
      final String basePath,
      final String clientId,
      final Map<String, String> authorization)
      throws Exception {
    final var code = "code-" + UUID.randomUUID();
    idp.issueCode(code, clientId, authorization.get("nonce"), "alice");
    return browser.get(
        basePath
            + "/sso-callback?code="
            + code
            + "&state="
            + URLEncoder.encode(authorization.get("state"), StandardCharsets.UTF_8));
  }

  private static Map<String, String> query(final String url) {
    final Map<String, String> values = new HashMap<>();
    for (final var pair : url.substring(url.indexOf('?') + 1).split("&")) {
      final var separator = pair.indexOf('=');
      values.put(
          pair.substring(0, separator),
          URLDecoder.decode(pair.substring(separator + 1), StandardCharsets.UTF_8));
    }
    return values;
  }

  static String sessionCookie(final String basePath) {
    return ScopedSecurityChainRegistrar.sessionCookieName(basePath);
  }

  static ScopedSecurityDescriptor oidc(
      final String basePath,
      final MockIdentityProvider idp,
      final String clientId,
      final String secret) {
    final var auth = new AuthenticationConfiguration();
    auth.setMethod(AuthenticationMethod.OIDC);
    auth.setOidc(provider(idp, clientId, secret));
    return new ScopedSecurityDescriptor(basePath, auth);
  }

  private static ScopedSecurityDescriptor providers(
      final String basePath, final Map<String, MockIdentityProvider> idpsByRegistrationId) {
    final var auth = new AuthenticationConfiguration();
    auth.setMethod(AuthenticationMethod.OIDC);
    final Map<String, OidcConfiguration> providers = new LinkedHashMap<>();
    idpsByRegistrationId.forEach(
        (registrationId, idp) -> providers.put(registrationId, provider(idp, registrationId, "s")));
    auth.getProviders().setOidc(providers);
    return new ScopedSecurityDescriptor(basePath, auth);
  }

  private static OidcConfiguration provider(
      final MockIdentityProvider idp, final String clientId, final String secret) {
    return OidcConfiguration.builder()
        .issuerUri(idp.issuer())
        .clientId(clientId)
        .clientSecret(secret)
        .scope(List.of("openid"))
        .build();
  }

  static ScopedSecurityDescriptor withAudience(
      final ScopedSecurityDescriptor descriptor, final String audience) {
    descriptor.authentication().getOidc().setAudiences(Set.of(audience));
    return descriptor;
  }

  @Configuration
  static class Paths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder()
          .apiPaths("/v2/**")
          .webappPaths("/**")
          .webComponentNames()
          .build();
    }
  }

  @Configuration
  static class Scopes {

    @Bean
    static CamundaSecurityScopeProvider runtimeScopes() {
      return CONTRIBUTED::get;
    }
  }
}
