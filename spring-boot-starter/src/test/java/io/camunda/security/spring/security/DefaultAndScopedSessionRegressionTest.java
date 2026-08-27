/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.context.CamundaAuthenticationProvider;
import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.api.model.session.PersistentSession;
import io.camunda.security.core.port.out.BasicAuthUserDetailsPort;
import io.camunda.security.core.port.out.BasicAuthUserDetailsPort.CamundaUserDetails;
import io.camunda.security.core.port.out.ScopedSessionStorePortProvider;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.core.port.out.SessionStorePort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcBeansConfiguration;
import io.camunda.security.spring.oidc.OidcClaimsProviderConfiguration;
import io.camunda.security.spring.oidc.OidcTestServer;
import io.camunda.security.spring.oidc.OidcWebappClientBeansConfiguration;
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
import io.camunda.security.spring.scope.ScopedSecurityChainConfiguration;
import io.camunda.security.spring.session.WebSessionConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import io.camunda.security.spring.user.UserConfiguration;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Regression guard for camunda#55852: a PT-scoped session must survive a second request even when
 * the default (non-scoped) chains coexist in the same application — exactly the configuration that
 * exposed the original bug (the global filter and a scope's filter both processing the same
 * request, corrupting Spring Session's shared {@code INVALID_SESSION_ID_ATTR}).
 *
 * <p>Unlike {@code DefaultSessionFilterChainIntegrationTest} (default chains only, sessions seeded
 * directly into the repository) and {@code ScopedWebappSessionIsolationTest} (scoped chains only),
 * this test drives real two-request round trips — login through the actual filter chain, then reuse
 * the resulting cookie — with both the default and a scoped chain registered in one {@link
 * FilterChainProxy}, mirroring how a real application assembles them.
 */
class DefaultAndScopedSessionRegressionTest {

  private static final String BASE_PT = "/physical-tenants/a";
  private static final String DEFAULT_COOKIE = CamundaSecurityFilterChainConstants.SESSION_COOKIE;
  private static final String SCOPED_COOKIE = "camunda-session-physical-tenants-a";

  private static OidcTestServer oidcServer;

  @BeforeAll
  static void startOidcServer() throws Exception {
    oidcServer = OidcTestServer.startRsa("key-regression");
  }

  @AfterAll
  static void stopOidcServer() {
    if (oidcServer != null) {
      oidcServer.stop();
    }
  }

  private WebApplicationContextRunner runner() {
    return new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class, StubUserDetailsPort.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                BasicAuthWebappSecurityConfiguration.class,
                BasicAuthApiSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                UserConfiguration.class))
        .withPropertyValues("camunda.security.authentication.method=basic");
  }

  /**
   * Baseline: a session committed via a real login on the default surface survives a second
   * request. Unlike seeding the repository directly, this drives the actual
   * SessionRepositoryFilter's commit-then-reuse path end to end.
   */
  @Test
  void sessionCommittedViaRealLoginSurvivesASecondRequestOnDefaultChain() throws Exception {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              stubResolvableUser(ctx, "alice", "s3cret");

              final var webappChain =
                  ctx.getBean("basicAuthWebappSecurityFilterChain", SecurityFilterChain.class);
              final var apiChain =
                  ctx.getBean("basicAuthApiSecurityFilterChain", SecurityFilterChain.class);
              final var proxy = new FilterChainProxy(List.of(webappChain, apiChain));

              final var sessionCookie = logIn(proxy, "/login", "alice", "s3cret", DEFAULT_COOKIE);

              // second request: reuse the cookie against the (session-authenticated) API chain
              final var request = new MockHttpServletRequest("GET", "/api/resource");
              request.setCookies(sessionCookie);
              final var response = new MockHttpServletResponse();
              final var next = new MockFilterChain();
              proxy.doFilter(request, response, next);

              assertThat(response.getStatus())
                  .as("the session committed at login must authenticate the very next request")
                  .isEqualTo(200);
              assertThat(next.getRequest()).isNotNull();
            });
  }

  /**
   * The actual regression: with the default chains AND a physical-tenant scope's chains registered
   * together (as a real application does), a session committed via a real login under the scope's
   * prefix must survive a second request. Before ADR-0009, the coexisting default (global) filter
   * would poison {@code INVALID_SESSION_ID_ATTR} for this exact sequence, making the scope's own
   * correct lookup on request 2 invisible.
   */
  @Test
  void scopedSessionCommittedViaRealLoginSurvivesASecondRequestWithDefaultChainsCoexisting()
      throws Exception {
    runner()
        .withConfiguration(AutoConfigurations.of(ScopedSecurityChainConfiguration.class))
        .withUserConfiguration(SingleBasicScopeProvider.class)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              stubResolvableUser(ctx, "alice", "s3cret");

              final var defaultWebappChain =
                  ctx.getBean("basicAuthWebappSecurityFilterChain", SecurityFilterChain.class);
              final var defaultApiChain =
                  ctx.getBean("basicAuthApiSecurityFilterChain", SecurityFilterChain.class);
              final var scopedWebappChain = scopedChain(ctx, "scopedWebappSecurityFilterChain-");
              final var scopedApiChain = scopedChain(ctx, "scopedApiSecurityFilterChain-");

              // All four chains coexist in one FilterChainProxy, exactly as a real application
              // assembles every registered SecurityFilterChain bean.
              final var proxy =
                  new FilterChainProxy(
                      List.of(
                          defaultWebappChain, defaultApiChain, scopedWebappChain, scopedApiChain));

              final var scopedCookie =
                  logIn(proxy, BASE_PT + "/login", "alice", "s3cret", SCOPED_COOKIE);

              // second request: reuse the scoped cookie against the scoped API chain
              final var request = new MockHttpServletRequest("GET", BASE_PT + "/api/resource");
              request.setCookies(scopedCookie);
              final var response = new MockHttpServletResponse();
              final var next = new MockFilterChain();
              proxy.doFilter(request, response, next);

              assertThat(response.getStatus())
                  .as(
                      "a PT-scoped session committed at login must authenticate the next scoped"
                          + " request even with the default chains present in the same"
                          + " FilterChainProxy — the core regression for camunda#55852")
                  .isEqualTo(200);
              assertThat(next.getRequest()).isNotNull();

              // and the default surface's own session must be unaffected / independent
              final var defaultCookie = logIn(proxy, "/login", "alice", "s3cret", DEFAULT_COOKIE);
              assertThat(defaultCookie.getValue())
                  .as("the default surface's session must be a distinct session from the scope's")
                  .isNotEqualTo(scopedCookie.getValue());
            });
  }

  /**
   * Durable-storage variant of the regression above: #55852 was specifically about persistent web
   * sessions, so this repeats the same mixed default+scoped, two-round-trip sequence with real
   * {@link SessionStorePort}-backed durable repositories — a distinct store for the default surface
   * and a distinct one for the scope, exactly the storage topology the original bug depended on.
   */
  @Test
  void scopedSessionCommittedViaRealLoginSurvivesASecondRequestWithDurablePersistentStores()
      throws Exception {
    final var defaultStore = new InMemorySessionStore();
    final var scopedStore = new InMemorySessionStore();
    final ScopedSessionStorePortProvider provider =
        basePath -> BASE_PT.equals(basePath) ? scopedStore : defaultStore;

    runner()
        .withConfiguration(
            AutoConfigurations.of(
                ScopedSecurityChainConfiguration.class, WebSessionConfiguration.class))
        .withUserConfiguration(SingleBasicScopeProvider.class)
        .withPropertyValues("camunda.security.session.persistent.enabled=true")
        .withBean("clusterSessionStore", SessionStorePort.class, () -> defaultStore)
        .withBean(ScopedSessionStorePortProvider.class, () -> provider)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              stubResolvableUser(ctx, "alice", "s3cret");

              final var defaultWebappChain =
                  ctx.getBean("basicAuthWebappSecurityFilterChain", SecurityFilterChain.class);
              final var defaultApiChain =
                  ctx.getBean("basicAuthApiSecurityFilterChain", SecurityFilterChain.class);
              final var scopedWebappChain = scopedChain(ctx, "scopedWebappSecurityFilterChain-");
              final var scopedApiChain = scopedChain(ctx, "scopedApiSecurityFilterChain-");

              final var proxy =
                  new FilterChainProxy(
                      List.of(
                          defaultWebappChain, defaultApiChain, scopedWebappChain, scopedApiChain));

              final var scopedCookie =
                  logIn(proxy, BASE_PT + "/login", "alice", "s3cret", SCOPED_COOKIE);

              assertThat(scopedStore.all())
                  .as("login must durably persist the session in the SCOPE's own store")
                  .hasSize(1);
              assertThat(defaultStore.all())
                  .as("the default surface's store must be untouched by the scope's login")
                  .isEmpty();

              // second request: reuse the scoped cookie — must be read back from the durable store
              final var request = new MockHttpServletRequest("GET", BASE_PT + "/api/resource");
              request.setCookies(scopedCookie);
              final var response = new MockHttpServletResponse();
              final var next = new MockFilterChain();
              proxy.doFilter(request, response, next);

              assertThat(response.getStatus())
                  .as(
                      "a durably-persisted PT-scoped session must authenticate the next scoped"
                          + " request even with the default chains present in the same"
                          + " FilterChainProxy")
                  .isEqualTo(200);
              assertThat(next.getRequest()).isNotNull();
            });
  }

  /**
   * Structural coverage for the OIDC configs: they take the same new {@code
   * defaultSessionRepositoryFilter} parameter as the BASIC configs, so this asserts the filter is
   * actually installed on both the OIDC webapp and API chains — the OIDC-specific gap flagged
   * against the BASIC-only round-trip tests above.
   */
  @Test
  void oidcDefaultChainsAlsoInstallTheSharedSessionRepositoryFilter() {
    new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class, StubAuthProvider.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                OidcWebappSecurityConfiguration.class,
                OidcApiSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                OidcBeansConfiguration.class,
                OidcWebappClientBeansConfiguration.class,
                OidcClaimsProviderConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class,
                UserConfiguration.class))
        .withPropertyValues(oidcProperties())
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var webappChain =
                  ctx.getBean("oidcWebappSecurityFilterChain", SecurityFilterChain.class);
              final var apiChain =
                  ctx.getBean("oidcApiSecurityFilterChain", SecurityFilterChain.class);

              assertThat(filtersOf(webappChain))
                  .as("OIDC webapp chain must install the default SessionRepositoryFilter")
                  .anySatisfy(f -> assertThat(f).isInstanceOf(SessionRepositoryFilter.class));
              assertThat(filtersOf(apiChain))
                  .as("OIDC API chain must install the default SessionRepositoryFilter")
                  .anySatisfy(f -> assertThat(f).isInstanceOf(SessionRepositoryFilter.class));

              assertThat(sessionRepositoryFilterOf(webappChain))
                  .as("the OIDC webapp and API chains must share the same filter instance")
                  .isSameAs(sessionRepositoryFilterOf(apiChain));
            });
  }

  private String[] oidcProperties() {
    final var issuer = oidcServer.issuerUri();
    return new String[] {
      "camunda.security.authentication.method=oidc",
      "camunda.security.authentication.oidc.issuer-uri=" + issuer,
      "camunda.security.authentication.oidc.client-id=test-client",
      "camunda.security.authentication.oidc.client-secret=secret",
      "camunda.security.authentication.oidc.redirect-uri=http://localhost/sso-callback"
    };
  }

  private static void stubResolvableUser(
      final org.springframework.context.ApplicationContext ctx,
      final String username,
      final String rawPassword) {
    final var encoder = ctx.getBean(PasswordEncoder.class);
    final var port = (ConfigurableUserDetailsPort) ctx.getBean(BasicAuthUserDetailsPort.class);
    port.resolve(username, encoder.encode(rawPassword));
  }

  /** Drives a real form login and returns the session cookie it commits. */
  private static jakarta.servlet.http.Cookie logIn(
      final FilterChainProxy proxy,
      final String loginUrl,
      final String username,
      final String password,
      final String expectedCookieName)
      throws Exception {
    final var request = new MockHttpServletRequest("POST", loginUrl);
    request.setParameter("username", username);
    request.setParameter("password", password);
    final var response = new MockHttpServletResponse();
    proxy.doFilter(request, response, new MockFilterChain());

    assertThat(response.getStatus())
        .as("login with valid credentials must succeed (204 from the form-login success handler)")
        .isEqualTo(204);

    final var cookie = response.getCookie(expectedCookieName);
    assertThat(cookie)
        .as("login must commit a session and set the " + expectedCookieName + " cookie")
        .isNotNull();
    return cookie;
  }

  private static SecurityFilterChain scopedChain(
      final org.springframework.context.ApplicationContext ctx, final String beanNamePrefix) {
    final var names = ctx.getBeanNamesForType(SecurityFilterChain.class);
    final var name =
        Arrays.stream(names)
            .filter(n -> n.startsWith(beanNamePrefix))
            .findFirst()
            .orElseThrow(
                () ->
                    new AssertionError(
                        "No "
                            + beanNamePrefix
                            + "* bean found; available chains: "
                            + Arrays.toString(names)));
    return ctx.getBean(name, SecurityFilterChain.class);
  }

  private static List<jakarta.servlet.Filter> filtersOf(final SecurityFilterChain chain) {
    return ((org.springframework.security.web.DefaultSecurityFilterChain) chain).getFilters();
  }

  private static SessionRepositoryFilter<?> sessionRepositoryFilterOf(
      final SecurityFilterChain chain) {
    return filtersOf(chain).stream()
        .filter(SessionRepositoryFilter.class::isInstance)
        .map(f -> (SessionRepositoryFilter<?>) f)
        .findFirst()
        .orElseThrow(
            () -> new AssertionError("No SessionRepositoryFilter found on chain " + chain));
  }

  @Configuration
  static class SingleBasicScopeProvider {

    @Bean
    CamundaSecurityScopeProvider singleBasicScope() {
      return () ->
          List.of(new ScopedSecurityDescriptor(BASE_PT, new AuthenticationConfiguration()));
    }
  }

  @Configuration
  static class StubPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder().build();
    }
  }

  @Configuration
  static class StubUserDetailsPort {

    @Bean
    BasicAuthUserDetailsPort userDetailsPort() {
      return new ConfigurableUserDetailsPort();
    }
  }

  /** Resolves whichever username/password was last configured via {@link #resolve}. */
  private static final class ConfigurableUserDetailsPort implements BasicAuthUserDetailsPort {

    private volatile CamundaUserDetails details;

    void resolve(final String username, final String encodedPassword) {
      details = new CamundaUserDetails(username, encodedPassword);
    }

    @Override
    public CamundaUserDetails loadUser(final String username) {
      final var current = details;
      return current != null && current.username().equals(username) ? current : null;
    }
  }

  @Configuration
  static class StubAuthProvider {

    @Bean
    CamundaAuthenticationProvider camundaAuthenticationProvider() {
      return CamundaAuthentication::anonymous;
    }
  }

  @Configuration
  static class ObjectMapperConfig {

    @Bean
    ObjectMapper objectMapper() {
      return new ObjectMapper();
    }
  }

  /** A real (if in-memory) {@link SessionStorePort}: genuine get/upsert/delete, not a no-op. */
  private static final class InMemorySessionStore implements SessionStorePort {

    private final Map<String, PersistentSession> sessions = new ConcurrentHashMap<>();

    @Override
    public PersistentSession get(final String sessionId) {
      return sessions.get(sessionId);
    }

    @Override
    public void upsert(final PersistentSession session) {
      sessions.put(session.id(), session);
    }

    @Override
    public void delete(final String sessionId) {
      sessions.remove(sessionId);
    }

    @Override
    public List<PersistentSession> getAll() {
      return List.copyOf(sessions.values());
    }

    Collection<PersistentSession> all() {
      return sessions.values();
    }
  }
}
