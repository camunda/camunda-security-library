/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.api.model.session.PersistentSession;
import io.camunda.security.core.port.out.ScopedSessionStorePortProvider;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.core.port.out.SessionStorePort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcTestServer;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.BasicAuthApiSecurityConfiguration;
import io.camunda.security.spring.session.WebSessionConfiguration;
import io.camunda.security.spring.session.WebSessionRepository;
import io.camunda.security.spring.session.WebSessionTestAccess;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import io.camunda.security.spring.user.UserConfiguration;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Cross-scope session isolation integration test.
 *
 * <p>Boots the full CSL auto-config with two OIDC scopes ({@code /physical-tenants/a} and {@code
 * /physical-tenants/b}) via a {@link CamundaSecurityScopeProvider}. Exercises three isolation
 * properties:
 *
 * <ol>
 *   <li><b>Per-scope cookie identity:</b> the {@link ScopedWebSessionComponentsFactory} wires each
 *       scope's {@link SessionRepositoryFilter} to a {@link
 *       org.springframework.session.web.http.DefaultCookieSerializer} that emits cookies named
 *       {@code camunda-session-physical-tenants-a} / {@code ...-b} with {@code
 *       Path=/physical-tenants/a} / {@code Path=/physical-tenants/b}.
 *   <li><b>Cross-scope session rejection:</b> a session seeded directly into scope A's {@link
 *       MapSessionRepository} is found by scope A's chain but is invisible to scope B's chain
 *       (because B's filter looks for a differently-named cookie). A protected request to scope B
 *       carrying only scope A's session cookie produces a 302 redirect to scope B's login.
 *   <li><b>Per-scope login redirect:</b> {@code GET /physical-tenants/a/login} redirects (302) to
 *       an authorization endpoint under {@code /physical-tenants/a/oauth2/authorization/…}, never
 *       under {@code /physical-tenants/b/…} (each scope has exactly one provider configured, so
 *       {@link io.camunda.security.spring.security.CamundaLoginPickerFilter} redirects straight to
 *       it rather than rendering a picker — ADR-0043).
 * </ol>
 */
class ScopedWebappSessionIsolationTest {

  private static final String BASE_A = "/physical-tenants/a";
  private static final String BASE_B = "/physical-tenants/b";

  private static final String COOKIE_A = "camunda-session-physical-tenants-a";
  private static final String COOKIE_B = "camunda-session-physical-tenants-b";

  private static OidcTestServer serverA;
  private static OidcTestServer serverB;

  @BeforeAll
  static void startOidcServers() throws Exception {
    serverA = OidcTestServer.startRsa("key-a");
    serverB = OidcTestServer.startRsa("key-b");
  }

  @AfterAll
  static void stopOidcServers() {
    if (serverA != null) {
      serverA.stop();
    }
    if (serverB != null) {
      serverB.stop();
    }
  }

  private WebApplicationContextRunner runner() {
    return new WebApplicationContextRunner()
        .withUserConfiguration(
            ObjectMapperConfig.class,
            StubPaths.class,
            StubUserDetailsPort.class,
            TwoScopeProvider.class)
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

  // Per-scope cookie identity — name and Path are distinct per scope
  @Test
  void perScopeCookieNamesAreDistinct() {
    // given
    final var serializerA = ScopedWebSessionComponentsFactory.cookieSerializer(BASE_A);
    final var serializerB = ScopedWebSessionComponentsFactory.cookieSerializer(BASE_B);

    // when — write a cookie value through each serializer
    final var responseA = new MockHttpServletResponse();
    final var requestA = new MockHttpServletRequest();
    requestA.setContextPath("");
    serializerA.writeCookieValue(
        new org.springframework.session.web.http.CookieSerializer.CookieValue(
            requestA, responseA, "session-value-a"));

    final var responseB = new MockHttpServletResponse();
    final var requestB = new MockHttpServletRequest();
    requestB.setContextPath("");
    serializerB.writeCookieValue(
        new org.springframework.session.web.http.CookieSerializer.CookieValue(
            requestB, responseB, "session-value-b"));

    // then — each serializer emits a cookie under its own scoped name with the correct Path
    final var cookieA = responseA.getCookie(COOKIE_A);
    final var cookieB = responseB.getCookie(COOKIE_B);

    assertThat(cookieA).as("scope A must emit cookie named " + COOKIE_A).isNotNull();
    assertThat(cookieA.getPath()).as("scope A cookie must have Path=" + BASE_A).isEqualTo(BASE_A);

    assertThat(cookieB).as("scope B must emit cookie named " + COOKIE_B).isNotNull();
    assertThat(cookieB.getPath()).as("scope B cookie must have Path=" + BASE_B).isEqualTo(BASE_B);
  }

  @Test
  void cookieNameMatchesDerivedConvention() {
    assertThat(ScopedSecurityChainRegistrar.sessionCookieName(BASE_A))
        .as("scope A cookie name must follow the camunda-session-<sanitize> convention")
        .isEqualTo(COOKIE_A);
    assertThat(ScopedSecurityChainRegistrar.sessionCookieName(BASE_B))
        .as("scope B cookie name must follow the camunda-session-<sanitize> convention")
        .isEqualTo(COOKIE_B);
  }

  // Cross-scope session rejection
  @Test
  void scopeASessionCookieIsNotHonouredByScopeBChain() throws Exception {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var chainAWrapper = webappChain(ctx, "a");
              final var chainBWrapper = webappChain(ctx, "b");

              final var sessionFilterA = sessionRepositoryFilter(chainAWrapper);
              final var repoA = sessionRepository(sessionFilterA);

              // given — seed an authenticated session in scope A's store
              final var seedSession = repoA.createSession();
              final var principal =
                  new UsernamePasswordAuthenticationToken(
                      "alice", null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
              final var securityContext = new SecurityContextImpl(principal);
              seedSession.setAttribute(
                  HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                  securityContext);
              repoA.save(seedSession);
              final var sessionId = seedSession.getId();

              // when — present scope A's cookie to a scope B chain request
              final var proxyB = new FilterChainProxy(List.of(chainBWrapper));
              final var request = new MockHttpServletRequest("GET", BASE_B + "/operate/dashboard");
              request.setCookies(new jakarta.servlet.http.Cookie(COOKIE_A, sessionId));
              final var response = new MockHttpServletResponse();
              proxyB.doFilter(request, response, new MockFilterChain());

              // then — scope B must not honour scope A's session: unauthenticated → 302 to login
              assertThat(response.getStatus())
                  .as(
                      "scope B chain must NOT authenticate a request bearing only scope A's session"
                          + " cookie — it should redirect to login (302)")
                  .isEqualTo(302);
            });
  }

  @Test
  void scopeBSessionCookieIsNotHonouredByScopeAChain() throws Exception {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var chainAWrapper = webappChain(ctx, "a");
              final var chainBWrapper = webappChain(ctx, "b");

              final var sessionFilterB = sessionRepositoryFilter(chainBWrapper);
              final var repoB = sessionRepository(sessionFilterB);

              // given — seed a session in scope B's store
              final var seedSession = repoB.createSession();
              final var principal =
                  new UsernamePasswordAuthenticationToken(
                      "bob", null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
              seedSession.setAttribute(
                  HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                  new SecurityContextImpl(principal));
              repoB.save(seedSession);
              final var sessionId = seedSession.getId();

              // when — present scope B's cookie to scope A's chain
              final var proxyA = new FilterChainProxy(List.of(chainAWrapper));
              final var request = new MockHttpServletRequest("GET", BASE_A + "/operate/dashboard");
              request.setCookies(new jakarta.servlet.http.Cookie(COOKIE_B, sessionId));
              final var response = new MockHttpServletResponse();
              proxyA.doFilter(request, response, new MockFilterChain());

              // then — scope A must not authenticate the request with scope B's cookie
              assertThat(response.getStatus())
                  .as(
                      "scope A chain must NOT authenticate a request bearing only scope B's session"
                          + " cookie — it should redirect to login (302)")
                  .isEqualTo(302);
            });
  }

  @Test
  void perScopeSessionRepositoriesAreDistinctAndSeedingIsEffective() {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var chainAWrapper = webappChain(ctx, "a");
              final var chainBWrapper = webappChain(ctx, "b");
              final var sessionFilterA = sessionRepositoryFilter(chainAWrapper);
              final var sessionFilterB = sessionRepositoryFilter(chainBWrapper);
              final var repoA = sessionRepository(sessionFilterA);
              final var repoB = sessionRepository(sessionFilterB);

              assertThat(repoA)
                  .as("scope A and scope B must use distinct MapSessionRepository instances")
                  .isNotSameAs(repoB);

              // given — seed a session in scope A's store
              final var seedSession = repoA.createSession();
              seedSession.setAttribute("test-marker", "scope-a-session");
              repoA.save(seedSession);
              final var sessionId = seedSession.getId();

              // then — scope A's repository can find the session by ID
              final var foundInA = repoA.findById(sessionId);
              assertThat(foundInA)
                  .as(
                      "session seeded into scope A's store must be findable by scope A's repository")
                  .isNotNull();
              assertThat((String) foundInA.getAttribute("test-marker"))
                  .as("found session must carry the seeded marker attribute")
                  .isEqualTo("scope-a-session");

              // then — scope B's repository cannot find the same session (different instance)
              final var foundInB = repoB.findById(sessionId);
              assertThat(foundInB)
                  .as(
                      "session seeded into scope A's store must NOT be findable by scope B's"
                          + " repository — the two stores are independent instances")
                  .isNull();
            });
  }

  // Per-scope login redirect — each scope has exactly one provider configured, so
  // CamundaLoginPickerFilter redirects straight to it (ADR-0043) rather than rendering a picker;
  // the redirect target must stay scoped to that scope's own prefix and never leak the other
  // scope's.
  @Test
  void scopeALoginRedirectsToScopeAProviderOnly() throws Exception {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var chainA = webappChain(ctx, "a");
              final var proxyA = new FilterChainProxy(List.of(chainA));
              final var request = new MockHttpServletRequest("GET", BASE_A + "/login");
              final var response = new MockHttpServletResponse();
              proxyA.doFilter(request, response, new MockFilterChain());

              assertThat(response.getStatus())
                  .as("GET /physical-tenants/a/login must redirect straight to scope A's provider")
                  .isEqualTo(302);

              final var redirectedUrl = response.getRedirectedUrl();

              assertThat(redirectedUrl)
                  .as("redirect must target scope A's OAuth2 authorization endpoint")
                  .startsWith(BASE_A + "/oauth2/authorization/");

              assertThat(redirectedUrl)
                  .as("redirect must NOT target scope B's OAuth2 authorization endpoint")
                  .doesNotContain(BASE_B + "/oauth2/authorization/");
            });
  }

  @Test
  void scopeBLoginRedirectsToScopeBProviderOnly() throws Exception {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var chainB = webappChain(ctx, "b");
              final var proxyB = new FilterChainProxy(List.of(chainB));
              final var request = new MockHttpServletRequest("GET", BASE_B + "/login");
              final var response = new MockHttpServletResponse();
              proxyB.doFilter(request, response, new MockFilterChain());

              assertThat(response.getStatus())
                  .as("GET /physical-tenants/b/login must redirect straight to scope B's provider")
                  .isEqualTo(302);

              final var redirectedUrl = response.getRedirectedUrl();

              assertThat(redirectedUrl)
                  .as("redirect must target scope B's OAuth2 authorization endpoint")
                  .startsWith(BASE_B + "/oauth2/authorization/");

              assertThat(redirectedUrl)
                  .as("redirect must NOT target scope A's OAuth2 authorization endpoint")
                  .doesNotContain(BASE_A + "/oauth2/authorization/");
            });
  }

  // With a provider present, each scope gets its own durable repository bound to its own store.
  @Test
  void perScopeChainsUseDistinctDurableRepositoriesBoundToTheirStore() {
    final SessionStorePort storeA = new NoopSessionStore();
    final SessionStorePort storeB = new NoopSessionStore();
    final ScopedSessionStorePortProvider provider =
        basePath -> {
          if (BASE_A.equals(basePath)) {
            return storeA;
          }
          if (BASE_B.equals(basePath)) {
            return storeB;
          }
          throw new AssertionError("unexpected basePath: " + basePath);
        };

    runner()
        .withConfiguration(AutoConfigurations.of(WebSessionConfiguration.class))
        .withPropertyValues("camunda.security.session.persistent.enabled=true")
        // the singleton WebSessionRepository (global filter + expiry sweep) still needs a store
        .withBean("clusterSessionStore", SessionStorePort.class, NoopSessionStore::new)
        .withBean(ScopedSessionStorePortProvider.class, () -> provider)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var repoA = durableRepository(webappChain(ctx, "a"));
              final var repoB = durableRepository(webappChain(ctx, "b"));

              assertThat(repoA)
                  .as("each scope must get its own durable WebSessionRepository instance")
                  .isNotSameAs(repoB);
              assertThat(WebSessionTestAccess.storePortOf(repoA))
                  .as("scope A's repository must be bound to scope A's store")
                  .isSameAs(storeA);
              assertThat(WebSessionTestAccess.storePortOf(repoB))
                  .as("scope B's repository must be bound to scope B's store")
                  .isSameAs(storeB);
            });
  }

  // Without a provider, scopes fall back to the shared singleton repository.
  @Test
  void perScopeChainsShareTheSingletonRepositoryWhenNoProvider() {
    runner()
        .withConfiguration(AutoConfigurations.of(WebSessionConfiguration.class))
        .withPropertyValues("camunda.security.session.persistent.enabled=true")
        .withBean("clusterSessionStore", SessionStorePort.class, NoopSessionStore::new)
        // no ScopedSessionStorePortProvider contributed
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var singleton = ctx.getBean(WebSessionRepository.class);
              final var repoA = durableRepository(webappChain(ctx, "a"));
              final var repoB = durableRepository(webappChain(ctx, "b"));

              assertThat(repoA)
                  .as("without a provider, scopes fall back to the shared singleton repository")
                  .isSameAs(singleton)
                  .isSameAs(repoB);
            });
  }

  // Commit-phase routing: a session created + committed through scope A's real
  // SessionRepositoryFilter
  // is written to scope A's store, not the default/other store. This exercises the actual
  // SessionRepositoryFilter -> WebSessionRepository.save -> SessionStorePort.upsert commit path.
  @Test
  void committingThroughAScopeFilterWritesToThatScopesStoreOnly() throws Exception {
    final var storeA = new RecordingSessionStore();
    final var storeB = new RecordingSessionStore();
    final ScopedSessionStorePortProvider provider =
        basePath -> {
          if (BASE_A.equals(basePath)) {
            return storeA;
          }
          if (BASE_B.equals(basePath)) {
            return storeB;
          }
          throw new AssertionError("unexpected basePath: " + basePath);
        };

    runner()
        .withConfiguration(AutoConfigurations.of(WebSessionConfiguration.class))
        .withPropertyValues("camunda.security.session.persistent.enabled=true")
        .withBean("clusterSessionStore", SessionStorePort.class, RecordingSessionStore::new)
        .withBean(ScopedSessionStorePortProvider.class, () -> provider)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var filterA = sessionRepositoryFilter(webappChain(ctx, "a"));
              // downstream creates + mutates a session; the filter commits it in its finally block
              final FilterChain createsSession =
                  (req, res) ->
                      ((HttpServletRequest) req).getSession(true).setAttribute("marker", "v");

              filterA.doFilter(
                  new MockHttpServletRequest("GET", BASE_A + "/operate/dashboard"),
                  new MockHttpServletResponse(),
                  createsSession);

              assertThat(storeA.upsertedIds())
                  .as("the commit through scope A's filter writes to scope A's store")
                  .hasSize(1);
              assertThat(storeB.upsertedIds()).as("scope B's store must be untouched").isEmpty();
            });
  }

  /**
   * The durable {@link WebSessionRepository} backing the scope's {@link SessionRepositoryFilter}.
   */
  private static WebSessionRepository durableRepository(final SecurityFilterChain chain) {
    return WebSessionTestAccess.durableRepositoryOf(sessionRepositoryFilter(chain));
  }

  /** Resolves the {@link OrderedSecurityFilterChainWrapper} for the given scope suffix (a or b). */
  private static OrderedSecurityFilterChainWrapper webappChain(
      final org.springframework.context.ApplicationContext ctx, final String scopeSuffix) {
    final var names = ctx.getBeanNamesForType(SecurityFilterChain.class);
    final var name =
        Arrays.stream(names)
            .filter(
                n -> n.startsWith("scopedWebappSecurityFilterChain-") && n.endsWith(scopeSuffix))
            .findFirst()
            .orElseThrow(
                () ->
                    new AssertionError(
                        "No scopedWebappSecurityFilterChain-*-"
                            + scopeSuffix
                            + " bean found; available chains: "
                            + Arrays.toString(names)));
    return (OrderedSecurityFilterChainWrapper) ctx.getBean(name, SecurityFilterChain.class);
  }

  private static SessionRepositoryFilter<?> sessionRepositoryFilter(
      final SecurityFilterChain chain) {
    return chain.getFilters().stream()
        .filter(SessionRepositoryFilter.class::isInstance)
        .map(f -> (SessionRepositoryFilter<?>) f)
        .findFirst()
        .orElseThrow(
            () -> new AssertionError("No SessionRepositoryFilter found on chain " + chain));
  }

  private static MapSessionRepository sessionRepository(final SessionRepositoryFilter<?> filter) {
    return WebSessionTestAccess.mapRepositoryOf(filter);
  }

  /** Provides two OIDC scopes, one per OidcTestServer. */
  @Configuration
  static class TwoScopeProvider {

    @Bean
    CamundaSecurityScopeProvider twoScopedDescriptors() {
      return () -> {
        try {
          return List.of(
              buildOidcDescriptor(BASE_A, serverA, "scope-client-a"),
              buildOidcDescriptor(BASE_B, serverB, "scope-client-b"));
        } catch (final Exception ex) {
          throw new IllegalStateException("Could not build scoped OIDC descriptors", ex);
        }
      };
    }

    private static ScopedSecurityDescriptor buildOidcDescriptor(
        final String basePath, final OidcTestServer server, final String clientId)
        throws Exception {
      final var auth = new AuthenticationConfiguration();
      auth.setMethod(AuthenticationMethod.OIDC);
      auth.setOidc(server.oidcConfiguration(clientId));
      return new ScopedSecurityDescriptor(basePath, auth);
    }
  }

  @Configuration
  static class StubPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder().apiPaths("/v2/**").build();
    }
  }

  @Configuration
  static class StubUserDetailsPort {

    @Bean
    io.camunda.security.core.port.out.BasicAuthUserDetailsPort userDetailsPort() {
      return username -> null;
    }
  }

  @Configuration
  static class ObjectMapperConfig {

    @Bean
    ObjectMapper objectMapper() {
      return new ObjectMapper();
    }
  }

  private static final class NoopSessionStore implements SessionStorePort {
    @Override
    public PersistentSession get(final String sessionId) {
      return null;
    }

    @Override
    public void upsert(final PersistentSession session) {}

    @Override
    public void delete(final String sessionId) {}

    @Override
    public List<PersistentSession> getAll() {
      return List.of();
    }
  }

  /** Records the ids upserted into it, so a commit can be asserted to land in this store. */
  private static final class RecordingSessionStore implements SessionStorePort {
    private final List<String> upsertedIds = new ArrayList<>();

    @Override
    public PersistentSession get(final String sessionId) {
      return null;
    }

    @Override
    public void upsert(final PersistentSession session) {
      upsertedIds.add(session.id());
    }

    @Override
    public void delete(final String sessionId) {}

    @Override
    public List<PersistentSession> getAll() {
      return List.of();
    }

    List<String> upsertedIds() {
      return upsertedIds;
    }
  }
}
