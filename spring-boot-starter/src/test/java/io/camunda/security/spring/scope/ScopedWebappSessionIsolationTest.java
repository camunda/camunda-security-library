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
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcTestServer;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.BasicAuthApiSecurityConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import io.camunda.security.spring.user.UserConfiguration;
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
import org.springframework.session.MapSession;
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
 *   <li><b>Per-scope picker:</b> {@code GET /physical-tenants/a/login} renders a 200 whose body
 *       contains links under {@code /physical-tenants/a/oauth2/authorization/…} but not under
 *       {@code /physical-tenants/b/…}.
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

  // Per-scope picker — only scope A's links appear on scope A's login page
  @Test
  void scopeALoginPickerListsOnlyScopeAProviderLinks() throws Exception {
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
                  .as("GET /physical-tenants/a/login must return 200 from the picker")
                  .isEqualTo(200);

              final var body = response.getContentAsString();

              assertThat(body)
                  .as("picker must contain scope A's OAuth2 authorization link")
                  .contains(BASE_A + "/oauth2/authorization/");

              assertThat(body)
                  .as("picker must NOT contain scope B's OAuth2 authorization link")
                  .doesNotContain(BASE_B + "/oauth2/authorization/");
            });
  }

  @Test
  void scopeBLoginPickerListsOnlyScopeBProviderLinks() throws Exception {
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
                  .as("GET /physical-tenants/b/login must return 200 from the picker")
                  .isEqualTo(200);

              final var body = response.getContentAsString();

              assertThat(body)
                  .as("picker must contain scope B's OAuth2 authorization link")
                  .contains(BASE_B + "/oauth2/authorization/");

              assertThat(body)
                  .as("picker must NOT contain scope A's OAuth2 authorization link")
                  .doesNotContain(BASE_A + "/oauth2/authorization/");
            });
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

  @SuppressWarnings("unchecked")
  private static SessionRepositoryFilter<MapSession> sessionRepositoryFilter(
      final SecurityFilterChain chain) {
    return chain.getFilters().stream()
        .filter(SessionRepositoryFilter.class::isInstance)
        .map(f -> (SessionRepositoryFilter<MapSession>) f)
        .findFirst()
        .orElseThrow(
            () -> new AssertionError("No SessionRepositoryFilter found on chain " + chain));
  }

  @SuppressWarnings("unchecked")
  private static MapSessionRepository sessionRepository(
      final SessionRepositoryFilter<MapSession> filter) {
    try {
      final var field = SessionRepositoryFilter.class.getDeclaredField("sessionRepository");
      field.setAccessible(true);
      final Object repo = field.get(filter);
      if (!(repo instanceof MapSessionRepository mapRepo)) {
        throw new AssertionError(
            "Expected MapSessionRepository backing the filter, got: " + repo.getClass());
      }
      return mapRepo;
    } catch (final ReflectiveOperationException ex) {
      throw new AssertionError("Could not access sessionRepository field on filter", ex);
    }
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
}
