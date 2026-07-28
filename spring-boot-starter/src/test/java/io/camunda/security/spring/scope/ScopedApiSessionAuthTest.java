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
import io.camunda.security.spring.session.WebSessionTestAccess;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import io.camunda.security.spring.user.UserConfiguration;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
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
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Verifies that the per-scope {@link SessionRepositoryFilter} (shared between the webapp and API
 * chains via {@link ScopedSecurityChainRegistrar}) allows a request carrying a valid per-scope
 * session cookie to authenticate the scoped API chain with no bearer token, while preserving
 * cross-scope isolation and {@code SessionCreationPolicy.NEVER} for bearer-only requests.
 */
class ScopedApiSessionAuthTest {

  private static final String BASE_A = "/physical-tenants/a";
  private static final String BASE_B = "/physical-tenants/b";

  private static final String COOKIE_A = ScopedSecurityChainRegistrar.sessionCookieName(BASE_A);

  // Probe path: basePath + apiPaths entry from StubPaths ("/api/**")
  private static final String API_PATH_A = BASE_A + "/api/authentication/me";
  private static final String API_PATH_B = BASE_B + "/api/authentication/me";

  private static OidcTestServer serverA;
  private static OidcTestServer serverB;

  @BeforeAll
  static void startOidcServers() throws Exception {
    serverA = OidcTestServer.startRsa("key-api-a");
    serverB = OidcTestServer.startRsa("key-api-b");
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

  // A session minted on the WEBAPP chain authenticates the same scope's API chain (shared filter)
  @Test
  void scopeASessionCookieAuthenticatesScopeAApiChain() throws Exception {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var apiChainA = apiChain(ctx, "a");
              final var webappChainA = webappChain(ctx, "a");

              // structural assertion: both chains share the exact same SessionRepositoryFilter
              assertThat(sessionRepositoryFilter(apiChainA))
                  .as(
                      "the API and webapp chains for scope A must share the same"
                          + " SessionRepositoryFilter instance")
                  .isSameAs(sessionRepositoryFilter(webappChainA));

              // given — seed an authenticated session via the WEBAPP chain's session store
              final var repoA =
                  WebSessionTestAccess.mapRepositoryOf(sessionRepositoryFilter(webappChainA));
              final var session = repoA.createSession();
              final var principal =
                  new UsernamePasswordAuthenticationToken(
                      "alice", null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
              session.setAttribute(
                  HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                  new SecurityContextImpl(principal));
              repoA.save(session);

              // when — present the webapp-minted cookie to the API chain (no bearer token)
              final var proxy = new FilterChainProxy(List.of(apiChainA));
              final var request = new MockHttpServletRequest("GET", API_PATH_A);
              request.setCookies(
                  new jakarta.servlet.http.Cookie(COOKIE_A, encodedCookieValue(session.getId())));
              final var response = new MockHttpServletResponse();
              final var next = new MockFilterChain();
              proxy.doFilter(request, response, next);

              // then — the shared session store honours the cookie: request must reach downstream
              // with status 200
              assertThat(response.getStatus())
                  .as(
                      "a request with scope A's session cookie (minted via webapp chain) must be"
                          + " authenticated on scope A's API chain and reach downstream with status"
                          + " 200")
                  .isEqualTo(200);
              assertThat(next.getRequest())
                  .as("authenticated request must reach the downstream filter")
                  .isNotNull();
            });
  }

  // A session seeded into scope A does NOT authenticate scope B's API chain
  @Test
  void scopeASessionCookieDoesNotAuthenticateScopeBApiChain() throws Exception {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var apiChainA = apiChain(ctx, "a");
              final var apiChainB = apiChain(ctx, "b");

              final var sessionFilterA = sessionRepositoryFilter(apiChainA);
              final var repoA = WebSessionTestAccess.mapRepositoryOf(sessionFilterA);

              // given — seed a session in scope A's store
              final var session = repoA.createSession();
              final var principal =
                  new UsernamePasswordAuthenticationToken(
                      "alice", null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
              session.setAttribute(
                  HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                  new SecurityContextImpl(principal));
              repoA.save(session);

              // when — present scope A's session cookie to scope B's API chain
              final var proxyB = new FilterChainProxy(List.of(apiChainB));
              final var request = new MockHttpServletRequest("GET", API_PATH_B);
              request.setCookies(
                  new jakarta.servlet.http.Cookie(COOKIE_A, encodedCookieValue(session.getId())));
              final var response = new MockHttpServletResponse();
              proxyB.doFilter(request, response, new MockFilterChain());

              // then — scope B must reject the request (wrong cookie name → unauthenticated → 401)
              assertThat(response.getStatus())
                  .as(
                      "scope A's session cookie must NOT authenticate on scope B's API chain — "
                          + "different cookie name means no session is found, request is rejected (401)")
                  .isEqualTo(401);
            });
  }

  // A valid bearer token still authenticates scope A's API chain
  @Test
  void validBearerTokenAuthenticatesScopeAApiChain() throws Exception {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var apiChainA = apiChain(ctx, "a");
              final var proxy = new FilterChainProxy(List.of(apiChainA));

              // given — a JWT signed by scope A's key with the correct issuer
              final var token = serverA.sign(serverA.issuerUri());
              final var request = new MockHttpServletRequest("GET", API_PATH_A);
              request.addHeader("Authorization", "Bearer " + token);
              final var response = new MockHttpServletResponse();
              final var next = new MockFilterChain();

              // when
              proxy.doFilter(request, response, next);

              // then — bearer auth succeeds: request reaches downstream
              assertThat(next.getRequest())
                  .as("a valid bearer token must authenticate on scope A's API chain")
                  .isNotNull();
              assertThat(response.getStatus())
                  .as(
                      "a valid bearer token must reach downstream with status 200 on scope A's API chain")
                  .isEqualTo(200);
            });
  }

  // A bearer token signed by scope B's key is rejected on scope A's API chain
  @Test
  void wrongIssuerBearerTokenIsRejectedByScopeAApiChain() throws Exception {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var apiChainA = apiChain(ctx, "a");
              final var proxy = new FilterChainProxy(List.of(apiChainA));

              // given — a JWT signed by scope B's key (wrong issuer for scope A)
              final var token = serverB.sign(serverB.issuerUri());
              final var request = new MockHttpServletRequest("GET", API_PATH_A);
              request.addHeader("Authorization", "Bearer " + token);
              final var response = new MockHttpServletResponse();

              // when
              proxy.doFilter(request, response, new MockFilterChain());

              // then — wrong issuer → 401
              assertThat(response.getStatus())
                  .as(
                      "a bearer token signed by scope B's key must be rejected on scope A's API chain (401)")
                  .isEqualTo(401);
            });
  }

  // A bearer-only request (no cookie) must not create a session
  @Test
  void bearerOnlyRequestDoesNotCreateSession() throws Exception {
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              final var apiChainA = apiChain(ctx, "a");
              final var proxy = new FilterChainProxy(List.of(apiChainA));

              // given — a valid bearer token, no session cookie
              final var token = serverA.sign(serverA.issuerUri());
              final var request = new MockHttpServletRequest("GET", API_PATH_A);
              request.addHeader("Authorization", "Bearer " + token);
              final var response = new MockHttpServletResponse();
              final var next = new MockFilterChain();

              // when
              proxy.doFilter(request, response, next);

              // then — request is authenticated and no Set-Cookie for the session cookie is emitted
              assertThat(next.getRequest())
                  .as("bearer-only request must be authenticated and pass downstream")
                  .isNotNull();
              // DefaultCookieSerializer writes via response.addHeader("Set-Cookie", ...), which
              // MockHttpServletResponse.getCookie() does not observe — check the raw headers
              // instead.
              final var setCookieHeaders = response.getHeaders("Set-Cookie");
              assertThat(setCookieHeaders)
                  .as(
                      "SessionCreationPolicy.NEVER must be honoured: no Set-Cookie header for the"
                          + " session cookie must be present on a bearer-only request to the API chain")
                  .noneMatch(h -> h.startsWith(COOKIE_A + "="));
            });
  }

  /**
   * Encodes a session ID for use in a cookie value.
   *
   * <p>{@link org.springframework.session.web.http.DefaultCookieSerializer} uses Base64 encoding by
   * default: {@code writeCookieValue} encodes and {@code readCookieValues} decodes. Tests that
   * simulate a browser sending a cookie must Base64-encode the raw session ID to match.
   */
  private static String encodedCookieValue(final String sessionId) {
    return Base64.getEncoder().encodeToString(sessionId.getBytes(StandardCharsets.UTF_8));
  }

  private static OrderedSecurityFilterChainWrapper apiChain(
      final org.springframework.context.ApplicationContext ctx, final String scopeSuffix) {
    final var names = ctx.getBeanNamesForType(SecurityFilterChain.class);
    final var name =
        Arrays.stream(names)
            .filter(n -> n.startsWith("scopedApiSecurityFilterChain-") && n.endsWith(scopeSuffix))
            .findFirst()
            .orElseThrow(
                () ->
                    new AssertionError(
                        "No scopedApiSecurityFilterChain-*-"
                            + scopeSuffix
                            + " bean found; available chains: "
                            + Arrays.toString(names)));
    return (OrderedSecurityFilterChainWrapper) ctx.getBean(name, SecurityFilterChain.class);
  }

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

  @Configuration
  static class TwoScopeProvider {

    @Bean
    CamundaSecurityScopeProvider twoScopedDescriptors() {
      return () -> {
        try {
          return List.of(
              buildOidcDescriptor(BASE_A, serverA, "api-session-client-a"),
              buildOidcDescriptor(BASE_B, serverB, "api-session-client-b"));
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
      return StubSecurityPaths.builder().apiPaths("/api/**").build();
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
