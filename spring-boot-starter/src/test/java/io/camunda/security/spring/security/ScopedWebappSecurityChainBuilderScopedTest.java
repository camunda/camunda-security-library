/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.config.oidc.OidcProvidersConfiguration;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.filter.AdminUserCheckFilter;
import io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcTokenEndpointCustomizer;
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Verifies {@link ScopedWebappSecurityChainBuilder#buildScopedWebappChain}: path-prefixed matchers,
 * session filter placement, login redirect, and picker link prefixing.
 */
class ScopedWebappSecurityChainBuilderScopedTest {

  private static final String BASE_PATH = "/physical-tenants/t1";

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withUserConfiguration(
              ObjectMapperConfig.class, StubPaths.class, ScopedSingleIdpConfig.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  BaseSecurityConfiguration.class,
                  AuthFailureHandlerConfiguration.class,
                  ScopedOidcInfrastructureConfiguration.class,
                  ScopedWebappSecurityChainBuilderConfiguration.class));

  @Test
  void scopedChainMatchesPrefixedPath() {
    runner.run(
        ctx -> {
          final var chain = ctx.getBean("scopedOidcTestChain", SecurityFilterChain.class);
          final var request = new MockHttpServletRequest("GET", BASE_PATH + "/operate/dashboard");
          assertThat(chain.matches(request))
              .as("chain must match requests under the scoped basePath")
              .isTrue();
        });
  }

  @Test
  void scopedChainDoesNotMatchUnprefixedPath() {
    runner.run(
        ctx -> {
          final var chain = ctx.getBean("scopedOidcTestChain", SecurityFilterChain.class);
          final var request = new MockHttpServletRequest("GET", "/operate/dashboard");
          assertThat(chain.matches(request))
              .as("chain must NOT match requests outside the scoped basePath")
              .isFalse();
        });
  }

  @Test
  void shouldMatchOAuth2EndpointsWhenHostIncludesThemInWebappPaths() {
    new WebApplicationContextRunner()
        .withUserConfiguration(
            ObjectMapperConfig.class, StubPathsWithOidcEndpoints.class, ScopedSingleIdpConfig.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class))
        .run(
            ctx -> {
              final var chain =
                  (DefaultSecurityFilterChain)
                      ctx.getBean("scopedOidcTestChain", SecurityFilterChain.class);
              assertThat(
                      chain.matches(
                          new MockHttpServletRequest(
                              "GET", BASE_PATH + "/oauth2/authorization/oidc")))
                  .as("scoped chain must match the prefixed OAuth2 authorization endpoint")
                  .isTrue();
              assertThat(
                      chain.matches(new MockHttpServletRequest("GET", BASE_PATH + "/sso-callback")))
                  .as("scoped chain must match the prefixed sso-callback endpoint")
                  .isTrue();
            });
  }

  @Test
  void anonymousRequestToProtectedScopedPathRedirectsToLogin() throws Exception {
    runner.run(
        ctx -> {
          final var chain = ctx.getBean("scopedOidcTestChain", SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(List.of(chain));
          final var request = new MockHttpServletRequest("GET", BASE_PATH + "/operate/dashboard");
          final var response = new MockHttpServletResponse();

          proxy.doFilter(request, response, new MockFilterChain());

          assertThat(response.getStatus())
              .as("anonymous access to protected scoped path must redirect (302)")
              .isEqualTo(302);
        });
  }

  @Test
  void shouldReturn401ForBearerTokenRequests() throws Exception {
    runner.run(
        ctx -> {
          final var chain = ctx.getBean("scopedOidcTestChain", SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(List.of(chain));
          final var request = new MockHttpServletRequest("GET", BASE_PATH + "/operate/dashboard");
          request.addHeader("Authorization", "Bearer sometoken");
          final var response = new MockHttpServletResponse();

          proxy.doFilter(request, response, new MockFilterChain());

          assertThat(response.getStatus())
              .as("bearer token on webapp path must return 401, not a redirect")
              .isEqualTo(401);
        });
  }

  @Test
  void sessionRepositoryFilterIsInstalledBeforeSecurityContextHolderFilter() {
    runner.run(
        ctx -> {
          final var chain =
              (DefaultSecurityFilterChain)
                  ctx.getBean("scopedOidcTestChain", SecurityFilterChain.class);
          final var filters = chain.getFilters();
          int sessionFilterIndex = -1;
          int securityContextIndex = -1;
          for (int i = 0; i < filters.size(); i++) {
            if (filters.get(i) instanceof SessionRepositoryFilter) {
              sessionFilterIndex = i;
            }
            if (filters.get(i) instanceof SecurityContextHolderFilter) {
              securityContextIndex = i;
            }
          }
          assertThat(sessionFilterIndex)
              .as("SessionRepositoryFilter must be present on the scoped chain")
              .isGreaterThanOrEqualTo(0);
          assertThat(securityContextIndex)
              .as("SecurityContextHolderFilter must be present on the scoped chain")
              .isGreaterThanOrEqualTo(0);
          assertThat(sessionFilterIndex)
              .as("SessionRepositoryFilter must appear before SecurityContextHolderFilter")
              .isLessThan(securityContextIndex);
        });
  }

  /**
   * Regression: the scoped OIDC chain must wire its logout success handler with the <em>scoped</em>
   * {@link ClientRegistrationRepository}, not the cluster one. Only the scoped repo carries the
   * scoped registration (prefixed redirect URI), so RP-initiated logout can resolve {@code
   * end_session_endpoint}/{@code client_id} for scoped users. Guards against reintroducing the
   * defect where the handler was taken from a cluster-level provider.
   */
  @Test
  void scopedOidcChainWiresLogoutSuccessHandlerWithScopedClientRegistrationRepository() {
    runner.run(
        ctx -> {
          final var chain =
              (DefaultSecurityFilterChain)
                  ctx.getBean("scopedOidcTestChain", SecurityFilterChain.class);
          final var logoutFilter =
              chain.getFilters().stream()
                  .filter(LogoutFilter.class::isInstance)
                  .map(LogoutFilter.class::cast)
                  .findFirst()
                  .orElseThrow(
                      () -> new AssertionError("scoped OIDC chain must have a LogoutFilter"));

          final var successHandler =
              (LogoutSuccessHandler)
                  ReflectionTestUtils.getField(logoutFilter, "logoutSuccessHandler");
          assertThat(successHandler)
              .as("scoped OIDC logout must use the CSL-owned OIDC logout success handler")
              .isInstanceOf(CamundaOidcLogoutSuccessHandler.class);

          final var repo =
              (ClientRegistrationRepository)
                  ReflectionTestUtils.getField(successHandler, "clientRegistrationRepository");
          final var registration = repo.findByRegistrationId("oidc");
          assertThat(registration)
              .as("logout handler's repository must resolve the scoped registration")
              .isNotNull();
          assertThat(registration.getRedirectUri())
              .as("resolved registration must be the scoped one (redirect URI carries the prefix)")
              .isEqualTo("{baseUrl}" + BASE_PATH + "/sso-callback");
        });
  }

  /**
   * A host may (wrongly) override {@link SecurityPathPort#postLogoutRedirectPath()} to return a
   * bare {@code null} despite the {@code Optional} return type. The builder must fail fast with a
   * clear message and migration hint, not NPE deep inside the redirect-URI template.
   */
  @Test
  void scopedOidcChainFailsFastWhenPostLogoutRedirectPathReturnsNull() {
    new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, NullPostLogoutPathConfig.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class))
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .isInstanceOf(NullPointerException.class)
                  .hasMessageContaining(
                      "SecurityPathPort#postLogoutRedirectPath() must not return null")
                  .hasMessageContaining("return Optional.empty()");
            });
  }

  @Test
  void pickerLinksArePrefixedWithBasePathForMultiIdp() throws Exception {
    new WebApplicationContextRunner()
        .withUserConfiguration(
            ObjectMapperConfig.class, StubPaths.class, ScopedMultiIdpConfig.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class))
        .run(
            ctx -> {
              final var chain =
                  ctx.getBean("scopedOidcMultiIdpTestChain", SecurityFilterChain.class);
              final var proxy = new FilterChainProxy(List.of(chain));
              final var request = new MockHttpServletRequest("GET", BASE_PATH + "/login");
              final var response = new MockHttpServletResponse();

              proxy.doFilter(request, response, new MockFilterChain());

              assertThat(response.getStatus()).as("picker must render 200").isEqualTo(200);
              final var body = response.getContentAsString();
              assertThat(body)
                  .as("picker links must be prefixed with basePath")
                  .contains(BASE_PATH + "/oauth2/authorization/oidc")
                  .contains(BASE_PATH + "/oauth2/authorization/oidc-secondary");
            });
  }

  @Test
  void scopedBasicChainLogoutClearsScopedCookiesAtBasePath() throws Exception {
    new WebApplicationContextRunner()
        .withUserConfiguration(
            ObjectMapperConfig.class,
            StubPaths.class,
            StubUserDetailsPortConfig.class,
            ScopedBasicConfig.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                io.camunda.security.spring.user.UserConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class))
        .run(
            ctx -> {
              final var chain = ctx.getBean("scopedBasicTestChain", SecurityFilterChain.class);
              final var proxy = new FilterChainProxy(List.of(chain));
              final var request = new MockHttpServletRequest("POST", BASE_PATH + "/logout");
              request.addParameter("_csrf", "dummy");
              final var response = new MockHttpServletResponse();
              proxy.doFilter(request, response, new MockFilterChain());

              final var cookieHeaders = response.getHeaders("Set-Cookie");

              final var sessionCookieName = "camunda-session-physical-tenants-t1";
              assertThat(cookieHeaders)
                  .as("logout must emit a Set-Cookie clearing the scoped session cookie")
                  .anyMatch(
                      h ->
                          h.contains(sessionCookieName + "=")
                              && h.contains("Max-Age=0")
                              && h.contains("Path=" + BASE_PATH));

              final var csrfCookieName = "X-CSRF-TOKEN-physical-tenants-t1";
              assertThat(cookieHeaders)
                  .as("logout must emit a Set-Cookie clearing the per-scope CSRF cookie")
                  .anyMatch(
                      h ->
                          h.contains(csrfCookieName + "=")
                              && h.contains("Max-Age=0")
                              && h.contains("Path=" + BASE_PATH));
            });
  }

  @Test
  void twoScopedChainsHaveIndependentCsrfCookiesThatDoNotCrossContaminate() throws Exception {
    new WebApplicationContextRunner()
        .withUserConfiguration(
            ObjectMapperConfig.class,
            StubPaths.class,
            StubUserDetailsPortConfig.class,
            TwoScopedBasicChainsConfig.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                io.camunda.security.spring.user.UserConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class))
        .run(
            ctx -> {
              final var chainT1 = ctx.getBean("scopedBasicChainForT1", SecurityFilterChain.class);
              final var chainT2 = ctx.getBean("scopedBasicChainForT2", SecurityFilterChain.class);

              final var requestT1 =
                  new MockHttpServletRequest("POST", "/physical-tenants/t1/logout");
              final var responseT1 = new MockHttpServletResponse();
              new FilterChainProxy(List.of(chainT1))
                  .doFilter(requestT1, responseT1, new MockFilterChain());

              final var requestT2 =
                  new MockHttpServletRequest("POST", "/physical-tenants/t2/logout");
              final var responseT2 = new MockHttpServletResponse();
              new FilterChainProxy(List.of(chainT2))
                  .doFilter(requestT2, responseT2, new MockFilterChain());

              final var cookiesT1 = responseT1.getHeaders("Set-Cookie");
              final var cookiesT2 = responseT2.getHeaders("Set-Cookie");

              assertThat(cookiesT1)
                  .as("t1 logout must clear its own per-scope CSRF cookie")
                  .anyMatch(
                      h ->
                          h.contains("X-CSRF-TOKEN-physical-tenants-t1=")
                              && h.contains("Max-Age=0"));
              assertThat(cookiesT1)
                  .as("t1 logout must not touch t2's CSRF cookie")
                  .noneMatch(h -> h.contains("X-CSRF-TOKEN-physical-tenants-t2="));

              assertThat(cookiesT2)
                  .as("t2 logout must clear its own per-scope CSRF cookie")
                  .anyMatch(
                      h ->
                          h.contains("X-CSRF-TOKEN-physical-tenants-t2=")
                              && h.contains("Max-Age=0"));
              assertThat(cookiesT2)
                  .as("t2 logout must not touch t1's CSRF cookie")
                  .noneMatch(h -> h.contains("X-CSRF-TOKEN-physical-tenants-t1="));
            });
  }

  @Test
  void buildScopedWebappChainRejectsRootBasePath() {
    runner.run(
        ctx -> {
          final var http = ctx.getBean(HttpSecurity.class);
          final var builder = ctx.getBean(ScopedWebappSecurityChainBuilder.class);
          final var authentication = new AuthenticationConfiguration();
          authentication.setMethod(AuthenticationMethod.BASIC);
          final var sessionFilter =
              new SessionRepositoryFilter<>(new MapSessionRepository(new ConcurrentHashMap<>()));
          assertThatIllegalArgumentException()
              .isThrownBy(
                  () ->
                      builder.buildScopedWebappChain(
                          http,
                          "/",
                          authentication,
                          sessionFilter,
                          "session-cookie",
                          "csrf-cookie"))
              .withMessageContaining("must not be the root path");
        });
  }

  @Configuration
  static class StubUserDetailsPortConfig {

    @Bean
    io.camunda.security.core.port.out.BasicAuthUserDetailsPort basicAuthUserDetailsPort() {
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

  @Configuration
  static class StubPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder().build();
    }
  }

  /**
   * Supplies a {@link SecurityPathPort} whose {@code postLogoutRedirectPath()} returns {@code null}
   * (a contract violation) and an OIDC scoped chain that exercises the logout handler wiring, so
   * the fail-fast guard is triggered during context startup.
   */
  @Configuration
  static class NullPostLogoutPathConfig {

    @Bean
    JwtDecoder jwtDecoderNullPostLogout() {
      return token -> {
        throw new UnsupportedOperationException("stub — not called in this test");
      };
    }

    @Bean
    SecurityPathPort securityPathPort() {
      final var delegate = StubSecurityPaths.builder().build();
      return new SecurityPathPort() {
        @Override
        public Set<String> apiPaths() {
          return delegate.apiPaths();
        }

        @Override
        public Set<String> unprotectedApiPaths() {
          return delegate.unprotectedApiPaths();
        }

        @Override
        public Set<String> unprotectedPaths() {
          return delegate.unprotectedPaths();
        }

        @Override
        public Set<String> webappPaths() {
          return delegate.webappPaths();
        }

        @Override
        public Set<String> webComponentNames() {
          return delegate.webComponentNames();
        }

        @Override
        public Optional<String> postLogoutRedirectPath() {
          return null;
        }
      };
    }

    @Bean("scopedOidcNullPostLogoutChain")
    SecurityFilterChain scopedOidcNullPostLogoutChain(
        final HttpSecurity http, final ScopedWebappSecurityChainBuilder builder) throws Exception {
      final var authentication = ScopedSingleIdpConfig.buildOidcAuthentication("oidc");
      final var sessionFilter =
          new SessionRepositoryFilter<>(new MapSessionRepository(new ConcurrentHashMap<>()));
      return builder.buildScopedWebappChain(
          http,
          BASE_PATH,
          authentication,
          sessionFilter,
          "camunda-session-physical-tenants-t1",
          "X-CSRF-TOKEN-physical-tenants-t1");
    }
  }

  @Configuration
  static class ScopedSingleIdpConfig {

    @Bean
    JwtDecoder jwtDecoder() {
      return token -> {
        throw new UnsupportedOperationException("stub — not called in this test");
      };
    }

    @Bean("scopedOidcTestChain")
    SecurityFilterChain scopedOidcTestChain(
        final HttpSecurity http,
        final ScopedWebappSecurityChainBuilder builder,
        final ObjectProvider<OidcTokenEndpointCustomizer> tokenEndpointCustomizerProvider,
        final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider,
        final ObjectProvider<AdminUserCheckFilter> adminUserCheckFilterProvider)
        throws Exception {
      final var authentication = buildOidcAuthentication("oidc");
      final var sessionFilter = buildSessionFilter();
      return builder.buildScopedWebappChain(
          http,
          BASE_PATH,
          authentication,
          sessionFilter,
          "camunda-session-physical-tenants-t1",
          "X-CSRF-TOKEN-physical-tenants-t1");
    }

    private static SessionRepositoryFilter<?> buildSessionFilter() {
      return new SessionRepositoryFilter<>(new MapSessionRepository(new ConcurrentHashMap<>()));
    }

    static AuthenticationConfiguration buildOidcAuthentication(final String... registrationIds) {
      final var auth = new AuthenticationConfiguration();
      auth.setMethod(AuthenticationMethod.OIDC);
      final var providers = new OidcProvidersConfiguration();
      final var oidcMap = new LinkedHashMap<String, OidcConfiguration>();
      for (final var id : registrationIds) {
        final var oidc =
            OidcConfiguration.builder()
                .clientId("client-" + id)
                .redirectUri("{baseUrl}" + BASE_PATH + "/sso-callback")
                .authorizationUri("http://localhost/" + id + "/auth")
                .tokenUri("http://localhost/" + id + "/token")
                .jwkSetUri("http://localhost/" + id + "/jwks")
                .build();
        oidcMap.put(id, oidc);
      }
      providers.setOidc(oidcMap);
      auth.setProviders(providers);
      return auth;
    }
  }

  @Configuration
  static class ScopedMultiIdpConfig {

    @Bean
    JwtDecoder jwtDecoderMulti() {
      return token -> {
        throw new UnsupportedOperationException("stub — not called in this test");
      };
    }

    @Bean("scopedOidcMultiIdpTestChain")
    SecurityFilterChain scopedOidcMultiIdpTestChain(
        final HttpSecurity http, final ScopedWebappSecurityChainBuilder builder) throws Exception {
      final var authentication = buildOidcAuthentication("oidc", "oidc-secondary");
      final var sessionFilter =
          new SessionRepositoryFilter<>(new MapSessionRepository(new ConcurrentHashMap<>()));
      return builder.buildScopedWebappChain(
          http,
          BASE_PATH,
          authentication,
          sessionFilter,
          "camunda-session-physical-tenants-t1",
          "X-CSRF-TOKEN-physical-tenants-t1");
    }

    private static AuthenticationConfiguration buildOidcAuthentication(
        final String... registrationIds) {
      final var auth = new AuthenticationConfiguration();
      auth.setMethod(AuthenticationMethod.OIDC);
      final var providers = new OidcProvidersConfiguration();
      final var oidcMap = new LinkedHashMap<String, OidcConfiguration>();
      for (final var id : registrationIds) {
        final var oidc =
            OidcConfiguration.builder()
                .clientId("client-" + id)
                .redirectUri("{baseUrl}" + BASE_PATH + "/sso-callback")
                .authorizationUri("http://localhost/" + id + "/auth")
                .tokenUri("http://localhost/" + id + "/token")
                .jwkSetUri("http://localhost/" + id + "/jwks")
                .build();
        oidcMap.put(id, oidc);
      }
      providers.setOidc(oidcMap);
      auth.setProviders(providers);
      return auth;
    }
  }

  @Configuration
  static class StubPathsWithOidcEndpoints {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder()
          .webappPaths(
              "/operate/**", "/login", "/logout", "/sso-callback", "/oauth2/authorization/**")
          .build();
    }
  }

  @Configuration
  static class ScopedBasicConfig {

    @Bean("scopedBasicTestChain")
    SecurityFilterChain scopedBasicTestChain(
        final HttpSecurity http, final ScopedWebappSecurityChainBuilder builder) throws Exception {
      final var authentication = new AuthenticationConfiguration();
      authentication.setMethod(AuthenticationMethod.BASIC);
      final var sessionFilter =
          new SessionRepositoryFilter<>(new MapSessionRepository(new ConcurrentHashMap<>()));
      return builder.buildScopedWebappChain(
          http,
          BASE_PATH,
          authentication,
          sessionFilter,
          "camunda-session-physical-tenants-t1",
          "X-CSRF-TOKEN-physical-tenants-t1");
    }
  }

  @Configuration
  static class TwoScopedBasicChainsConfig {

    @Bean("scopedBasicChainForT1")
    SecurityFilterChain scopedBasicChainForT1(
        final HttpSecurity http, final ScopedWebappSecurityChainBuilder builder) throws Exception {
      final var authentication = new AuthenticationConfiguration();
      authentication.setMethod(AuthenticationMethod.BASIC);
      final var sessionFilter =
          new SessionRepositoryFilter<>(new MapSessionRepository(new ConcurrentHashMap<>()));
      return builder.buildScopedWebappChain(
          http,
          "/physical-tenants/t1",
          authentication,
          sessionFilter,
          "camunda-session-physical-tenants-t1",
          "X-CSRF-TOKEN-physical-tenants-t1");
    }

    @Bean("scopedBasicChainForT2")
    SecurityFilterChain scopedBasicChainForT2(
        final HttpSecurity http, final ScopedWebappSecurityChainBuilder builder) throws Exception {
      final var authentication = new AuthenticationConfiguration();
      authentication.setMethod(AuthenticationMethod.BASIC);
      final var sessionFilter =
          new SessionRepositoryFilter<>(new MapSessionRepository(new ConcurrentHashMap<>()));
      return builder.buildScopedWebappChain(
          http,
          "/physical-tenants/t2",
          authentication,
          sessionFilter,
          "camunda-session-physical-tenants-t2",
          "X-CSRF-TOKEN-physical-tenants-t2");
    }
  }
}
