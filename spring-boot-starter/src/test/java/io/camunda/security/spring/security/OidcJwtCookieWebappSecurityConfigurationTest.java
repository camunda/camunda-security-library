/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.ORDER_UNPROTECTED;
import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.core.port.out.MembershipQuery;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.converter.LazyTokenClaimsConverter;
import io.camunda.security.spring.filter.JwtCookieAuthenticationFilter;
import io.camunda.security.spring.spi.JwtCookieTokenPort;
import io.camunda.security.spring.spi.OidcAuthenticationEntryPoint;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import jakarta.servlet.http.Cookie;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

class OidcJwtCookieWebappSecurityConfigurationTest {

  // Base runner without a SecurityPathPort — each test adds its own to avoid duplicate bean
  // conflicts when different tests need different path configurations.
  // TestWebSecurityBase provides @EnableWebSecurity and the unprotected-paths chain without the
  // deny-all /**  catch-all chain, so OidcJwtCookieWebappSecurityConfiguration's /** chain is
  // the sole catch-all and Spring Security's duplicate-matcher validator does not reject it.
  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withUserConfiguration(StubFilter.class, StubEntryPoint.class, TestWebSecurityBase.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  OidcJwtCookieWebappSecurityConfiguration.class));

  @Test
  void chainBeanIsPresent() {
    runner
        .withUserConfiguration(DefaultPaths.class)
        .run(ctx -> assertThat(ctx).hasBean("oidcJwtCookieWebappSecurityFilterChain"));
  }

  @Test
  void jwtCookieFilterIsWiredInChain() {
    // addFilterBefore(jwtCookieAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
    // registers the filter; form-login is disabled so UsernamePasswordAuthenticationFilter itself
    // is not in the chain, but the JWT cookie filter must still be wired in.
    runner
        .withUserConfiguration(DefaultPaths.class)
        .run(
            ctx -> {
              final var chain =
                  ctx.getBean("oidcJwtCookieWebappSecurityFilterChain", SecurityFilterChain.class);
              assertThat(chain.getFilters())
                  .as("JwtCookieAuthenticationFilter must be present in the chain")
                  .anyMatch(JwtCookieAuthenticationFilter.class::isInstance);
            });
  }

  @Test
  void statelessPolicyDoesNotCreateSession() throws Exception {
    // With STATELESS, Spring Security 7 uses NullSecurityContextRepository — it never saves or
    // reads the SecurityContext from an HttpSession, so no session should be created.
    runner
        .withUserConfiguration(DefaultPaths.class)
        .run(
            ctx -> {
              final var chain =
                  ctx.getBean("oidcJwtCookieWebappSecurityFilterChain", SecurityFilterChain.class);
              final var proxy = new FilterChainProxy(List.of(chain));

              final var request = new MockHttpServletRequest("GET", "/any-path");
              request.setCookies(
                  new Cookie(JwtCookieAuthenticationFilter.DEFAULT_COOKIE_NAME, "stub-token"));
              final var response = new MockHttpServletResponse();
              proxy.doFilter(request, response, new MockFilterChain());

              assertThat(request.getSession(false))
                  .as("STATELESS policy: no HttpSession must be created during the request")
                  .isNull();
            });
  }

  @Test
  void unprotectedPathsBypassAuthentication() throws Exception {
    // Paths returned by unprotectedPaths() are claimed by BaseSecurityConfiguration's
    // ORDER_UNPROTECTED chain (Order 0), which carries no authentication filters. A request
    // to such a path must therefore not require authentication (response is not 401).
    runner
        .withUserConfiguration(PathsWithUnprotected.class)
        .run(
            ctx -> {
              final var chains =
                  ctx.getBeansOfType(SecurityFilterChain.class).values().stream().toList();
              final var proxy = new FilterChainProxy(chains);

              final var request = new MockHttpServletRequest("GET", "/actuator");
              final var response = new MockHttpServletResponse();
              proxy.doFilter(request, response, new MockFilterChain());

              assertThat(response.getStatus())
                  .as("path in unprotectedPaths() must not require authentication")
                  .isNotEqualTo(401);
            });
  }

  @Test
  void unprotectedApiPathsArePermittedWhenAuthenticated() throws Exception {
    // Paths returned by unprotectedApiPaths() are configured as permitAll() in the cookie
    // chain's authorizeHttpRequests. An authenticated request (valid cookie present) to such a
    // path must be allowed (404 — no handler — not 401/403).
    runner
        .withUserConfiguration(PathsWithUnprotectedApi.class)
        .run(
            ctx -> {
              final var chain =
                  ctx.getBean("oidcJwtCookieWebappSecurityFilterChain", SecurityFilterChain.class);
              final var proxy = new FilterChainProxy(List.of(chain));

              final var request = new MockHttpServletRequest("GET", "/v2/status");
              request.setCookies(
                  new Cookie(JwtCookieAuthenticationFilter.DEFAULT_COOKIE_NAME, "stub-token"));
              final var response = new MockHttpServletResponse();
              proxy.doFilter(request, response, new MockFilterChain());

              assertThat(response.getStatus())
                  .as("authenticated request to path in unprotectedApiPaths() must not be denied")
                  .isNotIn(401, 403);
            });
  }

  @Test
  void hostChainSuppressesLibraryDefault() {
    // @ConditionalOnMissingBean(name = "oidcJwtCookieWebappSecurityFilterChain"): when the host
    // registers a bean with that name, the library must not create a second one. The custom chain
    // has no JwtCookieAuthenticationFilter — if the library default were created instead, that
    // assertion would fail.
    runner
        .withUserConfiguration(DefaultPaths.class, CustomChainConfig.class)
        .run(
            ctx -> {
              assertThat(ctx).hasBean("oidcJwtCookieWebappSecurityFilterChain");
              final var chain =
                  ctx.getBean("oidcJwtCookieWebappSecurityFilterChain", SecurityFilterChain.class);
              assertThat(chain.getFilters())
                  .as(
                      "host-supplied chain must take precedence; library default would include"
                          + " JwtCookieAuthenticationFilter")
                  .noneMatch(JwtCookieAuthenticationFilter.class::isInstance);
            });
  }

  // ---- stub configurations ----

  /** Provides @EnableWebSecurity and the unprotected-paths chain; no deny-all /** catch-all. */
  @Configuration
  @EnableWebSecurity
  static class TestWebSecurityBase {

    @Bean
    @Order(ORDER_UNPROTECTED)
    SecurityFilterChain unprotectedPathsSecurityFilterChain(
        final HttpSecurity http, final SecurityPathPort pathPort) throws Exception {
      return http.securityMatcher(pathPort.unprotectedPaths().toArray(String[]::new))
          .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
          .csrf(AbstractHttpConfigurer::disable)
          .cors(AbstractHttpConfigurer::disable)
          .formLogin(AbstractHttpConfigurer::disable)
          .anonymous(AbstractHttpConfigurer::disable)
          .build();
    }
  }

  @Configuration
  static class DefaultPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder().build();
    }
  }

  @Configuration
  static class PathsWithUnprotected {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder().unprotectedPaths("/actuator").build();
    }
  }

  @Configuration
  static class PathsWithUnprotectedApi {

    @Bean
    SecurityPathPort securityPathPort() {
      return new SecurityPathPort() {
        @Override
        public Set<String> apiPaths() {
          return Set.of("/v2/**");
        }

        @Override
        public Set<String> unprotectedApiPaths() {
          return Set.of("/v2/status");
        }

        @Override
        public Set<String> unprotectedPaths() {
          return Set.of("/error");
        }

        @Override
        public Set<String> webappPaths() {
          return Set.of("/operate/**");
        }

        @Override
        public Set<String> webComponentNames() {
          return Set.of("operate");
        }
      };
    }
  }

  /**
   * Stub filter. When the request carries the default cookie the token port returns minimal claims
   * so the filter authenticates the principal; when no cookie is present the real filter logic runs
   * and delegates to the injected entry point.
   */
  @Configuration
  static class StubFilter {

    @Bean
    JwtCookieAuthenticationFilter jwtCookieAuthenticationFilter(
        final OidcAuthenticationEntryPoint entryPoint) {
      final JwtCookieTokenPort tokenPort =
          new JwtCookieTokenPort() {
            @Override
            public String issue(final String userId) {
              throw new UnsupportedOperationException("stub");
            }

            @Override
            public Map<String, Object> validate(final String cookieToken) {
              return Map.of("sub", "test-user");
            }
          };
      final MembershipPort membershipPort =
          new MembershipPort() {
            @Override
            public List<String> mappingRuleIds(final MembershipQuery q) {
              return List.of();
            }

            @Override
            public List<String> groupIds(final MembershipQuery q) {
              return List.of();
            }

            @Override
            public List<String> roleIds(final MembershipQuery q) {
              return List.of();
            }

            @Override
            public List<String> tenantIds(final MembershipQuery q) {
              return List.of();
            }
          };
      final var converter = new LazyTokenClaimsConverter(new OidcConfiguration(), membershipPort);
      return new JwtCookieAuthenticationFilter(
          JwtCookieAuthenticationFilter.DEFAULT_COOKIE_NAME, tokenPort, converter, entryPoint);
    }
  }

  @Configuration
  static class StubEntryPoint {

    @Bean
    OidcAuthenticationEntryPoint oidcAuthenticationEntryPoint() {
      return (req, res, ex) -> res.setStatus(401);
    }
  }

  /** Host-supplied chain that replaces the library default to test @ConditionalOnMissingBean. */
  @Configuration
  static class CustomChainConfig {

    @Bean(name = "oidcJwtCookieWebappSecurityFilterChain")
    SecurityFilterChain customCookieChain(final HttpSecurity http) throws Exception {
      return http.securityMatcher("/**")
          .authorizeHttpRequests(auth -> auth.anyRequest().denyAll())
          .csrf(AbstractHttpConfigurer::disable)
          .build();
    }
  }
}
