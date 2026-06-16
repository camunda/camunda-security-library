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
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.config.oidc.OidcProvidersConfiguration;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.handler.AuthFailureHandler;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
import io.camunda.security.spring.scope.OAuth2AuthorizedClientManagerFactory;
import java.util.LinkedHashMap;
import java.util.List;
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
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;

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
                  ScopedOidcInfrastructureConfiguration.class));

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
                ScopedOidcInfrastructureConfiguration.class))
        .run(
            ctx -> {
              final var chain =
                  ctx.getBean("scopedOidcMultiIdpTestChain", SecurityFilterChain.class);
              final var proxy = new FilterChainProxy(List.of(chain));
              final var request = new MockHttpServletRequest("GET", BASE_PATH + "/login");
              final var response = new MockHttpServletResponse();

              proxy.doFilter(request, response, new MockFilterChain());

              // Multi-IdP: entry point sends to picker at /physical-tenants/t1/login → 200
              assertThat(response.getStatus()).as("picker must render 200").isEqualTo(200);
              final var body = response.getContentAsString();
              assertThat(body)
                  .as("picker links must be prefixed with basePath")
                  .contains(BASE_PATH + "/oauth2/authorization/oidc")
                  .contains(BASE_PATH + "/oauth2/authorization/oidc-secondary");
            });
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
      return new SecurityPathPort() {
        @Override
        public Set<String> apiPaths() {
          return Set.of("/api/**");
        }

        @Override
        public Set<String> unprotectedApiPaths() {
          return Set.of();
        }

        @Override
        public Set<String> unprotectedPaths() {
          return Set.of("/error");
        }

        @Override
        public Set<String> webappPaths() {
          return Set.of("/operate/**", "/login", "/logout");
        }

        @Override
        public Set<String> webComponentNames() {
          return Set.of("operate");
        }
      };
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
        final CamundaSecurityLibraryProperties properties,
        final AuthFailureHandler authFailureHandler,
        final SecurityPathPort pathPort,
        final ScopedClientRegistrationFactory clientRegistrationFactory,
        final ObjectProvider<io.camunda.security.spring.oidc.OidcTokenEndpointCustomizer>
            tokenEndpointCustomizerProvider,
        final ObjectProvider<
                org.springframework.security.web.authentication.logout.LogoutSuccessHandler>
            logoutSuccessHandlerProvider,
        final ObjectProvider<
                org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService>
            oidcUserServiceProvider,
        final ObjectProvider<io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter>
            webAppAuthorizationFilterProvider,
        final ObjectProvider<io.camunda.security.spring.filter.AdminUserCheckFilter>
            adminUserCheckFilterProvider)
        throws Exception {
      final var authentication = buildOidcAuthentication("oidc");
      final var sessionFilter = buildSessionFilter();
      final OAuth2AuthorizedClientManagerFactory managerFactory =
          (repo, clientRepo) -> new DefaultOAuth2AuthorizedClientManager(repo, clientRepo);
      return new ScopedWebappSecurityChainBuilder(clientRegistrationFactory)
          .buildScopedWebappChain(
              http,
              BASE_PATH,
              authentication,
              sessionFilter,
              authFailureHandler,
              managerFactory,
              tokenEndpointCustomizerProvider,
              logoutSuccessHandlerProvider,
              oidcUserServiceProvider,
              webAppAuthorizationFilterProvider,
              adminUserCheckFilterProvider,
              properties,
              pathPort);
    }

    private static SessionRepositoryFilter<?> buildSessionFilter() {
      return new SessionRepositoryFilter<>(new MapSessionRepository(new ConcurrentHashMap<>()));
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
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
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
        final HttpSecurity http,
        final CamundaSecurityLibraryProperties properties,
        final AuthFailureHandler authFailureHandler,
        final SecurityPathPort pathPort,
        final ScopedClientRegistrationFactory clientRegistrationFactory,
        final ObjectProvider<io.camunda.security.spring.oidc.OidcTokenEndpointCustomizer>
            tokenEndpointCustomizerProvider,
        final ObjectProvider<
                org.springframework.security.web.authentication.logout.LogoutSuccessHandler>
            logoutSuccessHandlerProvider,
        final ObjectProvider<
                org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService>
            oidcUserServiceProvider,
        final ObjectProvider<io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter>
            webAppAuthorizationFilterProvider,
        final ObjectProvider<io.camunda.security.spring.filter.AdminUserCheckFilter>
            adminUserCheckFilterProvider)
        throws Exception {
      final var authentication = buildOidcAuthentication("oidc", "oidc-secondary");
      final var sessionFilter =
          new SessionRepositoryFilter<>(new MapSessionRepository(new ConcurrentHashMap<>()));
      final OAuth2AuthorizedClientManagerFactory managerFactory =
          (repo, clientRepo) -> new DefaultOAuth2AuthorizedClientManager(repo, clientRepo);
      return new ScopedWebappSecurityChainBuilder(clientRegistrationFactory)
          .buildScopedWebappChain(
              http,
              BASE_PATH,
              authentication,
              sessionFilter,
              authFailureHandler,
              managerFactory,
              tokenEndpointCustomizerProvider,
              logoutSuccessHandlerProvider,
              oidcUserServiceProvider,
              webAppAuthorizationFilterProvider,
              adminUserCheckFilterProvider,
              properties,
              pathPort);
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
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
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
}
