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
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.core.port.out.SessionStorePort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.BasicAuthApiSecurityConfiguration;
import io.camunda.security.spring.session.WebSessionConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import io.camunda.security.spring.user.UserConfiguration;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.session.web.http.CookieHttpSessionIdResolver;
import org.springframework.session.web.http.HttpSessionIdResolver;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Verifies that, with persistent web sessions enabled, the global {@link SessionRepositoryFilter}
 * registered by {@code @EnableSpringHttpSession} writes per-scope session cookies rather than the
 * unscoped default — so cross-scope session isolation holds — and that cluster-only deployments
 * register no scope-aware resolver.
 */
class ScopedGlobalSessionCookieResolverTest {

  private static final String BASE_A = "/apps/alpha";
  private static final String BASE_B = "/apps/beta";
  private static final String COOKIE_B = "camunda-session-apps-beta";
  private static final String DEFAULT_COOKIE = "camunda-session";

  private WebApplicationContextRunner runner() {
    return new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class, StubUserDetailsPort.class)
        .withBean(SessionStorePort.class, NoopSessionStore::new)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                BasicAuthApiSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                UserConfiguration.class,
                WebSessionConfiguration.class,
                ScopedSecurityChainConfiguration.class))
        .withPropertyValues(
            "camunda.security.authentication.method=basic",
            "camunda.security.session.persistent.enabled=true");
  }

  @Test
  void globalSessionFilterWritesPerScopeCookieWhenScopesPresent() {
    runner()
        .withUserConfiguration(TwoScopeProvider.class)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              // given — the global Spring Session filter and a request under scope B
              final var globalFilter = ctx.getBean(SessionRepositoryFilter.class);
              final var request = new MockHttpServletRequest("GET", BASE_B + "/operate/dashboard");
              request.setContextPath("");
              final var response = new MockHttpServletResponse();
              final var downstream =
                  new HttpServlet() {
                    @Override
                    protected void doGet(
                        final HttpServletRequest req, final HttpServletResponse res) {
                      req.getSession(true); // trigger session creation → cookie write
                    }
                  };

              // when — the request passes through the global session filter
              RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
              try {
                globalFilter.doFilter(request, response, new MockFilterChain(downstream));
              } finally {
                RequestContextHolder.resetRequestAttributes();
              }

              // then — the session cookie is scope B's, not the unscoped default
              final var scopedCookie = response.getCookie(COOKIE_B);
              assertThat(scopedCookie)
                  .as("global filter must write the per-scope cookie for a scoped request")
                  .isNotNull();
              assertThat(scopedCookie.getPath()).isEqualTo(BASE_B);
              assertThat(response.getCookie(DEFAULT_COOKIE))
                  .as("global filter must NOT write the unscoped default cookie for a scoped path")
                  .isNull();
            });
  }

  @Test
  void skipsRegistrationWhenHostProvidesOwnResolver() {
    // a host that owns the resolver must not trigger a NoUniqueBeanDefinitionException
    runner()
        .withUserConfiguration(TwoScopeProvider.class, HostResolverConfig.class)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx)
                  .doesNotHaveBean(
                      ScopedSecurityChainRegistrar.SCOPED_SESSION_ID_RESOLVER_BEAN_NAME);
              // the host's resolver remains the single one wired into Spring Session
              assertThat(ctx).hasSingleBean(HttpSessionIdResolver.class);
            });
  }

  @Test
  void noScopeAwareResolverRegisteredWithoutScopes() {
    // no CamundaSecurityScopeProvider → cluster-only deployment is unchanged
    runner()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx)
                  .doesNotHaveBean(
                      ScopedSecurityChainRegistrar.SCOPED_SESSION_ID_RESOLVER_BEAN_NAME);
            });
  }

  @Configuration
  static class TwoScopeProvider {

    @Bean
    CamundaSecurityScopeProvider twoBasicScopedDescriptors() {
      return () -> List.of(basicDescriptor(BASE_A), basicDescriptor(BASE_B));
    }

    private static ScopedSecurityDescriptor basicDescriptor(final String basePath) {
      final var auth = new AuthenticationConfiguration();
      auth.setMethod(AuthenticationMethod.BASIC);
      return new ScopedSecurityDescriptor(basePath, auth);
    }
  }

  @Configuration
  static class HostResolverConfig {

    @Bean
    HttpSessionIdResolver hostHttpSessionIdResolver() {
      return new CookieHttpSessionIdResolver();
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

  static final class NoopSessionStore implements SessionStorePort {
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
}
