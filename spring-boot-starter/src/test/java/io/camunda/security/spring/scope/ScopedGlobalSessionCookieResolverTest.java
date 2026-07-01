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
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.web.http.CookieHttpSessionIdResolver;
import org.springframework.session.web.http.HttpSessionIdResolver;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Regression test for issue #476.
 *
 * <p>When persistent web sessions are enabled, {@code @EnableSpringHttpSession} registers a global
 * {@link SessionRepositoryFilter} that runs ahead of Spring Security and previously wrote the
 * unscoped default {@code camunda-session} cookie for every request — shadowing the per-scope
 * cookies and breaking cross-scope session isolation. These tests verify that, when scoped chains
 * are present, the global filter is wired with the scope-aware {@link
 * ScopeAwareSessionCookieSerializer}; and that cluster-only deployments register no such bean.
 */
class ScopedGlobalSessionCookieResolverTest {

  private static final String BASE_A = "/physical-tenants/tenanta";
  private static final String BASE_B = "/physical-tenants/tenantb";

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
  void globalSessionFilterIsWiredWithScopeAwareSerializerWhenScopesPresent() {
    runner()
        .withUserConfiguration(TwoScopeProvider.class)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();

              // the scope-aware resolver bean is registered
              assertThat(ctx)
                  .hasBean(ScopedSecurityChainRegistrar.SCOPED_SESSION_ID_RESOLVER_BEAN_NAME);
              final var resolver =
                  ctx.getBean(
                      ScopedSecurityChainRegistrar.SCOPED_SESSION_ID_RESOLVER_BEAN_NAME,
                      HttpSessionIdResolver.class);
              assertThat(resolver).isInstanceOf(CookieHttpSessionIdResolver.class);

              // the global Spring Session filter uses exactly that resolver
              final var globalFilter = ctx.getBean(SessionRepositoryFilter.class);
              final var wiredResolver = field(globalFilter, "httpSessionIdResolver");
              assertThat(wiredResolver)
                  .as("global session filter must use the scope-aware resolver")
                  .isSameAs(resolver);

              // and that resolver's serializer is the scope-aware one
              final var serializer = field(wiredResolver, "cookieSerializer");
              assertThat(serializer).isInstanceOf(ScopeAwareSessionCookieSerializer.class);
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

  private static Object field(final Object target, final String name) {
    try {
      var type = target.getClass();
      while (type != null) {
        try {
          final var f = type.getDeclaredField(name);
          f.setAccessible(true);
          return f.get(target);
        } catch (final NoSuchFieldException ignored) {
          type = type.getSuperclass();
        }
      }
      throw new AssertionError("Field '" + name + "' not found on " + target.getClass());
    } catch (final IllegalAccessException ex) {
      throw new AssertionError("Could not read field '" + name + "'", ex);
    }
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
