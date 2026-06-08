/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.auth;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.auth.AuthorizationChecker;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

class AuthorizationCheckerConfigurationTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(AuthorizationCheckerConfiguration.class));

  @Test
  void beanIsRegisteredWhenPortIsPresent() {
    runner
        .withBean(AuthorizationScopeRepositoryPort.class, NoopPort::new)
        .run(ctx -> assertThat(ctx).hasSingleBean(AuthorizationChecker.class));
  }

  @Test
  void beanIsAbsentWhenPortIsMissing() {
    runner.run(ctx -> assertThat(ctx).doesNotHaveBean(AuthorizationChecker.class));
  }

  @Test
  void hostCanOverrideAuthorizationChecker() {
    runner
        .withBean(AuthorizationScopeRepositoryPort.class, NoopPort::new)
        .withUserConfiguration(HostCheckerConfiguration.class)
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(AuthorizationChecker.class)
                    .getBean(AuthorizationChecker.class)
                    .isSameAs(HostCheckerConfiguration.INSTANCE));
  }

  private static final class NoopPort implements AuthorizationScopeRepositoryPort {
    @Override
    public List<AuthorizationScope> findAuthorizedScopes(
        final Map<EntityType, Set<String>> ownerIds,
        final AuthorizationResourceType resourceType,
        final PermissionType permissionType) {
      return List.of();
    }

    @Override
    public boolean hasAuthorizedScope(
        final Map<EntityType, Set<String>> ownerIds,
        final AuthorizationResourceType resourceType,
        final PermissionType permissionType,
        final List<String> resourceIds) {
      return false;
    }

    @Override
    public Set<PermissionType> findPermissionTypes(
        final Map<EntityType, Set<String>> ownerIds,
        final AuthorizationResourceType resourceType,
        final List<String> resourceIds) {
      return Set.of();
    }
  }

  @Configuration
  static class HostCheckerConfiguration {
    static final AuthorizationChecker INSTANCE = new AuthorizationChecker(new NoopPort());

    @Bean
    AuthorizationChecker authorizationChecker() {
      return INSTANCE;
    }
  }
}
