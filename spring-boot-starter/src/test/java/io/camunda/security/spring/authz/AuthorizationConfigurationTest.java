/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import io.camunda.security.api.context.PropertyAuthorizationEvaluator;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.authz.AuthorizationChecker;
import io.camunda.security.core.authz.AuthorizationService;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@ExtendWith(MockitoExtension.class)
class AuthorizationConfigurationTest {

  @Mock AuthorizationChecker mockChecker;
  @Mock AuthorizationCheckPort mockAuthorizationCheckPort;
  @Mock LazyTokenClaimsConverter mockConverter;

  @SuppressWarnings("unchecked")
  @Mock
  PropertyAuthorizationEvaluator<Object> mockEvaluator;

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class, AuthorizationConfiguration.class))
          .withBean(LazyTokenClaimsConverter.class, () -> mockConverter);

  @Test
  void beanIsRegisteredWhenAuthorizationCheckerIsPresent() {
    runner
        .withBean(AuthorizationChecker.class, () -> mockChecker)
        .run(ctx -> assertThat(ctx).hasSingleBean(AuthorizationService.class));
  }

  @Test
  void beanIsAbsentWhenAuthorizationCheckerIsMissing() {
    runner.run(ctx -> assertThat(ctx).doesNotHaveBean(AuthorizationService.class));
  }

  @Test
  void beanIsRegisteredWhenCheckerIsInSeparateUserConfiguration() {
    // Correct host pattern: checker in a separate @Configuration, service via AutoConfigurations.
    new ApplicationContextRunner()
        .withUserConfiguration(SeparateCheckerConfiguration.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class, AuthorizationConfiguration.class))
        .withBean(LazyTokenClaimsConverter.class, () -> mockConverter)
        .run(ctx -> assertThat(ctx).hasSingleBean(AuthorizationService.class));
  }

  @Test
  void hostCanOverrideWithCustomAuthorizationCheckPort() {
    // The more relevant override scenario: host supplies a different AuthorizationCheckPort
    // implementation. The library must not register its AuthorizationService in this case.
    runner
        .withBean(AuthorizationChecker.class, () -> mockChecker)
        .withBean(AuthorizationCheckPort.class, () -> mockAuthorizationCheckPort)
        .run(ctx -> assertThat(ctx).doesNotHaveBean(AuthorizationService.class));
  }

  @Test
  void propertyEvaluatorsAreInjected() {
    when(mockEvaluator.propertyName()).thenReturn("assignee");
    runner
        .withBean(AuthorizationChecker.class, () -> mockChecker)
        .withBean(PropertyAuthorizationEvaluator.class, () -> mockEvaluator)
        .run(ctx -> assertThat(ctx).hasSingleBean(AuthorizationService.class));
  }

  @Test
  void authorizationServiceUsesHostSuppliedAuthorizationChecker() {
    // given a host-overridden checker bean, the assembled service must delegate scope checks to it
    when(mockChecker.isAuthorized(
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any()))
        .thenReturn(true);
    runner
        .withPropertyValues("camunda.security.authorizations.enabled=true")
        .withBean(AuthorizationChecker.class, () -> mockChecker)
        .run(
            ctx -> {
              // when
              final var service = ctx.getBean(AuthorizationService.class);
              final var auth =
                  io.camunda.security.api.model.CamundaAuthentication.of(b -> b.user("alice"));
              final var req =
                  io.camunda.security.core.auth.RequiredAuthorization.of(
                      b -> b.processDefinition().readProcessDefinition().resourceId("p1"));
              final var result = service.check(auth, req);

              // then the host checker was consulted and its result honoured
              assertThat(result.isRight()).isTrue();
              org.mockito.Mockito.verify(mockChecker)
                  .isAuthorized(
                      org.mockito.ArgumentMatchers.any(),
                      org.mockito.ArgumentMatchers.eq(auth),
                      org.mockito.ArgumentMatchers.any());
            });
  }

  @Test
  void authorizationServiceUsesPropertiesFlags() {
    runner
        .withPropertyValues(
            "camunda.security.authorizations.enabled=false",
            "camunda.security.multiTenancy.checksEnabled=false")
        .withBean(AuthorizationChecker.class, () -> mockChecker)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(AuthorizationService.class);
              final var service = ctx.getBean(AuthorizationService.class);
              // Both disabled → skipChecks() must be true
              assertThat(service.skipChecks()).isTrue();
            });
  }

  @Configuration
  static class SeparateCheckerConfiguration {
    @Bean
    AuthorizationChecker separateChecker() {
      return new AuthorizationChecker(new NoopPort());
    }
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
}
