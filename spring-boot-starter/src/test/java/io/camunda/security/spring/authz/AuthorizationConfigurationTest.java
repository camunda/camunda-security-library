/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import io.camunda.security.api.context.PropertyAuthorizationEvaluator;
import io.camunda.security.api.context.ResourceAttributeExtractor;
import io.camunda.security.api.context.ResourceScopeExtractor;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.Condition;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.Operand;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceAttribute;
import io.camunda.security.api.model.authz.RoleMembership;
import io.camunda.security.api.model.authz.ScopedRoleMembership;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.authz.AuthorizationChecker;
import io.camunda.security.core.authz.AuthorizationService;
import io.camunda.security.core.authz.ConditionalResourceAccessProvider;
import io.camunda.security.core.authz.DisabledResourceAccessProvider;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.authz.ResourceAccessProvider;
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import io.camunda.security.core.port.out.AuthorizationCheckLatencyRecorder;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.context.CamundaAuthenticationBeansConfiguration;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
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
import org.springframework.mock.web.MockHttpServletRequest;

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
  void scopeExtractorsAreInjectedAndScopedRoleMembershipsComeFromTheAuthentication() {
    final ResourceScopeExtractor<String> extractor =
        new ResourceScopeExtractor<>() {
          @Override
          public AuthorizationResourceType resourceType() {
            return AuthorizationResourceType.PROCESS_APPLICATION;
          }

          @Override
          public Class<String> resourceClass() {
            return String.class;
          }

          @Override
          public String scopeIdOf(final String resource) {
            return resource;
          }
        };
    when(mockChecker.isAuthorized(any(), any(), any(), eq(Set.of("editor")))).thenReturn(true);
    runner
        .withPropertyValues("camunda.security.authorizations.enabled=true")
        .withBean(AuthorizationChecker.class, () -> mockChecker)
        .withBean(ResourceScopeExtractor.class, () -> extractor)
        .run(
            ctx -> {
              final var service = ctx.getBean(AuthorizationService.class);
              final var auth =
                  CamundaAuthentication.of(
                      b ->
                          b.user("alice")
                              .scopedRoleMemberships(
                                  List.of(new ScopedRoleMembership("editor", "w1"))));
              final var req =
                  RequiredAuthorization.<String>of(
                      b ->
                          b.resourceType(AuthorizationResourceType.PROCESS_APPLICATION)
                              .permissionType(PermissionType.UPDATE)
                              .resourceIdSupplier(resource -> "pa1"));

              assertThat(service.check(auth, req, "w1").isRight()).isTrue();
              assertThat(service.check(auth, req, "w2").isLeft()).isTrue();
            });
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
  void authorizationServiceRecordsCheckLatencyWhenMeterRegistryIsPresent() {
    // given a host-supplied MeterRegistry and an authorized check
    when(mockChecker.isAuthorized(
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any()))
        .thenReturn(true);
    final var meterRegistry = new SimpleMeterRegistry();
    runner
        .withPropertyValues("camunda.security.authorizations.enabled=true")
        .withBean(AuthorizationChecker.class, () -> mockChecker)
        .withBean(MeterRegistry.class, () -> meterRegistry)
        .run(
            ctx -> {
              // when
              final var service = ctx.getBean(AuthorizationService.class);
              final var auth =
                  io.camunda.security.api.model.CamundaAuthentication.of(b -> b.user("alice"));
              final var req =
                  io.camunda.security.core.auth.RequiredAuthorization.of(
                      b -> b.processDefinition().readProcessDefinition().resourceId("p1"));
              service.check(auth, req);

              // then a Timer matching the shared spec was recorded
              final var timer =
                  meterRegistry.find(AuthorizationCheckLatencyRecorder.METRIC_NAME).timer();
              assertThat(timer).isNotNull();
              assertThat(timer.count()).isEqualTo(1);
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

  /**
   * {@code CamundaAuthenticationBeansConfiguration#lazyTokenClaimsConverter} is deliberately not
   * gated on {@code camunda.security.authentication.method=oidc}, since authorization enforcement
   * needs it regardless of authentication method. Unlike the other tests here, this one imports the
   * real bean-producing configuration class instead of stubbing {@code LazyTokenClaimsConverter},
   * to prove the cross-class wiring actually resolves.
   */
  @Test
  void authorizationServiceResolvesWithRealConverterWhenMethodIsNotOidc() {
    new ApplicationContextRunner()
        .withBean(HttpServletRequest.class, MockHttpServletRequest::new)
        .withBean(MembershipPort.class, () -> org.mockito.Mockito.mock(MembershipPort.class))
        .withBean(AuthorizationChecker.class, () -> mockChecker)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                CamundaAuthenticationBeansConfiguration.class,
                AuthorizationConfiguration.class))
        .run(ctx -> assertThat(ctx).hasSingleBean(AuthorizationService.class));
  }

  @Test
  void attributeExtractorsAreInjectedAndRoleMembershipsComeFromTheAuthentication() {
    final ResourceAttributeExtractor<String> extractor = workspaceExtractor();
    when(mockChecker.isAuthorized(any(), any(), any(), eq(Set.of("editor")))).thenReturn(true);
    runner
        .withPropertyValues("camunda.security.authorizations.enabled=true")
        .withBean(AuthorizationChecker.class, () -> mockChecker)
        .withBean(ResourceAttributeExtractor.class, () -> extractor)
        .run(
            ctx -> {
              final var service = ctx.getBean(AuthorizationService.class);
              final var auth =
                  CamundaAuthentication.of(
                      b ->
                          b.user("alice")
                              .roleMemberships(
                                  List.of(
                                      new RoleMembership(
                                          "editor",
                                          List.of(
                                              new Condition(
                                                  ResourceAttribute.WORKSPACE,
                                                  new Operand.Values(Set.of("w1"))))))));
              final var req =
                  RequiredAuthorization.<String>of(
                      b ->
                          b.resourceType(AuthorizationResourceType.PROCESS_APPLICATION)
                              .permissionType(PermissionType.UPDATE)
                              .resourceIdSupplier(resource -> "pa1"));

              assertThat(service.check(auth, req, "w1").isRight()).isTrue();
              assertThat(service.check(auth, req, "w2").isLeft()).isTrue();
            });
  }

  @Test
  void attributeExtractorRegistryRejectsDuplicateExtractors() {
    final ResourceAttributeExtractor<String> extractor = workspaceExtractor();
    runner
        .withBean(AuthorizationChecker.class, () -> mockChecker)
        .withBean("first", ResourceAttributeExtractor.class, () -> extractor)
        .withBean("second", ResourceAttributeExtractor.class, () -> extractor)
        .run(ctx -> assertThat(ctx).hasFailed());
  }

  @Test
  void conflictingScopeAndAttributeExtractorsFailTheContext() {
    final ResourceAttributeExtractor<String> attributeExtractor = workspaceExtractor();
    final ResourceScopeExtractor<String> scopeExtractor =
        new ResourceScopeExtractor<>() {
          @Override
          public AuthorizationResourceType resourceType() {
            return AuthorizationResourceType.PROCESS_APPLICATION;
          }

          @Override
          public Class<String> resourceClass() {
            return String.class;
          }

          @Override
          public String scopeIdOf(final String resource) {
            return resource;
          }
        };
    runner
        .withBean(AuthorizationChecker.class, () -> mockChecker)
        .withBean(ResourceAttributeExtractor.class, () -> attributeExtractor)
        .withBean(ResourceScopeExtractor.class, () -> scopeExtractor)
        .run(ctx -> assertThat(ctx).hasFailed());
  }

  @Test
  void resourceAccessProviderIsTheConditionalProviderWhenAuthorizationsAreEnabled() {
    runner
        .withPropertyValues("camunda.security.authorizations.enabled=true")
        .withBean(AuthorizationChecker.class, () -> mockChecker)
        .run(
            ctx ->
                assertThat(ctx.getBean(ResourceAccessProvider.class))
                    .isInstanceOf(ConditionalResourceAccessProvider.class));
  }

  @Test
  void resourceAccessProviderIsTheDisabledProviderWhenAuthorizationsAreDisabled() {
    runner
        .withPropertyValues("camunda.security.authorizations.enabled=false")
        .withBean(AuthorizationChecker.class, () -> mockChecker)
        .run(
            ctx ->
                assertThat(ctx.getBean(ResourceAccessProvider.class))
                    .isInstanceOf(DisabledResourceAccessProvider.class));
  }

  @Test
  void hostCanOverrideTheResourceAccessProvider() {
    final var hostProvider = new DisabledResourceAccessProvider();
    runner
        .withBean(AuthorizationChecker.class, () -> mockChecker)
        .withBean(ResourceAccessProvider.class, () -> hostProvider)
        .run(ctx -> assertThat(ctx.getBean(ResourceAccessProvider.class)).isSameAs(hostProvider));
  }

  @Test
  void resourceAccessProviderIsAbsentWhenAuthorizationCheckerIsMissing() {
    runner.run(ctx -> assertThat(ctx).doesNotHaveBean(ResourceAccessProvider.class));
  }

  private static ResourceAttributeExtractor<String> workspaceExtractor() {
    return new ResourceAttributeExtractor<>() {
      @Override
      public AuthorizationResourceType resourceType() {
        return AuthorizationResourceType.PROCESS_APPLICATION;
      }

      @Override
      public Class<String> resourceClass() {
        return String.class;
      }

      @Override
      public Set<ResourceAttribute> providedAttributes() {
        return Set.of(ResourceAttribute.WORKSPACE);
      }

      @Override
      public Map<ResourceAttribute, Set<String>> attributesOf(final String resource) {
        return Map.of(ResourceAttribute.WORKSPACE, Set.of(resource));
      }
    };
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
