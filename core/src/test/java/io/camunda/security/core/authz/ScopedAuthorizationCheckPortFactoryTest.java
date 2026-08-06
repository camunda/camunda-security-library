/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.camunda.security.api.context.TokenClaimsAuthenticationResolver;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ScopedAuthorizationCheckPortFactoryTest {

  @Mock private AuthorizationScopeRepositoryPort tenantAScopeRepository;
  @Mock private AuthorizationScopeRepositoryPort tenantBScopeRepository;
  @Mock private TokenClaimsAuthenticationResolver claimsResolver;

  private final CamundaAuthentication alice = CamundaAuthentication.of(b -> b.user("alice"));
  private final RequiredAuthorization<?> req =
      RequiredAuthorization.of(b -> b.processDefinition().readProcessDefinition().resourceId("p"));

  private ScopedAuthorizationCheckPortFactory.ScopedAuthorizationCheckPorts createPorts() {
    return ScopedAuthorizationCheckPortFactory.create(
        Map.of("tenant-a", tenantAScopeRepository, "tenant-b", tenantBScopeRepository),
        claimsResolver,
        List.of(),
        true,
        false);
  }

  @Test
  void shouldAssembleOneCheckPortPerScope() {
    // given
    when(tenantAScopeRepository.hasAuthorizedScope(any(), any(), any(), anyList()))
        .thenReturn(true);
    when(tenantBScopeRepository.hasAuthorizedScope(any(), any(), any(), anyList()))
        .thenReturn(false);
    final var ports = createPorts();

    // when
    final AuthorizationCheckPort tenantAPort = ports.forScope("tenant-a");
    final AuthorizationCheckPort tenantBPort = ports.forScope("tenant-b");

    // then — each scope's port consults its own repository, not the other's
    assertThat(tenantAPort.check(alice, req).isRight()).isTrue();
    assertThat(tenantBPort.check(alice, req).isLeft()).isTrue();
  }

  @Test
  void shouldFailHardOnUnknownScopeRatherThanFallingBackToAnotherScope() {
    // given
    final var ports = createPorts();

    // when / then
    assertThatIllegalStateException()
        .isThrownBy(() -> ports.forScope("unknown-tenant"))
        .withMessageContaining("unknown-tenant");
  }

  @Test
  void shouldNeverInvokeClaimsResolverDuringConstruction() {
    // when
    createPorts();

    // then — the resolver is only stored, never called, so a throwing stub is safe to pass in
    verifyNoInteractions(claimsResolver);
  }

  @Test
  void shouldShareTheGivenClaimsResolverInstanceAcrossEveryScope() {
    // given
    when(claimsResolver.resolve(any())).thenReturn(alice);
    when(tenantAScopeRepository.hasAuthorizedScope(any(), any(), any(), anyList()))
        .thenReturn(true);
    final var ports = createPorts();

    // when — reach the claims-map overload, which delegates to the shared resolver
    final var result = ports.forScope("tenant-a").check(Map.of("sub", "alice"), req);

    // then
    assertThat(result.isRight()).isTrue();
  }

  @Test
  void shouldFailFastOnNullRequiredArguments() {
    final var scopeRepositories = Map.<String, AuthorizationScopeRepositoryPort>of();
    assertThatNullPointerException()
        .isThrownBy(
            () ->
                ScopedAuthorizationCheckPortFactory.create(
                    null, claimsResolver, List.of(), true, false))
        .withMessageContaining("scopeRepositoriesByScope");
    assertThatNullPointerException()
        .isThrownBy(
            () ->
                ScopedAuthorizationCheckPortFactory.create(
                    scopeRepositories, null, List.of(), true, false))
        .withMessageContaining("claimsResolver");
    assertThatNullPointerException()
        .isThrownBy(
            () ->
                ScopedAuthorizationCheckPortFactory.create(
                    scopeRepositories, claimsResolver, null, true, false))
        .withMessageContaining("propertyEvaluators");
  }

  @Test
  void shouldNotExposeTheBackingMapDirectly() {
    // A caller must go through forScope(...) to get the fail-hard guarantee; there is no
    // public accessor on the holder that would let a caller bypass it and read a silent null.
    final var methods =
        ScopedAuthorizationCheckPortFactory.ScopedAuthorizationCheckPorts.class
            .getDeclaredMethods();
    assertThat(methods).hasSize(1);
    assertThat(methods[0].getName()).isEqualTo("forScope");
  }
}
