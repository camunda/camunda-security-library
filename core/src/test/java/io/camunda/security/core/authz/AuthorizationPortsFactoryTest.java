/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.when;

import io.camunda.security.api.context.PropertyAuthorizationEvaluator;
import io.camunda.security.api.context.TokenClaimsAuthenticationResolver;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import io.camunda.security.core.port.out.MembershipPort;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AuthorizationPortsFactoryTest {

  @Mock private AuthorizationScopeRepositoryPort scopeRepository;
  @Mock private MembershipPort membershipPort;

  private final CamundaAuthentication alice = CamundaAuthentication.of(b -> b.user("alice"));

  private AuthorizationPortsFactory.AuthorizationPorts createGraph(
      final boolean authorizationEnabled) {
    return AuthorizationPortsFactory.create(
        scopeRepository,
        membershipPort,
        List.of(),
        authorizationEnabled,
        false,
        "sub",
        "client_id",
        false);
  }

  @Test
  void shouldProduceAuthorizationCheckPortThatAuthorizesWhenScopeGranted() {
    // given
    when(scopeRepository.hasAuthorizedScope(any(), any(), any(), anyList())).thenReturn(true);
    final AuthorizationCheckPort port = createGraph(true).checkPort();
    final var req =
        RequiredAuthorization.of(
            b -> b.processDefinition().readProcessDefinition().resourceId("proc-1"));

    // when
    final var result = port.check(alice, req);

    // then
    assertThat(result.isRight()).isTrue();
  }

  @Test
  void shouldProduceAuthorizationCheckPortThatRejectsWhenScopeMissing() {
    // given
    when(scopeRepository.hasAuthorizedScope(any(), any(), any(), anyList())).thenReturn(false);
    final AuthorizationCheckPort port = createGraph(true).checkPort();
    final var req =
        RequiredAuthorization.of(
            b -> b.processDefinition().readProcessDefinition().resourceId("proc-1"));

    // when
    final var result = port.check(alice, req);

    // then
    assertThat(result.isLeft()).isTrue();
  }

  @Test
  void shouldProduceAuthorizationCheckPortHonouringPropertyCheck() {
    // given
    final PropertyAuthorizationEvaluator<String> evaluator =
        new PropertyAuthorizationEvaluator<>() {
          @Override
          public String propertyName() {
            return "assignee";
          }

          @Override
          public boolean isAuthorized(final CamundaAuthentication auth, final String resource) {
            return true;
          }
        };
    when(scopeRepository.findAuthorizedPropertyScopes(any(), any(), any(), any()))
        .thenReturn(
            List.of(io.camunda.security.api.model.authz.AuthorizationScope.property("assignee")));
    final AuthorizationCheckPort port =
        AuthorizationPortsFactory.create(
                scopeRepository,
                membershipPort,
                List.of(evaluator),
                true,
                false,
                "sub",
                "client_id",
                false)
            .checkPort();
    final var req =
        RequiredAuthorization.of(
            b -> b.userTask().updateUserTask().authorizedByProperty("assignee"));

    // when
    final var result = port.check(alice, req, "alice");

    // then
    assertThat(result.isRight()).isTrue();
  }

  @Test
  void shouldSkipChecksWhenAuthorizationDisabled() {
    // given
    final AuthorizationCheckPort port = createGraph(false).checkPort();
    final var req =
        RequiredAuthorization.of(
            b -> b.processDefinition().readProcessDefinition().resourceId("proc-1"));

    // when
    final var result = port.check(alice, req);

    // then — authorized without consulting the scope repository
    assertThat(result.isRight()).isTrue();
  }

  @Test
  void shouldProduceResolverThatConvertsClaimsToUser() {
    // given
    final TokenClaimsAuthenticationResolver resolver = createGraph(true).claimsResolver();

    // when
    final CamundaAuthentication authentication = resolver.resolve(Map.of("sub", "bob"));

    // then
    assertThat(authentication.authenticatedUsername()).isEqualTo("bob");
  }

  @Test
  void shouldProduceResolverThatRejectsClaimsWithoutPrincipal() {
    // given
    final TokenClaimsAuthenticationResolver resolver = createGraph(true).claimsResolver();

    // when / then
    assertThatThrownBy(() -> resolver.resolve(Map.of("unrelated", "value")))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
