/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.in;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.Either;
import io.camunda.security.api.model.authz.AuthorizationRejection;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.authz.RejectionAggregator;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AuthorizationCheckPortTest {

  private final CamundaAuthentication auth = CamundaAuthentication.of(b -> b.user("alice"));

  @Test
  void checkWhenAuthorizedReturnsRight() {
    final AuthorizationCheckPort port = new AlwaysRight();
    final var req =
        RequiredAuthorization.of(
            b -> b.processDefinition().readProcessDefinition().resourceId("proc-1"));
    assertThat(port.check(auth, req).isRight()).isTrue();
  }

  @Test
  void checkWhenDeniedReturnsLeftWithPermissionRejection() {
    final var rejection =
        new AuthorizationRejection.Permission(
            AuthorizationResourceType.PROCESS_DEFINITION, PermissionType.READ, "proc-1");
    final AuthorizationCheckPort port = new AlwaysLeft(rejection);
    final var req =
        RequiredAuthorization.of(
            b -> b.processDefinition().readProcessDefinition().resourceId("proc-1"));
    final var result = port.check(auth, req);
    assertThat(result.isLeft()).isTrue();
    assertThat(result.leftValue()).isEqualTo(rejection);
  }

  @Test
  void checkWhenTenantDeniedReturnsLeftWithTenantRejection() {
    final var rejection = new AuthorizationRejection.Tenant("t1");
    final AuthorizationCheckPort port = new AlwaysLeft(rejection);
    final var req =
        RequiredAuthorization.of(
            b -> b.processDefinition().readProcessDefinition().resourceId("proc-1"));
    assertThat(port.check(auth, req).leftValue()).isEqualTo(rejection);
  }

  @Test
  void checkResultsComposableWithRejectionAggregator() {
    final AuthorizationCheckPort approveAll = new AlwaysRight();
    final var req1 =
        RequiredAuthorization.of(
            b -> b.processDefinition().readProcessDefinition().resourceId("p1"));
    final var req2 =
        RequiredAuthorization.of(
            b -> b.decisionDefinition().readDecisionDefinition().resourceId("d1"));
    final var result =
        new RejectionAggregator()
            .add(approveAll.check(auth, req1))
            .add(approveAll.check(auth, req2))
            .build();
    assertThat(result.isRight()).isTrue();
  }

  private static final class AlwaysRight implements AuthorizationCheckPort {
    @Override
    public <T> Either<AuthorizationRejection, Void> check(
        final CamundaAuthentication authentication, final RequiredAuthorization<T> authorization) {
      return Either.right(null);
    }

    @Override
    public <T> Either<AuthorizationRejection, Void> check(
        final Map<String, Object> claims, final RequiredAuthorization<T> authorization) {
      return Either.right(null);
    }
  }

  private static final class AlwaysLeft implements AuthorizationCheckPort {
    private final AuthorizationRejection rejection;

    private AlwaysLeft(final AuthorizationRejection rejection) {
      this.rejection = rejection;
    }

    @Override
    public <T> Either<AuthorizationRejection, Void> check(
        final CamundaAuthentication authentication, final RequiredAuthorization<T> authorization) {
      return Either.left(rejection);
    }

    @Override
    public <T> Either<AuthorizationRejection, Void> check(
        final Map<String, Object> claims, final RequiredAuthorization<T> authorization) {
      return Either.left(rejection);
    }
  }
}
