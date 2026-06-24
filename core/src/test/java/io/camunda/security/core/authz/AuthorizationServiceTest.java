/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static io.camunda.security.api.model.authz.AuthorizationResourceType.PROCESS_DEFINITION;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.USER_TASK;
import static io.camunda.security.api.model.authz.PermissionType.READ_PROCESS_DEFINITION;
import static io.camunda.security.api.model.authz.PermissionType.READ_USER_TASK;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.camunda.security.api.context.PropertyAuthorizationEvaluator;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationRejection;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.core.auth.RequiredAuthorization;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AuthorizationServiceTest {

  @Mock private AuthorizationChecker authorizationChecker;
  @Mock private PropertyAuthorizationEvaluatorRegistry propertyEvaluatorRegistry;

  @SuppressWarnings("unchecked")
  @Mock
  private PropertyAuthorizationEvaluator<String> evaluator;

  private final CamundaAuthentication alice = CamundaAuthentication.of(b -> b.user("alice"));

  private AuthorizationService service(
      final boolean authorizationEnabled, final boolean multiTenancyChecksEnabled) {
    return new AuthorizationService(
        authorizationChecker,
        propertyEvaluatorRegistry,
        authorizationEnabled,
        multiTenancyChecksEnabled);
  }

  // --- skipChecks ---

  @Test
  void skipChecksReturnsTrueWhenBothFlagsDisabled() {
    assertThat(service(false, false).skipChecks()).isTrue();
  }

  @Test
  void skipChecksReturnsFalseWhenAuthorizationEnabled() {
    assertThat(service(true, false).skipChecks()).isFalse();
  }

  @Test
  void skipChecksReturnsFalseWhenMultiTenancyEnabled() {
    assertThat(service(false, true).skipChecks()).isFalse();
  }

  // --- scope-based check ---

  @Test
  void scopeCheckReturnsRightWhenBothFlagsDisabled() {
    final var req =
        RequiredAuthorization.of(
            b -> b.processDefinition().readProcessDefinition().resourceId("p1"));
    assertThat(service(false, false).check(alice, req).isRight()).isTrue();
    verifyNoInteractions(authorizationChecker);
  }

  @Test
  void scopeCheckReturnsRightWhenCheckerApproves() {
    when(authorizationChecker.isAuthorized(any(), eq(alice), any())).thenReturn(true);
    final var req =
        RequiredAuthorization.of(
            b -> b.processDefinition().readProcessDefinition().resourceId("p1"));
    assertThat(service(true, false).check(alice, req).isRight()).isTrue();
  }

  @Test
  void scopeCheckReturnsPermissionRejectionWhenCheckerDenies() {
    when(authorizationChecker.isAuthorized(any(), eq(alice), any())).thenReturn(false);
    final var req =
        RequiredAuthorization.of(
            b -> b.processDefinition().readProcessDefinition().resourceId("p1"));
    final var result = service(true, false).check(alice, req);
    assertThat(result.isLeft()).isTrue();
    assertThat(result.leftValue())
        .isEqualTo(
            new AuthorizationRejection.Permission(
                PROCESS_DEFINITION, READ_PROCESS_DEFINITION, "p1"));
  }

  @Test
  void scopeCheckReturnsTenantRejectionForTenantResourceType() {
    when(authorizationChecker.isAuthorized(any(), eq(alice), any())).thenReturn(false);
    final var req = RequiredAuthorization.of(b -> b.tenant().read().resourceId("t1"));
    final var result = service(false, true).check(alice, req);
    assertThat(result.isLeft()).isTrue();
    assertThat(result.leftValue()).isEqualTo(new AuthorizationRejection.Tenant("t1"));
  }

  @Test
  void scopeCheckSkipsTenantCheckWhenMultiTenancyDisabled() {
    final var req = RequiredAuthorization.of(b -> b.tenant().read().resourceId("t1"));
    assertThat(service(true, false).check(alice, req).isRight()).isTrue();
    verifyNoInteractions(authorizationChecker);
  }

  @Test
  void scopeCheckSkipsPermissionCheckWhenAuthorizationDisabled() {
    final var req =
        RequiredAuthorization.of(
            b -> b.processDefinition().readProcessDefinition().resourceId("p1"));
    assertThat(service(false, true).check(alice, req).isRight()).isTrue();
    verifyNoInteractions(authorizationChecker);
  }

  @Test
  void scopeCheckReturnsRightWhenResourceIdsIsEmpty() {
    final var req = RequiredAuthorization.of(b -> b.processDefinition().readProcessDefinition());
    assertThat(service(true, false).check(alice, req).isRight()).isTrue();
    verifyNoInteractions(authorizationChecker);
  }

  @Test
  void scopeCheckReturnsFirstRejectionOnMultipleResourceIds() {
    when(authorizationChecker.isAuthorized(eq(AuthorizationScope.id("p1")), eq(alice), any()))
        .thenReturn(true);
    when(authorizationChecker.isAuthorized(eq(AuthorizationScope.id("p2")), eq(alice), any()))
        .thenReturn(false);
    final var req =
        RequiredAuthorization.of(
            b -> b.processDefinition().readProcessDefinition().resourceIds(List.of("p1", "p2")));
    final var result = service(true, false).check(alice, req);
    assertThat(result.isLeft()).isTrue();
    assertThat(result.leftValue())
        .isEqualTo(
            new AuthorizationRejection.Permission(
                PROCESS_DEFINITION, READ_PROCESS_DEFINITION, "p2"));
  }

  // --- property-based check ---

  @Test
  void propertyCheckReturnsRightWhenBothFlagsDisabled() {
    final var req =
        RequiredAuthorization.of(b -> b.userTask().readUserTask().authorizedByAssignee());
    assertThat(service(false, false).check(alice, req, "task-1").isRight()).isTrue();
    verifyNoInteractions(propertyEvaluatorRegistry);
  }

  @Test
  void propertyCheckReturnsRightWhenAuthorizationDisabled() {
    final var req =
        RequiredAuthorization.of(b -> b.userTask().readUserTask().authorizedByAssignee());
    assertThat(service(false, true).check(alice, req, "task-1").isRight()).isTrue();
    verifyNoInteractions(propertyEvaluatorRegistry);
  }

  @Test
  void propertyCheckReturnsRightWhenNoPropertyNamesSet() {
    final var req = RequiredAuthorization.of(b -> b.userTask().readUserTask().resourceId("t1"));
    assertThat(service(true, false).check(alice, req, "task-1").isRight()).isTrue();
    verifyNoInteractions(propertyEvaluatorRegistry);
  }

  @Test
  void propertyCheckDelegatesToRegistryAndReturnsRightWhenEvaluatorApproves() {
    when(evaluator.isAuthorized(alice, "task-1")).thenReturn(true);
    when(propertyEvaluatorRegistry.<String>findEvaluator(RequiredAuthorization.PROP_ASSIGNEE))
        .thenReturn(Optional.of(evaluator));
    final var req =
        RequiredAuthorization.of(b -> b.userTask().readUserTask().authorizedByAssignee());
    assertThat(service(true, false).check(alice, req, "task-1").isRight()).isTrue();
  }

  @Test
  void propertyCheckReturnsPermissionRejectionWhenEvaluatorDenies() {
    when(evaluator.isAuthorized(alice, "task-1")).thenReturn(false);
    when(propertyEvaluatorRegistry.<String>findEvaluator(RequiredAuthorization.PROP_ASSIGNEE))
        .thenReturn(Optional.of(evaluator));
    final var req =
        RequiredAuthorization.of(b -> b.userTask().readUserTask().authorizedByAssignee());
    final var result = service(true, false).check(alice, req, "task-1");
    assertThat(result.isLeft()).isTrue();
    assertThat(result.leftValue())
        .isEqualTo(
            new AuthorizationRejection.Permission(
                USER_TASK, READ_USER_TASK, RequiredAuthorization.PROP_ASSIGNEE));
  }

  @Test
  void propertyCheckReturnsRightWhenNoEvaluatorRegistered() {
    when(propertyEvaluatorRegistry.findEvaluator(any())).thenReturn(Optional.empty());
    final var req =
        RequiredAuthorization.of(b -> b.userTask().readUserTask().authorizedByAssignee());
    assertThat(service(true, false).check(alice, req, "task-1").isRight()).isTrue();
  }
}
