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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.camunda.security.api.context.PropertyAuthorizationEvaluator;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationRejection;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.port.out.MembershipPort;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AuthorizationServiceTest {

  @Mock private AuthorizationChecker authorizationChecker;
  @Mock private PropertyAuthorizationEvaluatorRegistry propertyEvaluatorRegistry;
  @Mock private MembershipPort membershipPort;

  @SuppressWarnings("unchecked")
  @Mock
  private PropertyAuthorizationEvaluator<String> evaluator;

  @SuppressWarnings("unchecked")
  @Mock
  private PropertyAuthorizationEvaluator<String> secondEvaluator;

  private final CamundaAuthentication alice = CamundaAuthentication.of(b -> b.user("alice"));

  private AuthorizationService service(
      final boolean authorizationEnabled, final boolean multiTenancyChecksEnabled) {
    final var converter =
        new LazyTokenClaimsConverter("sub", "client_id", false, membershipPort, null);
    return new AuthorizationService(
        authorizationChecker,
        propertyEvaluatorRegistry,
        authorizationEnabled,
        multiTenancyChecksEnabled,
        converter);
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

  // --- TENANT resource type: RBAC on tenant entities, gated on authorizationEnabled (#486) ---
  // The {authz on/off} x {multi-tenancy on/off} matrix. resourceType==TENANT is RBAC on tenant
  // entities (not the membership dimension), so it is gated on authorizationEnabled regardless of
  // multi-tenancy. See ADR-0030.

  @Test
  void tenantCheckReturnsTenantRejectionWhenAuthzAndMultiTenancyEnabledAndCheckerDenies() {
    when(authorizationChecker.isAuthorized(any(), eq(alice), any())).thenReturn(false);
    final var req = RequiredAuthorization.of(b -> b.tenant().read().resourceId("t1"));
    final var result = service(true, true).check(alice, req);
    assertThat(result.isLeft()).isTrue();
    assertThat(result.leftValue()).isEqualTo(new AuthorizationRejection.Tenant("t1"));
  }

  @Test
  void tenantCheckReturnsRightWhenAuthzAndMultiTenancyEnabledAndCheckerApproves() {
    when(authorizationChecker.isAuthorized(any(), eq(alice), any())).thenReturn(true);
    final var req = RequiredAuthorization.of(b -> b.tenant().read().resourceId("t1"));
    assertThat(service(true, true).check(alice, req).isRight()).isTrue();
  }

  @Test
  void tenantCheckRunsWhenAuthzEnabledAndMultiTenancyDisabledAndCheckerDenies() {
    // Fail-open regression fix (#486): tenant management RBAC must be enforced even when
    // multi-tenancy is off. Mirrors the real caller: TENANT permission on the wildcard scope.
    when(authorizationChecker.isAuthorized(any(), eq(alice), any())).thenReturn(false);
    final var req =
        RequiredAuthorization.of(
            b -> b.tenant().permissionType(PermissionType.CREATE).resourceId("*"));
    final var result = service(true, false).check(alice, req);
    assertThat(result.isLeft()).isTrue();
    assertThat(result.leftValue()).isEqualTo(new AuthorizationRejection.Tenant("*"));
  }

  @Test
  void tenantCheckReturnsRightWhenAuthzEnabledAndMultiTenancyDisabledAndCheckerApproves() {
    when(authorizationChecker.isAuthorized(any(), eq(alice), any())).thenReturn(true);
    final var req =
        RequiredAuthorization.of(
            b -> b.tenant().permissionType(PermissionType.CREATE).resourceId("*"));
    assertThat(service(true, false).check(alice, req).isRight()).isTrue();
  }

  @Test
  void tenantCheckReturnsRightWhenAuthorizationDisabledAndMultiTenancyEnabled() {
    // Fail-closed regression fix (#486): with authorizations off there is no RBAC to enforce,
    // so a TENANT check is authorized and the checker is never consulted.
    final var req = RequiredAuthorization.of(b -> b.tenant().read().resourceId("t1"));
    assertThat(service(false, true).check(alice, req).isRight()).isTrue();
    verifyNoInteractions(authorizationChecker);
  }

  @Test
  void tenantCheckReturnsRightWhenBothFlagsDisabled() {
    final var req = RequiredAuthorization.of(b -> b.tenant().read().resourceId("t1"));
    assertThat(service(false, false).check(alice, req).isRight()).isTrue();
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
    verifyNoInteractions(authorizationChecker, propertyEvaluatorRegistry);
  }

  @Test
  void propertyCheckReturnsRightWhenAuthorizationDisabled() {
    final var req =
        RequiredAuthorization.of(b -> b.userTask().readUserTask().authorizedByAssignee());
    assertThat(service(false, true).check(alice, req, "task-1").isRight()).isTrue();
    verifyNoInteractions(authorizationChecker, propertyEvaluatorRegistry);
  }

  @Test
  void propertyCheckReturnsRightWhenNoPropertyNamesSet() {
    final var req = RequiredAuthorization.of(b -> b.userTask().readUserTask().resourceId("t1"));
    assertThat(service(true, false).check(alice, req, "task-1").isRight()).isTrue();
    verifyNoInteractions(authorizationChecker, propertyEvaluatorRegistry);
  }

  @Test
  void propertyCheckReturnsRightWhenGrantedPropertyScopeAndEvaluatorApproves() {
    when(authorizationChecker.retrieveAuthorizedPropertyScopes(eq(alice), any(), any()))
        .thenReturn(List.of(AuthorizationScope.property(RequiredAuthorization.PROP_ASSIGNEE)));
    when(evaluator.isAuthorized(alice, "task-1")).thenReturn(true);
    when(propertyEvaluatorRegistry.<String>findEvaluator(RequiredAuthorization.PROP_ASSIGNEE))
        .thenReturn(Optional.of(evaluator));
    final var req =
        RequiredAuthorization.of(b -> b.userTask().readUserTask().authorizedByAssignee());
    assertThat(service(true, false).check(alice, req, "task-1").isRight()).isTrue();
  }

  @Test
  void propertyCheckReturnsRejectionWhenGrantedScopeButEvaluatorDenies() {
    when(authorizationChecker.retrieveAuthorizedPropertyScopes(eq(alice), any(), any()))
        .thenReturn(List.of(AuthorizationScope.property(RequiredAuthorization.PROP_ASSIGNEE)));
    when(evaluator.isAuthorized(alice, "task-1")).thenReturn(false);
    when(propertyEvaluatorRegistry.<String>findEvaluator(RequiredAuthorization.PROP_ASSIGNEE))
        .thenReturn(Optional.of(evaluator));
    final var req =
        RequiredAuthorization.of(b -> b.userTask().readUserTask().authorizedByAssignee());
    final var result = service(true, false).check(alice, req, "task-1");
    assertThat(result.isLeft()).isTrue();
    assertThat(result.leftValue())
        .isEqualTo(
            new AuthorizationRejection.Property(
                USER_TASK, READ_USER_TASK, Set.of(RequiredAuthorization.PROP_ASSIGNEE)));
  }

  @Test
  void propertyCheckReturnsRejectionWhenNoStoredScopeEvenIfResourceMatches() {
    // core fix: matching the resource property must NOT authorize without a stored property grant
    when(authorizationChecker.retrieveAuthorizedPropertyScopes(eq(alice), any(), any()))
        .thenReturn(List.of());
    final var req =
        RequiredAuthorization.of(b -> b.userTask().readUserTask().authorizedByAssignee());
    final var result = service(true, false).check(alice, req, "task-1");
    assertThat(result.isLeft()).isTrue();
    assertThat(result.leftValue())
        .isEqualTo(
            new AuthorizationRejection.Property(
                USER_TASK, READ_USER_TASK, Set.of(RequiredAuthorization.PROP_ASSIGNEE)));
    verifyNoInteractions(propertyEvaluatorRegistry);
  }

  @Test
  void propertyCheckReturnsRejectionWhenGrantedPropertyHasNoEvaluator() {
    when(authorizationChecker.retrieveAuthorizedPropertyScopes(eq(alice), any(), any()))
        .thenReturn(List.of(AuthorizationScope.property(RequiredAuthorization.PROP_ASSIGNEE)));
    when(propertyEvaluatorRegistry.findEvaluator(any())).thenReturn(Optional.empty());
    final var req =
        RequiredAuthorization.of(b -> b.userTask().readUserTask().authorizedByAssignee());
    assertThat(service(true, false).check(alice, req, "task-1").isLeft()).isTrue();
  }

  @Test
  void propertyCheckAuthorizesWhenAnyDeclaredGrantedPropertyMatches() {
    // request declares assignee + candidateGroups; principal holds a matching candidateGroups grant
    when(authorizationChecker.retrieveAuthorizedPropertyScopes(eq(alice), any(), any()))
        .thenReturn(
            List.of(AuthorizationScope.property(RequiredAuthorization.PROP_CANDIDATE_GROUPS)));
    when(evaluator.isAuthorized(alice, "task-1")).thenReturn(true);
    when(propertyEvaluatorRegistry.<String>findEvaluator(
            RequiredAuthorization.PROP_CANDIDATE_GROUPS))
        .thenReturn(Optional.of(evaluator));
    final var req =
        RequiredAuthorization.of(
            b -> b.userTask().readUserTask().authorizedByAssignee().authorizedByCandidateGroups());
    assertThat(service(true, false).check(alice, req, "task-1").isRight()).isTrue();
  }

  @Test
  void propertyCheckAuthorizesWhenFirstGrantedEvaluatorDeniesButSecondApproves() {
    // covers the loop's continue-past-denial path: the first granted+declared property scope's
    // evaluator denies, the second one approves
    when(authorizationChecker.retrieveAuthorizedPropertyScopes(eq(alice), any(), any()))
        .thenReturn(
            List.of(
                AuthorizationScope.property(RequiredAuthorization.PROP_ASSIGNEE),
                AuthorizationScope.property(RequiredAuthorization.PROP_CANDIDATE_GROUPS)));
    when(evaluator.isAuthorized(alice, "task-1")).thenReturn(false);
    when(propertyEvaluatorRegistry.<String>findEvaluator(RequiredAuthorization.PROP_ASSIGNEE))
        .thenReturn(Optional.of(evaluator));
    when(secondEvaluator.isAuthorized(alice, "task-1")).thenReturn(true);
    when(propertyEvaluatorRegistry.<String>findEvaluator(
            RequiredAuthorization.PROP_CANDIDATE_GROUPS))
        .thenReturn(Optional.of(secondEvaluator));
    final var req =
        RequiredAuthorization.of(
            b -> b.userTask().readUserTask().authorizedByAssignee().authorizedByCandidateGroups());
    assertThat(service(true, false).check(alice, req, "task-1").isRight()).isTrue();
  }

  @Test
  void propertyCheckRejectionListsAllDeclaredPropertyNames() {
    when(authorizationChecker.retrieveAuthorizedPropertyScopes(eq(alice), any(), any()))
        .thenReturn(List.of());
    final var req =
        RequiredAuthorization.of(
            b -> b.userTask().readUserTask().authorizedByCandidateUsers().authorizedByAssignee());
    final var result = service(true, false).check(alice, req, "task-1");
    assertThat(result.isLeft()).isTrue();
    assertThat(result.leftValue())
        .isEqualTo(
            new AuthorizationRejection.Property(
                USER_TASK,
                READ_USER_TASK,
                Set.of(
                    RequiredAuthorization.PROP_ASSIGNEE,
                    RequiredAuthorization.PROP_CANDIDATE_USERS)));
  }

  // --- claims-map check overload ---

  @Test
  void shouldDelegateCheckToClaimsConverterAndAuthorizationChecker() {
    // given
    when(authorizationChecker.isAuthorized(any(), any(), any())).thenReturn(true);
    final var req =
        RequiredAuthorization.of(
            b -> b.processDefinition().readProcessDefinition().resourceId("p1"));
    final var claims = Map.<String, Object>of("sub", "alice");

    // when
    final var result = service(true, false).check(claims, req);

    // then
    assertThat(result.isRight()).isTrue();
  }

  @Test
  void shouldReturnLeftWhenCheckerDeniesOnClaimsMap() {
    // given
    when(authorizationChecker.isAuthorized(any(), any(), any())).thenReturn(false);
    final var req =
        RequiredAuthorization.of(
            b -> b.processDefinition().readProcessDefinition().resourceId("p1"));
    final var claims = Map.<String, Object>of("sub", "alice");

    // when
    final var result = service(true, false).check(claims, req);

    // then
    assertThat(result.isLeft()).isTrue();
    assertThat(result.leftValue())
        .isEqualTo(
            new AuthorizationRejection.Permission(
                PROCESS_DEFINITION, READ_PROCESS_DEFINITION, "p1"));
  }

  @Test
  void shouldReturnRightWhenAuthorizationDisabledOnClaimsMap() {
    final var req =
        RequiredAuthorization.of(
            b -> b.processDefinition().readProcessDefinition().resourceId("p1"));
    final var claims = Map.<String, Object>of("sub", "alice");

    assertThat(service(false, false).check(claims, req).isRight()).isTrue();
  }

  @Test
  void shouldThrowIllegalArgumentExceptionWhenClaimsMissingPrincipal() {
    // given
    final var req =
        RequiredAuthorization.of(
            b -> b.processDefinition().readProcessDefinition().resourceId("p1"));

    // when / then
    assertThatThrownBy(() -> service(true, false).check(Map.of("x", "y"), req))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Neither username claim");
  }
}
