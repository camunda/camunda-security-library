/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static io.camunda.security.api.model.authz.AuthorizationResourceType.PROCESS_DEFINITION;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.TENANT;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.USER_TASK;
import static io.camunda.security.api.model.authz.PermissionType.READ_PROCESS_DEFINITION;
import static io.camunda.security.api.model.authz.PermissionType.READ_USER_TASK;
import static io.camunda.security.api.model.authz.ResourceAttribute.PROJECT_ID;
import static io.camunda.security.api.model.authz.ResourceAttribute.WORKSPACE_ID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.context.PropertyAuthorizationEvaluator;
import io.camunda.security.api.context.ResourceAttributeExtractor;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationRejection;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.ConditionalMembership;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.MembershipCondition;
import io.camunda.security.api.model.authz.Operand;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceAttribute;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.port.out.AuthorizationCheckLatencyRecorder;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/**
 * Conditional role memberships in single checks (ADR-0041). Runs a real {@link
 * AuthorizationChecker} against an in-memory grant store, so each test states which role holds
 * which grant and asserts only the outcome of the check.
 */
class AuthorizationServiceConditionalRoleTest {

  private static final String EDITOR = "editor";
  private static final String PAYMENTS = "payments";

  private final InMemoryGrants grants = new InMemoryGrants();
  private final RequiredAuthorization<Diagram> readDiagram =
      RequiredAuthorization.<Diagram>of(
          b -> b.processDefinition().readProcessDefinition().resourceIdSupplier(Diagram::id));

  @Test
  void conditionalMembershipCountsWhenTheResourceMeetsAllConditions() {
    // given
    grants.grant(EDITOR, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.WILDCARD);
    final var alice =
        userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS), projectIs("p1")));

    // when
    final var result =
        service(diagramExtractor()).check(alice, readDiagram, diagram("d1", PAYMENTS, "p1"));

    // then
    assertThat(result.isRight()).isTrue();
  }

  @Test
  void conditionalMembershipDoesNotCountWhenOneConditionIsNotMet() {
    // given
    grants.grant(EDITOR, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.WILDCARD);
    final var alice =
        userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS), projectIs("p1")));

    // when
    final var result =
        service(diagramExtractor()).check(alice, readDiagram, diagram("d1", PAYMENTS, "p2"));

    // then
    assertThat(result.leftValue())
        .isEqualTo(
            new AuthorizationRejection.Permission(
                PROCESS_DEFINITION, READ_PROCESS_DEFINITION, "d1"));
  }

  @Test
  void conditionalMembershipDoesNotCountWhenTheResourceHasNoValueForTheAttribute() {
    // given
    grants.grant(EDITOR, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.WILDCARD);
    final var alice = userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS)));

    // when
    final var result =
        service(diagramExtractor()).check(alice, readDiagram, diagram("d1", null, "p1"));

    // then
    assertThat(result.isLeft()).isTrue();
  }

  @Test
  void conditionMatchesWhenTheResourceHasTheValueAmongOthers() {
    // given
    grants.grant(EDITOR, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.WILDCARD);
    final var alice = userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS)));
    final var extractor =
        extractor(
            PROCESS_DEFINITION,
            Diagram.class,
            diagram -> Map.of(WORKSPACE_ID, Set.of("billing", PAYMENTS)));

    // when
    final var result = service(extractor).check(alice, readDiagram, diagram("d1", null, null));

    // then
    assertThat(result.isRight()).isTrue();
  }

  @Test
  void equalsOperandTreatsTheWildcardCharacterLiterally() {
    // given
    grants.grant(EDITOR, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.WILDCARD);
    final var wildcardCondition = userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, "*")));
    final var paymentsCondition =
        userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS)));
    final var service = service(diagramExtractor());

    // when / then: "*" in the condition does not match every value
    assertThat(
            service.check(wildcardCondition, readDiagram, diagram("d1", PAYMENTS, null)).isLeft())
        .isTrue();
    // "*" on the resource does not match every condition
    assertThat(service.check(paymentsCondition, readDiagram, diagram("d1", "*", null)).isLeft())
        .isTrue();
    // "*" matches "*"
    assertThat(service.check(wildcardCondition, readDiagram, diagram("d1", "*", null)).isRight())
        .isTrue();
  }

  @Test
  void conditionalMembershipCountsOnlyForTheGrantsOfItsRole() {
    // given the role of the membership has no grant for this permission
    grants.grant(EDITOR, PROCESS_DEFINITION, PermissionType.READ, AuthorizationScope.WILDCARD);
    final var alice = userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS)));

    // when
    final var result =
        service(diagramExtractor()).check(alice, readDiagram, diagram("d1", PAYMENTS, null));

    // then
    assertThat(result.isLeft()).isTrue();
  }

  @Test
  void conditionalMembershipCountsForAGrantOnTheResourceId() {
    // given
    grants.grant(EDITOR, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.id("d1"));
    final var alice = userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS)));
    final var service = service(diagramExtractor());

    // when / then
    assertThat(service.check(alice, readDiagram, diagram("d1", PAYMENTS, null)).isRight()).isTrue();
    assertThat(service.check(alice, readDiagram, diagram("d2", PAYMENTS, null)).isLeft()).isTrue();
  }

  @Test
  void conditionalMembershipCountsForASingleExplicitResourceId() {
    // given
    grants.grant(EDITOR, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.WILDCARD);
    final var alice = userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS)));
    final RequiredAuthorization<Diagram> readD1 =
        RequiredAuthorization.<Diagram>of(
            b -> b.processDefinition().readProcessDefinition().resourceId("d1"));

    // when
    final var result =
        service(diagramExtractor()).check(alice, readD1, diagram("d1", PAYMENTS, null));

    // then
    assertThat(result.isRight()).isTrue();
  }

  @Test
  void conditionalMembershipDoesNotCountForTheIdsOfAMultiIdCheck() {
    // given a membership that applies to the resource, and a check that also names another ID
    grants.grant(EDITOR, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.WILDCARD);
    final var alice = userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS)));
    final RequiredAuthorization<Diagram> readD1AndD2 =
        RequiredAuthorization.<Diagram>of(
            b -> b.processDefinition().readProcessDefinition().resourceIds(List.of("d1", "d2")));

    // when
    final var result =
        service(diagramExtractor()).check(alice, readD1AndD2, diagram("d1", PAYMENTS, null));

    // then
    assertThat(result.leftValue())
        .isEqualTo(
            new AuthorizationRejection.Permission(
                PROCESS_DEFINITION, READ_PROCESS_DEFINITION, "d1"));
  }

  @Test
  void deniedTenantCheckGivesTheTenantRejection() {
    // given a TENANT extractor and a membership whose condition the resource does not meet
    grants.grant(EDITOR, TENANT, PermissionType.READ, AuthorizationScope.WILDCARD);
    final var alice = userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS)));
    final RequiredAuthorization<Diagram> readTenant =
        RequiredAuthorization.<Diagram>of(b -> b.tenant().read().resourceIdSupplier(Diagram::id));
    final var tenantExtractor =
        extractor(
            TENANT, Diagram.class, diagram -> Map.of(WORKSPACE_ID, Set.of(diagram.workspace())));

    // when
    final var result =
        service(tenantExtractor).check(alice, readTenant, diagram("t1", "billing", null));

    // then
    assertThat(result.leftValue()).isEqualTo(new AuthorizationRejection.Tenant("t1"));
  }

  @Test
  void conditionalMembershipCountsForAPropertyGrant() {
    // given
    grants.grant(EDITOR, USER_TASK, READ_USER_TASK, AuthorizationScope.property("assignee"));
    final var alice = userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS)));
    final RequiredAuthorization<Task> readTask =
        RequiredAuthorization.<Task>of(b -> b.userTask().readUserTask().authorizedByAssignee());
    final var service =
        service(
            List.of(
                extractor(
                    USER_TASK, Task.class, task -> Map.of(WORKSPACE_ID, Set.of(task.workspace())))),
            List.of(assigneeEvaluator()));

    // when / then
    assertThat(service.check(alice, readTask, new Task(PAYMENTS, "alice")).isRight()).isTrue();
    assertThat(service.check(alice, readTask, new Task("billing", "alice")).leftValue())
        .isEqualTo(
            new AuthorizationRejection.Property(USER_TASK, READ_USER_TASK, Set.of("assignee")));
  }

  @Test
  void globalRoleMembershipCountsAsBefore() {
    // given
    grants.grant(EDITOR, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.WILDCARD);
    final var alice = CamundaAuthentication.of(b -> b.user("alice").roleIds(List.of(EDITOR)));

    // when
    final var result =
        service(diagramExtractor()).check(alice, readDiagram, diagram("d1", "billing", null));

    // then
    assertThat(result.isRight()).isTrue();
  }

  @Test
  void globalRoleMembershipStillCountsWhenTheExtractorThrows() {
    // given
    grants.grant(EDITOR, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.WILDCARD);
    final var alice =
        CamundaAuthentication.of(
            b ->
                b.user("alice")
                    .roleIds(List.of(EDITOR))
                    .conditionalRoleMemberships(
                        List.of(conditional("other", equalsCondition(WORKSPACE_ID, PAYMENTS)))));

    // when
    final var result =
        service(throwingExtractor()).check(alice, readDiagram, diagram("d1", PAYMENTS, null));

    // then
    assertThat(result.isRight()).isTrue();
  }

  @Test
  void conditionalMembershipDoesNotCountWhenTheExtractorThrows() {
    // given
    grants.grant(EDITOR, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.WILDCARD);
    final var alice = userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS)));
    final var service = service(throwingExtractor());

    // when / then, also on a later check after the first failure was reported
    assertThat(service.check(alice, readDiagram, diagram("d1", PAYMENTS, null)).isLeft()).isTrue();
    assertThat(service.check(alice, readDiagram, diagram("d1", PAYMENTS, null)).isLeft()).isTrue();
  }

  @Test
  void conditionalMembershipDoesNotCountWhenNoExtractorAcceptsTheResourceClass() {
    // given an extractor for the resource type, but for another class
    grants.grant(EDITOR, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.WILDCARD);
    final var alice = userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS)));
    final var stringExtractor =
        extractor(
            PROCESS_DEFINITION, String.class, value -> Map.of(WORKSPACE_ID, Set.of(PAYMENTS)));

    // when
    final var result =
        service(stringExtractor).check(alice, readDiagram, diagram("d1", PAYMENTS, null));

    // then
    assertThat(result.isLeft()).isTrue();
  }

  @Test
  void conditionalMembershipDoesNotCountForAResourceTypeWithoutExtractor() {
    // given the extractor serves process definitions, and the check is on a user task
    grants.grant(EDITOR, USER_TASK, READ_USER_TASK, AuthorizationScope.property("assignee"));
    final var alice = userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS)));
    final RequiredAuthorization<Task> readTask =
        RequiredAuthorization.<Task>of(b -> b.userTask().readUserTask().authorizedByAssignee());

    // when
    final var result =
        service(List.of(diagramExtractor()), List.of(assigneeEvaluator()))
            .check(alice, readTask, new Task(PAYMENTS, "alice"));

    // then
    assertThat(result.isLeft()).isTrue();
  }

  @Test
  void extractorIsNotCalledWithoutConditionalMemberships() {
    // given
    grants.grant(EDITOR, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.WILDCARD);
    final var calls = new AtomicInteger();
    final var countingExtractor =
        extractor(
            PROCESS_DEFINITION,
            Diagram.class,
            diagram -> {
              calls.incrementAndGet();
              return Map.of();
            });
    final var alice = CamundaAuthentication.of(b -> b.user("alice").roleIds(List.of(EDITOR)));

    // when
    service(countingExtractor).check(alice, readDiagram, diagram("d1", PAYMENTS, null));

    // then
    assertThat(calls).hasValue(0);
  }

  @Test
  void checkPassesWhenAuthorizationsAreDisabled() {
    // given no grants at all
    final var alice = userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS)));

    // when
    final var result =
        service(List.of(diagramExtractor()), List.of(), false)
            .check(alice, readDiagram, diagram("d1", "billing", null));

    // then
    assertThat(result.isRight()).isTrue();
  }

  @Test
  void resourceWithoutIdIsDeniedInsteadOfRejected() {
    // given a membership that applies, and a resource for which the supplier finds no ID
    grants.grant(EDITOR, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.WILDCARD);
    final var alice = userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS)));

    // when
    final var result =
        service(diagramExtractor()).check(alice, readDiagram, diagram(null, PAYMENTS, null));

    // then
    assertThat(result.leftValue())
        .isEqualTo(
            new AuthorizationRejection.Permission(
                PROCESS_DEFINITION, READ_PROCESS_DEFINITION, null));
  }

  @Test
  void checkWithoutResourceIdOrPropertyNamesIsRejected() {
    // given
    final var alice = userWith(conditional(EDITOR, equalsCondition(WORKSPACE_ID, PAYMENTS)));
    final RequiredAuthorization<Diagram> noTarget =
        RequiredAuthorization.<Diagram>of(b -> b.processDefinition().readProcessDefinition());

    // when / then
    assertThatThrownBy(
            () -> service(diagramExtractor()).check(alice, noTarget, diagram("d1", PAYMENTS, null)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("PROCESS_DEFINITION");
  }

  // --- fixtures ---

  private static Diagram diagram(final String id, final String workspace, final String project) {
    return new Diagram(id, workspace, project);
  }

  private AuthorizationService service(final ResourceAttributeExtractor<?> extractor) {
    return service(List.of(extractor), List.of());
  }

  private AuthorizationService service(
      final List<ResourceAttributeExtractor<?>> extractors,
      final List<PropertyAuthorizationEvaluator<?>> evaluators) {
    return service(extractors, evaluators, true);
  }

  private AuthorizationService service(
      final List<ResourceAttributeExtractor<?>> extractors,
      final List<PropertyAuthorizationEvaluator<?>> evaluators,
      final boolean authorizationEnabled) {
    return new AuthorizationService(
        new AuthorizationChecker(grants),
        new PropertyAuthorizationEvaluatorRegistry(evaluators),
        new ResourceAttributeExtractorRegistry(extractors),
        authorizationEnabled,
        false,
        claims -> CamundaAuthentication.none(),
        AuthorizationCheckLatencyRecorder.noop());
  }

  private static CamundaAuthentication userWith(final ConditionalMembership membership) {
    return CamundaAuthentication.of(
        b -> b.user("alice").conditionalRoleMemberships(List.of(membership)));
  }

  private static ConditionalMembership conditional(
      final String roleId, final MembershipCondition... conditions) {
    return new ConditionalMembership(roleId, List.of(conditions));
  }

  private static MembershipCondition equalsCondition(
      final ResourceAttribute attribute, final String value) {
    return new MembershipCondition(attribute, new Operand.Equals(value));
  }

  private static MembershipCondition projectIs(final String project) {
    return equalsCondition(PROJECT_ID, project);
  }

  private static ResourceAttributeExtractor<Diagram> diagramExtractor() {
    return extractor(
        PROCESS_DEFINITION,
        Diagram.class,
        diagram -> {
          final var attributes =
              new EnumMap<ResourceAttribute, Set<String>>(ResourceAttribute.class);
          if (diagram.workspace() != null) {
            attributes.put(WORKSPACE_ID, Set.of(diagram.workspace()));
          }
          if (diagram.project() != null) {
            attributes.put(PROJECT_ID, Set.of(diagram.project()));
          }
          return attributes;
        });
  }

  private static ResourceAttributeExtractor<Diagram> throwingExtractor() {
    return extractor(
        PROCESS_DEFINITION,
        Diagram.class,
        diagram -> {
          throw new IllegalStateException("attribute store unavailable");
        });
  }

  private static <T> ResourceAttributeExtractor<T> extractor(
      final AuthorizationResourceType resourceType,
      final Class<T> resourceClass,
      final Function<T, Map<ResourceAttribute, Set<String>>> attributes) {
    return new ResourceAttributeExtractor<>() {
      @Override
      public AuthorizationResourceType resourceType() {
        return resourceType;
      }

      @Override
      public Class<T> resourceClass() {
        return resourceClass;
      }

      @Override
      public Map<ResourceAttribute, Set<String>> attributesOf(final T resource) {
        return attributes.apply(resource);
      }
    };
  }

  private static PropertyAuthorizationEvaluator<Task> assigneeEvaluator() {
    return new PropertyAuthorizationEvaluator<>() {
      @Override
      public String propertyName() {
        return "assignee";
      }

      @Override
      public boolean isAuthorized(final CamundaAuthentication authentication, final Task task) {
        return task.assignee().equals(authentication.authenticatedUsername());
      }
    };
  }

  /** Grants held by roles, matched the way an authorization store matches them. */
  private static final class InMemoryGrants implements AuthorizationScopeRepositoryPort {

    private final List<Grant> grants = new ArrayList<>();

    void grant(
        final String roleId,
        final AuthorizationResourceType resourceType,
        final PermissionType permissionType,
        final AuthorizationScope scope) {
      grants.add(new Grant(roleId, resourceType, permissionType, scope));
    }

    @Override
    public List<AuthorizationScope> findAuthorizedScopes(
        final Map<EntityType, Set<String>> ownerIds,
        final AuthorizationResourceType resourceType,
        final PermissionType permissionType) {
      return grants.stream()
          .filter(grant -> grant.heldBy(ownerIds) && grant.covers(resourceType, permissionType))
          .map(Grant::scope)
          .toList();
    }

    @Override
    public boolean hasAuthorizedScope(
        final Map<EntityType, Set<String>> ownerIds,
        final AuthorizationResourceType resourceType,
        final PermissionType permissionType,
        final List<String> resourceIds) {
      return findAuthorizedScopes(ownerIds, resourceType, permissionType).stream()
          .anyMatch(scope -> resourceIds.contains(scope.getResourceId()));
    }

    @Override
    public Set<PermissionType> findPermissionTypes(
        final Map<EntityType, Set<String>> ownerIds,
        final AuthorizationResourceType resourceType,
        final List<String> resourceIds) {
      return Set.of();
    }

    private record Grant(
        String roleId,
        AuthorizationResourceType resourceType,
        PermissionType permissionType,
        AuthorizationScope scope) {

      boolean heldBy(final Map<EntityType, Set<String>> ownerIds) {
        return ownerIds.getOrDefault(EntityType.ROLE, Set.of()).contains(roleId);
      }

      boolean covers(final AuthorizationResourceType type, final PermissionType permission) {
        return resourceType == type && permissionType == permission;
      }
    }
  }

  private record Diagram(String id, String workspace, String project) {}

  private record Task(String workspace, String assignee) {}
}
