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
import static io.camunda.security.api.model.authz.ResourceAttribute.PROJECT_ID;
import static io.camunda.security.api.model.authz.ResourceAttribute.WORKSPACE_ID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.context.ResourceAttributeExtractor;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.ConditionalMembership;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.MembershipCondition;
import io.camunda.security.api.model.authz.Operand;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceAttribute;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.authz.ResourceAccessFilter.All;
import io.camunda.security.core.authz.ResourceAccessFilter.AnyOf;
import io.camunda.security.core.authz.ResourceAccessFilter.None;
import io.camunda.security.core.authz.ResourceAccessFilter.Term;
import io.camunda.security.core.port.out.AuthorizationCheckLatencyRecorder;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * Runs the provider against an in-memory grant store, so each test states which role holds which
 * grant. The parity test compares the filter with {@link AuthorizationService}'s single check.
 */
class ConditionalResourceAccessProviderTest {

  private static final String EDITOR = "editor";
  private static final String VIEWER = "viewer";
  private static final RequiredAuthorization<Diagram> READ_DIAGRAM =
      RequiredAuthorization.<Diagram>of(
          b -> b.processDefinition().readProcessDefinition().resourceIdSupplier(Diagram::id));

  private final InMemoryGrants grants = new InMemoryGrants();

  @Test
  void deniesWithoutGrants() {
    // given
    final var alice = user(List.of(), conditional(EDITOR, workspaceIs("payments")));

    // when
    final var access = provider().resolveResourceAccess(alice, READ_DIAGRAM);

    // then
    assertThat(access.denied()).isTrue();
    assertThat(access.filter()).isEqualTo(new None());
  }

  @Test
  void allowsEverythingOnlyForAGrantOnEveryResourceThroughAGlobalRole() {
    // given
    grantEverything(EDITOR);
    final var alice = user(List.of(EDITOR));

    // when
    final var access = provider().resolveResourceAccess(alice, READ_DIAGRAM);

    // then
    assertThat(access.wildcard()).isTrue();
    assertThat(access.filter()).isEqualTo(new All());
  }

  @Test
  void limitsAGrantOnEveryResourceThroughAConditionalRoleToItsConditions() {
    // given
    grantEverything(EDITOR);
    final var alice =
        user(List.of(), conditional(EDITOR, workspaceIs("payments"), projectIs("p1")));

    // when
    final var access = provider().resolveResourceAccess(alice, READ_DIAGRAM);

    // then
    assertThat(access.allowed()).isTrue();
    assertThat(access.wildcard()).isFalse();
    assertThat(access.filter())
        .isEqualTo(
            new AnyOf(
                List.of(new Term(Set.of(), List.of(workspaceIs("payments"), projectIs("p1"))))));
  }

  @Test
  void combinesGlobalGrantsOnIdsWithConditionalGrants() {
    // given
    grants.grant(VIEWER, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.id("d9"));
    grants.grant(EDITOR, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.id("d1"));
    final var alice = user(List.of(VIEWER), conditional(EDITOR, workspaceIs("payments")));

    // when
    final var access = provider().resolveResourceAccess(alice, READ_DIAGRAM);

    // then
    assertThat(access.filter())
        .isEqualTo(
            new AnyOf(
                List.of(
                    new Term(Set.of("d9"), List.of()),
                    new Term(Set.of("d1"), List.of(workspaceIs("payments"))))));
    // the legacy fields name only what is granted without conditions
    assertThat(access.authorization().resourceIds()).containsExactly("d9");
  }

  @Test
  void dropsRequestedResourceIdsThatNoGlobalGrantCovers() {
    // given only a conditional grant, which d2 may not meet
    grantEverything(EDITOR);
    final var alice = user(List.of(), conditional(EDITOR, workspaceIs("payments")));

    // when
    final var access = provider().resolveResourceAccess(alice, READ_DIAGRAM.withResourceId("d2"));

    // then
    assertThat(access.filter())
        .isEqualTo(new AnyOf(List.of(new Term(Set.of(), List.of(workspaceIs("payments"))))));
    assertThat(access.authorization().resourceIds()).isEmpty();
  }

  @Test
  void ignoresConditionalMembershipsForAResourceTypeWithoutExtractor() {
    // given
    grants.grant(EDITOR, USER_TASK, READ_USER_TASK, AuthorizationScope.WILDCARD);
    final var alice = user(List.of(), conditional(EDITOR, workspaceIs("payments")));
    final RequiredAuthorization<Object> readTask =
        RequiredAuthorization.of(b -> b.userTask().readUserTask());

    // when
    final var access = provider().resolveResourceAccess(alice, readTask);

    // then
    assertThat(access.denied()).isTrue();
  }

  @Test
  void readsTheGrantsOfEachConditionalRoleOnce() {
    // given two memberships of the same role
    final var queries = new AtomicInteger();
    final var provider =
        new ConditionalResourceAccessProvider(
            new AuthorizationChecker(new CountingGrants(grants, queries)),
            new ResourceAttributeExtractorRegistry(List.of(diagramExtractor())));
    final var alice =
        user(
            List.of(),
            conditional(EDITOR, workspaceIs("payments")),
            conditional(EDITOR, workspaceIs("billing")));

    // when
    provider.resolveResourceAccess(alice, READ_DIAGRAM);

    // then one query for the global grants, one for the role
    assertThat(queries).hasValue(2);
  }

  @Test
  void rejectsResourcePropertyNames() {
    // given
    final RequiredAuthorization<Diagram> byProperty =
        RequiredAuthorization.<Diagram>of(
            b -> b.processDefinition().readProcessDefinition().resourcePropertyNames(Set.of("x")));
    final var alice = user(List.of(EDITOR));
    final var provider = provider();

    // when / then
    assertThatThrownBy(() -> provider.resolveResourceAccess(alice, byProperty))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> provider.hasResourceAccess(alice, byProperty, diagram("d1", "x", "y")))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> provider.hasResourceAccessByResourceId(alice, byProperty, "d1"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void checksAResourceWithTheConditionalRolesWhoseConditionsItMeets() {
    // given
    grantEverything(EDITOR);
    final var alice = user(List.of(), conditional(EDITOR, workspaceIs("payments")));
    final var provider = provider();

    // when / then
    assertThat(provider.hasResourceAccess(alice, READ_DIAGRAM, diagram("d1", "payments", "p1")))
        .isEqualTo(ResourceAccess.allowed(READ_DIAGRAM.withResourceIds(List.of("d1"))));
    assertThat(
            provider
                .hasResourceAccess(alice, READ_DIAGRAM, diagram("d2", "billing", "p1"))
                .denied())
        .isTrue();
    assertThat(provider.hasResourceAccess(alice, READ_DIAGRAM, diagram(null, "payments", "p1")))
        .isEqualTo(ResourceAccess.denied(READ_DIAGRAM));
  }

  @Test
  void checksAResourceByItsOnlyResourceIdWithoutSupplier() {
    // given
    grantEverything(EDITOR);
    final var alice = user(List.of(), conditional(EDITOR, workspaceIs("payments")));
    final RequiredAuthorization<Diagram> readD1 =
        RequiredAuthorization.<Diagram>of(
            b -> b.processDefinition().readProcessDefinition().resourceId("d1"));
    final RequiredAuthorization<Diagram> readTwo =
        RequiredAuthorization.<Diagram>of(
            b -> b.processDefinition().readProcessDefinition().resourceIds(List.of("d1", "d2")));
    final var provider = provider();

    // when / then
    assertThat(provider.hasResourceAccess(alice, readD1, diagram("d1", "payments", null)).allowed())
        .isTrue();
    assertThatThrownBy(
            () -> provider.hasResourceAccess(alice, readTwo, diagram("d1", "payments", null)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void checksTheRequestedResourceIdBeforeTheSupplierAsTheSingleCheckDoes() {
    // given a grant on d1 only, and a requirement for d2 on the diagram d1
    grants.grant(VIEWER, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.id("d1"));
    final var alice = user(List.of(VIEWER));
    final var d1 = diagram("d1", "payments", null);
    final var readD2 = READ_DIAGRAM.withResourceId("d2");
    final var readTwo = READ_DIAGRAM.withResourceIds(List.of("d1", "d2"));
    final var provider = provider();

    // when / then
    assertThat(provider.hasResourceAccess(alice, readD2, d1).denied()).isTrue();
    assertThat(service().check(alice, readD2, d1).isLeft()).isTrue();
    assertThatThrownBy(() -> provider.hasResourceAccess(alice, readTwo, d1))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void checksAResourceIdWithGlobalRolesOnly() {
    // given
    grantEverything(EDITOR);
    final var provider = provider();

    // when / then
    assertThat(
            provider
                .hasResourceAccessByResourceId(
                    user(List.of(), conditional(EDITOR, workspaceIs("payments"))),
                    READ_DIAGRAM,
                    "d1")
                .denied())
        .isTrue();
    assertThat(
            provider
                .hasResourceAccessByResourceId(user(List.of(EDITOR)), READ_DIAGRAM, "d1")
                .allowed())
        .isTrue();
  }

  @Test
  void listFilteredByTheResultHasTheResourcesThatTheSingleCheckAllows() {
    // given grants on every resource, on IDs, through global and conditional roles
    grants.grant(VIEWER, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.id("d7"));
    grantEverything(EDITOR);
    grants.grant(
        "reviewer", PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.id("d2"));
    grants.grant(
        "reviewer", PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.id("d5"));
    final var principals =
        List.of(
            user(List.of()),
            user(List.of(VIEWER)),
            user(List.of(EDITOR)),
            user(List.of(), conditional(EDITOR, workspaceIs("payments"))),
            user(List.of(), conditional(EDITOR, workspaceIs("payments"), projectIs("p1"))),
            user(
                List.of(VIEWER),
                conditional(EDITOR, projectIs("p2")),
                conditional("reviewer", workspaceIs("billing"))),
            user(List.of(), conditional("reviewer", workspaceIs("payments"))));
    final var diagrams = new ArrayList<Diagram>();
    var id = 0;
    for (final String workspace : new String[] {"payments", "billing", null}) {
      for (final String project : new String[] {"p1", "p2", null}) {
        diagrams.add(diagram("d" + id++, workspace, project));
      }
    }
    final var provider = provider();
    final var service = service();
    final var extractor = diagramExtractor();

    for (final var principal : principals) {
      // when
      final var filter = provider.resolveResourceAccess(principal, READ_DIAGRAM).filter();

      // then
      for (final var diagram : diagrams) {
        assertThat(filter.matches(diagram.id(), extractor.attributesOf(diagram)))
            .as("%s on %s", principal.conditionalRoleMemberships(), diagram)
            .isEqualTo(service.check(principal, READ_DIAGRAM, diagram).isRight());
      }
    }
  }

  // --- fixtures ---

  private void grantEverything(final String roleId) {
    grants.grant(roleId, PROCESS_DEFINITION, READ_PROCESS_DEFINITION, AuthorizationScope.WILDCARD);
  }

  private ConditionalResourceAccessProvider provider() {
    return new ConditionalResourceAccessProvider(
        new AuthorizationChecker(grants),
        new ResourceAttributeExtractorRegistry(List.of(diagramExtractor())));
  }

  private AuthorizationService service() {
    return new AuthorizationService(
        new AuthorizationChecker(grants),
        new PropertyAuthorizationEvaluatorRegistry(List.of()),
        new ResourceAttributeExtractorRegistry(List.of(diagramExtractor())),
        true,
        false,
        claims -> CamundaAuthentication.none(),
        AuthorizationCheckLatencyRecorder.noop());
  }

  private static CamundaAuthentication user(
      final List<String> roleIds, final ConditionalMembership... memberships) {
    return CamundaAuthentication.of(
        b -> b.user("alice").roleIds(roleIds).conditionalRoleMemberships(List.of(memberships)));
  }

  private static ConditionalMembership conditional(
      final String roleId, final MembershipCondition... conditions) {
    return new ConditionalMembership(roleId, List.of(conditions));
  }

  private static MembershipCondition workspaceIs(final String workspace) {
    return new MembershipCondition(WORKSPACE_ID, new Operand.Equals(workspace));
  }

  private static MembershipCondition projectIs(final String project) {
    return new MembershipCondition(PROJECT_ID, new Operand.Equals(project));
  }

  private static Diagram diagram(final String id, final String workspace, final String project) {
    return new Diagram(id, workspace, project);
  }

  private static ResourceAttributeExtractor<Diagram> diagramExtractor() {
    return new ResourceAttributeExtractor<>() {
      @Override
      public AuthorizationResourceType resourceType() {
        return PROCESS_DEFINITION;
      }

      @Override
      public Class<Diagram> resourceClass() {
        return Diagram.class;
      }

      @Override
      public Map<ResourceAttribute, Set<String>> attributesOf(final Diagram diagram) {
        final var attributes = new EnumMap<ResourceAttribute, Set<String>>(ResourceAttribute.class);
        if (diagram.workspace() != null) {
          attributes.put(WORKSPACE_ID, Set.of(diagram.workspace()));
        }
        if (diagram.project() != null) {
          attributes.put(PROJECT_ID, Set.of(diagram.project()));
        }
        return attributes;
      }
    };
  }

  /** Counts the queries for scopes on {@link InMemoryGrants}. */
  private record CountingGrants(InMemoryGrants delegate, AtomicInteger queries)
      implements AuthorizationScopeRepositoryPort {

    @Override
    public List<AuthorizationScope> findAuthorizedScopes(
        final Map<EntityType, Set<String>> ownerIds,
        final AuthorizationResourceType resourceType,
        final PermissionType permissionType) {
      queries.incrementAndGet();
      return delegate.findAuthorizedScopes(ownerIds, resourceType, permissionType);
    }

    @Override
    public boolean hasAuthorizedScope(
        final Map<EntityType, Set<String>> ownerIds,
        final AuthorizationResourceType resourceType,
        final PermissionType permissionType,
        final List<String> resourceIds) {
      return delegate.hasAuthorizedScope(ownerIds, resourceType, permissionType, resourceIds);
    }

    @Override
    public Set<PermissionType> findPermissionTypes(
        final Map<EntityType, Set<String>> ownerIds,
        final AuthorizationResourceType resourceType,
        final List<String> resourceIds) {
      return delegate.findPermissionTypes(ownerIds, resourceType, resourceIds);
    }
  }

  private record Diagram(String id, String workspace, String project) {}
}
