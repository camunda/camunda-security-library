/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static io.camunda.security.api.model.authz.AuthorizationResourceType.PROCESS_APPLICATION;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.PROCESS_DEFINITION;
import static io.camunda.security.api.model.authz.PermissionType.READ;
import static io.camunda.security.api.model.authz.PermissionType.UPDATE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.context.ResourceAttributeExtractor;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.Condition;
import io.camunda.security.api.model.authz.Operand;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceAttribute;
import io.camunda.security.api.model.authz.RoleMembership;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.authz.ResourceAccessFilter.AnyOf;
import io.camunda.security.core.authz.ResourceAccessFilter.Term;
import io.camunda.security.core.port.out.AuthorizationCheckLatencyRecorder;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ConditionalResourceAccessProviderTest {

  private static final String EDITOR = "editor";
  private static final String VIEWER = "viewer";

  private final InMemoryAuthorizationStore store =
      new InMemoryAuthorizationStore()
          .roleGrant(EDITOR, PROCESS_APPLICATION, READ, AuthorizationScope.WILDCARD)
          .roleGrant(EDITOR, PROCESS_APPLICATION, UPDATE, AuthorizationScope.WILDCARD)
          .roleGrant(VIEWER, PROCESS_APPLICATION, READ, AuthorizationScope.WILDCARD);

  private final ResourceAttributeExtractor<Document> documentExtractor =
      new ResourceAttributeExtractor<>() {
        @Override
        public AuthorizationResourceType resourceType() {
          return PROCESS_APPLICATION;
        }

        @Override
        public Class<Document> resourceClass() {
          return Document.class;
        }

        @Override
        public Set<ResourceAttribute> providedAttributes() {
          return Set.of(ResourceAttribute.WORKSPACE);
        }

        @Override
        public Map<ResourceAttribute, Set<String>> attributesOf(final Document resource) {
          return resource.workspaceIds() == null
              ? Map.of()
              : Map.of(ResourceAttribute.WORKSPACE, resource.workspaceIds());
        }
      };

  private final ResourceAttributeExtractorRegistry registry =
      new ResourceAttributeExtractorRegistry(List.of(documentExtractor));

  private final AuthorizationService service =
      new AuthorizationService(
          new AuthorizationChecker(store),
          new PropertyAuthorizationEvaluatorRegistry(List.of()),
          new ResourceScopeExtractorRegistry(List.of()),
          registry,
          true,
          false,
          claims -> CamundaAuthentication.none(),
          AuthorizationCheckLatencyRecorder.noop());

  private final ConditionalResourceAccessProvider provider =
      new ConditionalResourceAccessProvider(new AuthorizationChecker(store), registry);

  private static RoleMembership inWorkspace(final String roleId, final String... workspaceIds) {
    return new RoleMembership(roleId, List.of(workspaceCondition(workspaceIds)));
  }

  private static Condition workspaceCondition(final String... workspaceIds) {
    return new Condition(ResourceAttribute.WORKSPACE, new Operand.Values(Set.of(workspaceIds)));
  }

  private static CamundaAuthentication aliceWith(final RoleMembership... memberships) {
    return CamundaAuthentication.of(b -> b.user("alice").roleMemberships(List.of(memberships)));
  }

  private static RequiredAuthorization<Document> onDocument(final PermissionType permission) {
    return RequiredAuthorization.of(
        b ->
            b.resourceType(PROCESS_APPLICATION)
                .permissionType(permission)
                .resourceIdSupplier(Document::id));
  }

  private static RequiredAuthorization<Document> listOf(final PermissionType permission) {
    return RequiredAuthorization.of(
        b -> b.resourceType(PROCESS_APPLICATION).permissionType(permission));
  }

  private void assertAccess(
      final CamundaAuthentication auth,
      final PermissionType permission,
      final Document document,
      final boolean expected) {
    final boolean single = service.check(auth, onDocument(permission), document).isRight();
    final boolean list =
        ListAccess.allows(
            provider.resolveResourceAccess(auth, listOf(permission)),
            document.id(),
            documentExtractor.attributesOf(document));
    final boolean perDocument =
        provider.hasResourceAccess(auth, onDocument(permission), document).allowed();

    assertThat(single).as("single check").isEqualTo(expected);
    assertThat(list).as("list filter").isEqualTo(expected);
    assertThat(perDocument).as("per-document access").isEqualTo(expected);
  }

  @Test
  void editorInOneWorkspaceAndViewerInAnotherAgreeOnSingleChecksAndListFilter() {
    final var auth = aliceWith(inWorkspace(EDITOR, "w1"), inWorkspace(VIEWER, "w2"));

    assertAccess(auth, UPDATE, new Document("pa1", Set.of("w1")), true);
    assertAccess(auth, UPDATE, new Document("pa2", Set.of("w2")), false);
    assertAccess(auth, READ, new Document("pa2", Set.of("w2")), true);
    assertAccess(auth, READ, new Document("pa3", Set.of("w3")), false);
    assertAccess(auth, READ, new Document("pa4", null), false);
  }

  @Test
  void filterHasOneTermPerConditionalMembershipWithTheRoleGrant() {
    final var auth = aliceWith(inWorkspace(EDITOR, "w1"), inWorkspace(VIEWER, "w2"));

    final var access = provider.resolveResourceAccess(auth, listOf(UPDATE));

    assertThat(access.allowed()).isTrue();
    assertThat(access.wildcard()).isFalse();
    assertThat(access.filter())
        .isEqualTo(new AnyOf(List.of(new Term(Set.of(), List.of(workspaceCondition("w1"))))));
  }

  @Test
  void filterListsATermForEveryWorkspaceOfTheSameRole() {
    final var auth = aliceWith(inWorkspace(EDITOR, "w1"), inWorkspace(EDITOR, "w2"));

    final var access = provider.resolveResourceAccess(auth, listOf(READ));

    assertThat(access.filter())
        .isEqualTo(
            new AnyOf(
                List.of(
                    new Term(Set.of(), List.of(workspaceCondition("w1"))),
                    new Term(Set.of(), List.of(workspaceCondition("w2"))))));
  }

  @Test
  void grantsOfARoleAreReadOncePerDistinctRole() {
    final var auth =
        aliceWith(inWorkspace(EDITOR, "w1"), inWorkspace(EDITOR, "w2"), inWorkspace(VIEWER, "w3"));

    provider.resolveResourceAccess(auth, listOf(READ));

    assertThat(store.scopeQueries()).isEqualTo(3);
  }

  @Test
  void membershipWithoutConditionsGrantsAccessToAll() {
    final var auth = aliceWith(new RoleMembership(VIEWER, List.of()));

    final var access = provider.resolveResourceAccess(auth, listOf(READ));

    assertThat(access.wildcard()).isTrue();
    assertThat(access.filter()).isEqualTo(new ResourceAccessFilter.All());
    assertAccess(auth, READ, new Document("pa", Set.of("w9")), true);
    assertAccess(auth, READ, new Document("pa", null), true);
  }

  @Test
  void unconditionalRoleAndDirectWildcardGrantGiveAccessToAll() {
    final var withRole = CamundaAuthentication.of(b -> b.user("alice").roleIds(List.of(EDITOR)));
    store.userGrant("bob", PROCESS_APPLICATION, READ, AuthorizationScope.WILDCARD);
    final var bob = CamundaAuthentication.of(b -> b.user("bob"));

    assertThat(provider.resolveResourceAccess(withRole, listOf(UPDATE)).wildcard()).isTrue();
    assertThat(provider.resolveResourceAccess(bob, listOf(READ)).wildcard()).isTrue();
    assertAccess(withRole, UPDATE, new Document("pa", Set.of("w2")), true);
    assertAccess(bob, READ, new Document("pa", Set.of("w2")), true);
  }

  @Test
  void idGrantsOfTheUserAndOfUnconditionalRolesAreMergedIntoOneTerm() {
    store
        .userGrant("alice", PROCESS_APPLICATION, READ, AuthorizationScope.id("pa1"))
        .roleGrant("pa2-reader", PROCESS_APPLICATION, READ, AuthorizationScope.id("pa2"));
    final var auth =
        CamundaAuthentication.of(
            b ->
                b.user("alice")
                    .roleIds(List.of("pa2-reader"))
                    .roleMemberships(List.of(new RoleMembership("pa3-reader", List.of()))));
    store.roleGrant("pa3-reader", PROCESS_APPLICATION, READ, AuthorizationScope.id("pa3"));

    final var access = provider.resolveResourceAccess(auth, listOf(READ));

    assertThat(access.filter())
        .isEqualTo(new AnyOf(List.of(new Term(Set.of("pa1", "pa2", "pa3"), List.of()))));
    assertAccess(auth, READ, new Document("pa1", Set.of("w1")), true);
    assertAccess(auth, READ, new Document("pa3", null), true);
    assertAccess(auth, READ, new Document("pa4", Set.of("w1")), false);
  }

  @Test
  void idGrantsOfAConditionalRoleAreRestrictedByTheConditions() {
    store.roleGrant("pa7-reader", PROCESS_APPLICATION, READ, AuthorizationScope.id("pa7"));
    final var auth = aliceWith(inWorkspace("pa7-reader", "w1"));

    final var access = provider.resolveResourceAccess(auth, listOf(READ));

    assertThat(access.filter())
        .isEqualTo(new AnyOf(List.of(new Term(Set.of("pa7"), List.of(workspaceCondition("w1"))))));
    assertAccess(auth, READ, new Document("pa7", Set.of("w1")), true);
    assertAccess(auth, READ, new Document("pa7", Set.of("w2")), false);
    assertAccess(auth, READ, new Document("pa8", Set.of("w1")), false);
  }

  @Test
  void directIdGrantsApplyIndependentOfTheMemberships() {
    store.userGrant("alice", PROCESS_APPLICATION, READ, AuthorizationScope.id("pa5"));
    final var auth = aliceWith(inWorkspace(VIEWER, "w1"));

    assertAccess(auth, READ, new Document("pa5", Set.of("w2")), true);
    assertAccess(auth, READ, new Document("pa6", Set.of("w2")), false);
    assertAccess(auth, READ, new Document("pa6", Set.of("w1")), true);
  }

  @Test
  void overlappingMultiValuedConditionsAgree() {
    final var auth = aliceWith(inWorkspace(EDITOR, "w1", "w2"));

    assertAccess(auth, UPDATE, new Document("pa", Set.of("w2", "w3")), true);
    assertAccess(auth, UPDATE, new Document("pa", Set.of("w3")), false);
  }

  @Test
  void accessIsDeniedWithoutAnyGrant() {
    final var access = provider.resolveResourceAccess(aliceWith(), listOf(READ));

    assertThat(access.denied()).isTrue();
    assertThat(access.filter()).isEqualTo(new ResourceAccessFilter.None());
    assertAccess(aliceWith(), READ, new Document("pa", Set.of("w1")), false);
  }

  @Test
  void accessIsDeniedWhenTheRoleOfTheMembershipLacksThePermission() {
    final var auth = aliceWith(inWorkspace(VIEWER, "w1"));

    assertThat(provider.resolveResourceAccess(auth, listOf(UPDATE)).denied()).isTrue();
    assertAccess(auth, UPDATE, new Document("pa", Set.of("w1")), false);
  }

  @Test
  void termsThatCanNeverMatchAreDropped() {
    final var noValues =
        new RoleMembership(
            EDITOR,
            List.of(new Condition(ResourceAttribute.WORKSPACE, new Operand.Values(Set.of()))));
    final var undeclaredAttribute =
        new RoleMembership(
            VIEWER,
            List.of(
                new Condition(ResourceAttribute.ASSIGNEE, new Operand.Values(Set.of("alice")))));
    final var auth = aliceWith(noValues, undeclaredAttribute);

    assertThat(provider.resolveResourceAccess(auth, listOf(READ)).denied()).isTrue();
    assertAccess(auth, READ, new Document("pa", Set.of("w1")), false);
  }

  @Test
  void conditionalMembershipsDoNotCountForTypesWithoutAttributeExtractor() {
    store.roleGrant(EDITOR, PROCESS_DEFINITION, READ, AuthorizationScope.WILDCARD);
    final var auth = aliceWith(new RoleMembership(EDITOR, List.of()));
    final RequiredAuthorization<Object> required =
        RequiredAuthorization.of(
            b ->
                b.resourceType(PROCESS_DEFINITION)
                    .permissionType(READ)
                    .resourceIdSupplier(resource -> "pd1"));

    assertThat(
            provider
                .resolveResourceAccess(
                    auth,
                    RequiredAuthorization.of(
                        b -> b.resourceType(PROCESS_DEFINITION).permissionType(READ)))
                .denied())
        .isTrue();
    assertThat(provider.hasResourceAccess(auth, required, new Object()).denied()).isTrue();
  }

  @Test
  void hasResourceAccessOfATypeWithoutExtractorDeniesPropertyRequests() {
    store.userGrant("alice", PROCESS_DEFINITION, READ, AuthorizationScope.property("propA"));
    final var auth = CamundaAuthentication.of(b -> b.user("alice"));
    final RequiredAuthorization<Object> required =
        RequiredAuthorization.of(
            b ->
                b.resourceType(PROCESS_DEFINITION)
                    .permissionType(READ)
                    .authorizedByProperty("propA"));

    assertThat(provider.hasResourceAccess(auth, required, new Object()).denied()).isTrue();
  }

  @Test
  void hasResourceAccessOfATypeWithoutExtractorEvaluatesTheIdFromTheSupplier() {
    store.userGrant("alice", PROCESS_DEFINITION, READ, AuthorizationScope.id("pd1"));
    final var auth = CamundaAuthentication.of(b -> b.user("alice"));
    final RequiredAuthorization<String> required =
        RequiredAuthorization.of(
            b ->
                b.resourceType(PROCESS_DEFINITION)
                    .permissionType(READ)
                    .resourceIdSupplier(String::toString));

    assertThat(provider.hasResourceAccess(auth, required, "pd1").allowed()).isTrue();
    assertThat(provider.hasResourceAccess(auth, required, "pd2").denied()).isTrue();
  }

  @Test
  void hasResourceAccessRequiresTheSupplierForTypesWithoutExtractor() {
    final var auth = CamundaAuthentication.of(b -> b.user("alice"));
    final RequiredAuthorization<Object> withIds =
        RequiredAuthorization.of(
            b -> b.resourceType(PROCESS_DEFINITION).permissionType(READ).resourceId("pd1"));

    assertThatThrownBy(() -> provider.hasResourceAccess(auth, withIds, new Object()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void hasResourceAccessDeniesResourcesOfAClassWithoutExtractor() {
    final var auth = aliceWith(new RoleMembership(EDITOR, List.of()));
    final RequiredAuthorization<Object> required =
        RequiredAuthorization.of(
            b ->
                b.resourceType(PROCESS_APPLICATION)
                    .permissionType(READ)
                    .resourceIdSupplier(resource -> "pa"));

    assertThat(provider.hasResourceAccess(auth, required, "not a document").denied()).isTrue();
  }

  @Test
  void hasResourceAccessByResourceIdCountsTheUnconditionalMembershipsOnly() {
    final var auth = aliceWith(new RoleMembership(EDITOR, List.of()), inWorkspace(VIEWER, "w1"));

    assertThat(provider.hasResourceAccessByResourceId(auth, listOf(UPDATE), "pa1").allowed())
        .isTrue();
    assertThat(
            provider
                .hasResourceAccessByResourceId(
                    aliceWith(inWorkspace(EDITOR, "w1")), listOf(UPDATE), "pa1")
                .denied())
        .isTrue();
  }

  @Test
  void forScopeRepositoryBuildsTheDisabledProviderWhenAuthorizationsAreDisabled() {
    assertThat(ConditionalResourceAccessProvider.forScopeRepository(store, registry, false))
        .isInstanceOf(DisabledResourceAccessProvider.class);
    assertThat(ConditionalResourceAccessProvider.forScopeRepository(store, registry, true))
        .isInstanceOf(ConditionalResourceAccessProvider.class);
  }

  @Test
  void sameRoleViaTwoMembershipsWithDifferentConditionsAgreesAcrossCheckAndList() {
    final var auth = aliceWith(inWorkspace(EDITOR, "w1"), inWorkspace(EDITOR, "w2"));

    assertAccess(auth, UPDATE, new Document("pa1", Set.of("w1")), true);
    assertAccess(auth, UPDATE, new Document("pa2", Set.of("w2")), true);
    assertAccess(auth, UPDATE, new Document("pa3", Set.of("w3")), false);
    assertAccess(auth, UPDATE, new Document("pa4", Set.of("w1", "w3")), true);
  }

  @Test
  void literalEmptyStringConditionValuesNeverMatchEmptyStringAttributes() {
    final var auth = aliceWith(inWorkspace(EDITOR, ""));

    assertThat(provider.resolveResourceAccess(auth, listOf(UPDATE)).denied()).isTrue();
    assertAccess(auth, UPDATE, new Document("pa", Set.of("")), false);
  }

  @Test
  void propertyGrantsOfATypeWithoutExtractorDoNotWidenTheList() {
    store.userGrant("alice", PROCESS_DEFINITION, READ, AuthorizationScope.property("propA"));
    final var auth = CamundaAuthentication.of(b -> b.user("alice"));
    final RequiredAuthorization<Object> required =
        RequiredAuthorization.of(
            b ->
                b.resourceType(PROCESS_DEFINITION)
                    .permissionType(READ)
                    .authorizedByProperty("propA"));
    final var singleCheck = service.check(auth, required, new Object());

    assertThat(provider.resolveResourceAccess(auth, required).denied()).isTrue();
    assertThat(singleCheck.isLeft()).isTrue();
  }

  private record Document(String id, Set<String> workspaceIds) {}
}
