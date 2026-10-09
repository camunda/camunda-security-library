/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static io.camunda.security.api.model.authz.AuthorizationResourceType.PROCESS_APPLICATION;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.WORKSPACE;
import static io.camunda.security.api.model.authz.PermissionType.READ;
import static io.camunda.security.api.model.authz.PermissionType.UPDATE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.context.ResourceAttributeExtractor;
import io.camunda.security.api.context.ResourceScopeExtractor;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationRejection;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.Condition;
import io.camunda.security.api.model.authz.Operand;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceAttribute;
import io.camunda.security.api.model.authz.RoleMembership;
import io.camunda.security.api.model.authz.ScopedRoleMembership;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.port.out.AuthorizationCheckLatencyRecorder;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class AuthorizationServiceConditionalRoleTest {

  private static final String EDITOR = "editor";
  private static final String VIEWER = "viewer";
  private static final String WORKSPACE_VIEWER = "workspace-viewer";

  private final InMemoryAuthorizationStore store =
      new InMemoryAuthorizationStore()
          .roleGrant(EDITOR, PROCESS_APPLICATION, READ, AuthorizationScope.WILDCARD)
          .roleGrant(EDITOR, PROCESS_APPLICATION, UPDATE, AuthorizationScope.WILDCARD)
          .roleGrant(VIEWER, PROCESS_APPLICATION, READ, AuthorizationScope.WILDCARD)
          .roleGrant(WORKSPACE_VIEWER, WORKSPACE, READ, AuthorizationScope.WILDCARD);

  private final AttributeExtractor<Document> documentExtractor =
      new AttributeExtractor<>(
          PROCESS_APPLICATION,
          Document.class,
          document ->
              document.workspaceIds() == null
                  ? Map.of()
                  : Map.of(ResourceAttribute.WORKSPACE, document.workspaceIds()));

  private final AttributeExtractor<CreateTarget> createTargetExtractor =
      new AttributeExtractor<>(
          PROCESS_APPLICATION,
          CreateTarget.class,
          target -> Map.of(ResourceAttribute.WORKSPACE, Set.of(target.workspaceId())));

  private final AttributeExtractor<Workspace> workspaceExtractor =
      new AttributeExtractor<>(
          WORKSPACE,
          Workspace.class,
          workspace -> Map.of(ResourceAttribute.WORKSPACE, Set.of(workspace.id())));

  private final CamundaAuthentication alice = CamundaAuthentication.of(b -> b.user("alice"));

  private AuthorizationService service(final ResourceAttributeExtractor<?>... extractors) {
    return service(new ResourceScopeExtractorRegistry(List.of()), true, extractors);
  }

  private AuthorizationService service(
      final ResourceScopeExtractorRegistry scopeRegistry,
      final boolean authorizationEnabled,
      final ResourceAttributeExtractor<?>... extractors) {
    return new AuthorizationService(
        new AuthorizationChecker(store),
        new PropertyAuthorizationEvaluatorRegistry(List.of()),
        scopeRegistry,
        new ResourceAttributeExtractorRegistry(List.of(extractors)),
        authorizationEnabled,
        false,
        claims -> alice,
        AuthorizationCheckLatencyRecorder.noop());
  }

  private AuthorizationService defaultService() {
    return service(documentExtractor, createTargetExtractor, workspaceExtractor);
  }

  private static RoleMembership inWorkspace(final String roleId, final String... workspaceIds) {
    return new RoleMembership(
        roleId,
        List.of(
            new Condition(ResourceAttribute.WORKSPACE, new Operand.Values(Set.of(workspaceIds)))));
  }

  private static CamundaAuthentication aliceWith(final RoleMembership... memberships) {
    return CamundaAuthentication.of(b -> b.user("alice").roleMemberships(List.of(memberships)));
  }

  private static <T> RequiredAuthorization<T> required(
      final AuthorizationResourceType type,
      final PermissionType permission,
      final Function<T, String> resourceIdSupplier) {
    return RequiredAuthorization.of(
        b ->
            b.resourceType(type).permissionType(permission).resourceIdSupplier(resourceIdSupplier));
  }

  private static RequiredAuthorization<Document> requiredOnDocument(
      final PermissionType permission) {
    return required(PROCESS_APPLICATION, permission, Document::id);
  }

  @Test
  void checkReturnsRightInWorkspaceWhereEditorAndRejectionInWorkspaceWhereViewer() {
    final var auth = aliceWith(inWorkspace(EDITOR, "w1"), inWorkspace(VIEWER, "w2"));

    final var inW1 =
        defaultService().check(auth, requiredOnDocument(UPDATE), new Document("pa1", Set.of("w1")));
    final var inW2 =
        defaultService().check(auth, requiredOnDocument(UPDATE), new Document("pa2", Set.of("w2")));

    assertThat(inW1.isRight()).isTrue();
    assertThat(inW2.isLeft()).isTrue();
    assertThat(inW2.leftValue())
        .isEqualTo(new AuthorizationRejection.Permission(PROCESS_APPLICATION, UPDATE, "pa2"));
  }

  @Test
  void checkReturnsRightWhenViewerReadsInOwnWorkspace() {
    final var auth = aliceWith(inWorkspace(VIEWER, "w2"));

    assertThat(
            defaultService()
                .check(auth, requiredOnDocument(READ), new Document("pa2", Set.of("w2")))
                .isRight())
        .isTrue();
  }

  @Test
  void checkReturnsRejectionWhenRoleIsConditionalOnOtherWorkspace() {
    final var auth = aliceWith(inWorkspace(EDITOR, "w1"));

    assertThat(
            defaultService()
                .check(auth, requiredOnDocument(READ), new Document("pa2", Set.of("w2")))
                .isLeft())
        .isTrue();
  }

  @Test
  void checkReturnsRejectionWhenResourceDoesNotProvideTheAttribute() {
    final var auth = aliceWith(inWorkspace(EDITOR, "w1"));

    assertThat(
            defaultService()
                .check(auth, requiredOnDocument(READ), new Document("pa", null))
                .isLeft())
        .isTrue();
    assertThat(
            defaultService()
                .check(auth, requiredOnDocument(READ), new Document("pa", Set.of()))
                .isLeft())
        .isTrue();
  }

  @Test
  void checkReturnsRightWhenTheValuesOfConditionAndAttributeOverlap() {
    final var auth = aliceWith(inWorkspace(EDITOR, "w1", "w2"));

    assertThat(
            defaultService()
                .check(auth, requiredOnDocument(UPDATE), new Document("pa", Set.of("w2", "w3")))
                .isRight())
        .isTrue();
    assertThat(
            defaultService()
                .check(auth, requiredOnDocument(UPDATE), new Document("pa", Set.of("w3")))
                .isLeft())
        .isTrue();
  }

  @Test
  void checkReturnsRightWhenUnconditionalRoleApplies() {
    final var withUnconditionalEditor =
        CamundaAuthentication.of(b -> b.user("alice").roleIds(List.of(EDITOR)));

    assertThat(
            defaultService()
                .check(
                    withUnconditionalEditor,
                    requiredOnDocument(UPDATE),
                    new Document("pa2", Set.of("w2")))
                .isRight())
        .isTrue();
  }

  @Test
  void checkReturnsRightWhenMembershipHasNoConditions() {
    final var auth = aliceWith(new RoleMembership(EDITOR, List.of()));

    assertThat(
            defaultService()
                .check(auth, requiredOnDocument(UPDATE), new Document("pa", Set.of("w9")))
                .isRight())
        .isTrue();
    assertThat(
            defaultService()
                .check(auth, requiredOnDocument(UPDATE), new Document("pa", null))
                .isRight())
        .isTrue();
  }

  @Test
  void checkReadsLazilySuppliedRoleMemberships() {
    final var lazy =
        CamundaAuthentication.of(
            b -> b.user("alice").roleMembershipsSupplier(() -> List.of(inWorkspace(EDITOR, "w1"))));

    assertThat(
            defaultService()
                .check(lazy, requiredOnDocument(UPDATE), new Document("pa1", Set.of("w1")))
                .isRight())
        .isTrue();
    assertThat(
            defaultService()
                .check(lazy, requiredOnDocument(UPDATE), new Document("pa2", Set.of("w2")))
                .isLeft())
        .isTrue();
  }

  @Test
  void checkReturnsRejectionWithoutRoleMemberships() {
    assertThat(
            defaultService()
                .check(alice, requiredOnDocument(READ), new Document("pa1", Set.of("w1")))
                .isLeft())
        .isTrue();
  }

  @Test
  void checkEvaluatesTheCreateTargetUnderTheWildcard() {
    final var auth = aliceWith(inWorkspace(EDITOR, "w1"));
    final RequiredAuthorization<CreateTarget> create =
        required(PROCESS_APPLICATION, UPDATE, target -> "*");

    assertThat(defaultService().check(auth, create, new CreateTarget("w1")).isRight()).isTrue();
    assertThat(defaultService().check(auth, create, new CreateTarget("w2")).isLeft()).isTrue();
  }

  @Test
  void checkEvaluatesWorkspacesByTheirOwnId() {
    final var auth = aliceWith(inWorkspace(WORKSPACE_VIEWER, "w1"));
    final RequiredAuthorization<Workspace> read = required(WORKSPACE, READ, Workspace::id);

    assertThat(defaultService().check(auth, read, new Workspace("w1")).isRight()).isTrue();
    assertThat(defaultService().check(auth, read, new Workspace("w2")).isLeft()).isTrue();
  }

  @Test
  void checkHonoursGrantsOnSingleResourcesOfTheRoleWithinTheConditions() {
    store.roleGrant("pa7-reader", PROCESS_APPLICATION, READ, AuthorizationScope.id("pa7"));
    final var auth = aliceWith(inWorkspace("pa7-reader", "w1"));

    assertThat(
            defaultService()
                .check(auth, requiredOnDocument(READ), new Document("pa7", Set.of("w1")))
                .isRight())
        .isTrue();
    assertThat(
            defaultService()
                .check(auth, requiredOnDocument(READ), new Document("pa7", Set.of("w2")))
                .isLeft())
        .isTrue();
    assertThat(
            defaultService()
                .check(auth, requiredOnDocument(READ), new Document("pa8", Set.of("w1")))
                .isLeft())
        .isTrue();
  }

  @Test
  void checkHonoursDirectUserGrantsIndependentOfTheMemberships() {
    store.userGrant("alice", PROCESS_APPLICATION, READ, AuthorizationScope.id("pa5"));

    assertThat(
            defaultService()
                .check(alice, requiredOnDocument(READ), new Document("pa5", Set.of("w2")))
                .isRight())
        .isTrue();
  }

  @Test
  void checkReturnsRightWhenAuthorizationIsDisabled() {
    final var disabled =
        service(new ResourceScopeExtractorRegistry(List.of()), false, documentExtractor);

    assertThat(
            disabled
                .check(alice, requiredOnDocument(UPDATE), new Document("pa", Set.of("w1")))
                .isRight())
        .isTrue();
  }

  @Test
  void checkThrowsIllegalArgumentExceptionWhenNoResourceIdSupplier() {
    final var auth = aliceWith(inWorkspace(EDITOR, "w1"));
    final RequiredAuthorization<Document> withoutSupplier =
        RequiredAuthorization.of(b -> b.resourceType(PROCESS_APPLICATION).permissionType(UPDATE));

    assertThatThrownBy(
            () -> defaultService().check(auth, withoutSupplier, new Document("pa", Set.of("w1"))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("resourceIdSupplier");
  }

  @Test
  void checkThrowsIllegalArgumentExceptionWhenExplicitResourceIds() {
    final var auth = aliceWith(inWorkspace(EDITOR, "w1"));
    final RequiredAuthorization<Document> withIds =
        RequiredAuthorization.of(
            b ->
                b.resourceType(PROCESS_APPLICATION)
                    .permissionType(UPDATE)
                    .resourceIdSupplier(Document::id)
                    .resourceIds(List.of("pa")));

    assertThatThrownBy(
            () -> defaultService().check(auth, withIds, new Document("pa", Set.of("w1"))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("explicit resource IDs");
  }

  @Test
  void checkThrowsIllegalArgumentExceptionWhenNoExtractorAcceptsResource() {
    final var auth = aliceWith(inWorkspace(EDITOR, "w1"));
    final RequiredAuthorization<Object> required = required(PROCESS_APPLICATION, UPDATE, r -> "pa");

    assertThatThrownBy(() -> defaultService().check(auth, required, "not a document"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("java.lang.String");
  }

  @Test
  void checkThrowsNullPointerExceptionWhenResourceIsNull() {
    final var auth = aliceWith(inWorkspace(EDITOR, "w1"));

    assertThatThrownBy(() -> defaultService().check(auth, requiredOnDocument(UPDATE), null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void checkPropagatesExceptionWhenMembershipLookupFails() {
    final var failing =
        CamundaAuthentication.of(
            b ->
                b.user("alice")
                    .roleMembershipsSupplier(
                        () -> {
                          throw new IllegalStateException("membership lookup failed");
                        }));

    assertThatThrownBy(
            () ->
                defaultService()
                    .check(failing, requiredOnDocument(UPDATE), new Document("pa", Set.of("w1"))))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void checkRejectsAttributesThatTheResourceTypeDoesNotDeclare() {
    final var undeclared =
        new AttributeExtractor<>(
            PROCESS_APPLICATION,
            Document.class,
            document -> Map.of(ResourceAttribute.ASSIGNEE, Set.of("a")));
    final var auth = aliceWith(inWorkspace(EDITOR, "w1"));

    assertThatThrownBy(
            () ->
                service(undeclared)
                    .check(auth, requiredOnDocument(UPDATE), new Document("pa", Set.of("w1"))))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("ASSIGNEE");
  }

  @Test
  void checkDispatchesPerResourceClassBetweenScopeAndAttributeExtractors() {
    final var scopeExtractor =
        new ResourceScopeExtractor<Workspace>() {
          @Override
          public AuthorizationResourceType resourceType() {
            return PROCESS_APPLICATION;
          }

          @Override
          public Class<Workspace> resourceClass() {
            return Workspace.class;
          }

          @Override
          public String scopeIdOf(final Workspace resource) {
            return resource.id();
          }
        };
    final var mixed =
        service(
            new ResourceScopeExtractorRegistry(List.of(scopeExtractor)), true, documentExtractor);
    final var auth =
        CamundaAuthentication.of(
            b ->
                b.user("alice")
                    .roleMemberships(List.of(inWorkspace(EDITOR, "w1")))
                    .scopedRoleMemberships(List.of(new ScopedRoleMembership(EDITOR, "w1"))));
    final RequiredAuthorization<Object> onWorkspace =
        required(PROCESS_APPLICATION, UPDATE, r -> "w1");

    assertThat(
            mixed
                .check(auth, requiredOnDocument(UPDATE), new Document("pa", Set.of("w1")))
                .isRight())
        .isTrue();
    assertThat(mixed.check(auth, onWorkspace, new Workspace("w1")).isRight()).isTrue();
    assertThat(mixed.check(auth, onWorkspace, new Workspace("w2")).isLeft()).isTrue();
  }

  @Test
  void constructorRejectsAClassWithBothAScopeAndAnAttributeExtractor() {
    final var scopeExtractor =
        new ResourceScopeExtractor<Document>() {
          @Override
          public AuthorizationResourceType resourceType() {
            return PROCESS_APPLICATION;
          }

          @Override
          public Class<Document> resourceClass() {
            return Document.class;
          }

          @Override
          public String scopeIdOf(final Document resource) {
            return "w1";
          }
        };
    final var scopeRegistry = new ResourceScopeExtractorRegistry(List.of(scopeExtractor));

    assertThatThrownBy(() -> service(scopeRegistry, true, documentExtractor))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("PROCESS_APPLICATION")
        .hasMessageContaining(Document.class.getName());
  }

  @Test
  void constructorRejectsScopeAndAttributeExtractorsForOverlappingClasses() {
    final var scopeExtractor =
        new ResourceScopeExtractor<CharSequence>() {
          @Override
          public AuthorizationResourceType resourceType() {
            return PROCESS_APPLICATION;
          }

          @Override
          public Class<CharSequence> resourceClass() {
            return CharSequence.class;
          }

          @Override
          public String scopeIdOf(final CharSequence resource) {
            return "w1";
          }
        };
    final var stringExtractor =
        new AttributeExtractor<>(PROCESS_APPLICATION, String.class, text -> Map.of());
    final var scopeRegistry = new ResourceScopeExtractorRegistry(List.of(scopeExtractor));

    assertThatThrownBy(() -> service(scopeRegistry, true, stringExtractor))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("java.lang.String")
        .hasMessageContaining("java.lang.CharSequence");
  }

  @Test
  void sameRoleViaTwoMembershipsWithDifferentConditionsAppliesInBothWorkspaces() {
    final var auth = aliceWith(inWorkspace(EDITOR, "w1"), inWorkspace(EDITOR, "w2"));

    for (final var workspace : List.of("w1", "w2")) {
      assertThat(
              defaultService()
                  .check(auth, requiredOnDocument(UPDATE), new Document("pa", Set.of(workspace)))
                  .isRight())
          .isTrue();
    }
    assertThat(
            defaultService()
                .check(auth, requiredOnDocument(UPDATE), new Document("pa", Set.of("w3")))
                .isLeft())
        .isTrue();
  }

  @Test
  void literalEmptyStringConditionValuesAreNeverMet() {
    final var auth = aliceWith(inWorkspace(EDITOR, ""));

    assertThat(
            defaultService()
                .check(auth, requiredOnDocument(UPDATE), new Document("pa", Set.of("")))
                .isLeft())
        .isTrue();
  }

  private record Document(String id, Set<String> workspaceIds) {}

  private record CreateTarget(String workspaceId) {}

  private record Workspace(String id) {}

  private record AttributeExtractor<T>(
      AuthorizationResourceType resourceType,
      Class<T> resourceClass,
      Function<T, Map<ResourceAttribute, Set<String>>> attributes)
      implements ResourceAttributeExtractor<T> {

    @Override
    public Set<ResourceAttribute> providedAttributes() {
      return resourceType.getSupportedAttributes();
    }

    @Override
    public Map<ResourceAttribute, Set<String>> attributesOf(final T resource) {
      return attributes.apply(resource);
    }
  }
}
