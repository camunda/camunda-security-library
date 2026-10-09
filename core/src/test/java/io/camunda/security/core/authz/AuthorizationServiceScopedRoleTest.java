/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static io.camunda.security.api.model.authz.AuthorizationResourceType.PROCESS_APPLICATION;
import static io.camunda.security.api.model.authz.PermissionType.READ;
import static io.camunda.security.api.model.authz.PermissionType.UPDATE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.context.ResourceScopeExtractor;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationRejection;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ScopedRoleMembership;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.port.out.AuthorizationCheckLatencyRecorder;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AuthorizationServiceScopedRoleTest {

  private static final String EDITOR = "editor";
  private static final String VIEWER = "viewer";

  private static final List<Grant> GRANTS =
      List.of(
          new Grant(EDITOR, PROCESS_APPLICATION, READ, "*"),
          new Grant(EDITOR, PROCESS_APPLICATION, UPDATE, "*"),
          new Grant(VIEWER, PROCESS_APPLICATION, READ, "*"));

  private final AuthorizationScopeRepositoryPort scopeRepository =
      new AuthorizationScopeRepositoryPort() {
        @Override
        public List<AuthorizationScope> findAuthorizedScopes(
            final Map<EntityType, Set<String>> ownerIds,
            final AuthorizationResourceType resourceType,
            final PermissionType permissionType) {
          throw new UnsupportedOperationException();
        }

        @Override
        public boolean hasAuthorizedScope(
            final Map<EntityType, Set<String>> ownerIds,
            final AuthorizationResourceType resourceType,
            final PermissionType permissionType,
            final List<String> resourceIds) {
          final var roleIds = ownerIds.getOrDefault(EntityType.ROLE, Set.of());
          return GRANTS.stream()
              .anyMatch(
                  grant ->
                      roleIds.contains(grant.roleId())
                          && grant.type() == resourceType
                          && grant.permission() == permissionType
                          && resourceIds.contains(grant.resourceId()));
        }

        @Override
        public Set<PermissionType> findPermissionTypes(
            final Map<EntityType, Set<String>> ownerIds,
            final AuthorizationResourceType resourceType,
            final List<String> resourceIds) {
          throw new UnsupportedOperationException();
        }
      };

  private final ResourceScopeExtractor<Document> extractor =
      new ResourceScopeExtractor<>() {
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
          return resource.workspaceId();
        }
      };

  private final ResourceScopeExtractor<CreateTarget> createTargetExtractor =
      new ResourceScopeExtractor<>() {
        @Override
        public AuthorizationResourceType resourceType() {
          return PROCESS_APPLICATION;
        }

        @Override
        public Class<CreateTarget> resourceClass() {
          return CreateTarget.class;
        }

        @Override
        public String scopeIdOf(final CreateTarget resource) {
          return resource.workspaceId();
        }
      };

  private final CamundaAuthentication alice = CamundaAuthentication.of(b -> b.user("alice"));

  private AuthorizationService service(final ResourceScopeExtractor<?>... extractors) {
    return new AuthorizationService(
        new AuthorizationChecker(scopeRepository),
        new PropertyAuthorizationEvaluatorRegistry(List.of()),
        new ResourceScopeExtractorRegistry(List.of(extractors)),
        true,
        false,
        claims -> alice,
        AuthorizationCheckLatencyRecorder.noop());
  }

  private AuthorizationService defaultService() {
    return service(extractor, createTargetExtractor);
  }

  private static CamundaAuthentication aliceWith(final ScopedRoleMembership... memberships) {
    return CamundaAuthentication.of(
        b -> b.user("alice").scopedRoleMemberships(List.of(memberships)));
  }

  private static RequiredAuthorization<Object> required(
      final PermissionType permission, final String resourceId) {
    return RequiredAuthorization.of(
        b ->
            b.resourceType(PROCESS_APPLICATION)
                .permissionType(permission)
                .resourceIdSupplier(resource -> resourceId));
  }

  private static RequiredAuthorization<Object> requiredWithIds(
      final PermissionType permission, final String resourceId) {
    return RequiredAuthorization.of(
        b -> b.resourceType(PROCESS_APPLICATION).permissionType(permission).resourceId(resourceId));
  }

  @Test
  void checkReturnsRightInScopeWhereEditorAndRejectionInScopeWhereViewer() {
    final var auth =
        aliceWith(new ScopedRoleMembership(EDITOR, "w1"), new ScopedRoleMembership(VIEWER, "w2"));

    final var inW1 = defaultService().check(auth, required(UPDATE, "pa1"), new Document("w1"));
    final var inW2 = defaultService().check(auth, required(UPDATE, "pa2"), new Document("w2"));

    assertThat(inW1.isRight()).isTrue();
    assertThat(inW2.isLeft()).isTrue();
    assertThat(inW2.leftValue())
        .isEqualTo(new AuthorizationRejection.Permission(PROCESS_APPLICATION, UPDATE, "pa2"));
  }

  @Test
  void checkReturnsRightWhenViewerReadsInOwnScope() {
    final var auth = aliceWith(new ScopedRoleMembership(VIEWER, "w2"));

    assertThat(defaultService().check(auth, required(READ, "pa2"), new Document("w2")).isRight())
        .isTrue();
  }

  @Test
  void checkReturnsRejectionWhenRoleIsScopedToOtherWorkspace() {
    final var auth = aliceWith(new ScopedRoleMembership(EDITOR, "w1"));

    assertThat(defaultService().check(auth, required(READ, "pa2"), new Document("w2")).isLeft())
        .isTrue();
  }

  @Test
  void checkReturnsRejectionWhenResourceHasNoScopeAndRolesAreScoped() {
    final var auth = aliceWith(new ScopedRoleMembership(EDITOR, "w1"));

    assertThat(defaultService().check(auth, required(READ, "pa"), new Document(null)).isLeft())
        .isTrue();
  }

  @Test
  void checkReturnsRightWhenUnscopedRoleApplies() {
    final var withUnscopedEditor =
        CamundaAuthentication.of(b -> b.user("alice").roleIds(List.of(EDITOR)));

    assertThat(
            defaultService()
                .check(withUnscopedEditor, required(UPDATE, "pa2"), new Document("w2"))
                .isRight())
        .isTrue();
  }

  @Test
  void checkReadsLazilySuppliedScopedRoleMemberships() {
    final var lazy =
        CamundaAuthentication.of(
            b ->
                b.user("alice")
                    .scopedRoleMembershipsSupplier(
                        () -> List.of(new ScopedRoleMembership(EDITOR, "w1"))));

    assertThat(defaultService().check(lazy, required(UPDATE, "pa1"), new Document("w1")).isRight())
        .isTrue();
    assertThat(defaultService().check(lazy, required(UPDATE, "pa2"), new Document("w2")).isLeft())
        .isTrue();
  }

  @Test
  void checkReturnsRejectionWithoutScopedRoleMemberships() {
    assertThat(defaultService().check(alice, required(READ, "pa1"), new Document("w1")).isLeft())
        .isTrue();
  }

  @Test
  void checkWithoutResourceReturnsRejectionWhenOnlyScopedRolesExist() {
    final var auth = aliceWith(new ScopedRoleMembership(EDITOR, "w1"));

    assertThat(defaultService().check(auth, requiredWithIds(UPDATE, "pa1")).isLeft()).isTrue();
  }

  @Test
  void checkDispatchesOnResourceClassForCreateTarget() {
    final var auth = aliceWith(new ScopedRoleMembership(EDITOR, "w1"));

    assertThat(
            defaultService().check(auth, required(UPDATE, "*"), new CreateTarget("w1")).isRight())
        .isTrue();
    assertThat(defaultService().check(auth, required(UPDATE, "*"), new CreateTarget("w2")).isLeft())
        .isTrue();
  }

  @Test
  void checkReturnsRightWithoutExtractorIgnoringScopedRoleMemberships() {
    final var auth = aliceWith(new ScopedRoleMembership(VIEWER, "w1"));

    assertThat(service().check(auth, required(UPDATE, "pa1"), new Document("w2")).isRight())
        .isTrue();
  }

  @Test
  void checkThrowsIllegalArgumentExceptionWhenNoResourceIdSupplierOnScopedPath() {
    final var auth = aliceWith(new ScopedRoleMembership(EDITOR, "w1"));
    final RequiredAuthorization<Object> withoutSupplier =
        RequiredAuthorization.of(b -> b.resourceType(PROCESS_APPLICATION).permissionType(UPDATE));

    assertThatThrownBy(() -> defaultService().check(auth, withoutSupplier, new Document("w1")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("resourceIdSupplier");
  }

  @Test
  void checkThrowsIllegalArgumentExceptionWhenExplicitResourceIdsOnScopedPath() {
    final var auth = aliceWith(new ScopedRoleMembership(EDITOR, "w1"));

    assertThatThrownBy(
            () -> defaultService().check(auth, requiredWithIds(UPDATE, "pa1"), new Document("w1")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("explicit resource IDs");
  }

  @Test
  void checkThrowsIllegalArgumentExceptionWhenSupplierReturnsNoIdOnScopedPath() {
    final var auth = aliceWith(new ScopedRoleMembership(EDITOR, "w1"));
    final var nullId = required(UPDATE, null);

    assertThatThrownBy(() -> defaultService().check(auth, nullId, new Document("w1")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("returned no resource ID");
  }

  @Test
  void checkThrowsIllegalArgumentExceptionWhenPropertyNamesOnScopedPath() {
    final var auth = aliceWith(new ScopedRoleMembership(EDITOR, "w1"));
    final var withProperty = required(UPDATE, "pa1").withResourcePropertyNames(Set.of("owner"));

    assertThatThrownBy(() -> defaultService().check(auth, withProperty, new Document("w1")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("property names");
  }

  @Test
  void checkThrowsIllegalArgumentExceptionWhenNoExtractorAcceptsResource() {
    final var auth = aliceWith(new ScopedRoleMembership(EDITOR, "w1"));

    assertThatThrownBy(
            () -> defaultService().check(auth, required(UPDATE, "pa1"), "not a document"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("java.lang.String");
  }

  @Test
  void checkThrowsNullPointerExceptionWhenResourceIsNullOnScopedPath() {
    final var auth = aliceWith(new ScopedRoleMembership(EDITOR, "w1"));

    assertThatThrownBy(() -> defaultService().check(auth, required(UPDATE, "pa1"), null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void checkPropagatesExceptionWhenMembershipLookupFails() {
    final var failing =
        CamundaAuthentication.of(
            b ->
                b.user("alice")
                    .scopedRoleMembershipsSupplier(
                        () -> {
                          throw new IllegalStateException("membership lookup failed");
                        }));

    assertThatThrownBy(
            () -> service(extractor).check(failing, required(UPDATE, "pa1"), new Document("w1")))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void checkPropagatesExceptionWhenExtractorFails() {
    final ResourceScopeExtractor<Document> failing =
        new ResourceScopeExtractor<>() {
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
            throw new IllegalStateException("scope lookup failed");
          }
        };
    final var auth = aliceWith(new ScopedRoleMembership(EDITOR, "w1"));

    assertThatThrownBy(
            () -> service(failing).check(auth, required(UPDATE, "pa1"), new Document("w1")))
        .isInstanceOf(IllegalStateException.class);
  }

  private record Document(String workspaceId) {}

  private record CreateTarget(String workspaceId) {}

  private record Grant(
      String roleId,
      AuthorizationResourceType type,
      PermissionType permission,
      String resourceId) {}
}
