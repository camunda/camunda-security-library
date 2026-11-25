/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

import static io.camunda.security.api.model.authz.AuthorizationResourceType.BUSINESS_VALUE;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.CATALOG;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.CATALOG_ASSET;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.CLUSTER;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.COMMENT;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.COMPONENT;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.ENVIRONMENT;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.FILE;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.GIT_SYNC;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.PROJECT;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.PROJECT_SNAPSHOT;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.VERSION;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.WORKSPACE;
import static java.util.Map.entry;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Asserts that the Hub roles from issue #813 can be expressed by the authorization catalogue: every
 * (resource type, permission) pair a seeded role needs must be a permission the resource type
 * supports. This guards the enums against a role becoming unexpressible — it does not reproduce
 * Hub's authorization logic, and CSL does not store these roles (Hub seeds them).
 *
 * <p>Pairs that reference a <em>deferred</em> resource type or permission are intentionally
 * excluded, because those values are gated by open questions on #813 and are not added in this
 * change. The deferred grants, for the record:
 *
 * <ul>
 *   <li>{@code ORGANIZATION} read/update — every organization role (issue Q4 overlap with {@code
 *       SYSTEM}, Q5 billing/ownership transfer).
 *   <li>{@code WORKSPACE_MEMBER} create/read/update — every workspace role (Q2 invitations, Q4
 *       overlap with {@code ROLE}/{@code USER}/{@code AUTHORIZATION}).
 *   <li>{@code IDP_APPLICATION} — workspace roles and the API create role's document uploads (Q8;
 *       may fold into {@code FILE}/{@code PROJECT}).
 *   <li>{@code CATALOG PUBLISH} — Q7 (Shared-resources / Catalog integration).
 * </ul>
 */
class HubRoleCatalogueTest {

  // --- Organization roles (unconditional memberships) ---

  // Organization Admin holds every organization-level grant plus each workspace-level permission on
  // each workspace (issue #813). ENVIRONMENT carries UPDATE here (admin manages environments),
  // unlike the workspace Editor/Viewer roles below.
  private static final Role ORGANIZATION_ADMIN =
      new Role(
          "Organization Admin",
          Map.ofEntries(
              entry(
                  CLUSTER,
                  Set.of(
                      PermissionType.READ,
                      PermissionType.READ_USAGE_METRIC,
                      PermissionType.CREATE,
                      PermissionType.UPDATE,
                      PermissionType.DELETE)),
              entry(
                  CATALOG,
                  Set.of(
                      PermissionType.READ,
                      PermissionType.READ_USAGE_METRIC,
                      PermissionType.CREATE,
                      PermissionType.UPDATE,
                      PermissionType.DELETE)),
              entry(CATALOG_ASSET, Set.of(PermissionType.READ, PermissionType.UPDATE)),
              entry(BUSINESS_VALUE, Set.of(PermissionType.READ, PermissionType.UPDATE)),
              entry(COMPONENT, Set.of(PermissionType.ACCESS)),
              entry(
                  WORKSPACE,
                  Set.of(
                      PermissionType.CREATE,
                      PermissionType.READ,
                      PermissionType.UPDATE,
                      PermissionType.DELETE,
                      PermissionType.RESTORE,
                      PermissionType.PURGE)),
              entry(
                  PROJECT,
                  Set.of(
                      PermissionType.CREATE,
                      PermissionType.READ,
                      PermissionType.UPDATE,
                      PermissionType.DELETE,
                      PermissionType.RESTORE,
                      PermissionType.PURGE)),
              entry(
                  PROJECT_SNAPSHOT,
                  Set.of(
                      PermissionType.CREATE,
                      PermissionType.READ,
                      PermissionType.UPDATE,
                      PermissionType.DELETE,
                      PermissionType.RESTORE,
                      PermissionType.REQUEST_REVIEW,
                      PermissionType.SUBMIT_REVIEW)),
              entry(
                  FILE,
                  Set.of(
                      PermissionType.CREATE,
                      PermissionType.READ,
                      PermissionType.UPDATE,
                      PermissionType.DELETE,
                      PermissionType.RESTORE,
                      PermissionType.PURGE,
                      PermissionType.DEPLOY,
                      PermissionType.EXECUTE,
                      PermissionType.SHARE)),
              entry(
                  VERSION,
                  Set.of(
                      PermissionType.CREATE,
                      PermissionType.READ,
                      PermissionType.UPDATE,
                      PermissionType.DELETE,
                      PermissionType.RESTORE)),
              entry(COMMENT, Set.of(PermissionType.CREATE, PermissionType.READ)),
              entry(ENVIRONMENT, Set.of(PermissionType.READ, PermissionType.UPDATE)),
              entry(GIT_SYNC, Set.of(PermissionType.READ, PermissionType.UPDATE))));

  // Organization Owner adds billing/ownership transfer (ORGANIZATION-level, deferred); among
  // implemented types its grants equal the Admin's.
  private static final Role ORGANIZATION_OWNER =
      new Role("Organization Owner", ORGANIZATION_ADMIN.grants());

  private static final Role DEVOPS =
      new Role(
          "DevOps",
          Map.of(
              WORKSPACE, Set.of(PermissionType.CREATE),
              CLUSTER,
                  Set.of(
                      PermissionType.READ,
                      PermissionType.READ_USAGE_METRIC,
                      PermissionType.CREATE,
                      PermissionType.UPDATE,
                      PermissionType.DELETE),
              CATALOG, Set.of(PermissionType.READ),
              ENVIRONMENT, Set.of(PermissionType.READ),
              COMPONENT, Set.of(PermissionType.ACCESS)));

  private static final Role ANALYST =
      new Role(
          "Analyst",
          Map.of(
              WORKSPACE, Set.of(PermissionType.CREATE),
              CLUSTER, Set.of(PermissionType.READ),
              CATALOG, Set.of(PermissionType.READ, PermissionType.READ_USAGE_METRIC),
              BUSINESS_VALUE, Set.of(PermissionType.READ, PermissionType.UPDATE),
              COMPONENT, Set.of(PermissionType.ACCESS)));

  private static final Role MEMBER =
      new Role(
          "Member",
          Map.of(
              WORKSPACE, Set.of(PermissionType.CREATE),
              CLUSTER, Set.of(PermissionType.READ),
              CATALOG, Set.of(PermissionType.READ),
              COMPONENT, Set.of(PermissionType.ACCESS)));

  // --- Workspace roles (memberships with a workspace condition) ---

  private static final Role WORKSPACE_ADMIN =
      new Role(
          "Workspace Admin",
          Map.of(
              WORKSPACE,
                  Set.of(
                      PermissionType.READ,
                      PermissionType.UPDATE,
                      PermissionType.DELETE,
                      PermissionType.RESTORE,
                      PermissionType.PURGE),
              PROJECT,
                  Set.of(
                      PermissionType.CREATE,
                      PermissionType.READ,
                      PermissionType.UPDATE,
                      PermissionType.DELETE,
                      PermissionType.RESTORE,
                      PermissionType.PURGE),
              PROJECT_SNAPSHOT,
                  Set.of(
                      PermissionType.CREATE,
                      PermissionType.READ,
                      PermissionType.UPDATE,
                      PermissionType.DELETE,
                      PermissionType.RESTORE,
                      PermissionType.REQUEST_REVIEW,
                      PermissionType.SUBMIT_REVIEW),
              FILE,
                  Set.of(
                      PermissionType.CREATE,
                      PermissionType.READ,
                      PermissionType.UPDATE,
                      PermissionType.DELETE,
                      PermissionType.RESTORE,
                      PermissionType.PURGE,
                      PermissionType.DEPLOY,
                      PermissionType.EXECUTE,
                      PermissionType.SHARE),
              VERSION,
                  Set.of(
                      PermissionType.CREATE,
                      PermissionType.READ,
                      PermissionType.UPDATE,
                      PermissionType.DELETE,
                      PermissionType.RESTORE),
              COMMENT, Set.of(PermissionType.CREATE, PermissionType.READ),
              ENVIRONMENT, Set.of(PermissionType.READ, PermissionType.UPDATE),
              GIT_SYNC, Set.of(PermissionType.READ, PermissionType.UPDATE),
              CATALOG_ASSET, Set.of(PermissionType.READ)));

  private static final Role EDITOR =
      new Role(
          "Editor",
          Map.of(
              WORKSPACE, Set.of(PermissionType.READ),
              PROJECT,
                  Set.of(
                      PermissionType.CREATE,
                      PermissionType.READ,
                      PermissionType.UPDATE,
                      PermissionType.DELETE,
                      PermissionType.RESTORE),
              PROJECT_SNAPSHOT,
                  Set.of(
                      PermissionType.CREATE,
                      PermissionType.READ,
                      PermissionType.UPDATE,
                      PermissionType.DELETE,
                      PermissionType.RESTORE,
                      PermissionType.REQUEST_REVIEW,
                      PermissionType.SUBMIT_REVIEW),
              FILE,
                  Set.of(
                      PermissionType.CREATE,
                      PermissionType.READ,
                      PermissionType.UPDATE,
                      PermissionType.DELETE,
                      PermissionType.RESTORE,
                      PermissionType.DEPLOY,
                      PermissionType.EXECUTE,
                      PermissionType.SHARE),
              VERSION,
                  Set.of(
                      PermissionType.CREATE,
                      PermissionType.READ,
                      PermissionType.UPDATE,
                      PermissionType.DELETE,
                      PermissionType.RESTORE),
              COMMENT, Set.of(PermissionType.CREATE, PermissionType.READ),
              ENVIRONMENT, Set.of(PermissionType.READ, PermissionType.UPDATE),
              GIT_SYNC, Set.of(PermissionType.READ),
              CATALOG_ASSET, Set.of(PermissionType.READ)));

  private static final Role COMMENTER =
      new Role(
          "Commenter",
          Map.of(
              WORKSPACE, Set.of(PermissionType.READ),
              PROJECT, Set.of(PermissionType.READ),
              FILE, Set.of(PermissionType.READ),
              COMMENT, Set.of(PermissionType.CREATE, PermissionType.READ),
              CATALOG_ASSET, Set.of(PermissionType.READ)));

  private static final Role VIEWER =
      new Role(
          "Viewer",
          Map.of(
              WORKSPACE, Set.of(PermissionType.READ),
              PROJECT, Set.of(PermissionType.READ),
              FILE, Set.of(PermissionType.READ),
              CATALOG_ASSET, Set.of(PermissionType.READ)));

  // --- Built-in API roles (public API scopes become roles) ---

  private static final Role API_READ =
      new Role(
          "API read",
          Map.ofEntries(
              entry(CLUSTER, Set.of(PermissionType.READ, PermissionType.READ_USAGE_METRIC)),
              entry(CATALOG, Set.of(PermissionType.READ, PermissionType.READ_USAGE_METRIC)),
              entry(ENVIRONMENT, Set.of(PermissionType.READ)),
              entry(WORKSPACE, Set.of(PermissionType.READ)),
              entry(PROJECT, Set.of(PermissionType.READ)),
              entry(PROJECT_SNAPSHOT, Set.of(PermissionType.READ)),
              entry(FILE, Set.of(PermissionType.READ)),
              entry(VERSION, Set.of(PermissionType.READ)),
              entry(COMMENT, Set.of(PermissionType.READ)),
              entry(GIT_SYNC, Set.of(PermissionType.READ)),
              entry(CATALOG_ASSET, Set.of(PermissionType.READ))));

  private static final Role API_CREATE =
      new Role(
          "API create",
          Map.of(
              CLUSTER, Set.of(PermissionType.CREATE),
              CATALOG, Set.of(PermissionType.CREATE),
              WORKSPACE, Set.of(PermissionType.CREATE),
              PROJECT, Set.of(PermissionType.CREATE),
              FILE, Set.of(PermissionType.CREATE),
              VERSION, Set.of(PermissionType.CREATE),
              PROJECT_SNAPSHOT,
                  Set.of(
                      PermissionType.CREATE,
                      PermissionType.REQUEST_REVIEW,
                      PermissionType.SUBMIT_REVIEW)));

  // POST /clusters needs create+update, so the update role carries CLUSTER UPDATE. The restoration
  // endpoints check the `update` scope but map to the RESTORE permission.
  private static final Role API_UPDATE =
      new Role(
          "API update",
          Map.of(
              CLUSTER, Set.of(PermissionType.UPDATE),
              CATALOG, Set.of(PermissionType.UPDATE),
              ENVIRONMENT, Set.of(PermissionType.UPDATE),
              WORKSPACE, Set.of(PermissionType.UPDATE, PermissionType.RESTORE),
              PROJECT, Set.of(PermissionType.UPDATE, PermissionType.RESTORE),
              FILE, Set.of(PermissionType.UPDATE, PermissionType.RESTORE),
              VERSION, Set.of(PermissionType.UPDATE, PermissionType.RESTORE),
              PROJECT_SNAPSHOT, Set.of(PermissionType.UPDATE, PermissionType.RESTORE)));

  // The permanent-delete endpoints check the `delete` scope but map to the PURGE permission.
  private static final Role API_DELETE =
      new Role(
          "API delete",
          Map.of(
              CLUSTER, Set.of(PermissionType.DELETE),
              CATALOG, Set.of(PermissionType.DELETE),
              WORKSPACE, Set.of(PermissionType.DELETE, PermissionType.PURGE),
              PROJECT, Set.of(PermissionType.DELETE, PermissionType.PURGE),
              FILE, Set.of(PermissionType.DELETE, PermissionType.PURGE),
              VERSION, Set.of(PermissionType.DELETE),
              PROJECT_SNAPSHOT, Set.of(PermissionType.DELETE)));

  private static List<Named<Role>> roles() {
    return List.of(
            ORGANIZATION_OWNER,
            ORGANIZATION_ADMIN,
            DEVOPS,
            ANALYST,
            MEMBER,
            WORKSPACE_ADMIN,
            EDITOR,
            COMMENTER,
            VIEWER,
            API_READ,
            API_CREATE,
            API_UPDATE,
            API_DELETE)
        .stream()
        .map(role -> named(role.name(), role))
        .toList();
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("roles")
  void everyRoleGrantIsSupportedByTheEnums(final Role role) {
    role.grants()
        .forEach(
            (resourceType, permissions) ->
                assertThat(resourceType.getSupportedPermissionTypes())
                    .as("%s grants %s on %s", role.name(), permissions, resourceType)
                    .containsAll(permissions));
  }

  private record Role(String name, Map<AuthorizationResourceType, Set<PermissionType>> grants) {}
}
