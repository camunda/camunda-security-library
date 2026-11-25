/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

import static java.util.Map.entry;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * Guards the two hand-maintained authorization enums. {@link AuthorizationResourceType} is the enum
 * the live check path uses; {@link ResourceType} is kept in parity for the ADR-0008 catalogue
 * contract. A value added to one but not the other (or with a different permission set) is a latent
 * authorization bug, so this test asserts they stay identical, and pins the exact permission set of
 * every Hub resource type.
 */
class AuthzResourceEnumParityTest {

  /** The exact supported-permission set each Hub resource type must expose. */
  private static final Map<String, Set<PermissionType>> HUB_TYPE_PERMISSIONS =
      Map.ofEntries(
          entry("BUSINESS_VALUE", Set.of(PermissionType.READ, PermissionType.UPDATE)),
          entry(
              "CATALOG",
              Set.of(
                  PermissionType.READ,
                  PermissionType.READ_USAGE_METRIC,
                  PermissionType.CREATE,
                  PermissionType.UPDATE,
                  PermissionType.DELETE)),
          entry("CATALOG_ASSET", Set.of(PermissionType.READ, PermissionType.UPDATE)),
          entry(
              "CLUSTER",
              Set.of(
                  PermissionType.READ,
                  PermissionType.READ_USAGE_METRIC,
                  PermissionType.CREATE,
                  PermissionType.UPDATE,
                  PermissionType.DELETE)),
          entry("COMMENT", Set.of(PermissionType.CREATE, PermissionType.READ)),
          entry("ENVIRONMENT", Set.of(PermissionType.READ, PermissionType.UPDATE)),
          entry(
              "FILE",
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
          entry("GIT_SYNC", Set.of(PermissionType.READ, PermissionType.UPDATE)),
          entry(
              "PROJECT",
              Set.of(
                  PermissionType.CREATE,
                  PermissionType.READ,
                  PermissionType.UPDATE,
                  PermissionType.DELETE,
                  PermissionType.RESTORE,
                  PermissionType.PURGE)),
          entry(
              "PROJECT_SNAPSHOT",
              Set.of(
                  PermissionType.CREATE,
                  PermissionType.READ,
                  PermissionType.UPDATE,
                  PermissionType.DELETE,
                  PermissionType.RESTORE,
                  PermissionType.REQUEST_REVIEW,
                  PermissionType.SUBMIT_REVIEW)),
          entry(
              "VERSION",
              Set.of(
                  PermissionType.CREATE,
                  PermissionType.READ,
                  PermissionType.UPDATE,
                  PermissionType.DELETE,
                  PermissionType.RESTORE)),
          entry(
              "WORKSPACE",
              Set.of(
                  PermissionType.CREATE,
                  PermissionType.READ,
                  PermissionType.UPDATE,
                  PermissionType.DELETE,
                  PermissionType.RESTORE,
                  PermissionType.PURGE)));

  @Test
  void authorizationResourceTypeAndResourceTypeStayInParity() {
    final var authNames =
        Arrays.stream(AuthorizationResourceType.values())
            .map(Enum::name)
            .collect(Collectors.toSet());
    final var resNames =
        Arrays.stream(ResourceType.values()).map(Enum::name).collect(Collectors.toSet());

    assertThat(resNames).isEqualTo(authNames);

    for (final var name : authNames) {
      final var authPerms = AuthorizationResourceType.valueOf(name).getSupportedPermissionTypes();
      final var resPerms = ResourceType.valueOf(name).getSupportedPermissionTypes();
      assertThat(resPerms).as("permission parity for %s", name).isEqualTo(authPerms);
    }
  }

  @Test
  void hubTypesExposeExactlyTheirPermissions() {
    HUB_TYPE_PERMISSIONS.forEach(
        (name, expected) ->
            assertThat(AuthorizationResourceType.valueOf(name).getSupportedPermissionTypes())
                .as("supported permissions for %s", name)
                .containsExactlyInAnyOrderElementsOf(expected));
  }
}
