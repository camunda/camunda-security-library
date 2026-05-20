/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.initialization;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.authz.AuthorizationOwnerType;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.PermissionType;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class ConfiguredAuthorizationTest {

  @Test
  void shouldCreateIdBasedAuthorizationWithResourceId() {
    final var auth =
        ConfiguredAuthorization.idBased(
            AuthorizationOwnerType.USER,
            "alice",
            AuthorizationResourceType.PROCESS_DEFINITION,
            "my-process",
            Set.of(PermissionType.READ));

    assertThat(auth.ownerType()).isEqualTo(AuthorizationOwnerType.USER);
    assertThat(auth.ownerId()).isEqualTo("alice");
    assertThat(auth.resourceType()).isEqualTo(AuthorizationResourceType.PROCESS_DEFINITION);
    assertThat(auth.resourceId()).isEqualTo("my-process");
    assertThat(auth.resourcePropertyName()).isNull();
    assertThat(auth.permissions()).containsExactlyInAnyOrder(PermissionType.READ);
    assertThat(auth.hasResourceId()).isTrue();
    assertThat(auth.hasResourcePropertyName()).isFalse();
  }

  @Test
  void shouldCreateWildcardAuthorizationWithWildcardResourceId() {
    final var auth =
        ConfiguredAuthorization.wildcard(
            AuthorizationOwnerType.ROLE,
            "admin-role",
            AuthorizationResourceType.PROCESS_DEFINITION,
            Set.of(PermissionType.READ, PermissionType.CREATE));

    assertThat(auth.resourceId()).isEqualTo(AuthorizationScope.WILDCARD_CHAR);
    assertThat(auth.resourcePropertyName()).isNull();
    assertThat(auth.hasResourceId()).isTrue();
    assertThat(auth.hasResourcePropertyName()).isFalse();
    assertThat(auth.ownerType()).isEqualTo(AuthorizationOwnerType.ROLE);
    assertThat(auth.ownerId()).isEqualTo("admin-role");
    assertThat(auth.resourceType()).isEqualTo(AuthorizationResourceType.PROCESS_DEFINITION);
    assertThat(auth.permissions())
        .containsExactlyInAnyOrder(PermissionType.READ, PermissionType.CREATE);
  }

  @Test
  void shouldCreatePropertyBasedAuthorizationWithResourcePropertyName() {
    final var auth =
        ConfiguredAuthorization.propertyBased(
            AuthorizationOwnerType.USER,
            "bob",
            AuthorizationResourceType.PROCESS_DEFINITION,
            "tenantId",
            Set.of(PermissionType.READ));

    assertThat(auth.resourcePropertyName()).isEqualTo("tenantId");
    assertThat(auth.resourceId()).isNull();
    assertThat(auth.hasResourcePropertyName()).isTrue();
    assertThat(auth.hasResourceId()).isFalse();
    assertThat(auth.ownerType()).isEqualTo(AuthorizationOwnerType.USER);
    assertThat(auth.ownerId()).isEqualTo("bob");
    assertThat(auth.resourceType()).isEqualTo(AuthorizationResourceType.PROCESS_DEFINITION);
    assertThat(auth.permissions()).containsExactlyInAnyOrder(PermissionType.READ);
  }

  @Test
  void shouldConvertValidPermissionStringsToPermissionTypes() {
    final var auth = new ConfiguredAuthorization();
    auth.setPermissions(Set.of("READ", "CREATE"));

    assertThat(auth.permissions())
        .containsExactlyInAnyOrder(PermissionType.READ, PermissionType.CREATE);
  }

  @Test
  void shouldReturnEmptyPermissionsWhenSetPermissionsCalledWithNull() {
    final var auth = new ConfiguredAuthorization();
    auth.setPermissions(null);

    assertThat(auth.permissions()).isEmpty();
  }

  static Stream<Set<String>> permissionsWithInvalidEntries() {
    final var withNull = new HashSet<String>();
    withNull.add("READ");
    withNull.add(null);
    return Stream.of(withNull, Set.of("READ", "   "), Set.of("READ", ""));
  }

  @ParameterizedTest
  @MethodSource("permissionsWithInvalidEntries")
  void shouldFilterInvalidPermissionEntries(final Set<String> permissions) {
    final var auth = new ConfiguredAuthorization();
    auth.setPermissions(permissions);

    assertThat(auth.permissions()).containsExactlyInAnyOrder(PermissionType.READ);
  }

  @Test
  void shouldStoreAllFieldsViaSetters() {
    final var auth = new ConfiguredAuthorization();
    auth.setOwnerType(AuthorizationOwnerType.USER);
    auth.setOwnerId("alice");
    auth.setResourceType(AuthorizationResourceType.PROCESS_DEFINITION);
    auth.setResourceId("my-process");
    auth.setResourcePropertyName("tenantId");
    auth.setPermissions(Set.of("READ"));

    assertThat(auth.ownerType()).isEqualTo(AuthorizationOwnerType.USER);
    assertThat(auth.ownerId()).isEqualTo("alice");
    assertThat(auth.resourceType()).isEqualTo(AuthorizationResourceType.PROCESS_DEFINITION);
    assertThat(auth.resourceId()).isEqualTo("my-process");
    assertThat(auth.resourcePropertyName()).isEqualTo("tenantId");
    assertThat(auth.permissions()).containsExactlyInAnyOrder(PermissionType.READ);
  }
}
