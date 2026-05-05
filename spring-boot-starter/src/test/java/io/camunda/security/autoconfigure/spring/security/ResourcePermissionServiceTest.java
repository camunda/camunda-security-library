/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.Authorization;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.PermissionType;
import io.camunda.security.api.model.ResourceType;
import io.camunda.security.core.port.out.AuthorizationRepositoryPort;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ResourcePermissionServiceTest {

  private final CamundaAuthentication authentication =
      CamundaAuthentication.of(b -> b.user("alice"));

  @Test
  void returnsTrueWhenGrantMatchesRequestedResourceIdAndPermission() {
    final var repository =
        new StubRepository(
            Set.of(
                new Authorization(ResourceType.COMPONENT, "operate", Set.of(PermissionType.ACCESS)),
                new Authorization(
                    ResourceType.COMPONENT, "tasklist", Set.of(PermissionType.ACCESS))));
    final var service = new ResourcePermissionService(repository);

    assertThat(
            service.hasPermission(
                authentication, ResourceType.COMPONENT, "operate", PermissionType.ACCESS))
        .isTrue();
  }

  @Test
  void returnsFalseWhenGrantsCoverDifferentResourceIds() {
    // Alice has ACCESS to "tasklist" but not to "operate" — must not over-authorize.
    final var repository =
        new StubRepository(
            Set.of(
                new Authorization(
                    ResourceType.COMPONENT, "tasklist", Set.of(PermissionType.ACCESS))));
    final var service = new ResourcePermissionService(repository);

    assertThat(
            service.hasPermission(
                authentication, ResourceType.COMPONENT, "operate", PermissionType.ACCESS))
        .isFalse();
  }

  @Test
  void returnsFalseWhenMatchingResourceLacksRequestedPermission() {
    final var repository =
        new StubRepository(
            Set.of(new Authorization(ResourceType.USER, "alice", Set.of(PermissionType.READ))));
    final var service = new ResourcePermissionService(repository);

    assertThat(
            service.hasPermission(
                authentication, ResourceType.USER, "alice", PermissionType.UPDATE))
        .isFalse();
  }

  @Test
  void returnsFalseWhenRepositoryReturnsNoAuthorizations() {
    final var service = new ResourcePermissionService(new StubRepository(Set.of()));

    assertThat(
            service.hasPermission(
                authentication, ResourceType.COMPONENT, "operate", PermissionType.ACCESS))
        .isFalse();
  }

  @Test
  void delegatesResourceTypeAndAuthenticationToRepository() {
    final var repository =
        new StubRepository(
            Set.of(
                new Authorization(
                    ResourceType.COMPONENT, "operate", Set.of(PermissionType.ACCESS))));
    final var service = new ResourcePermissionService(repository);

    service.hasPermission(authentication, ResourceType.COMPONENT, "operate", PermissionType.ACCESS);

    assertThat(repository.lastResourceType).isEqualTo(ResourceType.COMPONENT);
    assertThat(repository.lastAuthentication).isSameAs(authentication);
  }

  private static final class StubRepository implements AuthorizationRepositoryPort {
    ResourceType lastResourceType;
    CamundaAuthentication lastAuthentication;
    private final Set<Authorization> result;

    StubRepository(final Set<Authorization> result) {
      this.result = result;
    }

    @Override
    public Set<Authorization> findAuthorizations(
        final CamundaAuthentication authentication, final ResourceType resourceType) {
      lastAuthentication = authentication;
      lastResourceType = resourceType;
      return result;
    }
  }
}
