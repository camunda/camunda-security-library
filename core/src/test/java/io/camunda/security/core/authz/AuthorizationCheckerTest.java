/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AuthorizationCheckerTest {

  @Mock private AuthorizationScopeRepositoryPort scopeRepository;

  private AuthorizationChecker authorizationChecker;

  @BeforeEach
  void setUp() {
    authorizationChecker = new AuthorizationChecker(scopeRepository);
  }

  @Test
  void noScopesReturnedWhenOwnerIdsIsEmpty() {
    final var result =
        authorizationChecker.retrieveAuthorizedAuthorizationScopes(
            CamundaAuthentication.of(a -> a), RequiredAuthorization.of(a -> a));

    assertThat(result).isEmpty();
  }

  @Test
  void noPermissionTypesReturnedWhenOwnerIdsIsEmpty() {
    final var result =
        authorizationChecker.collectPermissionTypes(
            "foo", AuthorizationResourceType.PROCESS_DEFINITION, CamundaAuthentication.none());

    assertThat(result).isEmpty();
  }

  @Test
  void notAuthorizedWhenOwnerIdsIsEmpty() {
    final var authScope = AuthorizationScope.id("foo");

    final var result =
        authorizationChecker.isAuthorized(
            authScope, CamundaAuthentication.of(a -> a), RequiredAuthorization.of(a -> a));

    assertThat(result).isFalse();
  }

  @Nested
  class RetrieveAuthorizedAuthorizationScopes {

    @Test
    void delegatesToPortWithUserOwnerIds() {
      final var auth = CamundaAuthentication.of(a -> a.user("alice"));
      final var authorization =
          RequiredAuthorization.of(a -> a.processDefinition().readProcessDefinition());
      final var expectedScope = AuthorizationScope.WILDCARD;
      when(scopeRepository.findAuthorizedScopes(
              eq(Map.of(EntityType.USER, Set.of("alice"))),
              eq(AuthorizationResourceType.PROCESS_DEFINITION),
              eq(PermissionType.READ_PROCESS_DEFINITION)))
          .thenReturn(List.of(expectedScope));

      final var result =
          authorizationChecker.retrieveAuthorizedAuthorizationScopes(auth, authorization);

      assertThat(result).containsExactly(expectedScope);
    }

    @Test
    void delegatesToPortWithClientOwnerIds() {
      final var auth = CamundaAuthentication.of(a -> a.clientId("my-client"));
      final var authorization =
          RequiredAuthorization.of(a -> a.processDefinition().readProcessDefinition());
      final var expectedScope = AuthorizationScope.id("pd-1");
      when(scopeRepository.findAuthorizedScopes(
              eq(Map.of(EntityType.CLIENT, Set.of("my-client"))),
              eq(AuthorizationResourceType.PROCESS_DEFINITION),
              eq(PermissionType.READ_PROCESS_DEFINITION)))
          .thenReturn(List.of(expectedScope));

      final var result =
          authorizationChecker.retrieveAuthorizedAuthorizationScopes(auth, authorization);

      assertThat(result).containsExactly(expectedScope);
    }

    @Test
    void delegatesToPortWithGroupOwnerIds() {
      final var auth = CamundaAuthentication.of(a -> a.groupIds(List.of("g1", "g2")));
      final var authorization =
          RequiredAuthorization.of(a -> a.processDefinition().readProcessDefinition());
      when(scopeRepository.findAuthorizedScopes(
              eq(Map.of(EntityType.GROUP, Set.of("g1", "g2"))),
              eq(AuthorizationResourceType.PROCESS_DEFINITION),
              eq(PermissionType.READ_PROCESS_DEFINITION)))
          .thenReturn(List.of());

      final var result =
          authorizationChecker.retrieveAuthorizedAuthorizationScopes(auth, authorization);

      assertThat(result).isEmpty();
    }

    @Test
    void delegatesToPortWithRoleOwnerIds() {
      final var auth = CamundaAuthentication.of(a -> a.roleIds(List.of("role-admin")));
      final var authorization =
          RequiredAuthorization.of(a -> a.processDefinition().readProcessDefinition());
      final var expectedScope = AuthorizationScope.WILDCARD;
      when(scopeRepository.findAuthorizedScopes(
              eq(Map.of(EntityType.ROLE, Set.of("role-admin"))),
              eq(AuthorizationResourceType.PROCESS_DEFINITION),
              eq(PermissionType.READ_PROCESS_DEFINITION)))
          .thenReturn(List.of(expectedScope));

      final var result =
          authorizationChecker.retrieveAuthorizedAuthorizationScopes(auth, authorization);

      assertThat(result).containsExactly(expectedScope);
    }

    @Test
    void delegatesToPortWithMappingRuleOwnerIds() {
      final var auth = CamundaAuthentication.of(a -> a.mappingRules(List.of("mr-1")));
      final var authorization =
          RequiredAuthorization.of(a -> a.processDefinition().readProcessDefinition());
      final var expectedScope = AuthorizationScope.WILDCARD;
      when(scopeRepository.findAuthorizedScopes(
              eq(Map.of(EntityType.MAPPING_RULE, Set.of("mr-1"))),
              eq(AuthorizationResourceType.PROCESS_DEFINITION),
              eq(PermissionType.READ_PROCESS_DEFINITION)))
          .thenReturn(List.of(expectedScope));

      final var result =
          authorizationChecker.retrieveAuthorizedAuthorizationScopes(auth, authorization);

      assertThat(result).containsExactly(expectedScope);
    }
  }

  @Nested
  class IsAuthorized {

    @Test
    void returnsTrueWhenPortConfirmsAccess() {
      final var auth = CamundaAuthentication.of(a -> a.user("alice"));
      final var authorization =
          RequiredAuthorization.of(a -> a.processDefinition().readProcessDefinition());
      final var scope = AuthorizationScope.id("pd-1");
      when(scopeRepository.hasAuthorizedScope(
              eq(Map.of(EntityType.USER, Set.of("alice"))),
              eq(AuthorizationResourceType.PROCESS_DEFINITION),
              eq(PermissionType.READ_PROCESS_DEFINITION),
              eq(List.of(AuthorizationScope.WILDCARD.getResourceId(), "pd-1"))))
          .thenReturn(true);

      assertThat(authorizationChecker.isAuthorized(scope, auth, authorization)).isTrue();
    }

    @Test
    void returnsFalseWhenPortDeniesAccess() {
      final var auth = CamundaAuthentication.of(a -> a.user("alice"));
      final var authorization =
          RequiredAuthorization.of(a -> a.processDefinition().readProcessDefinition());
      final var scope = AuthorizationScope.id("pd-1");
      when(scopeRepository.hasAuthorizedScope(
              eq(Map.of(EntityType.USER, Set.of("alice"))),
              eq(AuthorizationResourceType.PROCESS_DEFINITION),
              eq(PermissionType.READ_PROCESS_DEFINITION),
              eq(List.of(AuthorizationScope.WILDCARD.getResourceId(), "pd-1"))))
          .thenReturn(false);

      assertThat(authorizationChecker.isAuthorized(scope, auth, authorization)).isFalse();
    }

    @Test
    void passesWildcardAndScopeIdToPort() {
      final var auth = CamundaAuthentication.of(a -> a.user("alice"));
      final var authorization =
          RequiredAuthorization.of(a -> a.processDefinition().readProcessDefinition());
      final var scope = AuthorizationScope.id("specific-pd");
      when(scopeRepository.hasAuthorizedScope(
              eq(Map.of(EntityType.USER, Set.of("alice"))),
              eq(AuthorizationResourceType.PROCESS_DEFINITION),
              eq(PermissionType.READ_PROCESS_DEFINITION),
              eq(List.of(AuthorizationScope.WILDCARD.getResourceId(), "specific-pd"))))
          .thenReturn(true);

      assertThat(authorizationChecker.isAuthorized(scope, auth, authorization)).isTrue();
    }
  }

  @Nested
  class CollectPermissionTypes {

    @Test
    void returnsPortResultForUser() {
      final var auth = CamundaAuthentication.of(a -> a.user("alice"));
      when(scopeRepository.findPermissionTypes(
              eq(Map.of(EntityType.USER, Set.of("alice"))),
              eq(AuthorizationResourceType.PROCESS_DEFINITION),
              eq(List.of(AuthorizationScope.WILDCARD.getResourceId(), "pd-1"))))
          .thenReturn(Set.of(PermissionType.READ_PROCESS_DEFINITION));

      final var result =
          authorizationChecker.collectPermissionTypes(
              "pd-1", AuthorizationResourceType.PROCESS_DEFINITION, auth);

      assertThat(result).containsExactly(PermissionType.READ_PROCESS_DEFINITION);
    }

    @Test
    void passesWildcardAndResourceIdToPort() {
      final var auth = CamundaAuthentication.of(a -> a.user("alice"));
      when(scopeRepository.findPermissionTypes(
              eq(Map.of(EntityType.USER, Set.of("alice"))),
              eq(AuthorizationResourceType.PROCESS_DEFINITION),
              eq(List.of(AuthorizationScope.WILDCARD.getResourceId(), "my-pd"))))
          .thenReturn(
              Set.of(PermissionType.READ_PROCESS_DEFINITION, PermissionType.READ_PROCESS_INSTANCE));

      final var result =
          authorizationChecker.collectPermissionTypes(
              "my-pd", AuthorizationResourceType.PROCESS_DEFINITION, auth);

      assertThat(result)
          .containsExactlyInAnyOrder(
              PermissionType.READ_PROCESS_DEFINITION, PermissionType.READ_PROCESS_INSTANCE);
    }

    @Test
    void returnsEmptySetForAnonymousAuthentication() {
      final var auth = CamundaAuthentication.anonymous();

      final var result =
          authorizationChecker.collectPermissionTypes(
              "pd-1", AuthorizationResourceType.PROCESS_DEFINITION, auth);

      assertThat(result).isEmpty();
    }
  }
}
