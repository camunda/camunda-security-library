/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.auth.condition;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.auth.RequiredAuthorization;
import java.util.List;
import org.junit.jupiter.api.Test;

class AuthorizationConditionsTest {

  private static final RequiredAuthorization<?> AUTH1 =
      RequiredAuthorization.of(
          b ->
              b.resourceType(AuthorizationResourceType.PROCESS_DEFINITION)
                  .permissionType(PermissionType.READ));

  private static final RequiredAuthorization<?> AUTH2 =
      RequiredAuthorization.of(
          b ->
              b.resourceType(AuthorizationResourceType.USER_TASK)
                  .permissionType(PermissionType.READ_USER_TASK));

  @Test
  void singleWrapsSingleCondition() {
    final var condition = AuthorizationConditions.single(AUTH1);
    assertThat(condition).isInstanceOf(SingleAuthorizationCondition.class);
    assertThat(condition.authorizations()).containsExactly(AUTH1);
  }

  @Test
  void anyOfListCreatesAnyOfCondition() {
    final var condition = AuthorizationConditions.anyOf(List.of(AUTH1, AUTH2));
    assertThat(condition).isInstanceOf(AnyOfAuthorizationCondition.class);
    assertThat(condition.authorizations()).containsExactly(AUTH1, AUTH2);
  }

  @Test
  void anyOfVarargsCreatesAnyOfCondition() {
    final var condition = AuthorizationConditions.anyOf(AUTH1, AUTH2);
    assertThat(condition).isInstanceOf(AnyOfAuthorizationCondition.class);
    assertThat(condition.authorizations()).containsExactly(AUTH1, AUTH2);
  }

  @Test
  void anyOfEmptyListThrows() {
    assertThatIllegalArgumentException().isThrownBy(() -> AuthorizationConditions.anyOf(List.of()));
  }
}
