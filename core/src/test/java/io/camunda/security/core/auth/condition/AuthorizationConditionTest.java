/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.auth.condition;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.auth.RequiredAuthorization;
import java.util.List;
import org.junit.jupiter.api.Test;

class AuthorizationConditionTest {

  private static final RequiredAuthorization<?> AUTH =
      RequiredAuthorization.of(
          b ->
              b.resourceType(AuthorizationResourceType.PROCESS_DEFINITION)
                  .permissionType(PermissionType.READ));

  @Test
  void singleConditionAuthorizationsReturnsSizeOneList() {
    final AuthorizationCondition condition = new SingleAuthorizationCondition(AUTH);
    assertThat(condition.authorizations()).containsExactly(AUTH);
  }

  @Test
  void anyOfConditionAuthorizationsReturnsAllChildren() {
    final var auth2 =
        RequiredAuthorization.of(
            b ->
                b.resourceType(AuthorizationResourceType.USER_TASK)
                    .permissionType(PermissionType.READ_USER_TASK));
    final AuthorizationCondition condition = new AnyOfAuthorizationCondition(List.of(AUTH, auth2));
    assertThat(condition.authorizations()).containsExactly(AUTH, auth2);
  }
}
