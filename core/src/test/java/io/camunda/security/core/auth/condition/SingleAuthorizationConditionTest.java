/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.auth.condition;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.auth.RequiredAuthorization;
import org.junit.jupiter.api.Test;

class SingleAuthorizationConditionTest {

  private static final RequiredAuthorization<?> SAMPLE =
      RequiredAuthorization.of(
          b ->
              b.resourceType(AuthorizationResourceType.PROCESS_DEFINITION)
                  .permissionType(PermissionType.READ));

  @Test
  void shouldRejectNullAuthorization() {
    assertThatNullPointerException()
        .isThrownBy(() -> new SingleAuthorizationCondition(null))
        .withMessageContaining("authorization");
  }

  @Test
  void shouldStoreAuthorization() {
    final var condition = new SingleAuthorizationCondition(SAMPLE);
    assertThat(condition.authorization()).isSameAs(SAMPLE);
  }
}
