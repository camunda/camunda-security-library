/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.auth;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.auth.condition.AuthorizationConditions;
import io.camunda.security.core.auth.condition.SingleAuthorizationCondition;
import org.junit.jupiter.api.Test;

class SecurityContextTest {

  private static final CamundaAuthentication USER_AUTH =
      CamundaAuthentication.of(b -> b.user("alice"));

  private static final RequiredAuthorization<?> SAMPLE_AUTH =
      RequiredAuthorization.of(
          b ->
              b.resourceType(AuthorizationResourceType.PROCESS_DEFINITION)
                  .permissionType(PermissionType.READ));

  @Test
  void shouldBuildWithAuthenticationOnly() {
    final var ctx = SecurityContext.of(b -> b.withAuthentication(USER_AUTH));
    assertThat(ctx.authentication()).isSameAs(USER_AUTH);
    assertThat(ctx.authorizationCondition()).isNull();
  }

  @Test
  void shouldBuildWithAuthorizationCondition() {
    final var condition = AuthorizationConditions.single(SAMPLE_AUTH);
    final var ctx =
        SecurityContext.of(
            b -> b.withAuthentication(USER_AUTH).withAuthorizationCondition(condition));
    assertThat(ctx.authorizationCondition()).isSameAs(condition);
  }

  @Test
  void shouldBuildWithAuthorizationShorthand() {
    final var ctx =
        SecurityContext.of(b -> b.withAuthentication(USER_AUTH).withAuthorization(SAMPLE_AUTH));
    assertThat(ctx.authorizationCondition()).isInstanceOf(SingleAuthorizationCondition.class);
    assertThat(ctx.authorizationCondition().authorizations()).containsExactly(SAMPLE_AUTH);
  }

  @Test
  void shouldBuildWithAuthenticationBuilderFunction() {
    final var ctx = SecurityContext.of(b -> b.withAuthentication(ab -> ab.user("bob")));
    assertThat(ctx.authentication().authenticatedUsername()).isEqualTo("bob");
  }

  @Test
  void shouldBuildWithAuthorizationBuilderFunction() {
    final var ctx =
        SecurityContext.of(
            b ->
                b.withAuthentication(USER_AUTH)
                    .withAuthorization(
                        ab ->
                            ab.resourceType(AuthorizationResourceType.USER_TASK)
                                .permissionType(PermissionType.READ_USER_TASK)));
    assertThat(ctx.authorizationCondition()).isInstanceOf(SingleAuthorizationCondition.class);
  }
}
