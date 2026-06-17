/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.model.Either;
import io.camunda.security.api.model.authz.AuthorizationRejection;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.PermissionType;
import org.junit.jupiter.api.Test;

class RejectionAggregatorTest {

  private static Either<AuthorizationRejection, Void> rejected(final String tenantId) {
    return Either.left(new AuthorizationRejection.Tenant(tenantId));
  }

  private static Either<AuthorizationRejection, Void> approved() {
    return Either.right(null);
  }

  @Test
  void shouldReturnRightWhenBuildWithNoResults() {
    assertThat(new RejectionAggregator().build().isRight()).isTrue();
  }

  @Test
  void shouldReturnLeftWithRejectionWhenBuildWithOneLeft() {
    final var result = new RejectionAggregator().add(rejected("t1")).build();
    assertThat(result.isLeft()).isTrue();
    assertThat(result.leftValue()).containsExactly(new AuthorizationRejection.Tenant("t1"));
  }

  @Test
  void shouldContainAllRejectionsWhenBuildWithMultipleLefts() {
    final var r1 = new AuthorizationRejection.Tenant("t1");
    final var r2 =
        new AuthorizationRejection.Permission(
            AuthorizationResourceType.PROCESS_DEFINITION, PermissionType.READ, "p1");
    final var result = new RejectionAggregator().add(Either.left(r1)).add(Either.left(r2)).build();
    assertThat(result.leftValue()).containsExactlyInAnyOrder(r1, r2);
  }

  @Test
  void shouldNotAddRightResultToRejections() {
    assertThat(new RejectionAggregator().add(approved()).build().isRight()).isTrue();
  }

  @Test
  void shouldReturnSameAggregatorForChaining() {
    final var agg = new RejectionAggregator();
    assertThat(agg.add(approved())).isSameAs(agg);
  }

  @Test
  void shouldContainOnlyRejectionsWhenBuildAfterMixedResults() {
    final var result =
        new RejectionAggregator().add(approved()).add(rejected("t1")).add(approved()).build();
    assertThat(result.isLeft()).isTrue();
    assertThat(result.leftValue()).hasSize(1);
  }

  @Test
  void shouldReturnImmutableList() {
    final var result = new RejectionAggregator().add(rejected("t1")).build();
    assertThatThrownBy(() -> result.leftValue().add(new AuthorizationRejection.Tenant("x")))
        .isInstanceOf(UnsupportedOperationException.class);
  }
}
