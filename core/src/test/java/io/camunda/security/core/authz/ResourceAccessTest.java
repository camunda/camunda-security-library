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

import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.authz.ResourceAccessFilter.All;
import io.camunda.security.core.authz.ResourceAccessFilter.AnyOf;
import io.camunda.security.core.authz.ResourceAccessFilter.None;
import io.camunda.security.core.authz.ResourceAccessFilter.Term;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ResourceAccessTest {

  private static final RequiredAuthorization<Object> PLAIN =
      RequiredAuthorization.of(a -> a.processDefinition().readProcessDefinition());

  @Test
  void deniedFactoryDerivesTheNoneFilter() {
    final var access = ResourceAccess.denied(PLAIN);

    assertThat(access.denied()).isTrue();
    assertThat(access.filter()).isEqualTo(new None());
  }

  @Test
  void wildcardFactoryDerivesTheAllFilter() {
    final var access = ResourceAccess.wildcard(PLAIN.withResourceId("*"));

    assertThat(access.wildcard()).isTrue();
    assertThat(access.filter()).isEqualTo(new All());
  }

  @Test
  void allowedFactoryDerivesAnIdTermFromTheResourceIds() {
    final var access = ResourceAccess.allowed(PLAIN.withResourceIds(List.of("a", "b")));

    assertThat(access.filter())
        .isEqualTo(new AnyOf(List.of(new Term(Set.of("a", "b"), List.of()))));
  }

  @Test
  void allowedFactoryHasNoFilterForResultsExpressedByPropertyNames() {
    final var access = ResourceAccess.allowed(PLAIN.withResourcePropertyNames(Set.of("assignee")));

    assertThat(access.allowed()).isTrue();
    assertThat(access.filter()).isNull();
  }

  @Test
  void allowedFactoryKeepsAnExplicitFilter() {
    final var filter = new AnyOf(List.of(new Term(Set.of(), List.of())));

    assertThat(ResourceAccess.allowed(PLAIN, filter).filter()).isEqualTo(filter);
  }

  @Test
  void threeArgumentConstructorDerivesTheFilter() {
    assertThat(new ResourceAccess(false, false, PLAIN).filter()).isEqualTo(new None());
    assertThat(new ResourceAccess(true, true, PLAIN).filter()).isEqualTo(new All());
  }

  @Test
  void deniedAccessMustNotCarryAFilterThatAllows() {
    assertThatThrownBy(() -> new ResourceAccess(false, false, PLAIN, new All()))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                new ResourceAccess(
                    false, false, PLAIN, new AnyOf(List.of(new Term(Set.of("a"), List.of())))))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void deniedAccessMayCarryNoneOrNoFilter() {
    assertThat(new ResourceAccess(false, false, PLAIN, new None()).denied()).isTrue();
    assertThat(new ResourceAccess(false, false, PLAIN, null).denied()).isTrue();
  }

  @Test
  void allowedAccessMustNotCarryTheNoneFilter() {
    assertThatThrownBy(() -> new ResourceAccess(true, false, PLAIN, new None()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void wildcardAccessMustBeAllowedAndMatchAll() {
    assertThatThrownBy(() -> new ResourceAccess(false, true, PLAIN, null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                new ResourceAccess(
                    true, true, PLAIN, new AnyOf(List.of(new Term(Set.of("a"), List.of())))))
        .isInstanceOf(IllegalArgumentException.class);
    assertThat(new ResourceAccess(true, true, PLAIN, null).wildcard()).isTrue();
  }
}
