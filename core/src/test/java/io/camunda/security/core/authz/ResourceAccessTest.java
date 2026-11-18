/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static io.camunda.security.api.model.authz.ResourceAttribute.WORKSPACE_ID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.model.authz.MembershipCondition;
import io.camunda.security.api.model.authz.Operand;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.authz.ResourceAccessFilter.All;
import io.camunda.security.core.authz.ResourceAccessFilter.AnyOf;
import io.camunda.security.core.authz.ResourceAccessFilter.None;
import io.camunda.security.core.authz.ResourceAccessFilter.Term;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ResourceAccessTest {

  private static final RequiredAuthorization<?> READ =
      RequiredAuthorization.of(b -> b.processDefinition().readProcessDefinition());
  private static final AnyOf PAYMENTS =
      new AnyOf(
          List.of(
              new Term(
                  Set.of(),
                  List.of(new MembershipCondition(WORKSPACE_ID, new Operand.Equals("payments"))))));

  @Test
  void derivesTheFilterFromTheVerdict() {
    assertThat(ResourceAccess.denied(READ).filter()).isEqualTo(new None());
    assertThat(ResourceAccess.wildcard(READ).filter()).isEqualTo(new All());
    assertThat(ResourceAccess.allowed(READ.withResourceIds(List.of("d1", "d2"))).filter())
        .isEqualTo(new AnyOf(List.of(new Term(Set.of("d1", "d2"), List.of()))));
  }

  @Test
  void allowedAccessWithoutResourceIdsHasNoFilter() {
    assertThat(ResourceAccess.allowed(READ).filter()).isNull();
  }

  @Test
  void createsTheResultThatMatchesAFilter() {
    assertThat(ResourceAccess.of(READ, new None())).isEqualTo(ResourceAccess.denied(READ));
    assertThat(ResourceAccess.of(READ, new All())).isEqualTo(ResourceAccess.wildcard(READ));
    assertThat(ResourceAccess.of(READ, PAYMENTS))
        .isEqualTo(new ResourceAccess(true, false, READ, PAYMENTS));
  }

  @Test
  void rejectsAFilterThatContradictsTheVerdict() {
    assertThatThrownBy(() -> new ResourceAccess(false, false, READ, PAYMENTS))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new ResourceAccess(false, false, READ, null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new ResourceAccess(true, false, READ, new None()))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new ResourceAccess(true, true, READ, PAYMENTS))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new ResourceAccess(true, false, READ, new All()))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
