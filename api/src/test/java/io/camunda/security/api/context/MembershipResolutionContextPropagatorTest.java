/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.context;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

class MembershipResolutionContextPropagatorTest {

  @Test
  void identityReturnsSupplierUnchanged() {
    // given
    final Supplier<List<String>> supplier = () -> List.of("a", "b");

    // when
    final var decorated = MembershipResolutionContextPropagator.identity().decorate(supplier);

    // then
    assertThat(decorated).isSameAs(supplier);
    assertThat(decorated.get()).containsExactly("a", "b");
  }

  @Test
  void decorateListAppliesTheDecorationToListsOfAnyElementType() {
    // given a propagator that records the order of binding and the deferred call
    final List<String> events = new ArrayList<>();
    final MembershipResolutionContextPropagator propagator =
        supplier ->
            () -> {
              events.add("bound");
              return supplier.get();
            };

    // when
    final Supplier<List<Integer>> decorated =
        propagator.decorateList(
            () -> {
              events.add("lookup");
              return List.of(1, 2);
            });

    // then the deferred lookup runs inside the host binding, not before the supplier is called
    assertThat(events).isEmpty();
    assertThat(decorated.get()).containsExactly(1, 2);
    assertThat(events).containsExactly("bound", "lookup");
  }

  @Test
  void decorateListWithIdentityReturnsTheLookupResult() {
    final Supplier<List<Integer>> decorated =
        MembershipResolutionContextPropagator.identity().decorateList(() -> List.of(1));

    assertThat(decorated.get()).containsExactly(1);
  }
}
