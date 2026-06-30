/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.context;

import static org.assertj.core.api.Assertions.assertThat;

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
}
