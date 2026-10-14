/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.policy;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class PolicyEntitiesTest {

  static Stream<Arguments> entities() {
    return Stream.of(
        factory("tenant", id -> new PolicyTenant(id, "n", "d")),
        factory("role", id -> new PolicyRole(id, "n", "d")),
        factory("group", id -> new PolicyGroup(id, "n", "d")),
        factory("mappingRule", id -> new PolicyMappingRule(id, "n", "claim", "value")));
  }

  private static Arguments factory(final String name, final Function<String, Object> create) {
    return Arguments.of(Named.of(name, create));
  }

  @ParameterizedTest
  @MethodSource("entities")
  void shouldRejectBlankId(final Function<String, Object> create) {
    assertThatThrownBy(() -> create.apply(null)).isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> create.apply("")).isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> create.apply("  ")).isInstanceOf(IllegalArgumentException.class);
  }
}
