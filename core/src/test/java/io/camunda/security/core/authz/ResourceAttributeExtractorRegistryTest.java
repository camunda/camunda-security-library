/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static io.camunda.security.api.model.authz.AuthorizationResourceType.PROCESS_DEFINITION;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.USER_TASK;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.context.ResourceAttributeExtractor;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.ResourceAttribute;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ResourceAttributeExtractorRegistryTest {

  @Test
  void findsTheExtractorWhoseClassAcceptsTheResource() {
    // given
    final var forStrings = new FixedExtractor<>(PROCESS_DEFINITION, String.class);
    final var forIntegers = new FixedExtractor<>(PROCESS_DEFINITION, Integer.class);
    final var registry = new ResourceAttributeExtractorRegistry(List.of(forStrings, forIntegers));

    // when / then
    assertThat(registry.findMatching(PROCESS_DEFINITION, "resource")).containsSame(forStrings);
    assertThat(registry.findMatching(PROCESS_DEFINITION, 42)).containsSame(forIntegers);
  }

  @Test
  void findsNoExtractorForAnotherClass() {
    // given
    final var registry =
        new ResourceAttributeExtractorRegistry(
            List.of(new FixedExtractor<>(PROCESS_DEFINITION, String.class)));

    // when / then
    assertThat(registry.findMatching(PROCESS_DEFINITION, 42L)).isEmpty();
  }

  @Test
  void findsNoExtractorForAnotherResourceType() {
    // given
    final var registry =
        new ResourceAttributeExtractorRegistry(
            List.of(new FixedExtractor<>(PROCESS_DEFINITION, String.class)));

    // when / then
    assertThat(registry.findMatching(USER_TASK, "resource")).isEmpty();
    assertThat(registry.hasExtractorsFor(USER_TASK)).isFalse();
    assertThat(registry.hasExtractorsFor(PROCESS_DEFINITION)).isTrue();
  }

  @Test
  void rejectsTwoExtractorsForTheSameResourceTypeAndClass() {
    // given
    final var extractors =
        List.of(
            new FixedExtractor<>(PROCESS_DEFINITION, String.class),
            new FixedExtractor<>(PROCESS_DEFINITION, String.class));

    // when / then
    assertThatThrownBy(() -> new ResourceAttributeExtractorRegistry(extractors))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("PROCESS_DEFINITION")
        .hasMessageContaining(String.class.getName());
  }

  @Test
  void acceptsTheSameClassForDifferentResourceTypes() {
    // given
    final var extractors =
        List.of(
            new FixedExtractor<>(PROCESS_DEFINITION, String.class),
            new FixedExtractor<>(USER_TASK, String.class));

    // when
    final var registry = new ResourceAttributeExtractorRegistry(extractors);

    // then
    assertThat(registry.hasExtractorsFor(PROCESS_DEFINITION)).isTrue();
    assertThat(registry.hasExtractorsFor(USER_TASK)).isTrue();
  }

  @Test
  void hasNoExtractorsWhenEmpty() {
    // given
    final var registry = new ResourceAttributeExtractorRegistry(List.of());

    // when / then
    assertThat(registry.hasExtractorsFor(PROCESS_DEFINITION)).isFalse();
    assertThat(registry.findMatching(PROCESS_DEFINITION, "resource")).isEmpty();
  }

  private record FixedExtractor<T>(AuthorizationResourceType resourceType, Class<T> resourceClass)
      implements ResourceAttributeExtractor<T> {

    @Override
    public Map<ResourceAttribute, Set<String>> attributesOf(final T resource) {
      return Map.of();
    }
  }
}
