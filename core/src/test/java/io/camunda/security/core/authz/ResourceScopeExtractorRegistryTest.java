/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static io.camunda.security.api.model.authz.AuthorizationResourceType.PROCESS_APPLICATION;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.WORKSPACE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.context.ResourceScopeExtractor;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import java.util.List;
import org.junit.jupiter.api.Test;

class ResourceScopeExtractorRegistryTest {

  @Test
  void findExtractorWithKnownResourceTypeAndClassReturnsExtractor() {
    final var extractor = new TestExtractor<>(PROCESS_APPLICATION, String.class);
    final var registry = new ResourceScopeExtractorRegistry(List.of(extractor));
    assertThat(registry.<String>findExtractor(PROCESS_APPLICATION, "pa")).contains(extractor);
  }

  @Test
  void findExtractorWithUnknownResourceTypeReturnsEmpty() {
    final var registry =
        new ResourceScopeExtractorRegistry(
            List.of(new TestExtractor<>(PROCESS_APPLICATION, String.class)));
    assertThat(registry.findExtractor(WORKSPACE, "w")).isEmpty();
  }

  @Test
  void findExtractorWithMultipleClassesPerResourceTypeReturnsMatchingExtractor() {
    final var stringExtractor = new TestExtractor<>(PROCESS_APPLICATION, String.class);
    final var integerExtractor = new TestExtractor<>(PROCESS_APPLICATION, Integer.class);
    final var registry =
        new ResourceScopeExtractorRegistry(List.of(stringExtractor, integerExtractor));
    assertThat(registry.<String>findExtractor(PROCESS_APPLICATION, "pa")).contains(stringExtractor);
    assertThat(registry.<Integer>findExtractor(PROCESS_APPLICATION, 1)).contains(integerExtractor);
  }

  @Test
  void findExtractorWithNoMatchingClassThrowsIllegalArgumentException() {
    final var registry =
        new ResourceScopeExtractorRegistry(
            List.of(new TestExtractor<>(PROCESS_APPLICATION, String.class)));
    assertThatThrownBy(() -> registry.findExtractor(PROCESS_APPLICATION, 1L))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("java.lang.Long");
  }

  @Test
  void findExtractorWithNullResourceThrowsNullPointerException() {
    final var registry =
        new ResourceScopeExtractorRegistry(
            List.of(new TestExtractor<>(PROCESS_APPLICATION, String.class)));
    assertThatThrownBy(() -> registry.findExtractor(PROCESS_APPLICATION, null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void constructorWithDuplicateResourceTypeAndClassThrowsIllegalStateException() {
    assertThatThrownBy(
            () ->
                new ResourceScopeExtractorRegistry(
                    List.of(
                        new TestExtractor<>(PROCESS_APPLICATION, String.class),
                        new TestExtractor<>(PROCESS_APPLICATION, String.class))))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void findMatchingReturnsEmptyWhenNoClassMatchesInsteadOfThrowing() {
    final var registry =
        new ResourceScopeExtractorRegistry(
            List.of(new TestExtractor<>(PROCESS_APPLICATION, String.class)));

    assertThat(registry.findMatching(PROCESS_APPLICATION, 1L)).isEmpty();
    assertThat(registry.findMatching(WORKSPACE, "w")).isEmpty();
  }

  @Test
  void findMatchingReturnsTheExtractorOfTheMatchingClass() {
    final var extractor = new TestExtractor<>(PROCESS_APPLICATION, String.class);
    final var registry = new ResourceScopeExtractorRegistry(List.of(extractor));

    assertThat(registry.<String>findMatching(PROCESS_APPLICATION, "pa")).contains(extractor);
  }

  @Test
  void hasExtractorsForIsTrueOnlyForRegisteredResourceTypes() {
    final var registry =
        new ResourceScopeExtractorRegistry(
            List.of(new TestExtractor<>(PROCESS_APPLICATION, String.class)));

    assertThat(registry.hasExtractorsFor(PROCESS_APPLICATION)).isTrue();
    assertThat(registry.hasExtractorsFor(WORKSPACE)).isFalse();
  }

  private record TestExtractor<T>(AuthorizationResourceType resourceType, Class<T> resourceClass)
      implements ResourceScopeExtractor<T> {

    @Override
    public String scopeIdOf(final T resource) {
      return String.valueOf(resource);
    }
  }
}
