/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static io.camunda.security.api.model.authz.AuthorizationResourceType.PROCESS_APPLICATION;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.PROCESS_DEFINITION;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.USER_TASK;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.WORKSPACE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.context.ResourceAttributeExtractor;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.ResourceAttribute;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ResourceAttributeExtractorRegistryTest {

  @Test
  void findMatchingWithKnownResourceTypeAndClassReturnsExtractor() {
    final var extractor = new TestExtractor<>(PROCESS_APPLICATION, String.class, Map.of());
    final var registry = new ResourceAttributeExtractorRegistry(List.of(extractor));

    assertThat(registry.<String>findMatching(PROCESS_APPLICATION, "pa")).contains(extractor);
  }

  @Test
  void findMatchingWithUnknownResourceTypeOrClassReturnsEmpty() {
    final var registry =
        new ResourceAttributeExtractorRegistry(
            List.of(new TestExtractor<>(PROCESS_APPLICATION, String.class, Map.of())));

    assertThat(registry.findMatching(WORKSPACE, "w")).isEmpty();
    assertThat(registry.findMatching(PROCESS_APPLICATION, 1L)).isEmpty();
  }

  @Test
  void findMatchingWithMultipleClassesPerResourceTypeReturnsMatchingExtractor() {
    final var stringExtractor = new TestExtractor<>(PROCESS_APPLICATION, String.class, Map.of());
    final var integerExtractor = new TestExtractor<>(PROCESS_APPLICATION, Integer.class, Map.of());
    final var registry =
        new ResourceAttributeExtractorRegistry(List.of(stringExtractor, integerExtractor));

    assertThat(registry.<String>findMatching(PROCESS_APPLICATION, "pa")).contains(stringExtractor);
    assertThat(registry.<Integer>findMatching(PROCESS_APPLICATION, 1)).contains(integerExtractor);
  }

  @Test
  void hasExtractorsForIsTrueOnlyForRegisteredResourceTypes() {
    final var registry =
        new ResourceAttributeExtractorRegistry(
            List.of(new TestExtractor<>(PROCESS_APPLICATION, String.class, Map.of())));

    assertThat(registry.hasExtractorsFor(PROCESS_APPLICATION)).isTrue();
    assertThat(registry.hasExtractorsFor(WORKSPACE)).isFalse();
  }

  @Test
  void attributesOfReturnsTheAttributesOfTheExtractor() {
    final var attributes = Map.of(ResourceAttribute.WORKSPACE, Set.of("w1"));
    final var registry =
        new ResourceAttributeExtractorRegistry(
            List.of(new TestExtractor<>(PROCESS_APPLICATION, String.class, attributes)));

    assertThat(registry.attributesOf(PROCESS_APPLICATION, "pa")).isEqualTo(attributes);
  }

  @Test
  void attributesOfTreatsNullAttributesAsEmpty() {
    final var registry =
        new ResourceAttributeExtractorRegistry(
            List.of(new TestExtractor<>(PROCESS_APPLICATION, String.class, null)));

    assertThat(registry.attributesOf(PROCESS_APPLICATION, "pa")).isEmpty();
  }

  @Test
  void attributesOfWithNoMatchingClassThrowsIllegalArgumentException() {
    final var registry =
        new ResourceAttributeExtractorRegistry(
            List.of(new TestExtractor<>(PROCESS_APPLICATION, String.class, Map.of())));

    assertThatThrownBy(() -> registry.attributesOf(PROCESS_APPLICATION, 1L))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("java.lang.Long");
  }

  @Test
  void attributesOfWithNullResourceThrowsNullPointerException() {
    final var registry =
        new ResourceAttributeExtractorRegistry(
            List.of(new TestExtractor<>(PROCESS_APPLICATION, String.class, Map.of())));

    assertThatThrownBy(() -> registry.attributesOf(PROCESS_APPLICATION, null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void attributesOfRejectsAttributesThatTheResourceTypeDoesNotDeclare() {
    final var registry =
        new ResourceAttributeExtractorRegistry(
            List.of(
                new TestExtractor<>(
                    PROCESS_APPLICATION,
                    String.class,
                    Map.of(ResourceAttribute.ASSIGNEE, Set.of("a")))));

    assertThatThrownBy(() -> registry.attributesOf(PROCESS_APPLICATION, "pa"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("ASSIGNEE");
  }

  @Test
  void constructorWithDuplicateResourceTypeAndClassThrowsIllegalStateException() {
    final var first = new TestExtractor<>(PROCESS_APPLICATION, String.class, Map.of());
    final var second = new TestExtractor<>(PROCESS_APPLICATION, String.class, Map.of());

    assertThatThrownBy(() -> new ResourceAttributeExtractorRegistry(List.of(first, second)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("PROCESS_APPLICATION")
        .hasMessageContaining("java.lang.String");
  }

  @Test
  void constructorWithResourceTypeThatDeclaresNoAttributesThrowsIllegalStateException() {
    final var extractor = new TestExtractor<>(PROCESS_DEFINITION, String.class, Map.of());

    assertThatThrownBy(() -> new ResourceAttributeExtractorRegistry(List.of(extractor)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("provides no attributes");
  }

  @Test
  void constructorRejectsProvidedAttributesThatTheResourceTypeDoesNotDeclare() {
    final var extractor =
        new TestExtractor<>(
            PROCESS_APPLICATION,
            String.class,
            Set.of(ResourceAttribute.WORKSPACE, ResourceAttribute.ASSIGNEE),
            Map.of());

    assertThatThrownBy(() -> new ResourceAttributeExtractorRegistry(List.of(extractor)))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("ASSIGNEE");
  }

  @Test
  void attributesOfRejectsDeclaredAttributesTheExtractorDoesNotProvide() {
    final var extractor =
        new TestExtractor<>(
            USER_TASK,
            String.class,
            Set.of(ResourceAttribute.ASSIGNEE),
            Map.of(ResourceAttribute.CANDIDATE_USERS, Set.of("a")));
    final var registry = new ResourceAttributeExtractorRegistry(List.of(extractor));

    assertThatThrownBy(() -> registry.attributesOf(USER_TASK, "task"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("CANDIDATE_USERS");
  }

  @Test
  void attributesOfRemovesNullElementsEmptyStringsAndNullValueSets() {
    final var withNull = new HashSet<String>();
    withNull.add(null);
    withNull.add("w1");
    withNull.add("");
    final var attributes = new HashMap<ResourceAttribute, Set<String>>();
    attributes.put(ResourceAttribute.WORKSPACE, withNull);
    final var nullSet =
        new TestExtractor<>(
            USER_TASK, Integer.class, Map.of(ResourceAttribute.ASSIGNEE, Set.of("")));
    final var registry =
        new ResourceAttributeExtractorRegistry(
            List.of(new TestExtractor<>(PROCESS_APPLICATION, String.class, attributes), nullSet));

    assertThat(registry.attributesOf(PROCESS_APPLICATION, "pa"))
        .isEqualTo(Map.of(ResourceAttribute.WORKSPACE, Set.of("w1")));
    assertThat(registry.attributesOf(USER_TASK, 1)).isEmpty();
  }

  private record TestExtractor<T>(
      AuthorizationResourceType resourceType,
      Class<T> resourceClass,
      Set<ResourceAttribute> providedAttributes,
      Map<ResourceAttribute, Set<String>> attributes)
      implements ResourceAttributeExtractor<T> {

    TestExtractor(
        final AuthorizationResourceType resourceType,
        final Class<T> resourceClass,
        final Map<ResourceAttribute, Set<String>> attributes) {
      this(resourceType, resourceClass, resourceType.getSupportedAttributes(), attributes);
    }

    @Override
    public Map<ResourceAttribute, Set<String>> attributesOf(final T resource) {
      return attributes;
    }
  }
}
