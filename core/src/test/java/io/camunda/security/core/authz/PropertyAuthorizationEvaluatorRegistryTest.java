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

import io.camunda.security.api.context.PropertyAuthorizationEvaluator;
import io.camunda.security.api.model.CamundaAuthentication;
import java.util.List;
import org.junit.jupiter.api.Test;

class PropertyAuthorizationEvaluatorRegistryTest {

  @Test
  void findEvaluatorWithKnownPropertyNameReturnsEvaluator() {
    final var evaluator = new TestEvaluator("assignee");
    final var registry = new PropertyAuthorizationEvaluatorRegistry(List.of(evaluator));
    assertThat(registry.<Task>findEvaluator("assignee")).contains(evaluator);
  }

  @Test
  void findEvaluatorWithUnknownPropertyNameReturnsEmpty() {
    final var registry =
        new PropertyAuthorizationEvaluatorRegistry(List.of(new TestEvaluator("assignee")));
    assertThat(registry.findEvaluator("candidateUsers")).isEmpty();
  }

  @Test
  void findEvaluatorWithEmptyRegistryReturnsEmpty() {
    final var registry = new PropertyAuthorizationEvaluatorRegistry(List.of());
    assertThat(registry.findEvaluator("assignee")).isEmpty();
  }

  @Test
  void findEvaluatorWithMultipleEvaluatorsReturnsCorrectOne() {
    final var assigneeEval = new TestEvaluator("assignee");
    final var candidateEval = new TestEvaluator("candidateUsers");
    final var registry =
        new PropertyAuthorizationEvaluatorRegistry(List.of(assigneeEval, candidateEval));
    assertThat(registry.<Task>findEvaluator("candidateUsers")).contains(candidateEval);
  }

  @Test
  void constructorWithDuplicatePropertyNamesThrowsIllegalStateException() {
    assertThatThrownBy(
            () ->
                new PropertyAuthorizationEvaluatorRegistry(
                    List.of(new TestEvaluator("assignee"), new TestEvaluator("assignee"))))
        .isInstanceOf(IllegalStateException.class);
  }

  record Task(String assignee) {}

  static final class TestEvaluator implements PropertyAuthorizationEvaluator<Task> {

    private final String name;

    TestEvaluator(final String name) {
      this.name = name;
    }

    @Override
    public String propertyName() {
      return name;
    }

    @Override
    public boolean isAuthorized(final CamundaAuthentication auth, final Task resource) {
      return true;
    }
  }
}
