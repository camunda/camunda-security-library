/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.context;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.CamundaAuthentication;
import org.junit.jupiter.api.Test;

class PropertyAuthorizationEvaluatorTest {

  private final CamundaAuthentication aliceAuth = CamundaAuthentication.of(b -> b.user("alice"));

  @Test
  void propertyNameIsReturnedCorrectly() {
    assertThat(new AssigneeEvaluator().propertyName()).isEqualTo("assignee");
  }

  @Test
  void isAuthorizedReturnsTrueWhenMatch() {
    assertThat(new AssigneeEvaluator().isAuthorized(aliceAuth, new Task("alice"))).isTrue();
  }

  @Test
  void isAuthorizedReturnsFalseWhenNoMatch() {
    assertThat(new AssigneeEvaluator().isAuthorized(aliceAuth, new Task("bob"))).isFalse();
  }

  @Test
  void isAuthorizedReceivesCorrectAuthAndResource() {
    final var receivedAuth = new CamundaAuthentication[1];
    final var receivedResource = new Task[1];
    final PropertyAuthorizationEvaluator<Task> evaluator =
        new PropertyAuthorizationEvaluator<>() {
          @Override
          public String propertyName() {
            return "assignee";
          }

          @Override
          public boolean isAuthorized(
              final CamundaAuthentication authentication, final Task resource) {
            receivedAuth[0] = authentication;
            receivedResource[0] = resource;
            return true;
          }
        };
    final var task = new Task("alice");
    evaluator.isAuthorized(aliceAuth, task);
    assertThat(receivedAuth[0]).isSameAs(aliceAuth);
    assertThat(receivedResource[0]).isSameAs(task);
  }

  record Task(String assignee) {}

  private static final class AssigneeEvaluator implements PropertyAuthorizationEvaluator<Task> {
    @Override
    public String propertyName() {
      return "assignee";
    }

    @Override
    public boolean isAuthorized(final CamundaAuthentication authentication, final Task resource) {
      return authentication.authenticatedUsername() != null
          && authentication.authenticatedUsername().equals(resource.assignee());
    }
  }
}
