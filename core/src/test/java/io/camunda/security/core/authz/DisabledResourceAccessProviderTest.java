/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.auth.RequiredAuthorization;
import org.junit.jupiter.api.Test;

class DisabledResourceAccessProviderTest {

  private final DisabledResourceAccessProvider resourceAccessProvider =
      new DisabledResourceAccessProvider();

  @Test
  void shouldWildcardResolveResourceAccessRegardlessOfAuthentication() {
    // given
    final var authentication = CamundaAuthentication.of(a -> a.user("foo"));
    final var authorization =
        RequiredAuthorization.of(a -> a.processDefinition().readProcessDefinition());

    // when
    final var result = resourceAccessProvider.resolveResourceAccess(authentication, authorization);

    // then
    assertThat(result.denied()).isFalse();
    assertThat(result.allowed()).isTrue();
    assertThat(result.wildcard()).isTrue();
  }

  @Test
  void shouldWildcardHasResourceAccessRegardlessOfResource() {
    // given
    final var authentication = CamundaAuthentication.of(a -> a.user("foo"));
    final var authorization =
        RequiredAuthorization.of(a -> a.processDefinition().readProcessDefinition());
    final var resource = new Object();

    // when
    final var result =
        resourceAccessProvider.hasResourceAccess(authentication, authorization, resource);

    // then
    assertThat(result.denied()).isFalse();
    assertThat(result.allowed()).isTrue();
    assertThat(result.wildcard()).isTrue();
  }

  @Test
  void shouldWildcardHasResourceAccessByResourceIdRegardlessOfResourceId() {
    // given
    final var authentication = CamundaAuthentication.of(a -> a.user("foo"));
    final var authorization =
        RequiredAuthorization.of(a -> a.processDefinition().readProcessDefinition());

    // when
    final var result =
        resourceAccessProvider.hasResourceAccessByResourceId(authentication, authorization, "any");

    // then
    assertThat(result.denied()).isFalse();
    assertThat(result.allowed()).isTrue();
    assertThat(result.wildcard()).isTrue();
  }
}
