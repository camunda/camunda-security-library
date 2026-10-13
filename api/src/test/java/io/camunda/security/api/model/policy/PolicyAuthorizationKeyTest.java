/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.model.authz.AuthorizationOwnerType;
import io.camunda.security.api.model.authz.AuthorizationResourceMatcher;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class PolicyAuthorizationKeyTest {

  private static PolicyAuthorizationKey key(
      final AuthorizationResourceMatcher matcher, final String id, final String property) {
    return new PolicyAuthorizationKey(
        AuthorizationOwnerType.ROLE,
        "role-1",
        AuthorizationResourceType.RESOURCE,
        matcher,
        id,
        property);
  }

  @Test
  void shouldAcceptValidKeys() {
    assertThat(key(AuthorizationResourceMatcher.ID, "p1", null).resourcePropertyName()).isEmpty();
    assertThat(key(AuthorizationResourceMatcher.ANY, "*", "").resourceId()).isEqualTo("*");
    assertThat(key(AuthorizationResourceMatcher.PROPERTY, null, "assignee").resourceId()).isEmpty();
  }

  @Test
  void shouldNormaliseNullToEmptyForEquality() {
    assertThat(key(AuthorizationResourceMatcher.PROPERTY, null, "assignee"))
        .isEqualTo(key(AuthorizationResourceMatcher.PROPERTY, "", "assignee"))
        .hasSameHashCodeAs(key(AuthorizationResourceMatcher.PROPERTY, "", "assignee"));
  }

  @ParameterizedTest
  @CsvSource(
      value = {
        "ID,,",
        "ID,'',",
        "ID,*,",
        "ID,p1,prop",
        "ANY,,",
        "ANY,p1,",
        "ANY,*,prop",
        "PROPERTY,,",
        "PROPERTY,p1,prop",
        "PROPERTY,,' '",
        "UNSPECIFIED,*,"
      })
  void shouldRejectInvalidScope(
      final AuthorizationResourceMatcher matcher, final String id, final String property) {
    assertThatThrownBy(() -> key(matcher, id, property))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void shouldRejectInvalidOwner() {
    assertThatThrownBy(
            () ->
                new PolicyAuthorizationKey(
                    AuthorizationOwnerType.UNSPECIFIED,
                    "o",
                    AuthorizationResourceType.RESOURCE,
                    AuthorizationResourceMatcher.ANY,
                    "*",
                    null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                new PolicyAuthorizationKey(
                    AuthorizationOwnerType.ROLE,
                    " ",
                    AuthorizationResourceType.RESOURCE,
                    AuthorizationResourceMatcher.ANY,
                    "*",
                    null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                new PolicyAuthorizationKey(
                    null,
                    "o",
                    AuthorizationResourceType.RESOURCE,
                    AuthorizationResourceMatcher.ANY,
                    "*",
                    null))
        .isInstanceOf(NullPointerException.class);
  }
}
