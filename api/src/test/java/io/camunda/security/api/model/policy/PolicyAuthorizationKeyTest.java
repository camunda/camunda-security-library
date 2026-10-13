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

  private static final AuthorizationResourceType RESOURCE = AuthorizationResourceType.RESOURCE;

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
  void shouldRejectUnspecifiedOwnerType() {
    assertThatThrownBy(() -> create(AuthorizationOwnerType.UNSPECIFIED, "o", RESOURCE))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void shouldRejectBlankOwnerId() {
    assertThatThrownBy(() -> create(AuthorizationOwnerType.ROLE, " ", RESOURCE))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void shouldRejectNullOwnerType() {
    assertThatThrownBy(() -> create(null, "o", RESOURCE)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void shouldRejectUnspecifiedResourceType() {
    assertThatThrownBy(
            () -> create(AuthorizationOwnerType.ROLE, "o", AuthorizationResourceType.UNSPECIFIED))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("resourceType");
  }

  private static PolicyAuthorizationKey create(
      final AuthorizationOwnerType ownerType,
      final String ownerId,
      final AuthorizationResourceType resourceType) {
    return new PolicyAuthorizationKey(
        ownerType, ownerId, resourceType, AuthorizationResourceMatcher.ANY, "*", null);
  }
}
