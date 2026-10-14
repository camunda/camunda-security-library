/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.policy;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.model.authz.EntityType;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class PolicyMembershipTest {

  static Stream<Arguments> allowed() {
    return Stream.of(
        Arguments.of(PolicyMembershipTarget.ROLE, EntityType.USER),
        Arguments.of(PolicyMembershipTarget.ROLE, EntityType.CLIENT),
        Arguments.of(PolicyMembershipTarget.ROLE, EntityType.MAPPING_RULE),
        Arguments.of(PolicyMembershipTarget.ROLE, EntityType.GROUP),
        Arguments.of(PolicyMembershipTarget.GROUP, EntityType.USER),
        Arguments.of(PolicyMembershipTarget.GROUP, EntityType.CLIENT),
        Arguments.of(PolicyMembershipTarget.GROUP, EntityType.MAPPING_RULE),
        Arguments.of(PolicyMembershipTarget.TENANT, EntityType.USER),
        Arguments.of(PolicyMembershipTarget.TENANT, EntityType.CLIENT),
        Arguments.of(PolicyMembershipTarget.TENANT, EntityType.MAPPING_RULE),
        Arguments.of(PolicyMembershipTarget.TENANT, EntityType.GROUP),
        Arguments.of(PolicyMembershipTarget.TENANT, EntityType.ROLE));
  }

  static Stream<Arguments> disallowed() {
    return Stream.of(
        Arguments.of(PolicyMembershipTarget.ROLE, EntityType.ROLE),
        Arguments.of(PolicyMembershipTarget.ROLE, EntityType.UNSPECIFIED),
        Arguments.of(PolicyMembershipTarget.GROUP, EntityType.ROLE),
        Arguments.of(PolicyMembershipTarget.GROUP, EntityType.GROUP),
        Arguments.of(PolicyMembershipTarget.GROUP, EntityType.UNSPECIFIED),
        Arguments.of(PolicyMembershipTarget.TENANT, EntityType.UNSPECIFIED));
  }

  @ParameterizedTest
  @MethodSource("allowed")
  void shouldAcceptCanonicalPair(final PolicyMembershipTarget target, final EntityType member) {
    assertThatCode(() -> new PolicyMembership(target, "t", member, "m")).doesNotThrowAnyException();
  }

  @ParameterizedTest
  @MethodSource("disallowed")
  void shouldRejectNonCanonicalPair(final PolicyMembershipTarget target, final EntityType member) {
    assertThatThrownBy(() -> new PolicyMembership(target, "t", member, "m"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @MethodSource("blankIds")
  void shouldRejectBlankIds(final String targetId, final String memberId) {
    assertThatThrownBy(
            () ->
                new PolicyMembership(
                    PolicyMembershipTarget.ROLE, targetId, EntityType.USER, memberId))
        .isInstanceOf(IllegalArgumentException.class);
  }

  static Stream<Arguments> blankIds() {
    return Stream.of(
        Arguments.of(null, "m"),
        Arguments.of(" ", "m"),
        Arguments.of("t", null),
        Arguments.of("t", ""));
  }

  @org.junit.jupiter.api.Test
  void shouldRejectNullEnums() {
    assertThatThrownBy(() -> new PolicyMembership(null, "t", EntityType.USER, "m"))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new PolicyMembership(PolicyMembershipTarget.ROLE, "t", null, "m"))
        .isInstanceOf(NullPointerException.class);
  }
}
