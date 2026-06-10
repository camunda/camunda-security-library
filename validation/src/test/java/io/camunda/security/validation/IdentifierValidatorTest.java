/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.validation;

import static io.camunda.security.validation.ErrorMessages.ERROR_MESSAGE_EMPTY_ATTRIBUTE;
import static io.camunda.security.validation.ErrorMessages.ERROR_MESSAGE_ILLEGAL_CHARACTER;
import static io.camunda.security.validation.ErrorMessages.ERROR_MESSAGE_TOO_MANY_CHARACTERS;
import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.authz.EntityType;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class IdentifierValidatorTest {

  private static final Pattern ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_~@.+-]+$");
  private static final Pattern GROUP_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_~@.+\\-/]+$");

  private static final IdentifierValidator VALIDATOR =
      new IdentifierValidator(ID_PATTERN, GROUP_ID_PATTERN);

  // ---- validateId (standard) ----

  @Test
  void shouldReturnNoViolationsForValidId() {
    // given
    final var violations = new ArrayList<String>();

    // when
    VALIDATOR.validateId("valid-id", "myId", violations);

    // then
    assertThat(violations).isEmpty();
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"   "})
  void shouldRejectBlankOrNullId(final String id) {
    // given
    final var violations = new ArrayList<String>();

    // when
    VALIDATOR.validateId(id, "myId", violations);

    // then
    assertThat(violations).containsExactly(ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("myId"));
  }

  @Test
  void shouldRejectIdExceedingMaxLength() {
    // given
    final var violations = new ArrayList<String>();
    final String longId = "a".repeat(ValidationConstants.MAX_FIELD_LENGTH + 1);

    // when
    VALIDATOR.validateId(longId, "myId", violations);

    // then
    assertThat(violations)
        .containsExactly(
            ERROR_MESSAGE_TOO_MANY_CHARACTERS.formatted(
                "myId", ValidationConstants.MAX_FIELD_LENGTH));
  }

  @Test
  void shouldAcceptIdAtMaxLength() {
    // given
    final var violations = new ArrayList<String>();
    final String maxId = "a".repeat(ValidationConstants.MAX_FIELD_LENGTH);

    // when
    VALIDATOR.validateId(maxId, "myId", violations);

    // then
    assertThat(violations).isEmpty();
  }

  @Test
  void shouldRejectIdWithIllegalCharacters() {
    // given
    final var violations = new ArrayList<String>();

    // when
    VALIDATOR.validateId("invalid id!", "myId", violations);

    // then
    assertThat(violations)
        .containsExactly(ERROR_MESSAGE_ILLEGAL_CHARACTER.formatted("myId", ID_PATTERN));
  }

  // ---- validateId with alternativeCheck ----

  @Test
  void shouldAcceptIdMatchingAlternativeCheck() {
    // given
    final var violations = new ArrayList<String>();

    // when — "*" is rejected by the standard pattern but accepted by the alternative check
    VALIDATOR.validateId("*", "resourceId", violations, "*"::equals);

    // then
    assertThat(violations).isEmpty();
  }

  @Test
  void shouldRejectIdFailingBothPatternAndAlternativeCheck() {
    // given
    final var violations = new ArrayList<String>();

    // when
    VALIDATOR.validateId("invalid$id", "resourceId", violations, "*"::equals);

    // then
    assertThat(violations)
        .containsExactly(ERROR_MESSAGE_ILLEGAL_CHARACTER.formatted("resourceId", ID_PATTERN));
  }

  // ---- validateTenantId ----

  @Test
  void shouldAcceptValidTenantId() {
    // given
    final var violations = new ArrayList<String>();

    // when
    VALIDATOR.validateTenantId("my-tenant", violations);

    // then
    assertThat(violations).isEmpty();
  }

  @Test
  void shouldAcceptDefaultTenantId() {
    // given
    final var violations = new ArrayList<String>();

    // when — "<default>" is the alternative-check special case for tenant IDs
    VALIDATOR.validateTenantId("<default>", violations);

    // then
    assertThat(violations).isEmpty();
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"   "})
  void shouldRejectBlankOrNullTenantId(final String id) {
    // given
    final var violations = new ArrayList<String>();

    // when
    VALIDATOR.validateTenantId(id, violations);

    // then
    assertThat(violations).containsExactly(ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("tenantId"));
  }

  @Test
  void shouldRejectTenantIdExceedingMaxLength() {
    // given
    final var violations = new ArrayList<String>();
    final String longId = "a".repeat(32); // max is 31

    // when
    VALIDATOR.validateTenantId(longId, violations);

    // then
    assertThat(violations)
        .containsExactly(ERROR_MESSAGE_TOO_MANY_CHARACTERS.formatted("tenantId", 31));
  }

  @Test
  void shouldAcceptTenantIdAtMaxLength() {
    // given
    final var violations = new ArrayList<String>();
    final String maxId = "a".repeat(31);

    // when
    VALIDATOR.validateTenantId(maxId, violations);

    // then
    assertThat(violations).isEmpty();
  }

  @Test
  void shouldRejectTenantIdWithIllegalCharacters() {
    // given
    final var violations = new ArrayList<String>();

    // when — tenant IDs use TENANT_ID_MASK, which disallows characters outside [\w.-]
    VALIDATOR.validateTenantId("invalid tenant!", violations);

    // then
    assertThat(violations)
        .containsExactly(
            ERROR_MESSAGE_ILLEGAL_CHARACTER.formatted(
                "tenantId", IdentifierValidator.TENANT_ID_MASK));
  }

  // ---- validateGroupId ----

  @Test
  void shouldAcceptValidGroupId() {
    // given
    final var violations = new ArrayList<String>();

    // when
    VALIDATOR.validateGroupId("my/group", violations);

    // then
    assertThat(violations).isEmpty();
  }

  @ParameterizedTest
  @NullAndEmptySource
  void shouldRejectBlankOrNullGroupId(final String id) {
    // given
    final var violations = new ArrayList<String>();

    // when
    VALIDATOR.validateGroupId(id, violations);

    // then
    assertThat(violations).containsExactly(ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("groupId"));
  }

  // ---- validateMemberId dispatch ----

  @Test
  void shouldDispatchUserMemberIdAsUsername() {
    // given
    final var violations = new ArrayList<String>();

    // when
    VALIDATOR.validateMemberId(null, EntityType.USER, violations);

    // then
    assertThat(violations).containsExactly(ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("username"));
  }

  @Test
  void shouldDispatchRoleMemberIdAsRoleId() {
    // given
    final var violations = new ArrayList<String>();

    // when
    VALIDATOR.validateMemberId(null, EntityType.ROLE, violations);

    // then
    assertThat(violations).containsExactly(ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("roleId"));
  }

  @Test
  void shouldDispatchMappingRuleMemberIdAsMappingRuleId() {
    // given
    final var violations = new ArrayList<String>();

    // when
    VALIDATOR.validateMemberId(null, EntityType.MAPPING_RULE, violations);

    // then
    assertThat(violations)
        .containsExactly(ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("mappingRuleId"));
  }

  @Test
  void shouldDispatchGroupMemberIdUsingGroupIdPattern() {
    // given
    final var violations = new ArrayList<String>();

    // when — "/" is valid in groupIdPattern but not in idPattern
    VALIDATOR.validateMemberId("group/name", EntityType.GROUP, violations);

    // then
    assertThat(violations).isEmpty();
  }

  @Test
  void shouldDispatchClientMemberIdAsClientId() {
    // given
    final var violations = new ArrayList<String>();

    // when
    VALIDATOR.validateMemberId(null, EntityType.CLIENT, violations);

    // then
    assertThat(violations).containsExactly(ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("clientId"));
  }

  // ---- validateMembers ----

  @Test
  void shouldReturnEmptyListForNullMembers() {
    // when
    final List<String> violations = VALIDATOR.validateMembers(null, EntityType.USER);

    // then
    assertThat(violations).isEmpty();
  }

  @Test
  void shouldReturnNoViolationsForValidMembers() {
    // when
    final List<String> violations =
        VALIDATOR.validateMembers(List.of("alice", "bob"), EntityType.USER);

    // then
    assertThat(violations).isEmpty();
  }

  @Test
  void shouldAccumulateViolationsAcrossAllMembers() {
    // when
    final List<String> violations =
        VALIDATOR.validateMembers(List.of("", "invalid id!"), EntityType.USER);

    // then
    assertThat(violations)
        .containsExactlyInAnyOrder(
            ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("username"),
            ERROR_MESSAGE_ILLEGAL_CHARACTER.formatted("username", ID_PATTERN));
  }
}
