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
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

class TenantValidatorTest {

  private static final Pattern ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_~@.+-]+$");

  private static final TenantValidator VALIDATOR =
      new TenantValidator(new IdentifierValidator(ID_PATTERN, ID_PATTERN));

  @Test
  void shouldValidateMandatoryFields() {
    // when:
    final List<String> violations = VALIDATOR.validateCreate(null, "");

    // then:
    assertThat(violations)
        .containsExactlyInAnyOrder(
            ErrorMessages.ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("tenantId"),
            ErrorMessages.ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("name"));
  }

  @Test
  void shouldSuccessfullyConfigure() {
    // when:
    final List<String> violations = VALIDATOR.validateCreate("foo", "Foo");

    // then:
    assertThat(violations).isEmpty();
  }

  @Test
  void shouldRejectNameExceedingMaxLengthOnCreate() {
    // given:
    final String longName = "a".repeat(ValidationConstants.MAX_FIELD_LENGTH + 1);

    // when:
    final List<String> violations = VALIDATOR.validateCreate("foo", longName);

    // then:
    assertThat(violations)
        .containsExactly(
            ERROR_MESSAGE_TOO_MANY_CHARACTERS.formatted(
                "name", ValidationConstants.MAX_FIELD_LENGTH));
  }

  @Test
  void shouldAcceptNameAtMaxLengthOnCreate() {
    // given:
    final String maxName = "a".repeat(ValidationConstants.MAX_FIELD_LENGTH);

    // when:
    final List<String> violations = VALIDATOR.validateCreate("foo", maxName);

    // then:
    assertThat(violations).isEmpty();
  }

  @Test
  void shouldRejectNameExceedingMaxLengthOnUpdate() {
    // given:
    final String longName = "a".repeat(ValidationConstants.MAX_FIELD_LENGTH + 1);

    // when:
    final List<String> violations = VALIDATOR.validateUpdate(longName);

    // then:
    assertThat(violations)
        .containsExactly(
            ERROR_MESSAGE_TOO_MANY_CHARACTERS.formatted(
                "name", ValidationConstants.MAX_FIELD_LENGTH));
  }

  @Test
  void shouldAcceptNameAtMaxLengthOnUpdate() {
    // given:
    final String maxName = "a".repeat(ValidationConstants.MAX_FIELD_LENGTH);

    // when:
    final List<String> violations = VALIDATOR.validateUpdate(maxName);

    // then:
    assertThat(violations).isEmpty();
  }

  // ---- validateTenantMembers ----

  @Test
  void shouldReturnNoViolationsForNullTenantMemberList() {
    final List<String> violations = VALIDATOR.validateTenantMembers(null, EntityType.USER);

    assertThat(violations).isEmpty();
  }

  @Test
  void shouldReturnNoViolationsForValidTenantMembers() {
    final List<String> violations =
        VALIDATOR.validateTenantMembers(List.of("alice", "bob"), EntityType.USER);

    assertThat(violations).isEmpty();
  }

  @Test
  void shouldRejectTenantMemberWithIllegalCharacters() {
    final List<String> violations =
        VALIDATOR.validateTenantMembers(List.of("valid", "invalid id!"), EntityType.USER);

    assertThat(violations)
        .contains(ERROR_MESSAGE_ILLEGAL_CHARACTER.formatted("username", ID_PATTERN));
  }

  @ParameterizedTest
  @NullAndEmptySource
  void shouldRejectBlankTenantMemberIds(final String memberId) {
    final List<String> violations =
        VALIDATOR.validateTenantMembers(List.of(memberId == null ? "" : memberId), EntityType.USER);

    assertThat(violations).contains(ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("username"));
  }

  // ---- validateTenantMember ----

  @Test
  void shouldReturnNoViolationsForValidTenantMember() {
    final List<String> violations =
        VALIDATOR.validateTenantMember("my-tenant", "alice", EntityType.USER);

    assertThat(violations).isEmpty();
  }

  @Test
  void shouldRejectMissingTenantIdInValidateTenantMember() {
    final List<String> violations = VALIDATOR.validateTenantMember(null, "alice", EntityType.USER);

    assertThat(violations).contains(ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("tenantId"));
  }

  @Test
  void shouldRejectMissingMemberIdInValidateTenantMember() {
    final List<String> violations =
        VALIDATOR.validateTenantMember("my-tenant", null, EntityType.USER);

    assertThat(violations).contains(ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("username"));
  }

  @Test
  void shouldReturnAllViolationsWhenBothTenantMemberFieldsInvalid() {
    final List<String> violations = VALIDATOR.validateTenantMember(null, null, EntityType.USER);

    assertThat(violations)
        .containsExactlyInAnyOrder(
            ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("tenantId"),
            ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("username"));
  }
}
