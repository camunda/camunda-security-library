/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.validation;

import static io.camunda.security.validation.ErrorMessages.ERROR_MESSAGE_EMPTY_ATTRIBUTE;
import static io.camunda.security.validation.ErrorMessages.ERROR_MESSAGE_TOO_MANY_CHARACTERS;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class ClusterVariableValidatorTest {

  private static final Pattern ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_~@.+-]+$");

  private static final ClusterVariableValidator VALIDATOR =
      new ClusterVariableValidator(new IdentifierValidator(ID_PATTERN, ID_PATTERN));

  // ---- validateGlobalClusterVariableRequest ----

  @Test
  void shouldReturnNoViolationsForValidGlobalRequest() {
    // when:
    final List<String> violations = VALIDATOR.validateGlobalClusterVariableRequest("my-var");

    // then:
    assertThat(violations).isEmpty();
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"   "})
  void shouldRejectMissingNameInGlobalRequest(final String name) {
    // when:
    final List<String> violations = VALIDATOR.validateGlobalClusterVariableRequest(name);

    // then:
    assertThat(violations).contains(ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("name"));
  }

  @Test
  void shouldRejectNameExceedingMaxLengthInGlobalRequest() {
    // given:
    final String longName = "a".repeat(ValidationConstants.MAX_FIELD_LENGTH + 1);

    // when:
    final List<String> violations = VALIDATOR.validateGlobalClusterVariableRequest(longName);

    // then:
    assertThat(violations)
        .contains(
            ERROR_MESSAGE_TOO_MANY_CHARACTERS.formatted(
                "name", ValidationConstants.MAX_FIELD_LENGTH));
  }

  // ---- validateGlobalClusterVariableRequestWithValue ----

  @Test
  void shouldReturnNoViolationsForValidGlobalRequestWithValue() {
    // when:
    final List<String> violations =
        VALIDATOR.validateGlobalClusterVariableRequestWithValue("my-var", "some-value");

    // then:
    assertThat(violations).isEmpty();
  }

  @Test
  void shouldRejectNullValueInGlobalRequest() {
    // when:
    final List<String> violations =
        VALIDATOR.validateGlobalClusterVariableRequestWithValue("my-var", null);

    // then:
    assertThat(violations).contains(ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("value"));
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"   "})
  void shouldRejectMissingNameInGlobalRequestWithValue(final String name) {
    // when:
    final List<String> violations =
        VALIDATOR.validateGlobalClusterVariableRequestWithValue(name, "some-value");

    // then:
    assertThat(violations).contains(ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("name"));
  }

  @Test
  void shouldCollectAllViolationsInGlobalRequestWithValue() {
    // when:
    final List<String> violations =
        VALIDATOR.validateGlobalClusterVariableRequestWithValue(null, null);

    // then:
    assertThat(violations)
        .containsExactlyInAnyOrder(
            ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("name"),
            ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("value"));
  }

  // ---- validateTenantClusterVariableRequest ----

  @Test
  void shouldReturnNoViolationsForValidTenantRequest() {
    // when:
    final List<String> violations =
        VALIDATOR.validateTenantClusterVariableRequest("my-var", "my-tenant");

    // then:
    assertThat(violations).isEmpty();
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"   "})
  void shouldRejectMissingNameInTenantRequest(final String name) {
    // when:
    final List<String> violations =
        VALIDATOR.validateTenantClusterVariableRequest(name, "my-tenant");

    // then:
    assertThat(violations).contains(ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("name"));
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"   "})
  void shouldRejectMissingTenantIdInTenantRequest(final String tenantId) {
    // when:
    final List<String> violations =
        VALIDATOR.validateTenantClusterVariableRequest("my-var", tenantId);

    // then:
    assertThat(violations).contains(ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("tenantId"));
  }

  @Test
  void shouldCollectAllViolationsInTenantRequest() {
    // when:
    final List<String> violations = VALIDATOR.validateTenantClusterVariableRequest(null, null);

    // then:
    assertThat(violations)
        .containsExactlyInAnyOrder(
            ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("name"),
            ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("tenantId"));
  }

  // ---- validateTenantClusterVariableRequestWithValue ----

  @Test
  void shouldReturnNoViolationsForValidTenantRequestWithValue() {
    // when:
    final List<String> violations =
        VALIDATOR.validateTenantClusterVariableRequestWithValue(
            "my-var", "some-value", "my-tenant");

    // then:
    assertThat(violations).isEmpty();
  }

  @Test
  void shouldRejectNullValueInTenantRequest() {
    // when:
    final List<String> violations =
        VALIDATOR.validateTenantClusterVariableRequestWithValue("my-var", null, "my-tenant");

    // then:
    assertThat(violations).contains(ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("value"));
  }

  @Test
  void shouldCollectAllViolationsInTenantRequestWithValue() {
    // when:
    final List<String> violations =
        VALIDATOR.validateTenantClusterVariableRequestWithValue(null, null, null);

    // then:
    assertThat(violations)
        .containsExactlyInAnyOrder(
            ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("name"),
            ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("tenantId"),
            ERROR_MESSAGE_EMPTY_ATTRIBUTE.formatted("value"));
  }
}
