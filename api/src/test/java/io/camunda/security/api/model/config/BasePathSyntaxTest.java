/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;

import org.junit.jupiter.api.Test;

class BasePathSyntaxTest {

  @Test
  void shouldAcceptSimplePath() {
    assertThat(BasePathSyntax.isValid("/scope")).isTrue();
  }

  @Test
  void shouldAcceptNestedPath() {
    assertThat(BasePathSyntax.isValid("/a/b")).isTrue();
  }

  @Test
  void shouldAcceptTrailingSlash() {
    assertThat(BasePathSyntax.isValid("/scope/")).isTrue();
  }

  @Test
  void shouldRejectNull() {
    assertThat(BasePathSyntax.isValid(null)).isFalse();
  }

  @Test
  void shouldRejectEmptyString() {
    assertThat(BasePathSyntax.isValid("")).isFalse();
  }

  @Test
  void shouldRejectRelativePath() {
    assertThat(BasePathSyntax.isValid("scope")).isFalse();
  }

  @Test
  void shouldRejectRoot() {
    assertThat(BasePathSyntax.isValid("/")).isFalse();
  }

  @Test
  void shouldRejectDoubleSlash() {
    assertThat(BasePathSyntax.isValid("//")).isFalse();
  }

  @Test
  void shouldRejectInternalDoubleSlash() {
    assertThat(BasePathSyntax.isValid("/a//b")).isFalse();
  }

  @Test
  void shouldRejectWildcard() {
    assertThat(BasePathSyntax.isValid("/scope/*")).isFalse();
  }

  @Test
  void shouldRejectQuestionMark() {
    assertThat(BasePathSyntax.isValid("/a?b")).isFalse();
  }

  @Test
  void shouldRejectPathVariableBraces() {
    assertThat(BasePathSyntax.isValid("/{x}")).isFalse();
  }

  @Test
  void requireValidReturnsPathWhenValid() {
    assertThat(BasePathSyntax.requireValid("/scope", "field")).isEqualTo("/scope");
  }

  @Test
  void requireValidThrowsOnNull() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePathSyntax.requireValid(null, "myField"))
        .withMessageContaining("myField");
  }

  @Test
  void requireValidThrowsOnInvalidPath() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePathSyntax.requireValid("/{x}", "myField"))
        .withMessageContaining("myField");
  }

  @Test
  void requireValidThrowsWithHelpfulMessage() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> BasePathSyntax.requireValid("/bad*path", "basePath"))
        .withMessageContaining("basePath")
        .withMessageContaining("literal");
  }

  @Test
  void shouldAcceptHyphenatedSegment() {
    assertThatNoException()
        .isThrownBy(() -> BasePathSyntax.requireValid("/physical-tenants/t1", "f"));
  }
}
