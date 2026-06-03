/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.jsonpath;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class JsonPathClaimSanitizerTest {

  @Test
  void wrapsPlainClaimNameInBracketNotation() {
    assertThat(JsonPathClaimSanitizer.sanitize("sub")).isEqualTo("$['sub']");
  }

  @Test
  void leavesExistingJsonPathExpressionUnchanged() {
    assertThat(JsonPathClaimSanitizer.sanitize("$.sub")).isEqualTo("$.sub");
    assertThat(JsonPathClaimSanitizer.sanitize("$['sub']")).isEqualTo("$['sub']");
    assertThat(JsonPathClaimSanitizer.sanitize("$.realm.roles")).isEqualTo("$.realm.roles");
  }

  @Test
  void escapesBackslashesAndSingleQuotesInPlainClaimNames() {
    assertThat(JsonPathClaimSanitizer.sanitize("weird\\'key")).isEqualTo("$['weird\\\\\\'key']");
    assertThat(JsonPathClaimSanitizer.sanitize("a'b")).isEqualTo("$['a\\'b']");
    assertThat(JsonPathClaimSanitizer.sanitize("a\\b")).isEqualTo("$['a\\\\b']");
  }
}
