/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.jsonpath;

/**
 * Converts a plain claim name into a valid JSONPath expression. Claim names that already start with
 * {@code $} are treated as JSONPath expressions and returned unchanged; all others are wrapped as
 * {@code $['<claim>']} with backslashes and single quotes escaped.
 */
public final class JsonPathClaimSanitizer {

  private JsonPathClaimSanitizer() {}

  public static String sanitize(final String claim) {
    if (claim.startsWith("$")) {
      return claim;
    }
    final var escaped = claim.replace("\\", "\\\\").replace("'", "\\'");
    return "$['" + escaped + "']";
  }
}
