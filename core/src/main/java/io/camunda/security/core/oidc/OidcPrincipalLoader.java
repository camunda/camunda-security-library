/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.oidc;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.JsonPathException;
import com.jayway.jsonpath.Option;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class OidcPrincipalLoader {

  private static final Configuration CONFIGURATION =
      Configuration.builder()
          // Ignore the common case that the last path element is not set
          .options(Option.DEFAULT_PATH_LEAF_TO_NULL)
          .jsonProvider(null)
          .mappingProvider(null)
          .build();

  private static final Logger LOG = LoggerFactory.getLogger(OidcPrincipalLoader.class);

  private final JsonPath usernamePath;
  private final JsonPath clientIdPath;

  // Lock to prevent concurrent evaluation of compiled JSONPath expressions. Necessary due to
  // https://github.com/json-path/JsonPath/issues/975
  private final ReentrantLock evaluationLock = new ReentrantLock();

  public OidcPrincipalLoader(final String usernameClaim, final String clientIdClaim) {
    usernamePath = usernameClaim != null ? JsonPath.compile(sanitize(usernameClaim)) : null;
    clientIdPath = clientIdClaim != null ? JsonPath.compile(sanitize(clientIdClaim)) : null;
  }

  public OidcPrincipals load(final Map<String, Object> claims) {
    evaluationLock.lock();
    try {
      return new OidcPrincipals(tryRead(claims, usernamePath), tryRead(claims, clientIdPath));
    } finally {
      evaluationLock.unlock();
    }
  }

  private static String tryRead(final Map<String, Object> claims, final JsonPath path) {
    if (path == null) {
      return null;
    }
    try {
      return switch (path.read(claims, CONFIGURATION)) {
        case final String s -> s;
        case null -> null;
        default ->
            throw new IllegalArgumentException(
                "Value for %s is not a string. Please check your OIDC configuration."
                    .formatted(path.getPath()));
      };
    } catch (final JsonPathException e) {
      // Avoid logging claim values — they may contain PII even at DEBUG. Log the path and the
      // set of claim keys only.
      LOG.debug(
          "Failed to evaluate expression {} on claims with keys {}", path, claims.keySet(), e);
      return null;
    }
  }

  private static String sanitize(final String claim) {
    // If the claim starts with a dollar sign, it is already a JSONPath expression.
    // Otherwise, wrap it with the dollar sign to denote a JSONPath. Escape backslashes and
    // single quotes in the claim name before quoting so claim names containing those characters
    // produce a valid JSONPath rather than breaking principal extraction.
    if (claim.startsWith("$")) {
      return claim;
    }
    final var escaped = claim.replace("\\", "\\\\").replace("'", "\\'");
    return "$['" + escaped + "']";
  }

  public record OidcPrincipals(String username, String clientId) {}
}
