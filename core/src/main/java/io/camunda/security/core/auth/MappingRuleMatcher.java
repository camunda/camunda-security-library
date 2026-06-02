/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.auth;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.JsonPathException;
import com.jayway.jsonpath.Option;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Matches mapping rules against claims by evaluating JSONPath expressions for each mapping rule.
 * Keeps a cache of compiled JSONPath expressions to avoid recompiling the same expressions multiple
 * times.
 */
public final class MappingRuleMatcher {
  private static final Configuration CONFIGURATION =
      Configuration.builder()
          // Ignore the common case that the last path element is not set
          .options(Option.DEFAULT_PATH_LEAF_TO_NULL)
          .jsonProvider(null)
          .mappingProvider(null)
          .build();
  private static final Logger LOG = LoggerFactory.getLogger(MappingRuleMatcher.class);

  private MappingRuleMatcher() {}

  public static <T extends MappingRule> Stream<T> matchingRules(
      final Stream<T> mappingRules, final Map<String, Object> claims) {
    if (claims == null) {
      return Stream.empty();
    }
    final EvaluationCache evaluationCache = new EvaluationCache(claims);
    return mappingRules.filter(mappingRule -> matchRule(evaluationCache, mappingRule));
  }

  private static boolean matchRule(
      final EvaluationCache evaluationCache, final MappingRule mappingRule) {
    final Object claimValue;
    try {
      claimValue = evaluationCache.evaluate(mappingRule.claimName());
    } catch (final JsonPathException e) {
      return false;
    }
    if (claimValue instanceof final Collection<?> claimValues) {
      return claimValues.contains(mappingRule.claimValue());
    }
    return mappingRule.claimValue().equals(claimValue);
  }

  private static String sanitize(final String claim) {
    // If the claim starts with a dollar sign, it is already a JSONPath expression.
    // Otherwise, wrap it with the dollar sign to denote a JSONPath. Escape backslashes and
    // single quotes in the claim name before quoting so claim names containing those characters
    // produce a valid JSONPath rather than silently failing to match.
    if (claim.startsWith("$")) {
      return claim;
    }
    final var escaped = claim.replace("\\", "\\\\").replace("'", "\\'");
    return "$['" + escaped + "']";
  }

  /**
   * A short-lived cache for evaluating many expressions against the same claims. Results are cached
   * so each expression is only evaluated once.
   */
  private static final class EvaluationCache {
    private final Map<String, Object> claims;
    private final Map<String, Object> evaluations = new HashMap<>();

    EvaluationCache(final Map<String, Object> claims) {
      this.claims = claims;
    }

    Object evaluate(final String expression) {
      return evaluations.computeIfAbsent(
          expression,
          exp -> {
            try {
              return JsonPath.compile(sanitize(exp)).read(claims, CONFIGURATION);
            } catch (final JsonPathException e) {
              // Avoid logging claim values — they may contain PII even at DEBUG. Log the
              // expression and the set of claim keys only.
              LOG.debug(
                  "Failed to evaluate expression {} on claims with keys {}",
                  exp,
                  claims.keySet(),
                  e);
              throw e;
            }
          });
    }
  }

  public interface MappingRule {
    String mappingRuleId();

    String claimName();

    String claimValue();
  }
}
