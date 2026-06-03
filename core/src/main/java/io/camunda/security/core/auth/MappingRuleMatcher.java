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
import io.camunda.security.core.jsonpath.JsonPathClaimSanitizer;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Matches mapping rules against claims by evaluating JSONPath expressions for each mapping rule.
 * Keeps a per-invocation cache of evaluation results so the same expression is compiled and
 * evaluated at most once per call.
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
    return Objects.equals(mappingRule.claimValue(), claimValue);
  }

  /**
   * A short-lived cache for evaluating many expressions against the same claims. Results are cached
   * so each expression is only evaluated once — including expressions that resolve to {@code null}
   * or that consistently fail with {@link JsonPathException}.
   *
   * <p>Access is serialized via {@link #evaluationLock} because Jayway JSONPath evaluation is not
   * thread-safe under concurrent calls (see <a
   * href="https://github.com/json-path/JsonPath/issues/975">json-path/JsonPath#975</a>), and the
   * cache itself is a plain {@link HashMap}. The lock guarantees correctness even when the input
   * stream is parallel.
   */
  private static final class EvaluationCache {
    private static final Object NULL_RESULT = new Object();
    private static final Object FAILED_EVALUATION = new Object();

    private final Map<String, Object> claims;
    private final Map<String, Object> evaluations = new HashMap<>();
    private final ReentrantLock evaluationLock = new ReentrantLock();

    EvaluationCache(final Map<String, Object> claims) {
      this.claims = claims;
    }

    Object evaluate(final String expression) {
      evaluationLock.lock();
      try {
        final Object cached = evaluations.get(expression);
        if (cached != null) {
          if (cached == FAILED_EVALUATION) {
            throw new JsonPathException("Cached failure for expression: " + expression);
          }
          return cached == NULL_RESULT ? null : cached;
        }
        try {
          final Object value =
              JsonPath.compile(JsonPathClaimSanitizer.sanitize(expression))
                  .read(claims, CONFIGURATION);
          evaluations.put(expression, value == null ? NULL_RESULT : value);
          return value;
        } catch (final JsonPathException e) {
          // Avoid logging claim values — they may contain PII even at DEBUG. Log the
          // expression and the set of claim keys only.
          LOG.debug(
              "Failed to evaluate expression {} on claims with keys {}",
              expression,
              claims.keySet(),
              e);
          evaluations.put(expression, FAILED_EVALUATION);
          throw e;
        }
      } finally {
        evaluationLock.unlock();
      }
    }
  }

  public interface MappingRule {
    String mappingRuleId();

    String claimName();

    String claimValue();
  }
}
