/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.context.PropertyAuthorizationEvaluator;
import io.camunda.security.api.context.TokenClaimsAuthenticationResolver;
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import io.camunda.security.core.port.out.AuthorizationCheckLatencyRecorder;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Assembles one {@link AuthorizationCheckPort} per scope for hosts that already own several {@link
 * AuthorizationScopeRepositoryPort}s and need a fail-hard, per-scope lookup instead of hand-rolling
 * the fan-out themselves. Reuses the host's existing {@link TokenClaimsAuthenticationResolver}
 * rather than building a new one. See ADR-0040 and ADR-0041.
 */
public final class ScopedAuthorizationCheckPortFactory {

  private ScopedAuthorizationCheckPortFactory() {}

  /**
   * Builds one {@link AuthorizationCheckPort} per entry in {@code scopeRepositoriesByScope},
   * sharing {@code claimsResolver}, {@code propertyEvaluators}, and both flags across every scope.
   *
   * @param scopeRepositoriesByScope one repository per scope; every scope looked up via {@link
   *     ScopedAuthorizationCheckPorts#forScope(String) forScope} must have an entry
   * @param claimsResolver the host's existing resolver, shared unchanged across every scope
   * @param propertyEvaluators evaluators shared across every scope
   * @param authorizationEnabled whether RBAC checks are globally enabled
   * @param multiTenancyChecksEnabled whether multi-tenancy checks are globally enabled
   * @return a holder exposing the fail-hard {@code forScope} lookup
   * @throws NullPointerException if {@code scopeRepositoriesByScope}, {@code claimsResolver}, or
   *     {@code propertyEvaluators} is {@code null}, or if {@code scopeRepositoriesByScope} contains
   *     a null scope key or a null repository value
   */
  public static ScopedAuthorizationCheckPorts create(
      final Map<String, AuthorizationScopeRepositoryPort> scopeRepositoriesByScope,
      final TokenClaimsAuthenticationResolver claimsResolver,
      final List<PropertyAuthorizationEvaluator<?>> propertyEvaluators,
      final boolean authorizationEnabled,
      final boolean multiTenancyChecksEnabled) {
    return create(
        scopeRepositoriesByScope,
        claimsResolver,
        propertyEvaluators,
        authorizationEnabled,
        multiTenancyChecksEnabled,
        AuthorizationCheckLatencyRecorder.noop());
  }

  /**
   * Full-control variant that also accepts an {@link AuthorizationCheckLatencyRecorder}, shared
   * across every scope's port, so non-Spring consumers can supply their own meter-backed
   * implementation. See ADR-0041.
   *
   * @throws NullPointerException if {@code scopeRepositoriesByScope}, {@code claimsResolver},
   *     {@code propertyEvaluators}, or {@code latencyRecorder} is {@code null}, or if {@code
   *     scopeRepositoriesByScope} contains a null scope key or a null repository value
   */
  public static ScopedAuthorizationCheckPorts create(
      final Map<String, AuthorizationScopeRepositoryPort> scopeRepositoriesByScope,
      final TokenClaimsAuthenticationResolver claimsResolver,
      final List<PropertyAuthorizationEvaluator<?>> propertyEvaluators,
      final boolean authorizationEnabled,
      final boolean multiTenancyChecksEnabled,
      final AuthorizationCheckLatencyRecorder latencyRecorder) {
    Objects.requireNonNull(scopeRepositoriesByScope, "scopeRepositoriesByScope must not be null");
    Objects.requireNonNull(claimsResolver, "claimsResolver must not be null");
    Objects.requireNonNull(propertyEvaluators, "propertyEvaluators must not be null");
    Objects.requireNonNull(latencyRecorder, "latencyRecorder must not be null");
    final var evaluatorRegistry = new PropertyAuthorizationEvaluatorRegistry(propertyEvaluators);
    final Map<String, AuthorizationCheckPort> checkPortsByScope = new HashMap<>();
    scopeRepositoriesByScope.forEach(
        (scope, scopeRepository) -> {
          Objects.requireNonNull(
              scope, "scopeRepositoriesByScope must not contain a null scope key");
          Objects.requireNonNull(
              scopeRepository,
              () ->
                  "scopeRepositoriesByScope must not contain a null repository for scope '"
                      + scope
                      + "'");
          checkPortsByScope.put(
              scope,
              new AuthorizationService(
                  new AuthorizationChecker(scopeRepository),
                  evaluatorRegistry,
                  authorizationEnabled,
                  multiTenancyChecksEnabled,
                  claimsResolver,
                  latencyRecorder));
        });
    return new ScopedAuthorizationCheckPorts(Map.copyOf(checkPortsByScope));
  }

  /**
   * Holder exposing a fail-hard {@link #forScope(String)} lookup; not a record, to keep that the
   * only way to read it.
   */
  public static final class ScopedAuthorizationCheckPorts {

    private final Map<String, AuthorizationCheckPort> checkPortsByScope;

    private ScopedAuthorizationCheckPorts(
        final Map<String, AuthorizationCheckPort> checkPortsByScope) {
      this.checkPortsByScope = checkPortsByScope;
    }

    /**
     * Returns the port assembled for {@code scope}.
     *
     * @throws IllegalStateException if no port was assembled for {@code scope} — never falls back
     *     to another scope's port
     */
    public AuthorizationCheckPort forScope(final String scope) {
      final var checkPort = scope == null ? null : checkPortsByScope.get(scope);
      if (checkPort == null) {
        throw new IllegalStateException(
            "No AuthorizationCheckPort assembled for scope '"
                + scope
                + "'; refusing to fall back to another scope's port, as resolving authorizations "
                + "against the wrong scope's storage would break scope isolation. This indicates a "
                + "configuration issue: the scope is unknown or has no authorization source.");
      }
      return checkPort;
    }
  }
}
