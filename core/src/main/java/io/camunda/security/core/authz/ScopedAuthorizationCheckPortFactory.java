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
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Plain-Java factory that assembles one {@link AuthorizationCheckPort} per <em>scope</em> — an
 * opaque key {@code core} does not attach meaning to (a host may map it to, for example, a physical
 * tenant) — sharing a single host-supplied {@link TokenClaimsAuthenticationResolver} across every
 * scope rather than building one per scope.
 *
 * <p>Unlike {@link AuthorizationPortsFactory}, which assembles a single-scope graph for non-Spring
 * consumers, this factory exists for hosts (typically Spring) that already own several {@link
 * AuthorizationScopeRepositoryPort} instances — one per scope — and need a fail-hard, per-scope
 * {@link AuthorizationCheckPort} lookup instead of hand-rolling the fan-out and the per-call {@link
 * AuthorizationService} construction themselves. See ADR-0040.
 *
 * <p>Deliberately takes the host's <em>existing</em> {@link TokenClaimsAuthenticationResolver}
 * rather than building one from a {@link io.camunda.security.core.port.out.MembershipPort}: a host
 * wiring several scope-specific {@link AuthorizationCheckPort}s already has one converter bean
 * shared across the rest of its authentication pipeline, and building a second one here would
 * silently diverge from it (see ADR-0028's rejected alternative on this point, and ADR-0040 for why
 * this factory is not that). The resolver is only stored, never invoked during {@link #create(Map,
 * TokenClaimsAuthenticationResolver, List, boolean, boolean) create}.
 */
public final class ScopedAuthorizationCheckPortFactory {

  private ScopedAuthorizationCheckPortFactory() {}

  /**
   * Assembles one {@link AuthorizationCheckPort} per entry in {@code scopeRepositoriesByScope},
   * each backed by its own {@link AuthorizationChecker} but sharing the given {@code
   * propertyEvaluators}, flags, and {@code claimsResolver}. Callers never name {@code
   * core}-internal types.
   *
   * @param scopeRepositoriesByScope one {@link AuthorizationScopeRepositoryPort} per scope; every
   *     scope the host will ever look up via {@link ScopedAuthorizationCheckPorts#forScope(String)
   *     forScope} must have an entry here, including the host's notion of a "default" scope
   * @param claimsResolver the host's existing claims-to-authentication resolver, shared unchanged
   *     across every scope's {@link AuthorizationCheckPort}
   * @param propertyEvaluators list of property-based evaluators (may be empty), shared across every
   *     scope
   * @param authorizationEnabled whether RBAC authorization checks are globally enabled
   * @param multiTenancyChecksEnabled whether multi-tenancy checks are globally enabled
   * @return a holder exposing a fail-hard {@link ScopedAuthorizationCheckPorts#forScope(String)}
   *     lookup
   * @throws NullPointerException if {@code scopeRepositoriesByScope}, {@code claimsResolver}, or
   *     {@code propertyEvaluators} is {@code null}
   */
  public static ScopedAuthorizationCheckPorts create(
      final Map<String, AuthorizationScopeRepositoryPort> scopeRepositoriesByScope,
      final TokenClaimsAuthenticationResolver claimsResolver,
      final List<PropertyAuthorizationEvaluator<?>> propertyEvaluators,
      final boolean authorizationEnabled,
      final boolean multiTenancyChecksEnabled) {
    Objects.requireNonNull(scopeRepositoriesByScope, "scopeRepositoriesByScope must not be null");
    Objects.requireNonNull(claimsResolver, "claimsResolver must not be null");
    Objects.requireNonNull(propertyEvaluators, "propertyEvaluators must not be null");
    final var evaluatorRegistry = new PropertyAuthorizationEvaluatorRegistry(propertyEvaluators);
    final Map<String, AuthorizationCheckPort> checkPortsByScope = new HashMap<>();
    scopeRepositoriesByScope.forEach(
        (scope, scopeRepository) ->
            checkPortsByScope.put(
                scope,
                new AuthorizationService(
                    new AuthorizationChecker(scopeRepository),
                    evaluatorRegistry,
                    authorizationEnabled,
                    multiTenancyChecksEnabled,
                    claimsResolver)));
    return new ScopedAuthorizationCheckPorts(Map.copyOf(checkPortsByScope));
  }

  /**
   * Holder for the assembled per-scope {@link AuthorizationCheckPort}s. Deliberately not a {@code
   * record} exposing the backing map: a caller reading the map directly would get a silent {@code
   * null} on an unknown scope instead of the fail-hard behaviour {@link #forScope(String)}
   * guarantees.
   */
  public static final class ScopedAuthorizationCheckPorts {

    private final Map<String, AuthorizationCheckPort> checkPortsByScope;

    private ScopedAuthorizationCheckPorts(
        final Map<String, AuthorizationCheckPort> checkPortsByScope) {
      this.checkPortsByScope = checkPortsByScope;
    }

    /**
     * Returns the {@link AuthorizationCheckPort} assembled for {@code scope}.
     *
     * @throws IllegalStateException if no port was assembled for {@code scope}; this never falls
     *     back to another scope's port, as doing so would break scope isolation
     */
    public AuthorizationCheckPort forScope(final String scope) {
      final var checkPort = checkPortsByScope.get(scope);
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
