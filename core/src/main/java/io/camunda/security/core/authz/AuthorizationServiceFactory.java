/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.api.context.TokenClaimsAuthenticationResolver;
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import io.camunda.security.core.port.out.MembershipPort;
import java.util.Objects;

/**
 * Plain-Java factory that assembles the authorization graph without a Spring context.
 *
 * <p>The full assembly ({@link AuthorizationChecker} + {@link LazyTokenClaimsConverter} + {@link
 * AuthorizationService}) previously existed only as Spring {@code @Configuration} in the {@code
 * spring-boot-starter}. Per ADR-0008 (no auto-configuration), non-Spring consumers such as the
 * Zeebe engine cannot use those starter beans and had to hand-assemble the graph, naming the {@code
 * core}-internal {@link AuthorizationChecker} and {@link LazyTokenClaimsConverter} types directly.
 * This factory captures the same assembly in {@code core} so those consumers can depend only on
 * ports: {@link #create} returns an {@link Authorization} holder exposing the {@link
 * AuthorizationCheckPort} and the {@link TokenClaimsAuthenticationResolver} — both backed by the
 * <em>same</em> converter instance, matching the Spring wiring where a single converter bean is
 * shared. See ADR-0033.
 *
 * <p>The {@code spring-boot-starter} configuration classes delegate their final wiring step to this
 * factory (via {@link #newAuthorizationChecker} / {@link #newAuthorizationService}), so both entry
 * points build the graph the same way (DRY) while the Spring side keeps its per-bean override
 * points intact.
 */
public final class AuthorizationServiceFactory {

  private AuthorizationServiceFactory() {}

  /**
   * Assembles the full authorization graph from outbound ports and configuration, with no Spring
   * context. Internally builds a {@link LazyTokenClaimsConverter}, an {@link AuthorizationChecker},
   * and an {@link AuthorizationService}; callers never name those {@code core}-internal types.
   *
   * <p>Uses {@link MembershipResolutionContextPropagator#identity()} — appropriate for consumers
   * whose {@link MembershipPort} does not depend on request-scoped state. Use {@link
   * #create(AuthorizationScopeRepositoryPort, MembershipPort,
   * PropertyAuthorizationEvaluatorRegistry, boolean, boolean, String, String, boolean,
   * MembershipResolutionContextPropagator)} to supply a custom propagator.
   *
   * @param scopeRepository the host-supplied authorization store adapter
   * @param membershipPort the host-supplied membership resolution adapter
   * @param propertyEvaluatorRegistry registry of property-based evaluators (may be empty)
   * @param authorizationEnabled whether RBAC authorization checks are globally enabled
   * @param multiTenancyChecksEnabled whether multi-tenancy checks are globally enabled
   * @param usernameClaim the OIDC claim carrying the username (may be {@code null})
   * @param clientIdClaim the OIDC claim carrying the client id (may be {@code null})
   * @param preferUsernameClaim whether to prefer the username claim over the client-id claim
   * @return a holder exposing the {@link AuthorizationCheckPort} and {@link
   *     TokenClaimsAuthenticationResolver}
   */
  public static Authorization create(
      final AuthorizationScopeRepositoryPort scopeRepository,
      final MembershipPort membershipPort,
      final PropertyAuthorizationEvaluatorRegistry propertyEvaluatorRegistry,
      final boolean authorizationEnabled,
      final boolean multiTenancyChecksEnabled,
      final String usernameClaim,
      final String clientIdClaim,
      final boolean preferUsernameClaim) {
    return create(
        scopeRepository,
        membershipPort,
        propertyEvaluatorRegistry,
        authorizationEnabled,
        multiTenancyChecksEnabled,
        usernameClaim,
        clientIdClaim,
        preferUsernameClaim,
        MembershipResolutionContextPropagator.identity());
  }

  /**
   * Full-control variant of {@link #create(AuthorizationScopeRepositoryPort, MembershipPort,
   * PropertyAuthorizationEvaluatorRegistry, boolean, boolean, String, String, boolean)} that also
   * accepts a {@link MembershipResolutionContextPropagator} for hosts whose membership lookups
   * depend on request-scoped state.
   */
  public static Authorization create(
      final AuthorizationScopeRepositoryPort scopeRepository,
      final MembershipPort membershipPort,
      final PropertyAuthorizationEvaluatorRegistry propertyEvaluatorRegistry,
      final boolean authorizationEnabled,
      final boolean multiTenancyChecksEnabled,
      final String usernameClaim,
      final String clientIdClaim,
      final boolean preferUsernameClaim,
      final MembershipResolutionContextPropagator contextPropagator) {
    final var converter =
        newTokenClaimsConverter(
            usernameClaim, clientIdClaim, preferUsernameClaim, membershipPort, contextPropagator);
    final var checker = newAuthorizationChecker(scopeRepository);
    final var service =
        newAuthorizationService(
            checker,
            propertyEvaluatorRegistry,
            authorizationEnabled,
            multiTenancyChecksEnabled,
            converter);
    return new Authorization(service, converter);
  }

  /**
   * Builds the claims-to-authentication converter. Exposed so the {@code spring-boot-starter}
   * builds its {@link LazyTokenClaimsConverter} bean through the same code path as {@link #create}.
   *
   * @param usernameClaim the OIDC claim carrying the username (may be {@code null})
   * @param clientIdClaim the OIDC claim carrying the client id (may be {@code null})
   * @param preferUsernameClaim whether to prefer the username claim over the client-id claim
   * @param membershipPort the host-supplied membership resolution adapter
   * @param contextPropagator propagator that rebinds request-scoped state around deferred lookups
   */
  public static LazyTokenClaimsConverter newTokenClaimsConverter(
      final String usernameClaim,
      final String clientIdClaim,
      final boolean preferUsernameClaim,
      final MembershipPort membershipPort,
      final MembershipResolutionContextPropagator contextPropagator) {
    return new LazyTokenClaimsConverter(
        usernameClaim,
        clientIdClaim,
        preferUsernameClaim,
        Objects.requireNonNull(membershipPort, "membershipPort"),
        Objects.requireNonNull(contextPropagator, "contextPropagator"));
  }

  /**
   * Builds the scope-evaluation kernel. Exposed so the {@code spring-boot-starter} builds its
   * {@link AuthorizationChecker} bean through the same code path as {@link #create}.
   *
   * @param scopeRepository the host-supplied authorization store adapter
   */
  public static AuthorizationChecker newAuthorizationChecker(
      final AuthorizationScopeRepositoryPort scopeRepository) {
    return new AuthorizationChecker(scopeRepository);
  }

  /**
   * Builds the {@link AuthorizationService} from an already-constructed checker and converter.
   * Exposed so the {@code spring-boot-starter} builds its {@link AuthorizationService} bean through
   * the same code path as {@link #create}, while keeping the checker and converter as separately
   * host-overridable beans.
   */
  public static AuthorizationService newAuthorizationService(
      final AuthorizationChecker authorizationChecker,
      final PropertyAuthorizationEvaluatorRegistry propertyEvaluatorRegistry,
      final boolean authorizationEnabled,
      final boolean multiTenancyChecksEnabled,
      final LazyTokenClaimsConverter claimsConverter) {
    return new AuthorizationService(
        authorizationChecker,
        propertyEvaluatorRegistry,
        authorizationEnabled,
        multiTenancyChecksEnabled,
        claimsConverter);
  }

  /**
   * Holder for the assembled authorization graph. Both accessors are backed by the same converter
   * instance, mirroring the shared-converter wiring in the {@code spring-boot-starter}.
   *
   * @param authorizationCheckPort the assembled authorization check port
   * @param tokenClaimsAuthenticationResolver the claims-to-authentication resolver
   */
  public record Authorization(
      AuthorizationCheckPort authorizationCheckPort,
      TokenClaimsAuthenticationResolver tokenClaimsAuthenticationResolver) {}
}
