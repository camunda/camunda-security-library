/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.api.context.PropertyAuthorizationEvaluator;
import io.camunda.security.api.context.TokenClaimsAuthenticationResolver;
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.core.port.out.OrganizationPort;
import java.util.List;
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
 * ports: {@link #create(AuthorizationScopeRepositoryPort, MembershipPort, OrganizationPort, List,
 * boolean, boolean, String, String, boolean) create} returns an {@link AuthorizationPorts} holder
 * exposing the {@link AuthorizationCheckPort} and the {@link TokenClaimsAuthenticationResolver} —
 * both backed by the <em>same</em> converter instance, matching the Spring wiring where a single
 * converter bean is shared. See ADR-0028.
 *
 * <p>This is the entry point for non-Spring consumers only; its sole public method is {@code
 * create(...)} (two overloads differing only in the optional {@link
 * MembershipResolutionContextPropagator}), which exposes nothing but the two inbound ports. The
 * {@code spring-boot-starter} constructs its own {@link AuthorizationChecker} / {@link
 * AuthorizationService} / {@link LazyTokenClaimsConverter} beans directly (it legitimately names
 * those {@code core} types as its bean types), keeping each a separately overridable bean — it does
 * not route through this factory.
 */
public final class AuthorizationPortsFactory {

  private AuthorizationPortsFactory() {}

  /**
   * Assembles the full authorization graph from outbound ports and configuration, with no Spring
   * context. Internally builds a {@link LazyTokenClaimsConverter}, an {@link AuthorizationChecker},
   * and an {@link AuthorizationService}; callers never name those {@code core}-internal types.
   *
   * <p>Uses {@link MembershipResolutionContextPropagator#identity()} — appropriate for consumers
   * whose {@link MembershipPort} does not depend on request-scoped state. Use {@link
   * #create(AuthorizationScopeRepositoryPort, MembershipPort, OrganizationPort, List, boolean,
   * boolean, String, String, boolean, MembershipResolutionContextPropagator)} to supply a custom
   * propagator.
   *
   * @param scopeRepository the host-supplied authorization store adapter
   * @param membershipPort the host-supplied membership resolution adapter
   * @param organizationPort the host-supplied organization resolution adapter
   * @param propertyEvaluators list of property-based evaluators (may be empty)
   * @param authorizationEnabled whether RBAC authorization checks are globally enabled
   * @param multiTenancyChecksEnabled whether multi-tenancy checks are globally enabled
   * @param usernameClaim the OIDC claim carrying the username (may be {@code null})
   * @param clientIdClaim the OIDC claim carrying the client id (may be {@code null})
   * @param preferUsernameClaim whether to prefer the username claim over the client-id claim
   * @return a holder exposing the {@link AuthorizationCheckPort} and {@link
   *     TokenClaimsAuthenticationResolver}
   * @throws NullPointerException if {@code scopeRepository}, {@code membershipPort}, or {@code
   *     propertyEvaluators} is {@code null}
   */
  public static AuthorizationPorts create(
      final AuthorizationScopeRepositoryPort scopeRepository,
      final MembershipPort membershipPort,
      final OrganizationPort organizationPort,
      final List<PropertyAuthorizationEvaluator<?>> propertyEvaluators,
      final boolean authorizationEnabled,
      final boolean multiTenancyChecksEnabled,
      final String usernameClaim,
      final String clientIdClaim,
      final boolean preferUsernameClaim) {
    return create(
        scopeRepository,
        membershipPort,
        organizationPort,
        propertyEvaluators,
        authorizationEnabled,
        multiTenancyChecksEnabled,
        usernameClaim,
        clientIdClaim,
        preferUsernameClaim,
        MembershipResolutionContextPropagator.identity());
  }

  /**
   * Full-control variant of {@link #create(AuthorizationScopeRepositoryPort, MembershipPort,
   * OrganizationPort, List, boolean, boolean, String, String, boolean)} that also accepts a {@link
   * MembershipResolutionContextPropagator} for hosts whose membership lookups depend on
   * request-scoped state.
   */
  public static AuthorizationPorts create(
      final AuthorizationScopeRepositoryPort scopeRepository,
      final MembershipPort membershipPort,
      final OrganizationPort organizationPort,
      final List<PropertyAuthorizationEvaluator<?>> propertyEvaluators,
      final boolean authorizationEnabled,
      final boolean multiTenancyChecksEnabled,
      final String usernameClaim,
      final String clientIdClaim,
      final boolean preferUsernameClaim,
      final MembershipResolutionContextPropagator contextPropagator) {
    Objects.requireNonNull(scopeRepository, "scopeRepository must not be null");
    Objects.requireNonNull(membershipPort, "membershipPort must not be null");
    Objects.requireNonNull(propertyEvaluators, "propertyEvaluators must not be null");
    Objects.requireNonNull(contextPropagator, "contextPropagator must not be null");
    final var converter =
        new LazyTokenClaimsConverter(
            usernameClaim,
            clientIdClaim,
            preferUsernameClaim,
            membershipPort,
            organizationPort,
            contextPropagator);
    final var checker = new AuthorizationChecker(scopeRepository);
    final var service =
        new AuthorizationService(
            checker,
            new PropertyAuthorizationEvaluatorRegistry(propertyEvaluators),
            authorizationEnabled,
            multiTenancyChecksEnabled,
            converter);
    return new AuthorizationPorts(service, converter);
  }

  /**
   * Holder for the assembled authorization in-ports. Both accessors are backed by the same
   * converter instance, mirroring the shared-converter wiring in the {@code spring-boot-starter}.
   *
   * @param checkPort the assembled authorization check port
   * @param claimsResolver the claims-to-authentication resolver
   */
  public record AuthorizationPorts(
      AuthorizationCheckPort checkPort, TokenClaimsAuthenticationResolver claimsResolver) {}
}
