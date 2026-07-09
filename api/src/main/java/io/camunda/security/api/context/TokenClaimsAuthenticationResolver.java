/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.context;

import io.camunda.security.api.model.CamundaAuthentication;
import java.util.Map;

/**
 * Inbound port that resolves a raw OIDC/JWT claims map into a {@link CamundaAuthentication}.
 *
 * <p>Unlike {@link CamundaAuthenticationConverter}, which converts a framework-specific
 * authentication object and offers a {@code supports(...)} probe, this port has a single,
 * unconditional responsibility: turn the claims map that a host has already extracted from a token
 * into the platform's authentication context. Membership fields (groups, roles, tenants, mapping
 * rules) may be resolved lazily by the implementation.
 *
 * <p>Exposing this as an {@code api} port lets non-Spring consumers (for example the Zeebe engine)
 * depend only on the public surface for claims-to-authentication conversion — used both for
 * authorization checks and for tenant resolution — instead of the concrete {@code core}
 * implementation. See ADR-0028.
 */
public interface TokenClaimsAuthenticationResolver {

  /**
   * Resolves the given claims map into a {@link CamundaAuthentication}.
   *
   * @param claims the raw token claims (for example the decoded JWT payload)
   * @return the resolved authentication context
   * @throws IllegalArgumentException when the claims contain no identifiable principal (as
   *     determined by the implementation's configured principal claims)
   */
  CamundaAuthentication resolve(Map<String, Object> claims);
}
