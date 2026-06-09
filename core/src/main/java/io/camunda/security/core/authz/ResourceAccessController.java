/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.auth.SecurityContext;
import java.util.function.Function;

/**
 * Translates a {@link SecurityContext} into a {@link ResourceAccessChecks} and applies it to a
 * backend operation. Implementations select the appropriate access-control strategy (e.g. OIDC
 * authenticated, basic-auth, anonymous) and produce the {@link ResourceAccessChecks} that the
 * search/read backend uses to scope its query.
 *
 * <p>Two entry points are provided because get and search operations may require different
 * access-control semantics: get operations typically enforce strict single-resource authorization,
 * while search operations filter results to the set of authorized resources.
 *
 * <p>Multiple implementations may coexist in a host application. A delegating controller (e.g.
 * {@code ResourceAccessDelegatingController}) selects the first implementation whose {@link
 * #supports(SecurityContext)} returns {@code true}.
 */
public interface ResourceAccessController {

  /**
   * Resolves access checks for a get-by-id operation and passes them to {@code
   * resourceChecksApplier}, returning whatever the applier produces.
   *
   * @param securityContext the authentication and authorization context for the caller
   * @param resourceChecksApplier function that performs the actual backend operation given the
   *     resolved access checks
   */
  <T> T doGet(
      SecurityContext securityContext, Function<ResourceAccessChecks, T> resourceChecksApplier);

  /**
   * Resolves access checks for a search/list operation and passes them to {@code
   * resourceChecksApplier}, returning whatever the applier produces.
   *
   * @param securityContext the authentication and authorization context for the caller
   * @param resourceChecksApplier function that performs the actual backend operation given the
   *     resolved access checks
   */
  <T> T doSearch(
      SecurityContext securityContext, Function<ResourceAccessChecks, T> resourceChecksApplier);

  /**
   * Returns {@code true} if this controller can handle the given security context. Used by
   * delegating controllers to select the correct implementation at runtime.
   */
  boolean supports(SecurityContext securityContext);

  /**
   * Returns {@code true} when the authentication represents an anonymous (unauthenticated) caller.
   * Default implementation delegates to {@link CamundaAuthentication#isAnonymous()}.
   */
  default boolean isAnonymousAuthentication(final CamundaAuthentication authentication) {
    return authentication.isAnonymous();
  }
}
