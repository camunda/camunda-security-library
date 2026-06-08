/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.reader;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.auth.SecurityContext;
import java.util.function.Function;

public interface ResourceAccessController {

  <T> T doGet(
      SecurityContext securityContext, Function<ResourceAccessChecks, T> resourceChecksApplier);

  <T> T doSearch(
      SecurityContext securityContext, Function<ResourceAccessChecks, T> resourceChecksApplier);

  boolean supports(SecurityContext securityContext);

  default boolean isAnonymousAuthentication(final CamundaAuthentication authentication) {
    return authentication.isAnonymous();
  }
}
