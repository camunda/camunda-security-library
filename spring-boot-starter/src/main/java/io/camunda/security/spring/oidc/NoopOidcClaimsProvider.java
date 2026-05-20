/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.context.OidcClaimsProvider;
import java.util.Map;

/**
 * Pass-through {@link OidcClaimsProvider}. Returns the JWT claims unchanged without calling the
 * UserInfo endpoint. Used when UserInfo augmentation is disabled or unavailable.
 */
public final class NoopOidcClaimsProvider implements OidcClaimsProvider {

  @Override
  public Map<String, Object> claimsFor(
      final Map<String, Object> jwtClaims, final String tokenValue) {
    return jwtClaims;
  }
}
