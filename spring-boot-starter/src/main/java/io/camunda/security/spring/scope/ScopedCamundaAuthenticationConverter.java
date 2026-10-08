/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import io.camunda.security.api.context.CamundaAuthenticationConverter;
import io.camunda.security.api.model.CamundaAuthentication;
import org.springframework.security.core.Authentication;

/**
 * Unwraps a {@link ScopedCamundaAuthenticationToken} back into the {@link CamundaAuthentication} it
 * carries — the principal a scoped OIDC API chain already resolved with that scope's own claim
 * configuration.
 *
 * <p>Registered as a {@link CamundaAuthenticationConverter} bean so {@code
 * DefaultCamundaAuthenticationProvider}'s delegating converter routes scoped tokens here. Because
 * it supports only {@link ScopedCamundaAuthenticationToken} — a sibling of {@code
 * JwtAuthenticationToken}, not a subtype — it never competes with a host's global {@code
 * OidcTokenAuthenticationConverter}, so no bean ordering is required between them. See ADR-0033.
 */
public final class ScopedCamundaAuthenticationConverter
    implements CamundaAuthenticationConverter<Authentication> {

  @Override
  public boolean supports(final Authentication authentication) {
    return authentication instanceof ScopedCamundaAuthenticationToken;
  }

  @Override
  public CamundaAuthentication convert(final Authentication authentication) {
    return ((ScopedCamundaAuthenticationToken) authentication).getCamundaAuthentication();
  }
}
