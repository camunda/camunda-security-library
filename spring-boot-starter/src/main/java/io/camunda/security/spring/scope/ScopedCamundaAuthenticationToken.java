/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import io.camunda.security.api.model.CamundaAuthentication;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * The Spring {@link Authentication} a scoped OIDC API chain produces for a successfully
 * authenticated bearer token. Unlike a plain {@link
 * org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken}, it
 * already carries the {@link CamundaAuthentication} resolved with <em>that scope's own</em> claim
 * configuration.
 *
 * <p>This is what lets two scopes that share one OIDC issuer but configure different claims resolve
 * their principals independently: the scope-correct resolution happens inside the scope's own
 * filter chain, where the path (and therefore the scope) is known, and is carried on this token
 * instead of being recomputed later by the single, path-unaware global converter. See ADR-0032 and
 * {@link ScopedCamundaAuthenticationConverter}, which unwraps this token back into its {@link
 * CamundaAuthentication}.
 *
 * <p>Deliberately <b>not</b> a {@code JwtAuthenticationToken}: the host's global {@code
 * OidcTokenAuthenticationConverter} opts in only to {@code JwtAuthenticationToken}, so keeping this
 * a sibling type means that converter never re-resolves a scoped principal with the global,
 * issuer-only map — no bean-ordering coupling required. The raw {@link Jwt} is still carried for
 * callers that need the token.
 */
public final class ScopedCamundaAuthenticationToken extends AbstractAuthenticationToken {

  private final transient Jwt jwt;
  private final transient CamundaAuthentication camundaAuthentication;

  /**
   * @param jwt the verified bearer token
   * @param camundaAuthentication the principal resolved with the scope's own claim configuration
   * @param authorities the Spring authorities for this token; CSL authorization runs off {@code
   *     camundaAuthentication} rather than these, so an empty collection is the normal case
   */
  public ScopedCamundaAuthenticationToken(
      final Jwt jwt,
      final CamundaAuthentication camundaAuthentication,
      final Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    this.jwt = Objects.requireNonNull(jwt, "jwt must not be null");
    this.camundaAuthentication =
        Objects.requireNonNull(camundaAuthentication, "camundaAuthentication must not be null");
    setAuthenticated(true);
  }

  /** Convenience constructor with no Spring authorities. */
  public ScopedCamundaAuthenticationToken(
      final Jwt jwt, final CamundaAuthentication camundaAuthentication) {
    this(jwt, camundaAuthentication, List.of());
  }

  public Jwt getToken() {
    return jwt;
  }

  public CamundaAuthentication getCamundaAuthentication() {
    return camundaAuthentication;
  }

  @Override
  public Object getCredentials() {
    return jwt.getTokenValue();
  }

  @Override
  public Object getPrincipal() {
    return jwt;
  }

  @Override
  public String getName() {
    final var username = camundaAuthentication.authenticatedUsername();
    return username != null ? username : camundaAuthentication.authenticatedClientId();
  }
}
