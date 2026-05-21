/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import io.camunda.security.api.model.auth.MembershipProvider;
import java.util.Map;

/**
 * Outbound port the host implements to provide per-field membership resolution for an authenticated
 * principal. The host returns a {@link MembershipProvider} whose accessor methods the library wires
 * as {@code *Supplier} fields on the produced {@code CamundaAuthentication}, so each membership
 * type is resolved only when its field is actually read.
 *
 * <p>The library does not prescribe how the provider is implemented — eager precomputation wrapped
 * behind the accessors, fully lazy with per-method memoisation, or anything in between is a host
 * concern. The contract is just "given a principal, return an object that answers groups / roles /
 * tenants / mapping rules".
 */
public interface MembershipPort {

  /**
   * Returns a per-field accessor for an OIDC-style principal identified by token claims.
   *
   * @param tokenClaims the raw claims carried by the authentication token (may be queried by the
   *     host's provider implementation, e.g. for OIDC groups-claim extraction)
   * @param principalId the principal ID (username or client ID)
   * @param principalType USER or CLIENT
   */
  MembershipProvider createProvider(
      Map<String, Object> tokenClaims, String principalId, PrincipalType principalType);

  /** Returns a per-field accessor for a BASIC-style principal (username, no claims, USER type). */
  MembershipProvider createProviderForUser(String username);

  /** Identity type of the authenticated principal. */
  enum PrincipalType {
    USER,
    CLIENT
  }
}
