/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.context;

import java.util.Map;

/**
 * Resolves the final claims map used for authentication from a validated JWT's claims and raw token
 * value. Implementations may augment JWT claims with a UserInfo response. Fail-open implementations
 * return JWT-only claims on failure; fail-closed implementations propagate exceptions.
 */
public interface OidcClaimsProvider {

  Map<String, Object> claimsFor(Map<String, Object> jwtClaims, String tokenValue);
}
