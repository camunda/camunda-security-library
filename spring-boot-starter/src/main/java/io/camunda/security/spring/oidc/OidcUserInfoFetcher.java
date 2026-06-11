/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import java.util.Map;

/**
 * Internal contract for fetching claims from an OIDC UserInfo endpoint. Kept package-private; the
 * public contract is {@link io.camunda.security.api.context.OidcClaimsProvider}.
 */
interface OidcUserInfoFetcher {

  /**
   * Calls {@code userInfoUri} with the given bearer token and returns the parsed JSON body as a
   * claims map.
   *
   * @throws OidcUserInfoFetchException on any network, HTTP, or parse failure
   */
  Map<String, Object> fetch(String userInfoUri, String bearerToken);
}
