/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.oidc;

import java.util.Map;

/** Configures named authentication providers keyed by provider identifier. */
public class OidcProvidersConfiguration {

  private Map<String, OidcConfiguration> oidc;

  public Map<String, OidcConfiguration> getOidc() {
    return oidc;
  }

  public void setOidc(final Map<String, OidcConfiguration> oidc) {
    this.oidc = oidc;
  }
}
