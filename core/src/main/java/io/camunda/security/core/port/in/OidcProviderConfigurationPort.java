/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.in;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.Map;

/** Inbound port for reading the merged OIDC provider configuration keyed by registration ID. */
public interface OidcProviderConfigurationPort {

  OidcConfiguration getOidcAuthenticationConfigurationById(String registrationId);

  Map<String, OidcConfiguration> getOidcAuthenticationConfigurations();
}
