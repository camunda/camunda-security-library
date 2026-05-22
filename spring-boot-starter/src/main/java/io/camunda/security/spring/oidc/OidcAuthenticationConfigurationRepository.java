/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.port.in.OidcProviderConfigurationPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.util.StringUtils;

/**
 * Default implementation of {@link OidcProviderConfigurationPort}. Merges the flat {@code
 * authentication.oidc.*} block and the {@code authentication.providers.oidc.*} map into a single
 * provider map keyed by registrationId. The flat block contributes one entry under its {@link
 * OidcConfiguration#getRegistrationId()} when {@code clientId} is set; provider entries are put on
 * top so a colliding provider id overwrites the flat entry.
 */
public class OidcAuthenticationConfigurationRepository implements OidcProviderConfigurationPort {

  public static final String REGISTRATION_ID = OidcConfiguration.DEFAULT_REGISTRATION_ID;

  private final Map<String, OidcConfiguration> providers;

  public OidcAuthenticationConfigurationRepository(
      final CamundaSecurityLibraryProperties securityConfiguration) {
    providers = initializeProviders(securityConfiguration);
  }

  protected Map<String, OidcConfiguration> initializeProviders(
      final CamundaSecurityLibraryProperties securityConfiguration) {
    final var authentication = securityConfiguration.getAuthentication();
    final var flat = authentication.getOidc();
    final Map<String, OidcConfiguration> result = new LinkedHashMap<>();
    if (StringUtils.hasText(flat.getClientId())) {
      result.put(flat.getRegistrationId(), flat);
    }
    result.putAll(authentication.getProviders().getOidc());
    return result;
  }

  @Override
  public OidcConfiguration getOidcAuthenticationConfigurationById(final String registrationId) {
    return providers.get(registrationId);
  }

  @Override
  public Map<String, OidcConfiguration> getOidcAuthenticationConfigurations() {
    return providers;
  }
}
