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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Default implementation of {@link OidcProviderConfigurationPort}. Merges the flat {@code
 * authentication.oidc.*} block and the {@code authentication.providers.oidc.*} map into a single
 * provider map keyed by registrationId. The flat block contributes one entry under its {@link
 * OidcConfiguration#getRegistrationId()} when {@code clientId} is set; provider entries are put on
 * top so a colliding provider id overwrites the flat entry.
 */
public class OidcAuthenticationConfigurationRepository implements OidcProviderConfigurationPort {

  public static final String REGISTRATION_ID = OidcConfiguration.DEFAULT_REGISTRATION_ID;

  private final ScopedClientRegistrationFactory clientRegistrationFactory;
  private final Map<String, OidcConfiguration> providers;

  public OidcAuthenticationConfigurationRepository(
      final CamundaSecurityLibraryProperties securityConfiguration,
      final ScopedClientRegistrationFactory clientRegistrationFactory) {
    this.clientRegistrationFactory = clientRegistrationFactory;
    providers = initializeProviders(securityConfiguration);
  }

  protected Map<String, OidcConfiguration> initializeProviders(
      final CamundaSecurityLibraryProperties securityConfiguration) {
    return clientRegistrationFactory.flatten(securityConfiguration.getAuthentication());
  }

  @Override
  public OidcConfiguration getOidcAuthenticationConfigurationById(final String registrationId) {
    return providers.get(registrationId);
  }

  /**
   * Returns an immutable map of all OIDC authentication configurations keyed by registration ID.
   *
   * <p>The map keeps the order of the configuration, with the flat block first, which is the order
   * of the merge. Where two providers declare the same issuer, the steps of a request take the
   * first of them, so the order decides which provider owns that issuer and the map must not
   * scramble it.
   *
   * <p>The returned map is a defensive copy and cannot be modified by callers. The contained {@link
   * OidcConfiguration} instances are shared references and may still be mutable.
   *
   * @return an immutable map of registration IDs to {@link OidcConfiguration} objects; never {@code
   *     null}
   */
  @Override
  public Map<String, OidcConfiguration> getOidcAuthenticationConfigurations() {
    return Collections.unmodifiableMap(new LinkedHashMap<>(providers));
  }
}
