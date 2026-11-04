/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import io.camunda.security.core.port.in.OidcProviderConfigurationPort;
import io.camunda.security.core.port.in.PrimaryCredentialsReloadPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.oidc.ClientCredentialsCheck;
import io.camunda.security.spring.oidc.LazyClientRegistrationRepository;
import io.camunda.security.spring.oidc.OidcAuthenticationConfigurationRepository;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import io.camunda.security.spring.security.ProtectedOidcWebappCondition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * Registers {@link PrimaryCredentialsReloadPort} for the primary OIDC webapp chain, as long as its
 * registrations and provider configurations are the library's own; a host that replaced them holds
 * the credentials itself, and the port then refuses every rotation.
 */
@Configuration
@Conditional(ProtectedOidcWebappCondition.class)
public class PrimaryCredentialsReloadConfiguration {

  @Bean
  public PrimaryCredentialsReloadPort primaryCredentialsReloadPort(
      final CamundaSecurityLibraryProperties properties,
      final ClientRegistrationRepository clientRegistrationRepository,
      final OidcProviderConfigurationPort oidcProviderConfigurationPort,
      final ScopedClientRegistrationFactory scopedClientRegistrationFactory) {
    if (clientRegistrationRepository instanceof final LazyClientRegistrationRepository lazy
        && oidcProviderConfigurationPort
            instanceof final OidcAuthenticationConfigurationRepository providers) {
      return new PrimaryCredentialsReloadService(
          properties.getAuthentication(),
          lazy,
          providers,
          scopedClientRegistrationFactory,
          new ClientCredentialsCheck());
    }
    return authentication -> {
      throw new IllegalStateException(
          "The host replaced the library's client registrations or provider configurations, so"
              + " it rotates the credentials of the primary chains itself");
    };
  }
}
