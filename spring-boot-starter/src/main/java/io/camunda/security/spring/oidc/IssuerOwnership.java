/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.StringUtils;

/**
 * Decides which {@link ClientRegistration} owns an issuer when several registrations declare the
 * same {@code issuer-uri}. The first registration of an issuer owns it, and every step of a request
 * asks this class, so one provider verifies, validates and maps a token.
 *
 * <p>The registrations reach a step in the order of the configuration, with the flat {@code
 * authentication.oidc} block first, so the owner of an issuer is the provider the deployment
 * declares first.
 */
final class IssuerOwnership {

  private IssuerOwnership() {}

  /**
   * @param registrations the registrations of one scope, in the order of the configuration
   * @param log the logger of the calling step, so the warning names the step that drops the
   *     configuration
   * @param ignoredConfiguration what the calling step reads from the owning registration, in the
   *     wording of the warning, for example {@code "the JWK Set URI"}
   * @return the owning registration per issuer; a registration without an {@code issuer-uri}
   *     contributes no entry
   */
  static Map<String, ClientRegistration> byIssuer(
      final Iterable<ClientRegistration> registrations,
      final Logger log,
      final String ignoredConfiguration) {
    final Map<String, ClientRegistration> owners = new LinkedHashMap<>();
    for (final ClientRegistration registration : registrations) {
      final var issuerUri = registration.getProviderDetails().getIssuerUri();
      if (!StringUtils.hasText(issuerUri)) {
        continue;
      }
      final var owner = owners.putIfAbsent(issuerUri, registration);
      if (owner != null) {
        log.warn(
            "Issuer '{}' is claimed by multiple OIDC registrations: '{}' wins, {} of '{}' is"
                + " ignored.",
            issuerUri,
            owner.getRegistrationId(),
            ignoredConfiguration,
            registration.getRegistrationId());
      }
    }
    return owners;
  }
}
