/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * The claims converter of a token's issuer for a host's own {@code ClientRegistrationRepository},
 * routed as the decoder of {@code OidcWebappClientBeansConfiguration#jwtDecoder} routes the token:
 * by the issuer each registration carries, first registration first. A registration that discovery
 * resolved to another issuer than the configured issuer-uri, such as {@code https://idp/realm} for
 * {@code https://idp/realm/}, keeps the claim settings of its provider, and a registration that no
 * provider configures gets none.
 *
 * <p>The registrations are read on the first lookup, as the decoder reads them, so building the
 * bean starts no discovery.
 */
final class RegisteredIssuerClaimsConverters implements Function<String, LazyTokenClaimsConverter> {

  private static final Logger LOG = LoggerFactory.getLogger(RegisteredIssuerClaimsConverters.class);

  private final Iterable<ClientRegistration> registrations;
  private final Map<String, LazyTokenClaimsConverter> byRegistrationId;
  private volatile Map<String, LazyTokenClaimsConverter> byIssuer;

  RegisteredIssuerClaimsConverters(
      final Iterable<ClientRegistration> registrations,
      final Map<String, LazyTokenClaimsConverter> byRegistrationId) {
    this.registrations = registrations;
    this.byRegistrationId = Map.copyOf(byRegistrationId);
  }

  /**
   * @return the converter of the registration that owns {@code issuer}, or {@code null} when none
   *     does or no provider configures it
   */
  @Override
  public LazyTokenClaimsConverter apply(final String issuer) {
    return byIssuer().get(issuer);
  }

  private Map<String, LazyTokenClaimsConverter> byIssuer() {
    var result = byIssuer;
    if (result == null) {
      synchronized (this) {
        result = byIssuer;
        if (result == null) {
          result = resolve();
          byIssuer = result;
        }
      }
    }
    return result;
  }

  private Map<String, LazyTokenClaimsConverter> resolve() {
    final Map<String, LazyTokenClaimsConverter> result = new HashMap<>();
    IssuerOwnership.byIssuer(registrations, LOG, "the claim configuration")
        .forEach(
            (issuer, registration) -> {
              final var converter = byRegistrationId.get(registration.getRegistrationId());
              if (converter != null) {
                result.put(issuer, converter);
              }
            });
    return Map.copyOf(result);
  }
}
