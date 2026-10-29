/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import com.nimbusds.jose.jwk.JWK;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.port.in.OidcProviderConfigurationPort;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * The {@code private_key_jwt} signing keys of one scope generation, read from the scope's own
 * provider configuration and kept once read.
 *
 * <p>Reading a keystore for every token request would be wasteful, so a key is kept after its first
 * use — but by the generation, not by the application: a rotated keystore is read again by the
 * scope's next generation, and the keys of a retired generation go with it. The cluster-wide {@link
 * AssertionJwkProvider} bean cannot serve a scope, because the cluster-wide port it reads does not
 * know the scope's registrations.
 */
public final class ScopedAssertionJwks implements Function<ClientRegistration, JWK> {

  private final AssertionJwkProvider provider;
  private final Map<String, JWK> resolved = new ConcurrentHashMap<>();

  public ScopedAssertionJwks(final Map<String, OidcConfiguration> providers) {
    provider = new AssertionJwkProvider(port(providers));
  }

  @Override
  public JWK apply(final ClientRegistration registration) {
    return resolved.computeIfAbsent(registration.getRegistrationId(), provider::createJwk);
  }

  /** How many keys this generation has read. */
  public int resolvedCount() {
    return resolved.size();
  }

  private static OidcProviderConfigurationPort port(
      final Map<String, OidcConfiguration> providers) {
    final Map<String, OidcConfiguration> byRegistrationId =
        Collections.unmodifiableMap(new LinkedHashMap<>(providers));
    return new OidcProviderConfigurationPort() {
      @Override
      public OidcConfiguration getOidcAuthenticationConfigurationById(final String registrationId) {
        return byRegistrationId.get(registrationId);
      }

      @Override
      public Map<String, OidcConfiguration> getOidcAuthenticationConfigurations() {
        return byRegistrationId;
      }
    };
  }
}
